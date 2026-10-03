@file:Suppress(
    "TooManyFunctions",
    "LargeClass",
    "CyclomaticComplexMethod",
    "LongMethod",
    "NestedBlockDepth",
    "ReturnCount",
    "ComplexCondition",
    "LoopWithTooManyJumpStatements",
    "MagicNumber",
)

package one.rarebit.voidwhichbinds.roster

import one.rarebit.voidwhichbinds.Ed25519Verifier
import one.rarebit.voidwhichbinds.IntList
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.OpDag
import one.rarebit.voidwhichbinds.crypto.GoStrings

/**
 * One [Roster.evaluate] call's working state: a structure-for-structure port of
 * void-which-binds-go `roster/evaluate.go` (ADR-0014 amended #80, #99, #106, the Phase 3
 * G0 errata and the #122 history cap; ADR-0015 amended G3). Each op is judged from its
 * own closure:
 *
 *  1. Structure: parse, typ, fields, signatures, prev integrity, and every signature's
 *     bprev must name person ops the evaluator holds (`missing_person_context`).
 *  2. Authority: the authority key, or a primary signature that counts under the
 *     cross-identity rule (a valid key of an admin person in the view of the op's
 *     closure, at its iat, with sovereign devices judged by
 *     [Membership.Log.memberAt] over bprev). A self-remove needs only a valid key.
 *  3. Quorum: k = min(2, max(H(X), 1)) distinct admin persons, plus two keys when
 *     H(X) ≤ 1, where H(X) is the op's own admin high-water.
 *  4. Least privilege over concurrency.
 *  5. Resolution: a person's role is the minimum over their causal frontier.
 *  6. History cap (#122): at most [Roster.MAX_LOG_OPS] ops are evaluated; a larger set
 *     is judged by its anchored history ([applyCap]).
 *
 * A *frame* is a downward-closed set of valid ops evaluated as if it were the whole
 * roster; "the roster view of X's closure" is the frame closure(X). Since #122 a frame
 * is judged lazily (its chain when made, an op's verdict only when a rule asks, four
 * bits per op in a closure frame), shares the DAG's ancestor bitset as its set, and the
 * rules read the ops they need through kind indexes. Names, memo keys and evaluation
 * order follow the Go source so the two can be read side by side; where Go compares op
 * pointers this compares hashes. Where Go's goroutine stacks would simply grow, this
 * port settles the deep recursions (authority clause (1), #106's qualifying grants,
 * independence) oldest first, so a long history is judged on a small mobile stack.
 */
internal class RosterEvaluator(
    private val org: String,
    private val persons: ((String) -> List<String>)?,
    private val verifier: Ed25519Verifier,
) {
    /** The pinned founding op's hash: the root of independence. */
    var founding: String = ""

    /**
     * One person's log prepared for MemberAt questions, or null when it cannot be
     * (an unusable usr, or over the cap).
     */
    private class PersonLog(val log: Membership.Log?)

    private val logs = HashMap<String, PersonLog>()
    private val memberAt = HashMap<String, MemberAt>()

    private var dag = newDag()
    private var ops = HashMap<String, RosterOp>() // valid ops, final
    private val rejected = HashMap<String, String>()

    // Indexes over the valid ops, filled as resolve accepts them, so a rule that wants
    // one kind of op in a closure looks only at that kind.
    private val adminSets = ArrayList<Ent>() // `set`s to admin or owner: the only possible weak grants
    private val resets = ArrayList<Ent>() // `reset`s
    private val authReroots = ArrayList<RosterOp>() // authority-shape re-roots
    private val authResolve = ArrayList<RosterOp>() // authority-shape resolves
    private val rerootsBy = HashMap<String, MutableList<RosterOp>>() // authority-shape re-roots by `by`
    private val rerootsTo = HashMap<String, MutableList<RosterOp>>() // authority-shape re-roots by `succ`
    private val withMem = HashMap<String, MutableList<RosterOp>>() // ops by `mem`
    private val memOps = HashMap<String, MutableList<Ent>>() // `set`s and `remove`s by `mem`
    private val keyOps = HashMap<String, MutableList<Ent>>() // `enrol`s and `unenrol`s by `mem`
    private val personReds = ArrayList<Ent>() // persons' reductions (isReduction)

    // Rule 4 and the high-water read a frame only through the ops in it that are
    // concurrent with the op judged and are admin grants or reductions ("relevant" ops).
    // A person's op concurrent with no relevant op of the set has the same base and
    // verdict in every frame: isolated, memoised once (#122). resolve settles ops oldest
    // first and only ever judges an op in a frame of ops settled before the current one,
    // so iso is kept for the ops settled so far and cleared as each relevant op arrives.
    private var iso = BooleanArray(0) // by topological index
    private val isoLive = IntList() // the ops iso still holds for
    private val relevant = IntList() // the relevant ops settled so far
    private var isoMemo = arrayOfNulls<String>(0) // an isolated op's verdict, once settled
    private var isoDone = BooleanArray(0)

    // Likewise for H(X) alone, whose frame enters only through the admin grants
    // concurrent with X: with none anywhere, H(X) is the same in every frame.
    private var hwIsoOK = BooleanArray(0)
    private val hwIsoLive = IntList()
    private val grants = IntList() // the admin grants settled so far
    private var hwIsoMemo = IntArray(0) // H(X) when hwIsoOK, once settled (-1 before)

    private val redsOf = HashMap<String, MutableList<Ent>>() // persons' reductions, by the person each reduces
    private val authRedsOf = HashMap<String, MutableList<Ent>>() // authority-shape reductions, by person reduced
    private val ownerChg = HashMap<String, Boolean>()
    private val qsum = HashMap<String, QuorumSum>()
    private val nums = HashMap<String, Int>()
    private val primary = HashMap<String, Boolean>()
    private val frameOf = HashMap<String, Frame>() // each op's closure frame
    private var built = 0 // closure frames exist for every op numbered below this

    private val frames = HashMap<String, Frame>()
    private val sigs = HashMap<String, List<SigKey>>()
    private val counted = HashMap<String, Map<String, Set<String>>>()
    private val grant = HashMap<String, Boolean>()
    private val pweak = HashMap<String, Boolean>()
    private val auth = HashMap<String, Boolean>()
    private val admins = HashMap<String, Set<String>>()
    private val er = HashMap<String, Set<String>>()
    private val qualify = HashMap<String, Boolean>()
    private val resetsIn = HashMap<String, List<Ent>>()
    private val indep = HashMap<String, Boolean>()
    private val indepG = HashMap<String, Boolean>()
    private val indepWarm = HashSet<String>() // (op, context) pairs whose causal past has had independence settled

    private data class SigKey(val usr: String, val by: String)

    /** A valid op and its number in the DAG's topological index. */
    private class Ent(val o: RosterOp, val i: Int)

    private enum class MemberAt { MEMBER, NOT_MEMBER, MISSING_CONTEXT, ERROR }

    private fun newDag() = OpDag<RosterOp>({ it.prev }, { child, parent -> parent.iat <= child.iat })

    // --- person logs -------------------------------------------------------------

    /**
     * [Membership.Log.memberAt] over the person-op set L(usr), memoised (Go `memberOf`).
     * The log is prepared once per person, not once per question. A log over
     * [Membership.MAX_LOG_OPS] is an error, like an unusable usr: no signature of that
     * person counts, and the context still resolves.
     */
    private fun memberOf(usr: String, by: String, bprev: List<String>, at: Long): MemberAt {
        val k = usr + "|" + by + "|" + bprev.joinToString(",") + "|" + at
        memberAt[k]?.let { return it }
        val r = if (!RosterWire.isEdKey(usr) || at == 0L) {
            MemberAt.ERROR // enrolment.ErrNoUser / a zero clock
        } else {
            val pl = logs.getOrPut(usr) {
                PersonLog(
                    try {
                        Membership.newLog(usr, persons?.invoke(usr).orEmpty(), verifier)
                    } catch (_: IllegalArgumentException) {
                        null // ErrNoUser, or ErrLogTooLarge
                    },
                )
            }
            val log = pl.log
            if (log == null) {
                MemberAt.ERROR
            } else {
                try {
                    if (log.memberAt(by, bprev, at)) MemberAt.MEMBER else MemberAt.NOT_MEMBER
                } catch (_: Membership.MissingContextException) {
                    MemberAt.MISSING_CONTEXT
                } catch (_: IllegalArgumentException) {
                    MemberAt.ERROR
                }
            }
        }
        memberAt[k] = r
        return r
    }

    // --- rule 1 ------------------------------------------------------------------

    /** Rule 1's op-local half: parse, typ, fields, primary signature, org, and every signature's person context. */
    fun ingest(tokens: List<String>) {
        for (raw in tokens) {
            val tok = GoStrings.trimSpace(raw)
            if (tok.isEmpty()) continue
            val h = Roster.opHash(tok)
            if (rejected.containsKey(h) || dag.has(h)) continue
            val o = try {
                Roster.verify(tok, verifier)
            } catch (e: RosterException) {
                rejected[h] = when (e.failure) {
                    RosterException.Failure.WRONG_TYPE -> RosterReason.WRONG_TYPE
                    RosterException.Failure.BAD_SIGNATURE -> RosterReason.BAD_SIGNATURE
                    else -> RosterReason.MALFORMED
                }
                continue
            } catch (@Suppress("TooGenericExceptionCaught") _: Throwable) {
                // Anything else Roster.verify throws is malformed, as in Membership.evaluate:
                // one junk token never takes the roster down.
                rejected[h] = RosterReason.MALFORMED
                continue
            }
            when {
                o.org != org -> {
                    rejected[h] = RosterReason.FOREIGN_USER
                    continue
                }

                o.mem == org -> {
                    rejected[h] = RosterReason.MALFORMED // the org is never its own member
                    continue
                }
            }
            if (!contextResolves(o)) {
                rejected[h] = RosterReason.MISSING_PERSON_CONTEXT
                continue
            }
            dag.add(h, o)
        }
    }

    /**
     * Offer [o] under [hash] straight to the DAG, past [ingest]'s checks: Go
     * `CheckDraftClosure`'s `e.dag.Add`, for a draft that has no token (or signatures) yet.
     */
    fun addUnchecked(hash: String, o: RosterOp) {
        dag.add(hash, o)
    }

    /** The rule-1 rejection [resolve] recorded for [hash], or null. */
    fun rejectedReason(hash: String): String? = rejected[hash]

    /**
     * The cross-identity rule's first bullet: every hash in every signature's bprev names
     * a structurally valid op of L(usr) issued no later than the roster op.
     */
    private fun contextResolves(o: RosterOp): Boolean {
        fun check(by: String, usr: String, bprev: List<String>): Boolean {
            if (bprev.isEmpty() || usr.startsWith(Roster.MANAGED_PREFIX)) return true
            return memberOf(usr, by, bprev, o.iat) != MemberAt.MISSING_CONTEXT
        }
        if (!check(o.by, o.usr, o.bprev)) return false
        for (c in o.cosig) {
            if (!check(c.by, c.usr, c.bprev)) return false
        }
        return true
    }

    /**
     * ADR-0014's history cap (see [Roster.MAX_LOG_OPS]). A set of at most [maxOps]
     * well-formed ops is evaluated whole. A larger one keeps only its anchored history and
     * rejects the rest as unanchored; if that history is itself over maxOps the set is
     * refused with [RosterException.Failure.LOG_TOO_LARGE]. The walk is iterative.
     */
    fun applyCap(maxOps: Int) {
        val pend = dag.pending()
        if (pend.size <= maxOps) return
        val anchored = anchoredOps(pend)
        val keep = HashSet<String>()
        val stack = ArrayList<String>(anchored)
        while (stack.isNotEmpty()) {
            val h = stack.removeAt(stack.size - 1)
            val o = pend[h] ?: continue
            if (!keep.add(h)) continue
            stack.addAll(o.prev)
        }
        if (keep.size > maxOps) {
            throw RosterException(
                RosterException.Failure.LOG_TOO_LARGE,
                "roster: the roster log's anchored history exceeds MaxLogOps: ${keep.size} anchored ops > $maxOps",
            )
        }
        val d = newDag()
        for ((h, o) in pend) {
            if (h in keep) d.add(h, o) else rejected[h] = RosterReason.UNANCHORED
        }
        dag = d
    }

    /**
     * The cap's anchoring fixpoint over the well-formed ops (see [Roster.MAX_LOG_OPS]),
     * by worklist: an op that is not yet anchored waits on what would anchor it (an
     * authority key, a person being named, a managed key being enrolled) and is tried
     * again when that arrives. It ignores prev, time, verdicts and removal, so it
     * over-approximates: every op an evaluation could find effective, count toward a
     * high-water, or apply to the authority chain is anchored (a self-remove by someone
     * never named aside).
     */
    private fun anchoredOps(pend: Map<String, RosterOp>): Set<String> {
        val authKeys = hashSetOf(org)
        val named = HashSet<String>() // persons an anchored `set` names
        val enrolled = HashSet<String>() // usr|key an anchored `enrol` enrols
        val anchored = HashSet<String>()
        val waiting = HashMap<String, MutableList<RosterOp>>()
        val fired = ArrayList<String>()
        val cosigOK = HashMap<String, BooleanArray>()
        fun tryOp(o: RosterOp) {
            if (o.hash in anchored) return
            var ok = o.usr.isEmpty() && o.by in authKeys
            val waits = ArrayList<String>()
            if (o.usr.isEmpty() && !ok) waits.add("a|" + o.by)
            fun plausible(by: String, usr: String, bprev: List<String>) {
                when {
                    ok || usr.isEmpty() -> {}

                    usr !in named -> waits.add("p|$usr")

                    usr.startsWith(Roster.MANAGED_PREFIX) ->
                        if ("$usr|$by" in enrolled) ok = true else waits.add("k|$usr|$by")

                    by == usr -> ok = bprev.isEmpty()

                    else -> ok = memberOf(usr, by, bprev, o.iat) == MemberAt.MEMBER
                }
            }
            plausible(o.by, o.usr, o.bprev)
            val verified = cosigOK.getOrPut(o.hash) {
                BooleanArray(o.cosig.size) { Roster.verifyCosig(o, o.cosig[it], verifier) }
            }
            for ((i, c) in o.cosig.withIndex()) {
                if (verified[i]) plausible(c.by, c.usr, c.bprev)
            }
            if (!ok) {
                for (w in waits) waiting.getOrPut(w) { ArrayList() }.add(o)
                return
            }
            anchored.add(o.hash)
            when {
                o.kind == OpKind.REROOT && o.usr.isEmpty() && o.succ !in authKeys -> {
                    authKeys.add(o.succ)
                    fired.add("a|" + o.succ)
                }

                o.kind == OpKind.SET && o.mem !in named -> {
                    named.add(o.mem)
                    fired.add("p|" + o.mem)
                }

                o.kind == OpKind.ENROL && (o.mem + "|" + o.key) !in enrolled -> {
                    enrolled.add(o.mem + "|" + o.key)
                    fired.add("k|" + o.mem + "|" + o.key)
                }
            }
        }
        for (o in pend.values) tryOp(o)
        while (fired.isNotEmpty()) {
            val ev = fired.removeAt(fired.size - 1)
            val ws = waiting.remove(ev) ?: continue
            for (o in ws) tryOp(o)
        }
        return anchored
    }

    /**
     * Rule 1's set-dependent half: prev integrity, then the rules that need the op's
     * closure (an `exp` only on a grant; ADR-0015's key-reuse rules). Everything citing a
     * malformed op is bad_prev. The DAG's topological index is (depth, hash) order: every
     * op is judged after everything it cites.
     */
    fun resolve() {
        for (h in dag.resolveAll()) rejected[h] = RosterReason.BAD_PREV
        val cand = dag.valid()
        ops = HashMap(cand.size)
        val n = dag.size()
        iso = BooleanArray(n)
        isoMemo = arrayOfNulls(n)
        isoDone = BooleanArray(n)
        hwIsoOK = BooleanArray(n)
        hwIsoMemo = IntArray(n)
        for (i in 0 until n) {
            val h = dag.hash(i)
            val o = cand.getValue(h)
            if (o.prev.any { !ops.containsKey(it) }) {
                rejected[h] = RosterReason.BAD_PREV
                continue
            }
            ops[h] = o
            if (reusesKey(o) || (o.kind == OpKind.SET && o.exp != 0L && !isGrant(o))) {
                ops.remove(h)
                rejected[h] = RosterReason.MALFORMED
                continue
            }
            index(o)
        }
    }

    private fun concIdx(a: Int, b: Int): Boolean = !dag.precedesIndex(a, b) && !dag.precedesIndex(b, a)

    /** [settleIso] for H(X)'s isolation, whose only relevant ops are the admin grants. */
    private fun settleHWIso(i: Int, isGrantOp: Boolean) {
        hwIsoMemo[i] = -1
        var ok = true
        for (x in 0 until grants.size) {
            if (concIdx(i, grants[x])) {
                ok = false
                break
            }
        }
        if (ok) {
            hwIsoOK[i] = true
            hwIsoLive.add(i)
        }
        if (!isGrantOp) return
        val keep = IntList(hwIsoLive.size)
        hwIsoLive.forEach { j ->
            if (j != i && concIdx(i, j)) hwIsoOK[j] = false else keep.add(j)
        }
        hwIsoLive.clear()
        keep.forEach { hwIsoLive.add(it) }
        grants.add(i)
    }

    /**
     * Keep [iso] as the op numbered [i] is settled: i is isolated so far if no relevant op
     * settled before it is concurrent with it, and, if i is itself relevant (an admin
     * grant, or a person's or authority reduction), every isolated op concurrent with it
     * stops being so.
     */
    private fun settleIso(o: RosterOp, i: Int, isRelevant: Boolean) {
        if (o.usr.isNotEmpty()) {
            var isolated = true
            for (x in 0 until relevant.size) {
                if (concIdx(i, relevant[x])) {
                    isolated = false
                    break
                }
            }
            if (isolated) {
                iso[i] = true
                isoLive.add(i)
            }
        }
        if (!isRelevant) return
        val keep = IntList(isoLive.size)
        isoLive.forEach { j ->
            if (j != i && concIdx(i, j)) iso[j] = false else keep.add(j)
        }
        isoLive.clear()
        keep.forEach { isoLive.add(it) }
        relevant.add(i)
    }

    /**
     * The closure half of ADR-0015's "succ must not equal the org id, any earlier
     * authority key, or any roster mem" and ADR-0014's "mem equal to … any authority key
     * is malformed", read through the indexes: an earlier authority key is the `by` or
     * `succ` of an authority-shape re-root in the closure, and a roster mem the `mem` of
     * an op in it.
     */
    private fun reusesKey(o: RosterOp): Boolean {
        if (o.kind != OpKind.REROOT && o.mem.isEmpty()) return false
        val anc = dag.ancestors(o.hash)
        fun any(list: List<RosterOp>?): Boolean = list?.any { it.hash in anc } == true
        if (o.kind == OpKind.REROOT && (any(withMem[o.succ]) || any(rerootsBy[o.succ]) || any(rerootsTo[o.succ]))) {
            return true
        }
        return o.mem.isNotEmpty() && any(rerootsTo[o.mem])
    }

    /**
     * File a valid op in the evaluator's indexes, as [resolve] settles it. Every op an
     * index lists is final: resolve settles ops oldest first, and an op is only ever
     * asked about the ops in its own closure.
     */
    private fun index(o: RosterOp) {
        val en = Ent(o, num(o))
        val isAdminGrant = o.kind == OpKind.SET && Role.isAdmin(o.role)
        var isRelevant = isAdminGrant
        if (o.usr.isNotEmpty() && isReduction(o)) {
            personReds.add(en)
            isRelevant = true
            val p = reductionOf(o)
            if (p != "") redsOf.getOrPut(p) { ArrayList() }.add(en)
        }
        if (o.usr.isEmpty()) {
            val p = reductionOf(o)
            if (p != "") {
                authRedsOf.getOrPut(p) { ArrayList() }.add(en)
                isRelevant = true
            }
        }
        settleIso(o, en.i, isRelevant)
        settleHWIso(en.i, isAdminGrant)
        if (o.mem.isNotEmpty()) withMem.getOrPut(o.mem) { ArrayList() }.add(o)
        when (o.kind) {
            OpKind.SET, OpKind.REMOVE -> {
                memOps.getOrPut(o.mem) { ArrayList() }.add(en)
                if (o.kind == OpKind.SET && Role.isAdmin(o.role)) adminSets.add(en)
            }

            OpKind.ENROL, OpKind.UNENROL -> keyOps.getOrPut(o.mem) { ArrayList() }.add(en)

            OpKind.RESET -> resets.add(en)

            else -> {}
        }
        if (o.usr.isEmpty()) {
            when (o.kind) {
                OpKind.REROOT -> {
                    authReroots.add(o)
                    rerootsBy.getOrPut(o.by) { ArrayList() }.add(o)
                    rerootsTo.getOrPut(o.succ) { ArrayList() }.add(o)
                }

                OpKind.RESOLVE -> authResolve.add(o)

                else -> {}
            }
        }
    }

    // --- frames ------------------------------------------------------------------

    /**
     * A downward-closed set of valid ops evaluated as if it were the whole roster: its
     * own high-waters, its own concurrency, its own verdicts. Judged lazily (#122): its
     * authority chain when it is made, and an op's verdict only when something asks for
     * it, memoised. Its set is the DAG's own ancestor bitset, shared; a closure frame
     * memoises its verdicts in four bits per op, and only the top frame keeps reasons,
     * H(X) and maps: they are the view's.
     */
    private class Frame(val key: String, val set: OpDag.OpSet, top: Boolean) {
        lateinit var chain: Chain // ADR-0015's authority chain over the frame
        val elig = HashMap<String, String>() // re-root eligibility in the frame ("" = eligible)
        val views = HashMap<Long, State>()

        val reason: HashMap<String, String>? = if (top) HashMap() else null // the top frame's verdicts
        val baseReason: HashMap<String, String>? = if (top) HashMap() else null // its base verdicts of persons' ops
        val hw: HashMap<String, Int>? = if (top) HashMap() else null // its H(X)
        private var memo: LongArray? = null // a closure frame's verdicts: 4 bits per op by topological index

        /** Op i's memo bits in a closure frame. */
        fun cell(i: Int): Int {
            val m = memo ?: return 0
            if (i / CELLS >= m.size) return 0
            return ((m[i / CELLS] ushr ((i % CELLS) * 4)) and 15L).toInt()
        }

        fun mark(i: Int, bits: Int) {
            val m = memo ?: LongArray((set.bound + CELLS - 1) / CELLS).also { memo = it }
            m[i / CELLS] = m[i / CELLS] or (bits.toLong() shl ((i % CELLS) * 4))
        }
    }

    private fun precedes(a: String, b: String): Boolean = dag.precedes(a, b)

    private fun concurrent(a: String, b: String): Boolean = a != b && !precedes(a, b) && !precedes(b, a)

    /**
     * The frame closure(h): h's ancestors. Closure frames are made oldest first, in the
     * DAG's topological order: before h's, every op numbered below h gets its own. Making
     * a frame builds only its authority chain, which reads only closure frames of ops
     * inside it, all numbered below it, so they are always there already and making
     * frames never nests.
     */
    private fun closureFrame(h: String): Frame {
        frameOf[h]?.let { return it }
        val i = dag.index(h)
        while (built < i) {
            val j = built
            built++
            val a = dag.hash(j)
            if (ops.containsKey(a) && !frameOf.containsKey(a)) frameOf[a] = buildClosureFrame(a)
        }
        val f = buildClosureFrame(h)
        frameOf[h] = f
        return f
    }

    /**
     * closure(h) as a frame, shared with every op of the same closure. A closure is
     * downward closed, so it is named by its maximal ops: h's prevs that no other prev of
     * h cites.
     */
    private fun buildClosureFrame(h: String): Frame {
        val o = dag.node(h)!!
        val top = ArrayList<String>()
        for (p in o.prev) {
            if (o.prev.none { q -> q != p && precedes(p, q) }) top.add(p)
        }
        top.sort()
        return frameFor("c:" + top.joinToString(","), dag.ancestors(h), false)
    }

    private fun topFrame(): Frame = frameFor("top", dag.setOf(ops.keys), true)

    private fun frameFor(key: String, set: OpDag.OpSet, top: Boolean): Frame {
        frames[key]?.let { return it }
        val f = Frame(key, set, top)
        frames[key] = f
        // The chain first: an authority-shape op's verdict reads it, and building it reads
        // only closures and persons' ops, never the chain itself.
        f.chain = chainOf(f)
        return f
    }

    /** A frame's rule-5 resolution at one instant; it resolves a person only when asked, memoised. */
    private class State(val f: Frame, val t: Long) {
        val people = HashMap<String, Resolved>()
    }

    /** One person's rule-5 resolution in a frame at an instant. */
    private class Resolved {
        var on = false // on the roster: a role
        var removed = false // off it by an effective remove in their frontier
        var person: RosterPerson? = null
        var keys: HashMap<String, Boolean>? = null // live keys of an on-roster managed person
        var next = 0L // earliest exp after the instant among the role and live keys, 0 if none
    }

    /** The roster view of [f] at instant [t] (ADR-0014 rule 5). */
    private fun viewAt(f: Frame, t: Long): State = f.views.getOrPut(t) { State(f, t) }

    /**
     * Resolve [mem] in [s]: the minimum role over their causal frontier of effective
     * `set`s and `remove`s (a remove or an expired set counting as ⊥), and, for a managed
     * person on the roster, each key live on the frontier of its effective `enrol`s and
     * `unenrol`s.
     */
    private fun of(s: State, mem: String): Resolved {
        s.people[mem]?.let { return it }
        val f = s.f
        val t = s.t
        val r = Resolved()
        s.people[mem] = r
        fun noteExp(x: Long) {
            if (x != 0L && x > t && (r.next == 0L || x < r.next)) r.next = x
        }
        // The frontier of mem's effective sets and removes in f: an op another effective
        // one cites is never asked for its verdict.
        val front = frontierIn(f, memOps[mem].orEmpty())
        if (front.isEmpty()) return r
        var min = 5
        var hasRemove = false
        val assigned = ArrayList<String>()
        var expires = 0L
        for (o in front) {
            assigned.add(o.hash)
            var rk = 0
            when {
                o.kind == OpKind.REMOVE -> hasRemove = true

                o.exp != 0L && t >= o.exp -> rk = 0

                else -> {
                    rk = Role.rank(o.role)
                    if (o.exp != 0L && (expires == 0L || o.exp < expires)) expires = o.exp
                }
            }
            if (rk < min) min = rk
        }
        if (min == 0) {
            r.removed = hasRemove
            return r
        }
        assigned.sort()
        r.on = true
        val managed = mem.startsWith(Roster.MANAGED_PREFIX)
        noteExp(expires)
        val keys = if (managed) LinkedHashMap<String, Boolean>() else null
        if (keys != null) {
            val byKey = LinkedHashMap<String, MutableList<Ent>>()
            for (en in keyOps[mem].orEmpty()) {
                if (f.set.hasIndex(en.i)) byKey.getOrPut(en.o.key) { ArrayList() }.add(en)
            }
            for ((key, list) in byKey) {
                val kf = frontierIn(f, list)
                if (kf.isEmpty()) continue // no effective enrol or unenrol of this key
                var live = true
                var exp = 0L
                for (o in kf) {
                    if (o.kind == OpKind.UNENROL || (o.exp != 0L && t >= o.exp)) {
                        live = false
                        break
                    }
                    if (o.exp != 0L && (exp == 0L || o.exp < exp)) exp = o.exp
                }
                if (!live) continue
                keys[key] = RosterWire.canSign(key)
                (r.keys ?: HashMap<String, Boolean>().also { r.keys = it })[key] = true
                noteExp(exp)
            }
        }
        r.person = RosterPerson(
            id = mem,
            kind = if (managed) PersonKind.MANAGED else PersonKind.SOVEREIGN,
            role = Role.ofRank(min),
            keys = keys,
            assignedBy = assigned,
            expires = expires,
        )
        return r
    }

    /** mem's role in the view, "" when off the roster. */
    private fun role(s: State, mem: String): String {
        val r = of(s, mem)
        return if (r.on) r.person!!.role else ""
    }

    /** Whether key is a live key of the on-roster managed person mem. */
    private fun hasKey(s: State, mem: String, key: String): Boolean = of(s, mem).keys?.get(key) == true

    /**
     * The persons whose role in the view satisfies [keep]. Only a person some effective
     * `set` to admin or owner names can be an admin or owner, so those are the only ones
     * resolved; keep must hold for no lesser role.
     */
    private fun withRole(s: State, keep: (String) -> Boolean): MutableSet<String> {
        val out = HashSet<String>()
        for (en in adminSets) {
            if (!s.f.set.hasIndex(en.i) || verdictAt(s.f, en.o, en.i) != "") continue
            val mem = en.o.mem
            if (mem !in out && keep(role(s, mem))) out.add(mem)
        }
        return out
    }

    /**
     * The causal frontier of the ops of [list] effective in [f]: those no other such op
     * cites. list is in topological order, as every index keeps its ops; an op that an
     * effective op of list cites is not asked for its verdict.
     */
    private fun frontierIn(f: Frame, list: List<Ent>): List<RosterOp> {
        val bound = f.set.bound
        var lo = 0
        var hi = list.size
        while (lo < hi) {
            val mid = (lo + hi) ushr 1
            if (list[mid].i >= bound) hi = mid else lo = mid + 1
        }
        val ks = dag.frontier(lo, { list[it].i }) { k ->
            val en = list[k]
            f.set.hasIndex(en.i) && verdictAt(f, en.o, en.i) == ""
        }
        return ks.map { list[it].o }
    }

    /** "The roster view of closure(X), at X.iat". */
    private fun closureView(o: RosterOp): State = viewAt(closureFrame(o.hash), o.iat)

    // --- signatures --------------------------------------------------------------

    /**
     * Every signature on [o] that passes the cross-identity rule's steps 1–3, as distinct
     * (usr, key) pairs. The authority signature is not a person's and is not among them.
     */
    private fun validSigs(o: RosterOp): List<SigKey> {
        sigs[o.hash]?.let { return it }
        val seen = HashSet<SigKey>()
        val out = ArrayList<SigKey>()
        fun add(by: String, usr: String, bprev: List<String>) {
            val k = SigKey(usr, by)
            if (usr.isEmpty() || k in seen) return
            if (!personSigOK(o, by, usr, bprev)) return
            seen.add(k)
            out.add(k)
        }
        add(o.by, o.usr, o.bprev)
        for (c in o.cosig) {
            if (!Roster.verifyCosig(o, c, verifier)) continue
            add(c.by, c.usr, c.bprev)
        }
        sigs[o.hash] = out
        return out
    }

    /** Cross-identity steps 2–3 for one already-verified signature. */
    private fun personSigOK(o: RosterOp, by: String, usr: String, bprev: List<String>): Boolean {
        if (usr.startsWith(Roster.MANAGED_PREFIX)) {
            return hasKey(closureView(o), usr, by) && RosterWire.canSign(by)
        }
        if (by == usr) return bprev.isEmpty()
        return memberOf(usr, by, bprev, o.iat) == MemberAt.MEMBER
    }

    /** Step 4: the valid signatures of admin persons in the view of o's closure at o.iat, as person → keys. */
    private fun countedSigs(o: RosterOp): Map<String, Set<String>> {
        counted[o.hash]?.let { return it }
        val c = HashMap<String, HashSet<String>>()
        val vs = validSigs(o)
        if (vs.isNotEmpty()) {
            val st = closureView(o)
            for (s in vs) {
                if (Role.isAdmin(role(st, s.usr))) c.getOrPut(s.usr) { HashSet() }.add(s.by)
            }
        }
        counted[o.hash] = c
        return c
    }

    /** Whether [o] is a self-remove whose primary signature passes cross-identity steps 1–3 (rule 2's exception). */
    private fun selfRemove(o: RosterOp): Boolean {
        if (o.kind != OpKind.REMOVE || o.usr.isEmpty() || o.mem != o.usr) return false
        return primaryValid(o)
    }

    /** Cross-identity steps 1–3 for o's PRIMARY signature, judged against the primary's own bprev, memoised. */
    private fun primaryValid(o: RosterOp): Boolean = primary.getOrPut(o.hash) {
        o.usr.isNotEmpty() && personSigOK(o, o.by, o.usr, o.bprev)
    }

    /** Rule 2 for a non-authority op: the primary is valid and its person an admin in the view of o's closure. */
    private fun primaryCounts(o: RosterOp): Boolean = primaryValid(o) && Role.isAdmin(role(closureView(o), o.usr))

    // --- classification ----------------------------------------------------------

    /** A `set` whose role is at least mem's role in the op's closure (at its iat), or an `enrol`. */
    private fun isGrant(o: RosterOp): Boolean {
        when (o.kind) {
            OpKind.ENROL -> return true
            OpKind.SET -> {}
            else -> return false
        }
        grant[o.hash]?.let { return it }
        val g = Role.rank(o.role) >= Role.rank(role(closureView(o), o.mem))
        grant[o.hash] = g
        return g
    }

    private fun isReduction(o: RosterOp): Boolean = when (o.kind) {
        OpKind.REMOVE, OpKind.UNENROL -> true
        OpKind.SET -> !isGrant(o)
        else -> false
    }

    /** The person a reduction reduces (a remove or a downward set); "" for anything else, an unenrol included. */
    private fun reductionOf(o: RosterOp): String =
        if (o.kind == OpKind.REMOVE || (o.kind == OpKind.SET && !isGrant(o))) o.mem else ""

    /**
     * A `set` to owner; a `set`/`remove` whose target is an owner in the op's closure; an
     * `enrol`/`unenrol` of a managed owner's keys. Memoised.
     */
    private fun ownerChange(o: RosterOp): Boolean = ownerChg.getOrPut(o.hash) {
        when (o.kind) {
            OpKind.SET -> o.role == Role.OWNER || role(closureView(o), o.mem) == Role.OWNER
            OpKind.REMOVE, OpKind.ENROL, OpKind.UNENROL -> role(closureView(o), o.mem) == Role.OWNER
            else -> false
        }
    }

    // --- the admin high-water ----------------------------------------------------

    /**
     * The op X a high-water count is for: ADR-0015's chain over closure(X) and, when X is
     * itself a re-root, X. Every X whose chain has no step and that is not a re-root
     * shares the key "plain".
     */
    private class HwCtx(val key: String, val chain: Chain, val reroot: RosterOp?)

    private fun ctxFor(x: RosterOp): HwCtx {
        val ch = closureFrame(x.hash).chain
        val rr = if (x.kind == OpKind.REROOT && x.usr.isEmpty()) x else null
        if (ch.steps.isEmpty() && rr == null) return HwCtx("plain", ch, null)
        return HwCtx(x.hash, ch, rr)
    }

    /** Whether a is b or in closure(b). */
    private fun inClosure(a: String, b: String): Boolean = a == b || precedes(a, b)

    /**
     * The authority signature on g, by key K, counts for X iff (1) K is the org id, or
     * the succ of a re-root in closure(g) whose authority signature counts for X; (2) the
     * chain over closure(X) has not retired K, or retired it by a re-root R and g is R or
     * in closure(R); and (3) if X is a re-root signed by K, g is X or in closure(X).
     */
    private fun authCounts(g: RosterOp, c: HwCtx): Boolean {
        if (g.usr.isNotEmpty()) return false
        auth[g.hash + "|" + c.key]?.let { return it }
        if (g.by != org) {
            // Clause (1) recurses along re-roots in closure(g): settle them oldest first.
            val anc = dag.ancestors(g.hash)
            for (r in authReroots) {
                if (r.hash in anc && !auth.containsKey(r.hash + "|" + c.key)) authStep(r, c)
            }
        }
        return authStep(g, c)
    }

    /** [authCounts] for g, given every re-root in closure(g) already settled for c. */
    private fun authStep(g: RosterOp, c: HwCtx): Boolean {
        val k = g.hash + "|" + c.key
        auth[k]?.let { return it }
        var ok = g.by == org
        if (!ok) {
            for (r in rerootsTo[g.by].orEmpty()) {
                if (precedes(r.hash, g.hash) && authCounts(r, c)) {
                    ok = true
                    break
                }
            }
        }
        if (ok) {
            for (st in c.chain.steps) {
                if (st.from == g.by && !inClosure(g.hash, st.reroot.hash)) ok = false
            }
        }
        val rr = c.reroot
        if (ok && rr != null && g.by == rr.by && !inClosure(g.hash, rr.hash)) ok = false
        auth[k] = ok
        return ok
    }

    /** weakAdmins' person branch for g: valid signatures from ≥ 2 distinct keys of admin persons in closure(g). */
    private fun personWeak(g: RosterOp): Boolean = pweak.getOrPut(g.hash) { keyCount(countedSigs(g), null) >= 2 }

    /** g sets a person to admin or owner, and carries an authority signature that counts for X or the person branch. */
    private fun weakGrant(g: RosterOp, c: HwCtx): Boolean {
        if (g.kind != OpKind.SET || !Role.isAdmin(g.role)) return false
        return authCounts(g, c) || personWeak(g)
    }

    /** A_r: the admin persons in the view of closure(r), at r.iat. */
    private fun adminsAt(r: RosterOp): Set<String> = admins.getOrPut(r.hash) {
        withRole(closureView(r)) { Role.isAdmin(it) }
    }

    /** Whether grant g is unseen by reset r (not in closure(r)). */
    private fun unseen(g: RosterOp, r: RosterOp): Boolean = !precedes(g.hash, r.hash) && g.hash != r.hash

    /** An unseen weak grant g qualifies under r (#106). */
    private fun qualifies(g: RosterOp, r: RosterOp, c: HwCtx): Boolean {
        val k = r.hash + "|" + g.hash + "|" + c.key
        qualify[k]?.let { return it }
        if (weakGrant(g, c) && !authCounts(g, c)) {
            // erClosure recurses into qualifies over closure(g): settle it oldest first.
            val anc = dag.ancestors(g.hash)
            for (en in adminSets) {
                if (!anc.hasIndex(en.i)) continue
                val a = en.o
                if (!qualify.containsKey(r.hash + "|" + a.hash + "|" + c.key) && weakGrant(a, c) && unseen(a, r)) {
                    qualifyStep(a, r, c)
                }
            }
        }
        return qualifyStep(g, r, c)
    }

    /** [qualifies] for g, given closure(g) already settled for (r, c). */
    private fun qualifyStep(g: RosterOp, r: RosterOp, c: HwCtx): Boolean {
        val k = r.hash + "|" + g.hash + "|" + c.key
        qualify[k]?.let { return it }
        val q = weakGrant(g, c) && (authCounts(g, c) || keyCount(countedSigs(g), erClosure(r, g, c)) >= 2)
        qualify[k] = q
        return q
    }

    /** E_r(closure(g)): A_r plus the persons of the qualifying unseen grants in closure(g). */
    private fun erClosure(r: RosterOp, g: RosterOp, c: HwCtx): Set<String> {
        val k = r.hash + "|" + g.hash + "|" + c.key
        er[k]?.let { return it }
        val s = HashSet(adminsAt(r))
        val anc = dag.ancestors(g.hash)
        for (en in adminSets) {
            if (!anc.hasIndex(en.i)) continue
            val ga = en.o
            if (weakGrant(ga, c) && unseen(ga, r) && qualifies(ga, r, c)) s.add(ga.mem)
        }
        er[k] = s
        return s
    }

    /**
     * H over the ops S (those [inS] reports true for), for the context [c], with the
     * frontier of the given effective [resetList] applied. Only a `set` to admin or owner
     * can be a weak grant, so only those are looked at.
     */
    private fun highWater(inS: (Int) -> Boolean, resetList: List<Ent>, c: HwCtx): Int {
        val front = dag.frontier(resetList.size, { resetList[it].i }) { true }.map { resetList[it].o }
        if (front.isEmpty()) {
            val adm = HashSet<String>()
            for (en in adminSets) {
                if (!inS(en.i)) continue
                if (weakGrant(en.o, c)) adm.add(en.o.mem)
            }
            return adm.size
        }
        var best = 0
        for (r in front) {
            val set = HashSet(adminsAt(r))
            for (en in adminSets) {
                if (!inS(en.i)) continue
                val g = en.o
                if (weakGrant(g, c) && unseen(g, r) && qualifies(g, r, c)) set.add(g.mem)
            }
            if (set.size > best) best = set.size
        }
        return best
    }

    /** The resets in closure(h) that are effective in the roster view of closure(h). */
    private fun effectiveResetsIn(h: String): List<Ent> = resetsIn.getOrPut(h) {
        val f = closureFrame(h)
        resets.filter { en -> f.set.hasIndex(en.i) && verdictAt(f, en.o, en.i) == "" }
    }

    /**
     * H(X) in frame [f]: S(X) is f less X and the ops of f that cite X. Only the top frame
     * memoises it. A null f is the isolated judgement (see [iso]), where S(X) holds no
     * admin grant outside closure(X).
     */
    private fun hwIn(f: Frame?, x: RosterOp): Int {
        f?.hw?.get(x.hash)?.let { return it }
        val xi = num(x)
        if (f == null || hwIsoOK[xi]) {
            // No admin grant concurrent with X: S(X)'s grants are closure(X)'s.
            if (hwIsoMemo[xi] >= 0) return hwIsoMemo[xi]
            val hw = highWater({ dag.precedesIndex(it, xi) }, effectiveResetsIn(x.hash), ctxFor(x))
            hwIsoMemo[xi] = hw
            return hw
        }
        val hw = highWater(
            { f.set.hasIndex(it) && it != xi && !dag.precedesIndex(xi, it) },
            effectiveResetsIn(x.hash),
            ctxFor(x),
        )
        f.hw?.put(x.hash, hw)
        return hw
    }

    // --- the authority chain (ADR-0015) ------------------------------------------

    /** One applied re-root: from → reroot.succ. */
    private class ChainStep(val from: String, val reroot: RosterOp, val resolve: RosterOp?)

    /** ADR-0015's authority chain over a frame. */
    private class Chain(org: String) {
        val keys = arrayListOf(org) // the org id, then each applied re-root's succ
        val steps = ArrayList<ChainStep>()
        var frozen = false
        val conflict = ArrayList<String>() // while frozen: the eligible re-roots of the last key
        val inE = HashSet<String>() // every re-root that was eligible at its key

        fun current(): String = keys.last()

        /** The hash of the re-root that installed the current key; "" for the org id. */
        fun installer(): String = steps.lastOrNull()?.reroot?.hash ?: ""
    }

    /**
     * ADR-0015's chain over [f]: for each authority key K in chain order, the eligible
     * re-roots signed by K decide the next key — one holding every other applies;
     * otherwise exactly one resolve by K citing them all and picking one applies the
     * pick; otherwise the org is frozen at K. Eligibility reads only closures of the
     * re-roots and ops of f that are not authority-signed, never f's own chain.
     */
    private fun chainOf(f: Frame): Chain {
        val c = Chain(org)
        fun inF(list: List<RosterOp>): List<RosterOp> = list.filter { it.hash in f.set }.sortedBy { it.hash }
        val reroots = inF(authReroots)
        val resolves = inF(authResolve)
        val seen = hashSetOf(org)
        while (reroots.isNotEmpty()) {
            val k = c.current()
            val elig = reroots.filter { it.by == k && eligible(f, it) == "" }
            if (elig.isEmpty()) break
            for (r in elig) c.inE.add(r.hash)
            var reroot: RosterOp
            var resolve: RosterOp? = null
            val d = dominant(elig)
            if (d != null) {
                reroot = d
            } else {
                val valid = resolves.filter { it.by == k && settles(it, elig) != null }
                val z = dominant(valid)
                if (z == null) {
                    c.frozen = true
                    for (r in elig) c.conflict.add(r.hash)
                    break
                }
                reroot = settles(z, elig)!!
                resolve = z
            }
            if (reroot.succ in seen) break // defensive: reusesKey refuses a successor that repeats a key
            seen.add(reroot.succ)
            c.steps.add(ChainStep(k, reroot, resolve))
            c.keys.add(reroot.succ)
        }
        return c
    }

    /** The member of [list] whose closure holds every other member; null if none. */
    private fun dominant(list: List<RosterOp>): RosterOp? =
        list.firstOrNull { d -> list.all { o -> o.hash == d.hash || precedes(o.hash, d.hash) } }

    /**
     * The re-root resolve [z] picks when z cites every conflicting re-root and its pick is
     * one of them; null otherwise.
     */
    private fun settles(z: RosterOp, conflict: List<RosterOp>): RosterOp? {
        var pick: RosterOp? = null
        for (r in conflict) {
            if (!precedes(r.hash, z.hash)) return null
            if (r.hash == z.pick) pick = r
        }
        return pick
    }

    /** ADR-0015's eligibility of the authority-shape re-root [r] in [f]: "" when eligible, else why not. */
    private fun eligible(f: Frame, r: RosterOp): String =
        f.elig[r.hash] ?: eligibility(f, r).also { f.elig[r.hash] = it }

    private fun eligibility(f: Frame, r: RosterOp): String {
        val cc = closureFrame(r.hash).chain
        if (r.by != cc.current()) return RosterReason.UNAUTHORISED
        val ic = IndepCtx(r.by, cc.installer())
        val c = HashMap<String, Set<String>>()
        for ((p, ks) in countedSigs(r)) {
            if (independent(p, ic, r)) c[p] = ks
        }
        val h = hwIn(f, r)
        if (!meets(c, h)) return RosterReason.UNDER_THRESHOLD
        for (p in notCurrent(f, r, c)) c.remove(p)
        if (!meets(c, h)) return RosterReason.OUTRANKED
        return ""
    }

    /**
     * Eligibility rule 4 (currency): the signers in [c] that a reduction below admin,
     * concurrent with [r] and itself effective, takes out (amended G3). Such a reduction is
     * judged by rules 2 and 3, the owner guard and the last-owner rule in f, and voided
     * only by the effective authority-key reductions inside r's closure.
     */
    private fun notCurrent(f: Frame, r: RosterOp, c: Map<String, Set<String>>): Set<String> {
        val cf = closureFrame(r.hash)
        val out = HashSet<String>()
        // Only a person's remove or downward set reduces a person (reductionOf).
        for (en in personReds) {
            val q = en.o
            if (!f.set.hasIndex(en.i)) continue
            var p = ""
            if (q.usr.isNotEmpty() && concurrent(q.hash, r.hash)) p = reductionOf(q)
            if (p == "" || c[p] == null || p in out || (q.kind == OpKind.SET && Role.isAdmin(q.role))) continue
            val self = selfRemove(q)
            if ((self && !Role.isAdmin(role(closureView(q), q.usr))) || base(f, q) != "") continue
            val v = voider(cf, q, false)
            if ((self && v(q.usr)) || (!self && quorum(f, q, v) != "")) continue
            out.add(p)
        }
        return out
    }

    /** The authority key K whose re-root is judged, and the re-root that installed K ("" for the org id). */
    private class IndepCtx(val key: String, val installer: String)

    /**
     * Person [p] is independent of K in closure([o]) iff p is an admin person there and
     * every op in p's frontier is the pinned founding op, an op of an authority key that
     * precedes K, or a non-authority op with at least k counted signers independent of K
     * in that op's own closure (amended G3).
     */
    private fun independent(p: String, c: IndepCtx, o: RosterOp): Boolean {
        val k = p + "|" + c.key + "|" + c.installer + "|" + o.hash
        indep[k]?.let { return it }
        val st = closureView(o)
        var v = Role.isAdmin(role(st, p))
        if (v) {
            for (h in of(st, p).person!!.assignedBy) {
                if (!independentGrant(ops.getValue(h), c, o)) {
                    v = false
                    break
                }
            }
        }
        indep[k] = v
        return v
    }

    private fun independentGrant(g: RosterOp, c: IndepCtx, o: RosterOp): Boolean {
        when {
            g.hash == founding -> return true
            g.usr.isEmpty() -> return c.installer != "" && inClosure(g.hash, c.installer)
        }
        val k = g.hash + "|" + c.key + "|" + c.installer + "|" + o.hash
        indepG[k]?.let { return it }
        warmIndependence(g, c)
        val need = minOf(2, maxOf(hwIn(closureFrame(o.hash), g), 1))
        var n = 0
        for (q in countedSigs(g).keys) {
            if (independent(q, c, g)) n++
        }
        val v = n >= need
        indepG[k] = v
        return v
    }

    /**
     * Independence recurses down chains of appointments (a grant's signers, their own
     * grants' signers, …). Settle it oldest first: for every person op x in closure(g)
     * and g itself, in causal order, the independence of each of x's counted signers in
     * closure(x). Each such answer then reads only answers already memoised. A pair is
     * marked once its op and everything before it is settled. (kmp only: Go's growable
     * goroutine stacks need no warming.)
     */
    private fun warmIndependence(g: RosterOp, c: IndepCtx) {
        val ctx = "|" + c.key + "|" + c.installer
        if (g.hash + ctx in indepWarm) return
        val todo = ArrayList<RosterOp>()
        dag.ancestors(g.hash).forEachIndex { todo.add(ops.getValue(dag.hash(it))) }
        todo.add(g)
        for (x in todo) {
            if (x.hash + ctx in indepWarm) continue
            if (x.usr.isNotEmpty() && x.hash != founding) {
                for (q in countedSigs(x).keys) independent(q, c, x)
            }
            indepWarm.add(x.hash + ctx)
        }
    }

    /** Rule 2 for an authority-shape op [x] in [f], along f's chain (ADR-0015). */
    private fun authVerdict(f: Frame, x: RosterOp): String {
        val c = f.chain
        val idx = c.keys.indexOf(x.by)
        if (idx < 0) return RosterReason.UNAUTHORISED
        if (idx > 0 && !precedes(c.steps[idx - 1].reroot.hash, x.hash)) return RosterReason.UNAUTHORISED
        if (idx < c.steps.size) {
            val st = c.steps[idx]
            when {
                x.hash == st.reroot.hash || x.hash == st.resolve?.hash -> return ""
                x.kind == OpKind.REROOT && x.hash in c.inE -> return RosterReason.REROOT_CONFLICT
                !precedes(x.hash, st.reroot.hash) -> return RosterReason.RETIRED_AUTHORITY
            }
        }
        return when (x.kind) {
            OpKind.REROOT -> {
                if (x.hash in c.inE) return RosterReason.REROOT_CONFLICT
                val r = eligible(f, x)
                // defensive: an eligible re-root of a chain key is in E
                if (r != "") r else RosterReason.REROOT_CONFLICT
            }

            OpKind.RESOLVE -> RosterReason.REROOT_CONFLICT

            else -> ""
        }
    }

    // --- the rules ---------------------------------------------------------------

    /** What rule 3 reads of x's counted signers when none is voided. */
    private class QuorumSum(val persons: List<String>, val keys: Int) {
        var owner = 0 // whether one is an owner in the view of closure(x): 0 unsettled, 1 yes, 2 no
    }

    private fun quorumSummary(x: RosterOp): QuorumSum = qsum.getOrPut(x.hash) {
        val c = countedSigs(x)
        QuorumSum(c.keys.sorted(), keyCount(c, null))
    }

    /** Whether one of x's counted signers is an owner in the view of closure(x), memoised. */
    private fun ownerSigned(x: RosterOp, qs: QuorumSum): Boolean {
        if (qs.owner == 0) {
            qs.owner = 2
            val st = closureView(x)
            for (p in qs.persons) {
                if (role(st, p) == Role.OWNER) {
                    qs.owner = 1
                    break
                }
            }
        }
        return qs.owner == 1
    }

    /**
     * Rule 3 plus the owner guard, with the persons [voided] reports (rule 4's recheck;
     * null voids no one) not counted. "" when x passes.
     */
    private fun quorum(f: Frame?, x: RosterOp, voided: ((String) -> Boolean)?): String {
        val qs = quorumSummary(x)
        val none = voided == null || qs.persons.none { voided(it) }
        if (none) {
            // No counted signer is voided: rule 3 over x's counted signers as they stand,
            // which are the same in every frame.
            val h = hwIn(f, x)
            val k = minOf(2, maxOf(h, 1))
            if (qs.persons.size < k || (h <= 1 && qs.keys < 2)) return RosterReason.UNDER_THRESHOLD
            if (ownerChange(x)) {
                return if (ownerSigned(x, qs)) "" else RosterReason.OWNER_REQUIRED
            }
            return ""
        }
        val c = HashMap<String, Set<String>>()
        for ((p, ks) in countedSigs(x)) {
            if (!voided!!(p)) c[p] = ks
        }
        if (!meets(c, hwIn(f, x))) return RosterReason.UNDER_THRESHOLD
        if (ownerChange(x)) {
            val st = closureView(x)
            for (p in c.keys) {
                if (role(st, p) == Role.OWNER) return ""
            }
            return RosterReason.OWNER_REQUIRED
        }
        return ""
    }

    /**
     * A self-remove by an owner p is refused if no owner remains in the view of x's
     * closure once p, and every owner whose own self-remove is concurrent with x in f,
     * are taken out. A null f is the isolated judgement: no self-remove is concurrent.
     */
    private fun lastOwner(f: Frame?, x: RosterOp): Boolean {
        val st = closureView(x)
        if (role(st, x.usr) != Role.OWNER) return false
        val owners = withRole(st) { it == Role.OWNER }
        owners.remove(x.usr)
        if (f == null) return owners.isEmpty()
        // A self-remove is a person's remove, so among the person reductions.
        for (en in personReds) {
            val y = en.o
            if (!f.set.hasIndex(en.i)) continue
            if (y.usr in owners && y.kind == OpKind.REMOVE && y.mem == y.usr && concurrent(x.hash, y.hash) &&
                selfRemove(y)
            ) {
                owners.remove(y.usr)
            }
        }
        return owners.isEmpty()
    }

    /**
     * Rules 2 and 3, the owner guard and the last-owner rule for [x] in [f]: everything
     * but rule 4. An authority-shape op is judged along f's chain; a person's op never
     * reads the chain of f, only closures.
     */
    private fun base(f: Frame, x: RosterOp): String {
        if (x.usr.isEmpty()) return authVerdict(f, x)
        val i = num(x)
        if (iso[i]) return isolated(x, i)
        val br = f.baseReason
        if (br != null) {
            br[x.hash]?.let { return it }
        } else {
            val c = f.cell(i)
            if (c and BASE_DONE != 0) return if (c and BASE_EFFECTIVE != 0) "" else REASON_INEFFECTIVE
        }
        val r = personBase(f, x)
        when {
            br != null -> br[x.hash] = r
            r == "" -> f.mark(i, BASE_DONE or BASE_EFFECTIVE)
            else -> f.mark(i, BASE_DONE)
        }
        return r
    }

    private fun personBase(f: Frame?, x: RosterOp): String {
        when {
            Roster.authorityOnly(x.kind) -> return RosterReason.UNAUTHORISED
            selfRemove(x) -> return if (lastOwner(f, x)) RosterReason.LAST_OWNER else ""
        }
        if (!primaryCounts(x)) return RosterReason.UNAUTHORISED
        return quorum(f, x, null)
    }

    /** Op x's number in the DAG's topological index. */
    private fun num(x: RosterOp): Int = nums.getOrPut(x.hash) { dag.index(x.hash) }

    /**
     * The verdict in [f] of [x], the op numbered [i], settled on demand and memoised:
     * base (rules 2 and 3, the owner guard, the last-owner rule), then rule 4, least
     * privilege ([judge]). A closure frame's non-empty verdicts all read as
     * [REASON_INEFFECTIVE].
     */
    private fun verdictAt(f: Frame, x: RosterOp, i: Int): String {
        if (x.usr.isNotEmpty() && iso[i]) return isolated(x, i)
        val fr = f.reason
        if (fr != null) {
            fr[x.hash]?.let { return it }
        } else {
            val c = f.cell(i)
            if (c and VERDICT_DONE != 0) return if (c and VERDICT_EFFECTIVE != 0) "" else REASON_INEFFECTIVE
        }
        val r = judge(f, x)
        when {
            fr != null -> fr[x.hash] = r
            r == "" -> f.mark(i, VERDICT_DONE or VERDICT_EFFECTIVE)
            else -> f.mark(i, VERDICT_DONE)
        }
        return r
    }

    /**
     * The base, and the verdict, of an isolated person op (see [iso]), the same in every
     * frame that holds it: no concurrent self-remove for the last-owner rule, no
     * concurrent admin grant in S(X), and no concurrent reduction for rule 4 to void a
     * signer with, so rule 4's recheck repeats rule 3's and the verdict is the base.
     */
    private fun isolated(x: RosterOp, i: Int): String {
        if (!isoDone[i]) {
            isoMemo[i] = personBase(null, x)
            isoDone[i] = true
        }
        return isoMemo[i]!!
    }

    /**
     * x's verdict in f, unmemoised. An authority-shape op's verdict is its base; a
     * person's reduction is rechecked without the persons a concurrent effective
     * authority-key reduction takes out (4a), and a grant without those any concurrent
     * effective reduction takes out (4b).
     */
    private fun judge(f: Frame, x: RosterOp): String {
        val r = base(f, x)
        if (r != "" || x.usr.isEmpty()) return r
        when {
            isReduction(x) -> {
                // A reduction is judged from its closure plus (a) only.
                val v = voider(f, x, false)
                if (selfRemove(x)) {
                    if (v(x.usr)) return RosterReason.OUTRANKED
                } else if (quorum(f, x, v) != "") {
                    return RosterReason.OUTRANKED
                }
            }

            isGrant(x) -> {
                // (b) a grant loses the signatures of persons reduced concurrently.
                if (quorum(f, x, voider(f, x, true)) != "") return RosterReason.OUTRANKED
            }
        }
        return ""
    }

    /**
     * Rule 4's voided signers for x in f: whether a person p is taken out by (a) an
     * effective authority-key reduction of p in f concurrent with x, or, for a grant
     * ([quorumReds] true), also by (b) an effective quorum reduction of p in f concurrent
     * with x. A self-remove is a quorum reduction for rule 4(b) only when it takes an
     * admin or owner out of that role. Only the reductions of the person asked about are
     * looked at.
     */
    private fun voider(f: Frame, x: RosterOp, quorumReds: Boolean): (String) -> Boolean = { p ->
        var hit = false
        for (en in authRedsOf[p].orEmpty()) {
            if (f.set.hasIndex(en.i) && concurrent(en.o.hash, x.hash) && verdictAt(f, en.o, en.i) == "") {
                hit = true
                break
            }
        }
        if (!hit && quorumReds) {
            for (en in redsOf[p].orEmpty()) {
                val r = en.o
                if (f.set.hasIndex(en.i) && concurrent(r.hash, x.hash) && verdictAt(f, r, en.i) == "" &&
                    (!selfRemove(r) || Role.isAdmin(role(closureView(r), r.usr)))
                ) {
                    hit = true
                    break
                }
            }
        }
        hit
    }

    /**
     * Settle, oldest first, what judging an op in any frame reads of its own closure: an
     * isolated op's verdict, a person op's primary signature, counted signers and grant
     * shape, and an op's frame-independent H(X). Every one is a memoised function of the
     * set, so this changes no value; it only means that a later question (the top frame's
     * chain first of all, whose re-root eligibility asks after a whole chain of
     * appointments) finds its elders settled instead of descending the history one
     * closure frame at a time. kmp only: Go's goroutine stacks simply grow.
     */
    private fun warm() {
        for (i in 0 until dag.size()) {
            val o = ops[dag.hash(i)] ?: continue
            if (o.usr.isNotEmpty()) {
                if (iso[i]) {
                    isolated(o, i)
                } else {
                    primaryValid(o)
                    countedSigs(o)
                    role(closureView(o), o.usr)
                    isGrant(o)
                }
            }
            if (hwIsoOK[i]) hwIn(null, o)
        }
    }

    /** Assemble the top frame's [RosterView] at [now]. */
    fun view(now: Long): RosterView {
        warm()
        val f = topFrame()
        val highWater = HashMap<String, Int>(ops.size)
        val ineffective = HashMap<String, String>()
        val effResets = ArrayList<Ent>()
        // Oldest first, so each op's verdict finds what it reads already settled. (Go
        // resolves the persons first; every verdict is a memoised function of the set, so
        // settling them first changes nothing but how deep the first questions recurse.)
        for (i in 0 until dag.size()) {
            val h = dag.hash(i)
            val o = ops[h] ?: continue
            highWater[h] = hwIn(f, o)
            val r = verdictAt(f, o, i)
            if (r != "") ineffective[h] = r
            if (o.kind == OpKind.RESET && r == "") effResets.add(Ent(o, i))
        }
        val st = viewAt(f, now)
        val persons = HashMap<String, RosterPerson>()
        val removed = HashSet<String>()
        var next = 0L
        for (mem in memOps.keys) {
            val r = of(st, mem)
            when {
                r.on -> {
                    persons[mem] = r.person!!
                    if (r.next != 0L && (next == 0L || r.next < next)) next = r.next
                }

                r.removed -> removed.add(mem)
            }
        }
        // A new op citing every head: S is the whole set, the chain is the view's, and every effective reset applies.
        val c = HwCtx(if (f.chain.steps.isNotEmpty()) "top" else "plain", f.chain, null)
        val adminHighWater = highWater({ f.set.hasIndex(it) }, effResets, c)
        val cited = HashSet<String>()
        for (o in ops.values) cited.addAll(o.prev)
        val heads = ops.keys.filter { it !in cited }.sorted()
        return RosterView(
            org = org,
            authority = f.chain.current(),
            persons = persons,
            removed = removed,
            heads = heads,
            adminHighWater = adminHighWater,
            highWater = highWater,
            frozen = f.chain.frozen,
            conflict = if (f.chain.frozen) f.chain.conflict.toList() else null,
            accepted = HashMap(ops),
            rejected = rejected,
            ineffective = ineffective,
            nextExpiry = next,
        )
    }

    private companion object {
        // A closure frame's per-op memo bits.
        const val BASE_DONE = 1
        const val BASE_EFFECTIVE = 2
        const val VERDICT_DONE = 4
        const val VERDICT_EFFECTIVE = 8

        /** Four-bit cells per memo word. */
        const val CELLS = 16

        /**
         * Stands for whatever non-empty reason a closure frame found: only the top frame's
         * reasons are ever reported, and every rule that reads a closure frame's verdict
         * asks only whether it is effective.
         */
        const val REASON_INEFFECTIVE = "ineffective"

        /** keyCount: the distinct keys in [c], of persons in [only] (all persons when null). */
        fun keyCount(c: Map<String, Set<String>>, only: Set<String>?): Int {
            val keys = HashSet<String>()
            for ((p, ks) in c) {
                if (only != null && p !in only) continue
                keys.addAll(ks)
            }
            return keys.size
        }

        /** Rule 3's threshold: k = min(2, max(h, 1)) persons, and two distinct keys when h ≤ 1. */
        fun meets(c: Map<String, Set<String>>, h: Int): Boolean {
            val k = minOf(2, maxOf(h, 1))
            return c.size >= k && (h > 1 || keyCount(c, null) >= 2)
        }
    }
}
