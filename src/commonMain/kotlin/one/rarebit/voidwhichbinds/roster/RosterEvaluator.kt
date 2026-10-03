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
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.OpDag
import one.rarebit.voidwhichbinds.crypto.GoStrings

/**
 * One [Roster.evaluate] call's working state: a structure-for-structure port of
 * void-which-binds-go `roster/evaluate.go` (ADR-0014 amended #80, #99, #106 and the
 * Phase 3 G0 errata; ADR-0015 amended G3). Each op is judged from its own closure:
 *
 *  1. Structure: parse, typ, fields, signatures, prev integrity, and every signature's
 *     bprev must name person ops the evaluator holds (`missing_person_context`).
 *  2. Authority: the authority key, or a primary signature that counts under the
 *     cross-identity rule (a valid key of an admin person in the view of the op's
 *     closure, at its iat, with sovereign devices judged by
 *     [Membership.memberAt] over bprev). A self-remove needs only a valid key.
 *  3. Quorum: k = min(2, max(H(X), 1)) distinct admin persons, plus two keys when
 *     H(X) ≤ 1, where H(X) is the op's own admin high-water.
 *  4. Least privilege over concurrency.
 *  5. Resolution: a person's role is the minimum over their causal frontier.
 *
 * A *frame* is a downward-closed set of valid ops evaluated as if it were the whole
 * roster; "the roster view of X's closure" is the frame closure(X). Every recursion is
 * over strictly smaller closures, memoised per closure, exactly as in Go. Names,
 * memo keys and evaluation order follow the Go source so the two can be read side by
 * side; where Go compares op pointers this compares hashes.
 */
internal class RosterEvaluator(
    private val org: String,
    private val persons: ((String) -> List<String>)?,
    private val verifier: Ed25519Verifier,
) {
    /** The pinned founding op's hash: the root of independence. */
    var founding: String = ""

    private val plog = HashMap<String, Membership.PersonLog>()
    private val memberAt = HashMap<String, MemberAt>()

    private val dag = OpDag<RosterOp>({ it.prev }, { child, parent -> parent.iat <= child.iat })
    private var ops = HashMap<String, RosterOp>() // valid ops, final
    private val rejected = HashMap<String, String>()

    private val frames = HashMap<String, Frame>()
    private val ancKey = HashMap<String, String>()
    private val sigs = HashMap<String, List<SigKey>>()
    private val counted = HashMap<String, Map<String, Set<String>>>()
    private val grant = HashMap<String, Boolean>()
    private val pweak = HashMap<String, Boolean>()
    private val auth = HashMap<String, Boolean>()
    private val admins = HashMap<String, Set<String>>()
    private val er = HashMap<String, Set<String>>()
    private val qualify = HashMap<String, Boolean>()
    private val resetsIn = HashMap<String, List<String>>()
    private val indep = HashMap<String, Boolean>()
    private val indepG = HashMap<String, Boolean>()

    // Stack depth (see [byDepth]): each valid op's place in causal order, and the
    // (op, context) pairs whose causal past has had its recursive memos filled.
    private val rank = HashMap<String, Int>()
    private val qualifyWarm = HashSet<String>()
    private val indepWarm = HashSet<String>()

    private data class SigKey(val usr: String, val by: String)

    private enum class MemberAt { MEMBER, NOT_MEMBER, MISSING_CONTEXT, ERROR }

    // --- person logs -------------------------------------------------------------

    /** [Membership.memberAt] over the person-op set L(usr), memoised (Go `memberOf`). */
    private fun memberOf(usr: String, by: String, bprev: List<String>, at: Long): MemberAt {
        val k = usr + "|" + by + "|" + bprev.joinToString(",") + "|" + at
        memberAt[k]?.let { return it }
        val r = if (!RosterWire.isEdKey(usr) || at == 0L) {
            MemberAt.ERROR // enrolment.ErrNoUser / a zero clock
        } else {
            val log = plog.getOrPut(usr) { Membership.PersonLog(usr, persons?.invoke(usr).orEmpty(), verifier) }
            try {
                if (log.memberAt(by, bprev, at)) MemberAt.MEMBER else MemberAt.NOT_MEMBER
            } catch (_: Membership.MissingContextException) {
                MemberAt.MISSING_CONTEXT
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
     * Rule 1's set-dependent half: prev integrity, then the rules that need the op's
     * closure (an `exp` only on a grant; ADR-0015's key-reuse rules). Everything citing a
     * malformed op is bad_prev.
     */
    fun resolve() {
        for (h in dag.resolveAll()) rejected[h] = RosterReason.BAD_PREV
        val cand = dag.valid()
        val order = cand.keys.sortedWith(compareBy<String> { dag.depth(it) }.thenBy { it })
        ops = HashMap(cand.size)
        for ((i, h) in order.withIndex()) rank[h] = i
        for (h in order) {
            val o = cand.getValue(h)
            if (o.prev.any { !ops.containsKey(it) }) {
                rejected[h] = RosterReason.BAD_PREV
                continue
            }
            ops[h] = o
            // Settle closure(h)'s frame now, in causal order, so building it only ever
            // reads frames already built: judging a frame never recurses down a long chain.
            closureFrame(h)
            if (reusesKey(o) || (o.kind == OpKind.SET && o.exp != 0L && !isGrant(o))) {
                ops.remove(h)
                rejected[h] = RosterReason.MALFORMED
            }
        }
    }

    /**
     * The closure half of ADR-0015's "succ must not equal the org id, any earlier
     * authority key, or any roster mem" and ADR-0014's "mem equal to … any authority key
     * is malformed".
     */
    private fun reusesKey(o: RosterOp): Boolean {
        if (o.kind != OpKind.REROOT && o.mem.isEmpty()) return false
        for (a in ancestors(o.hash)) {
            val ao = ops.getValue(a)
            val isReroot = ao.kind == OpKind.REROOT && ao.usr.isEmpty()
            when {
                o.kind == OpKind.REROOT &&
                    (ao.mem == o.succ || (isReroot && (ao.by == o.succ || ao.succ == o.succ))) -> return true

                o.mem.isNotEmpty() && isReroot && ao.succ == o.mem -> return true
            }
        }
        return false
    }

    // --- frames ------------------------------------------------------------------

    /** A downward-closed set of valid ops evaluated as if it were the whole roster. */
    private class Frame(val key: String, val set: Set<String>) {
        val verdict = HashMap<String, String>(set.size) // "" = effective
        val hw = HashMap<String, Int>()
        val views = HashMap<Long, State>()
        lateinit var chain: Chain // ADR-0015's authority chain over the frame
        val elig = HashMap<String, String>() // re-root eligibility in the frame ("" = eligible)
        val base = HashMap<String, String>() // memoised base verdicts of non-authority ops
        val sorted: List<String> by lazy { set.sorted() }

        fun verdictOf(h: String): String = verdict[h] ?: ""
    }

    /** A frame's rule-5 resolution at one instant. */
    private class State {
        val roles = HashMap<String, String>()
        val persons = HashMap<String, RosterPerson>()
        val removed = HashSet<String>()
        val keys = HashMap<String, HashMap<String, Boolean>>() // live keys of on-roster managed persons
        var next = 0L // earliest exp after the instant, 0 if none

        fun role(p: String): String = roles[p] ?: ""
    }

    private fun ancestors(h: String): Set<String> = dag.ancestors(h)

    private fun precedes(a: String, b: String): Boolean = dag.precedes(a, b)

    private fun concurrent(a: String, b: String): Boolean = a != b && !precedes(a, b) && !precedes(b, a)

    /** The frame closure(h): h's ancestors. */
    private fun closureFrame(h: String): Frame {
        val anc = ancestors(h)
        val key = ancKey.getOrPut(h) { "c:" + MembershipOp.hash(anc.sorted().joinToString(",")) }
        return frameFor(key, anc)
    }

    private fun topFrame(): Frame = frameFor("top", ops.keys.toHashSet())

    private fun frameFor(key: String, set: Set<String>): Frame {
        frames[key]?.let { return it }
        val f = Frame(key, set)
        frames[key] = f
        judge(f)
        return f
    }

    /** The roster view of [f] at instant [t] (ADR-0014 rule 5). */
    private fun viewAt(f: Frame, t: Long): State {
        f.views[t]?.let { return it }
        val s = State()
        val byMem = LinkedHashMap<String, MutableList<RosterOp>>()
        val byKey = LinkedHashMap<Pair<String, String>, MutableList<RosterOp>>()
        for (h in f.sorted) {
            if (f.verdictOf(h) != "") continue
            val o = ops.getValue(h)
            when (o.kind) {
                OpKind.SET, OpKind.REMOVE -> byMem.getOrPut(o.mem) { ArrayList() }.add(o)
                OpKind.ENROL, OpKind.UNENROL -> byKey.getOrPut(o.mem to o.key) { ArrayList() }.add(o)
                else -> {}
            }
        }
        fun noteExp(x: Long) {
            if (x != 0L && x > t && (s.next == 0L || x < s.next)) s.next = x
        }
        for ((mem, list) in byMem) {
            val front = frontier(list)
            var min = 5
            var hasRemove = false
            val assigned = ArrayList<String>()
            var expires = 0L
            for (o in front) {
                assigned.add(o.hash)
                var r = 0
                when {
                    o.kind == OpKind.REMOVE -> hasRemove = true

                    o.exp != 0L && t >= o.exp -> r = 0

                    else -> {
                        r = Role.rank(o.role)
                        if (o.exp != 0L && (expires == 0L || o.exp < expires)) expires = o.exp
                    }
                }
                if (r < min) min = r
            }
            if (min == 0) {
                if (hasRemove) s.removed.add(mem)
                continue
            }
            assigned.sort()
            val role = Role.ofRank(min)
            s.roles[mem] = role
            val managed = mem.startsWith(Roster.MANAGED_PREFIX)
            s.persons[mem] = RosterPerson(
                id = mem,
                kind = if (managed) PersonKind.MANAGED else PersonKind.SOVEREIGN,
                role = role,
                keys = if (managed) LinkedHashMap<String, Boolean>() else null,
                assignedBy = assigned,
                expires = expires,
            )
            noteExp(expires)
        }
        for ((k, list) in byKey) {
            val (mem, key) = k
            val p = s.persons[mem] ?: continue
            var live = true
            var exp = 0L
            for (o in frontier(list)) {
                if (o.kind == OpKind.UNENROL || (o.exp != 0L && t >= o.exp)) {
                    live = false
                    break
                }
                if (o.exp != 0L && (exp == 0L || o.exp < exp)) exp = o.exp
            }
            if (!live) continue
            (p.keys as MutableMap<String, Boolean>)[key] = RosterWire.canSign(key)
            s.keys.getOrPut(mem) { HashMap() }[key] = true
            noteExp(exp)
        }
        f.views[t] = s
        return s
    }

    /** The members of [list] not in the closure of another member. */
    private fun frontier(list: List<RosterOp>): List<RosterOp> =
        list.filter { o -> list.none { q -> q.hash != o.hash && precedes(o.hash, q.hash) } }

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
            val st = closureView(o)
            return st.keys[usr]?.get(by) == true && RosterWire.canSign(by)
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
                if (Role.isAdmin(st.role(s.usr))) c.getOrPut(s.usr) { HashSet() }.add(s.by)
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

    /** Cross-identity steps 1–3 for o's PRIMARY signature, judged against the primary's own bprev. */
    private fun primaryValid(o: RosterOp): Boolean = o.usr.isNotEmpty() && personSigOK(o, o.by, o.usr, o.bprev)

    /** Rule 2 for a non-authority op: the primary is valid and its person an admin in the view of o's closure. */
    private fun primaryCounts(o: RosterOp): Boolean = primaryValid(o) && Role.isAdmin(closureView(o).role(o.usr))

    // --- classification ----------------------------------------------------------

    /** A `set` whose role is at least mem's role in the op's closure (at its iat), or an `enrol`. */
    private fun isGrant(o: RosterOp): Boolean {
        when (o.kind) {
            OpKind.ENROL -> return true
            OpKind.SET -> {}
            else -> return false
        }
        grant[o.hash]?.let { return it }
        val g = Role.rank(o.role) >= Role.rank(closureView(o).role(o.mem))
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
     * `enrol`/`unenrol` of a managed owner's keys.
     */
    private fun ownerChange(o: RosterOp): Boolean = when (o.kind) {
        OpKind.SET -> o.role == Role.OWNER || closureView(o).role(o.mem) == Role.OWNER
        OpKind.REMOVE, OpKind.ENROL, OpKind.UNENROL -> closureView(o).role(o.mem) == Role.OWNER
        else -> false
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
            for (r in byDepth(g.hash)) {
                if (r.kind == OpKind.REROOT && r.usr.isEmpty() && !auth.containsKey(r.hash + "|" + c.key)) {
                    authStep(r, c)
                }
            }
        }
        return authStep(g, c)
    }

    /** [authCounts] for g, given every re-root in closure(g) already settled for c. */
    private fun authStep(g: RosterOp, c: HwCtx): Boolean {
        val k = g.hash + "|" + c.key
        var ok = g.by == org
        if (!ok) {
            for (a in ancestors(g.hash)) {
                val r = ops.getValue(a)
                if (r.kind == OpKind.REROOT && r.usr.isEmpty() && r.succ == g.by && authCounts(r, c)) {
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
        closureView(r).roles.filterValues { Role.isAdmin(it) }.keys.toHashSet()
    }

    /** Whether grant g is unseen by reset r (not in closure(r)). */
    private fun unseen(g: RosterOp, r: RosterOp): Boolean = !precedes(g.hash, r.hash) && g.hash != r.hash

    /** An unseen weak grant g qualifies under r (#106). */
    private fun qualifies(g: RosterOp, r: RosterOp, c: HwCtx): Boolean {
        qualify[r.hash + "|" + g.hash + "|" + c.key]?.let { return it }
        if (weakGrant(g, c) && !authCounts(g, c)) {
            // erClosure recurses into qualifies over closure(g): settle it oldest first.
            val wk = r.hash + "|" + g.hash + "|" + c.key
            if (wk !in qualifyWarm) {
                for (a in byDepth(g.hash)) {
                    val ak = r.hash + "|" + a.hash + "|" + c.key
                    if (ak in qualifyWarm) continue
                    if (!qualify.containsKey(ak) && weakGrant(a, c) && unseen(a, r)) qualifyStep(a, r, c)
                    qualifyWarm.add(ak)
                }
                qualifyWarm.add(wk)
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
        for (a in ancestors(g.hash)) {
            val ga = ops.getValue(a)
            if (weakGrant(ga, c) && unseen(ga, r) && qualifies(ga, r, c)) s.add(ga.mem)
        }
        er[k] = s
        return s
    }

    /** H over the ops [s], for the context [c], with the frontier of the effective [resets] applied. */
    private fun highWater(s: Set<String>, resets: List<RosterOp>, c: HwCtx): Int {
        val front = resets.filter { r -> resets.none { q -> q.hash != r.hash && precedes(r.hash, q.hash) } }
        if (front.isEmpty()) {
            val adm = HashSet<String>()
            for (h in s) {
                val g = ops.getValue(h)
                if (weakGrant(g, c)) adm.add(g.mem)
            }
            return adm.size
        }
        var best = 0
        for (r in front) {
            val set = HashSet(adminsAt(r))
            for (h in s) {
                val g = ops.getValue(h)
                if (weakGrant(g, c) && unseen(g, r) && qualifies(g, r, c)) set.add(g.mem)
            }
            if (set.size > best) best = set.size
        }
        return best
    }

    /** The resets in closure(h) that are effective in the roster view of closure(h). */
    private fun effectiveResetsIn(h: String): List<RosterOp> {
        resetsIn[h]?.let { return opsOf(it) }
        val f = closureFrame(h)
        val rs = ancestors(h).filter { ops.getValue(it).kind == OpKind.RESET && f.verdictOf(it) == "" }.sorted()
        resetsIn[h] = rs
        return opsOf(rs)
    }

    private fun opsOf(hs: List<String>): List<RosterOp> = hs.map { ops.getValue(it) }

    /** H(X) in frame [f]: S(X) is f less X and the ops of f that cite X. */
    private fun hwIn(f: Frame, x: RosterOp): Int {
        f.hw[x.hash]?.let { return it }
        val s = HashSet<String>(f.set.size)
        for (h in f.set) {
            if (h == x.hash || precedes(x.hash, h)) continue
            s.add(h)
        }
        val hw = highWater(s, effectiveResetsIn(x.hash), ctxFor(x))
        f.hw[x.hash] = hw
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
     * pick; otherwise the org is frozen at K.
     */
    private fun chainOf(f: Frame): Chain {
        val c = Chain(org)
        val reroots = ArrayList<RosterOp>()
        val resolves = ArrayList<RosterOp>()
        for (h in f.sorted) {
            val o = ops.getValue(h)
            if (o.usr.isNotEmpty()) continue
            when (o.kind) {
                OpKind.REROOT -> reroots.add(o)
                OpKind.RESOLVE -> resolves.add(o)
                else -> {}
            }
        }
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
    private fun eligible(f: Frame, r: RosterOp): String = f.elig.getOrPut(r.hash) { eligibility(f, r) }

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
     * concurrent with [r] and itself effective, takes out (amended G3).
     */
    private fun notCurrent(f: Frame, r: RosterOp, c: Map<String, Set<String>>): Set<String> {
        val cf = closureFrame(r.hash)
        val authRed = cf.sorted.map { ops.getValue(it) }
            .filter { it.usr.isEmpty() && cf.verdictOf(it.hash) == "" && reductionOf(it) != "" }
        val out = HashSet<String>()
        for (h in f.sorted) {
            val q = ops.getValue(h)
            var p = ""
            if (q.usr.isNotEmpty() && concurrent(q.hash, r.hash)) p = reductionOf(q)
            if (p == "" || c[p] == null || p in out || (q.kind == OpKind.SET && Role.isAdmin(q.role))) continue
            val self = selfRemove(q)
            if ((self && !Role.isAdmin(closureView(q).role(q.usr))) || base(f, q) != "") continue
            val v = HashSet<String>()
            for (a in authRed) {
                if (concurrent(a.hash, q.hash)) v.add(reductionOf(a))
            }
            if ((self && q.usr in v) || (!self && quorum(f, q, v) != "")) continue
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
        var v = Role.isAdmin(st.role(p))
        if (v) {
            for (h in st.persons.getValue(p).assignedBy) {
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
     * marked once its op and everything before it is settled.
     */
    private fun warmIndependence(g: RosterOp, c: IndepCtx) {
        val ctx = "|" + c.key + "|" + c.installer
        if (g.hash + ctx in indepWarm) return
        for (x in byDepth(g.hash) + g) {
            if (x.hash + ctx in indepWarm) continue
            if (x.usr.isNotEmpty() && x.hash != founding) {
                for (q in countedSigs(x).keys) independent(q, c, x)
            }
            indepWarm.add(x.hash + ctx)
        }
    }

    /** The ops of closure(h), oldest first (causal depth, then hash). */
    private fun byDepth(h: String): List<RosterOp> =
        ancestors(h).sortedBy { rank.getValue(it) }.map { ops.getValue(it) }

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

    /** Rule 3 plus the owner guard, with the persons in [voided] not counted. "" when x passes. */
    private fun quorum(f: Frame, x: RosterOp, voided: Set<String>?): String {
        val c = HashMap<String, Set<String>>()
        for ((p, ks) in countedSigs(x)) {
            if (voided == null || p !in voided) c[p] = ks
        }
        if (!meets(c, hwIn(f, x))) return RosterReason.UNDER_THRESHOLD
        if (ownerChange(x)) {
            val st = closureView(x)
            for (p in c.keys) {
                if (st.role(p) == Role.OWNER) return ""
            }
            return RosterReason.OWNER_REQUIRED
        }
        return ""
    }

    /**
     * A self-remove by an owner p is refused if no owner remains in the view of x's
     * closure once p, and every owner whose own self-remove is concurrent with x in f,
     * are taken out.
     */
    private fun lastOwner(f: Frame, x: RosterOp): Boolean {
        val st = closureView(x)
        if (st.role(x.usr) != Role.OWNER) return false
        val owners = HashSet<String>()
        for ((p, r) in st.roles) {
            if (r == Role.OWNER && p != x.usr) owners.add(p)
        }
        for (h in f.set) {
            val y = ops.getValue(h)
            if (y.usr in owners && y.kind == OpKind.REMOVE && y.mem == y.usr && concurrent(x.hash, h) &&
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
        return f.base.getOrPut(x.hash) { personBase(f, x) }
    }

    private fun personBase(f: Frame, x: RosterOp): String {
        when {
            Roster.authorityOnly(x.kind) -> return RosterReason.UNAUTHORISED
            selfRemove(x) -> return if (lastOwner(f, x)) RosterReason.LAST_OWNER else ""
        }
        if (!primaryCounts(x)) return RosterReason.UNAUTHORISED
        return quorum(f, x, null)
    }

    /** Settle every verdict in [f]: the chain, then base, then rule 4 (least privilege). */
    private fun judge(f: Frame) {
        f.chain = chainOf(f)
        val hs = f.sorted
        for (h in hs) f.verdict[h] = base(f, ops.getValue(h))
        // (a) the effective authority-key reductions of persons.
        val authRed = hs.map { ops.getValue(it) }
            .filter { f.verdictOf(it.hash) == "" && it.usr.isEmpty() && reductionOf(it) != "" }
        fun voidedBy(x: RosterOp, reds: List<RosterOp>): Set<String> {
            val v = HashSet<String>()
            for (r in reds) {
                if (concurrent(r.hash, x.hash)) v.add(reductionOf(r))
            }
            return v
        }
        // A reduction is judged from its closure plus (a) only.
        val quorumRed = ArrayList<RosterOp>()
        for (h in hs) {
            val x = ops.getValue(h)
            if (f.verdictOf(h) != "" || x.usr.isEmpty() || !isReduction(x)) continue
            val v = voidedBy(x, authRed)
            if (selfRemove(x)) {
                if (x.usr in v) f.verdict[h] = RosterReason.OUTRANKED
            } else if (quorum(f, x, v) != "") {
                f.verdict[h] = RosterReason.OUTRANKED
            }
            // A self-remove is a quorum reduction for rule 4(b) only when it takes an admin
            // or owner out of that role.
            if (f.verdictOf(h) == "" && reductionOf(x) != "" &&
                (!selfRemove(x) || Role.isAdmin(closureView(x).role(x.usr)))
            ) {
                quorumRed.add(x)
            }
        }
        // (b) a grant loses the signatures of persons reduced concurrently.
        val reds = authRed + quorumRed
        for (h in hs) {
            val x = ops.getValue(h)
            if (f.verdictOf(h) != "" || x.usr.isEmpty() || !isGrant(x)) continue
            if (quorum(f, x, voidedBy(x, reds)) != "") f.verdict[h] = RosterReason.OUTRANKED
        }
    }

    /** Assemble the top frame's [RosterView] at [now]. */
    fun view(now: Long): RosterView {
        val f = topFrame()
        val st = viewAt(f, now)
        val highWater = HashMap<String, Int>(ops.size)
        val ineffective = HashMap<String, String>()
        val resets = ArrayList<RosterOp>()
        for ((h, o) in ops) {
            highWater[h] = hwIn(f, o)
            val r = f.verdictOf(h)
            if (r != "") ineffective[h] = r
            if (o.kind == OpKind.RESET && r == "") resets.add(o)
        }
        resets.sortBy { it.hash }
        // A new op citing every head: S is the whole set, the chain is the view's, and every effective reset applies.
        val c = HwCtx(if (f.chain.steps.isNotEmpty()) "top" else "plain", f.chain, null)
        val adminHighWater = highWater(f.set, resets, c)
        val cited = HashSet<String>()
        for (o in ops.values) cited.addAll(o.prev)
        val heads = ops.keys.filter { it !in cited }.sorted()
        return RosterView(
            org = org,
            authority = f.chain.current(),
            persons = st.persons,
            removed = st.removed,
            heads = heads,
            adminHighWater = adminHighWater,
            highWater = highWater,
            frozen = f.chain.frozen,
            conflict = if (f.chain.frozen) f.chain.conflict.toList() else null,
            accepted = HashMap(ops),
            rejected = rejected,
            ineffective = ineffective,
            nextExpiry = st.next,
        )
    }

    private companion object {
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
