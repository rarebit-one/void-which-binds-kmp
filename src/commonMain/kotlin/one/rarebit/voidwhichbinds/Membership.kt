package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.MembershipOp.Kind

/**
 * The membership **evaluator** — a line-for-line port of void-which-binds-go
 * `enrolment/membership.go` (ADR-0007). It turns a bag of membership op tokens
 * into an identity's current device set, as a state-based CRDT over a grow-only
 * set of signed ops:
 *
 *  - the STATE is the set of structurally valid ops, keyed by hash (a G-Set);
 *  - MERGE ([merge]) is set union — commutative, associative, idempotent by
 *    construction — so two relying parties, or a device and an RP, that have seen
 *    different subsets converge on the same state once they exchange ops;
 *  - the VIEW ([evaluate]) is a pure function of that state and a clock, so it too
 *    is the same everywhere the state is the same. Nothing depends on the order
 *    tokens arrive in: every judgement about an op is made from the op's OWN causal
 *    past (its prev closure), which is a property of the set.
 *
 * The rules (each a function of the set):
 *
 *  1. **Structure.** An op must parse, its signature must verify under its `by`
 *     ([MembershipOp.verify]), every key in it (`usr`, `by`, `dev`, each cosig `by`)
 *     must be that key's one canonical spelling (#116: a padded or re-cased rendering
 *     would otherwise be a second member for one key), it must name this `usr`, and every prev it cites must
 *     be a structurally valid op in the set issued no later than it. Anything else is
 *     REJECTED and uncitable ([View.rejected]).
 *  2. **Authority.** Genesis (`by == usr`) is always authorised. Any other op X is
 *     authorised iff its signer was a member in X's own prev closure, evaluated by
 *     these same rules at X's issued-at. An unauthorised op is INEFFECTIVE.
 *  3. **Remove wins, causally.** A device is a member iff it has an authorised,
 *     in-window add that every effective remove of it precedes, and — if there is
 *     any remove — that add is genesis-signed. Removes never expire.
 *  4. **Seniority resolves concurrency.** The frame's authorised ops are replayed in
 *     seniority order of their signer (genesis first; then by each device's earliest
 *     authorised add — causal depth, then issued-at, then hash). A remove tombstones
 *     its device as it replays; an op whose signer is already tombstoned is
 *     OUTRANKED. So a senior's remove voids the junior's concurrent ops; nothing in
 *     the remove's closure is touched.
 *  5. **Threshold (ADR-0008, high-water N).** A member's REMOVE takes effect only if
 *     at least k(N) DISTINCT members signed it — the primary `by` plus each valid
 *     member co-signature ([MembershipOp.Cosig]) over the op's core under the cosig
 *     domain. WHO may count is judged against the remove's OWN prev closure
 *     ([membersInClosure]); HOW MANY are needed, k(N), is driven by the fleet
 *     HIGH-WATER ([fleetHighWater] — distinct non-genesis Ed25519 devices that ever
 *     held an authorised add; a `webauthn:` passkey member cannot cosign, so it never
 *     counts, ADR-0018), not the closure size, so neither a minimal prev nor a
 *     backdated iat can shrink the quorum (the downgrade fix). k(N) is 2 for N ≥ 3,
 *     else 1. Checked BEFORE seniority; genesis removes bypass it. A remove short of
 *     quorum is INEFFECTIVE (`under_threshold`).
 *  6. **History cap** (amended 2026-10-03, #122). A set evaluates at most
 *     [MAX_LOG_OPS] ops. Up to that many well-formed ops (those passing rule 1's
 *     op-local half: parse, signature, canonical keys, this `usr`) are judged as above.
 *     A larger set is judged by its ANCHORED HISTORY alone: the ops signed by an
 *     anchored key — genesis, or the device of a well-formed add signed by an anchored
 *     key (a fixpoint that ignores prev, time, removal and cosigs) — plus every op they
 *     cite, transitively. Every other op is REJECTED as `unanchored`; no anchored op
 *     cites one, and none could be authorised, so the anchored ops' verdicts are exactly
 *     what the whole set would give them. If the anchored history itself exceeds
 *     [MAX_LOG_OPS], [evaluate] fails closed with [LogTooLargeException]. A stranger's
 *     junk can only ever be rejected: it can never push an honest log over the cap.
 *
 * Evaluation is compact (#122, no verdict change): [OpDag] holds reachability as
 * per-op bitsets over a (depth, hash) topological index, and frames are replayed
 * oldest first from pooled scratch.
 *
 * The golden vectors in void-which-binds-go's `testvectors/vectors/membership/` are replayed
 * verbatim by `MembershipVectorTest`; a divergence there is a bug in this port,
 * never a "flaky key".
 */
@Suppress("TooManyFunctions")
object Membership {

    /** The same skew rule as the cert's: skew only ever shortens the honoured window. */
    const val SKEW_SECONDS: Long = 5 * 60

    /**
     * Reasons an op changes nothing. Rendered exactly as void-which-binds-go does so the
     * vectors compare as strings. The structural ones (rejected) make an op
     * uncitable; the effect ones (ineffective) leave it in the DAG.
     */
    object Reason {
        const val OK = "ok"
        const val MALFORMED = "malformed"
        const val BAD_SIGNATURE = "bad_signature"
        const val FOREIGN_USER = "foreign_usr"
        const val BAD_PREV = "bad_prev"
        const val UNAUTHORISED = "unauthorised"
        const val OUTRANKED = "outranked"
        const val REMOVED = "removed"
        const val SUPERSEDED = "superseded"
        const val EXPIRED = "expired"
        const val NOT_YET_VALID = "not_yet_valid"

        /** Rule 5 (ADR-0008): a member's remove short of its k(N) cosig quorum. */
        const val UNDER_THRESHOLD = "under_threshold"

        /** Rule 6 (#122): an op of a set over [MAX_LOG_OPS] outside the anchored history (rejected). */
        const val UNANCHORED = "unanchored"
    }

    /** One device currently in the identity's set. */
    data class Member(
        val device: String,
        /** The X25519 encryption key from the device's most recent effective add; empty for a v1-shaped add. */
        val deviceEnc: String,
        /** The hash of the earliest effective add — the op the device presents as its credential. */
        val admittedBy: String,
        /** That add's issued-at (unix seconds). */
        val admittedAt: Long,
        /** The latest expiry over the device's effective adds (unix seconds). */
        val expiresAt: Long,
    )

    /** The evaluated membership: the pure function of (usr, ops, now). */
    class View(
        val user: String,
        /** The current device set, by rendered device key. */
        val members: Map<String, Member>,
        /** Every device with an effective remove and no genesis re-add that covers it. */
        val removed: Set<String>,
        /** The frontier of the structurally valid DAG (ops nothing cites), sorted — what a member cites as prev. */
        val heads: List<String>,
        /** Every structurally valid op by hash — the state an RP records and a device replicates. */
        val accepted: Map<String, MembershipOp>,
        /** Structurally invalid tokens by hash (of the raw token) with the reason. */
        val rejected: Map<String, String>,
        /** Accepted ops that change nothing right now, with why. */
        val ineffective: Map<String, String>,
    ) {
        /** Each member's admitting op hash. */
        val admittedBy: Map<String, String> get() = members.mapValues { it.value.admittedBy }

        fun isMember(dev: String): Boolean = members.containsKey(dev)

        /** The accepted ops' tokens in hash order — the state to record or replicate. */
        fun tokens(): List<String> = accepted.keys.sorted().map { accepted.getValue(it).token }
    }

    /**
     * The CRDT join: the union of op token sets, de-duplicated by hash and returned
     * in hash order so equal sets are equal lists. It does not verify — [evaluate]
     * does — so a junk token merges like any other and is rejected there.
     */
    fun merge(vararg sets: List<String>): List<String> {
        val byHash = HashMap<String, String>()
        for (set in sets) {
            for (tok in set) {
                if (tok.isEmpty()) continue
                byHash[MembershipOp.hash(tok)] = tok
            }
        }
        return byHash.keys.sorted().map { byHash.getValue(it) }
    }

    /**
     * Rule 6's history cap (ADR-0007, amended 2026-10-03, #122): the most ops one
     * identity's membership log is evaluated over. Generous for any honest fleet (a
     * device-add and the odd renewal or remove per device), it bounds evaluation memory:
     * reachability over n ops is at most about n²/16 bytes. Mirrors void-which-binds-go
     * `enrolment.MaxLogOps`.
     */
    const val MAX_LOG_OPS: Int = 10_000

    /**
     * A set whose anchored history exceeds [MAX_LOG_OPS] (rule 6): it is refused whole,
     * fail-closed, rather than evaluated in part. Mirrors void-which-binds-go
     * `enrolment.ErrLogTooLarge`. An [IllegalArgumentException], as every other refusal
     * of the set as a whole is.
     */
    class LogTooLargeException(anchored: Int, maxOps: Int) :
        IllegalArgumentException(
            "the membership log's anchored history exceeds MaxLogOps: $anchored anchored ops > $maxOps",
        )

    /**
     * Compute the [View] of identity [usr] over [tokens] at [now] (unix seconds).
     * Throws for an unusable [usr] or clock — [usr] must be the identity's one
     * canonical spelling, the same one every op's `usr` carries (#116; void-which-binds-go
     * `ErrNoUser`) — and [LogTooLargeException] for a set whose anchored history exceeds
     * [MAX_LOG_OPS] (rule 6). Every other problem with an individual op is reported in
     * the view, never fatal, so one junk token can never take an identity's devices
     * offline.
     */
    @Throws(Exception::class)
    fun evaluate(
        usr: String,
        tokens: List<String>,
        now: Long,
        verifier: Ed25519Verifier = Ed25519Engine.verifier(),
    ): View = evaluateWithCap(usr, tokens, now, verifier, MAX_LOG_OPS)

    /**
     * [evaluate] with the history cap as a parameter: [MAX_LOG_OPS] in production,
     * smaller in the `op-log-cap` vectors so they stay readable (Go's test-only
     * `evaluate(…, maxOps)` seam).
     */
    internal fun evaluateWithCap(
        usr: String,
        tokens: List<String>,
        now: Long,
        verifier: Ed25519Verifier,
        maxOps: Int,
    ): View {
        requireUser(usr)
        require(now > 0) { "a clock is required" }
        val e = prepare(usr, tokens, verifier, maxOps)
        // Settle the fleet high-water (rule 5's N) once, before any frame reads it,
        // so every frame — the authority frames and the top view frame — is judged
        // against the same, final threshold.
        e.fleetHighWater()
        return e.view(now)
    }

    private fun requireUser(usr: String) {
        try {
            KeyRef.parseCanonicalEd25519(usr)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("an identity (genesis key) is required: ${e.message}")
        }
    }

    /** Parse, cap (rule 6) and resolve a token set: everything evaluation needs before any frame is judged. */
    private fun prepare(usr: String, tokens: List<String>, verifier: Ed25519Verifier, maxOps: Int): Evaluator {
        val e = Evaluator(usr, verifier)
        e.ingest(tokens)
        e.applyCap(maxOps)
        e.resolveAll()
        return e
    }

    /**
     * [memberAt] given a head that is not a structurally valid op of the set, or one
     * issued after the instant asked about: membership cannot be judged against a past
     * the evaluator has not seen (rule 1, carried across logs as the org roster's
     * `missing_person_context`). Mirrors void-which-binds-go `enrolment.ErrMissingContext`.
     */
    class MissingContextException :
        IllegalArgumentException(
            "a head is not a valid op of the set issued no later than the instant asked about",
        )

    /**
     * Whether [dev] is a member of [usr]'s fleet in the view of [heads], at the instant
     * [at] (unix seconds): would an op signed by dev, citing heads as its prev and issued
     * at `at`, be authorised? The org roster (ADR-0014) asks it of a person's log for
     * every roster signature (by ∈ membership as of bprev, at X.iat).
     *
     * Over the op set [ops] (judged by [evaluate]'s rules, including the fleet
     * high-water of rule 5 over the WHOLE set), the frame is closure(heads): the heads
     * plus every op they cite, transitively — ops outside it play no part, so a later
     * remove does not reach back. Rules 2–5 are replayed over that frame with each add's
     * window judged STRICTLY at `at` (no skew), and dev is a member iff it is in that
     * frame's member set. The identity key itself is never a fleet member; no heads is
     * the empty frame, in which nobody is a member.
     *
     * Throws [IllegalArgumentException] for an unusable [usr] or a zero [at],
     * [LogTooLargeException] for ops whose anchored history exceeds [MAX_LOG_OPS]
     * (rule 6), and [MissingContextException] if any head is not a structurally valid
     * op in [ops] or is issued after `at` (an unanchored op of a set over the cap is not
     * one). Like [evaluate] it is a pure function of the set of ops. Mirrors
     * void-which-binds-go `enrolment.MemberAt` (Phase 3 G1).
     */
    @Suppress("LongParameterList") // Go's MemberAt(usr, dev, ops, heads, at) plus the verifier seam
    @Throws(Exception::class)
    fun memberAt(
        usr: String,
        dev: String,
        ops: List<String>,
        heads: List<String>,
        at: Long,
        verifier: Ed25519Verifier = Ed25519Engine.verifier(),
    ): Boolean {
        requireUser(usr)
        require(at != 0L) { "a clock is required" }
        return newLog(usr, ops, verifier).memberAt(dev, heads, at)
    }

    /**
     * Prepare [usr]'s op set [ops] for [Log.memberAt] questions: parsed, capped and
     * resolved once. Throws [IllegalArgumentException] for an unusable [usr] and
     * [LogTooLargeException] for ops whose anchored history exceeds [MAX_LOG_OPS]
     * (rule 6). Mirrors void-which-binds-go `enrolment.NewLog` (#122).
     */
    @Throws(Exception::class)
    fun newLog(usr: String, ops: List<String>, verifier: Ed25519Verifier = Ed25519Engine.verifier()): Log =
        newLogWithCap(usr, ops, verifier, MAX_LOG_OPS)

    /** [newLog] with the history cap as a parameter (the test-only `max_ops` seam). */
    internal fun newLogWithCap(usr: String, ops: List<String>, verifier: Ed25519Verifier, maxOps: Int): Log {
        requireUser(usr)
        return Log(prepare(usr, ops, verifier, maxOps))
    }

    /**
     * One identity's op set, parsed, capped and resolved once, so that many
     * [memberAt] questions can be asked of it without re-evaluating the set for each (the
     * org roster evaluator asks one per person signature). Its answers are exactly
     * [Membership.memberAt]'s. It memoises as it answers and is not safe for concurrent
     * use. Mirrors void-which-binds-go `enrolment.Log`.
     */
    class Log internal constructor(private val e: Evaluator) {
        /** [Membership.memberAt] over the log's ops. */
        @Throws(Exception::class)
        fun memberAt(dev: String, heads: List<String>, at: Long): Boolean {
            require(at != 0L) { "a clock is required" }
            val closure = e.dag.closure(heads) ?: throw MissingContextException()
            for (h in heads) {
                if (e.ops.getValue(h).issuedAt > at) throw MissingContextException()
            }
            e.fleetHighWater()
            return dev in e.membersAt(closure, at)
        }
    }

    // --- the evaluator ------------------------------------------------------------

    /**
     * k(N): how many DISTINCT member signatures a member's remove needs when the
     * identity's fleet high-water is N (ADR-0008 rule 5). Fixed at 2-of-N for
     * N ≥ 3, else 1 — a pure function of N, so evaluation stays order-independent.
     * This is the single seam a future k(N) curve would replace. Mirrors void-which-binds-go
     * `enrolment.requiredThreshold`.
     */
    private fun requiredThreshold(n: Int): Int = if (n >= 3) 2 else 1

    internal class FrameState(
        val members: MutableMap<String, Member> = LinkedHashMap(),
        val removed: MutableSet<String> = LinkedHashSet(),
        val ineffective: MutableMap<String, String> = LinkedHashMap(),
    )

    /** Rule 1's second half: every prev structurally valid and issued no later than the op citing it. */
    private fun newDag() = OpDag<MembershipOp>({ it.prev }, { child, parent -> parent.issuedAt <= child.issuedAt })

    /**
     * Rule 6's anchored-key fixpoint over the well-formed [ops]: genesis, and the device
     * of every add signed by an anchored key. It ignores prev, time, removal and cosigs,
     * so it over-approximates every key that could ever be a member: a member's admitting
     * add is authorised, so signed by genesis or by a member of its own closure, and by
     * induction its device is anchored. An op whose signer is not anchored can therefore
     * never be authorised. Mirrors void-which-binds-go `anchorKeys`.
     */
    private fun anchorKeys(usr: String, ops: Collection<MembershipOp>): Set<String> {
        val addsBy = HashMap<String, MutableList<String>>()
        for (op in ops) {
            if (op.kind == Kind.ADD) addsBy.getOrPut(op.by) { ArrayList() }.add(op.device)
        }
        val anchored = hashSetOf(usr)
        val queue = arrayListOf(usr)
        while (queue.isNotEmpty()) {
            val k = queue.removeAt(queue.size - 1)
            for (dev in addsBy[k].orEmpty()) {
                if (anchored.add(dev)) queue.add(dev)
            }
        }
        return anchored
    }

    /** Strictly at [at]: the admitting add must have opened and not yet closed (no skew; both are signer clocks). */
    private fun strictlyAt(at: Long): (MembershipOp) -> String = { a ->
        when {
            a.issuedAt > at -> Reason.NOT_YET_VALID
            at >= a.expiresAt -> Reason.EXPIRED
            else -> Reason.OK
        }
    }

    // Rule 2 memo states (0 is unsettled).
    private const val AUTH_YES: Byte = 1
    private const val AUTH_NO: Byte = 2
    private const val AUTH_SETTLING: Byte = 3
    private const val NO_RANK = -3
    private const val GENESIS_RANK = -2 // genesis is senior to every device
    private const val UNRANKED = -1 // a signer with no authorised add in the frame (cannot occur)
    private const val LOW32 = 0xffffffffL
    private const val RANK_BIAS = 2

    /**
     * One [evaluate] call's working state. Every memo is keyed by op (its hash, or its
     * number in the DAG's topological index) and every memoised value is a function of
     * the op's own closure, which is what keeps the result independent of the order
     * anything is walked in. Mirrors void-which-binds-go `enrolment.evaluator` (#122).
     */
    @Suppress("TooManyFunctions")
    internal class Evaluator(val usr: String, val verifier: Ed25519Verifier) {
        var dag = newDag() // rule 1's prev structure: resolution, depth, ancestors
        var ops: Map<String, MembershipOp> = emptyMap() // structurally valid (the dag's valid set, after resolveAll)
        val rejected = LinkedHashMap<String, String>()
        private var anchored: Set<String> = emptySet() // rule 6's anchored keys
        private var list: List<MembershipOp> = emptyList() // the valid ops by topological index
        private var okey = IntArray(0) // each op's rank in rule 4's causal order (depth, iat, hash), by index
        private var byOkey = IntArray(0) // okey -> index
        private var by = IntArray(0) // each op's signer as a key number, by index
        private var dev = IntArray(0) // each op's device as a key number, by index
        private val keyName = ArrayList<String>() // key number -> key; 0 is usr
        private var auth = ByteArray(0) // rule 2 by index
        private var closureMem = HashMap<Int, Set<String>>() // rule 5: closure device-members by index
        private val cosigOK = HashMap<String, BooleanArray>() // whether each cosig of an op verifies
        private val pool = ArrayList<Scratch>() // frame replay scratch, for reuse
        private var hw = 0 // rule 5: fleet high-water N (see fleetHighWater)
        private var hwReady = false // hw has reached its fixpoint
        private var hwComputing = false // a fleetHighWater fixpoint pass is in flight

        /** Parse and signature-check every token (rule 1, first half). */
        fun ingest(tokens: List<String>) {
            for (tok in tokens) {
                if (tok.isEmpty()) continue
                val h = MembershipOp.hash(tok)
                if (dag.has(h) || rejected.containsKey(h)) continue
                val op = try {
                    MembershipOp.verify(tok, verifier)
                } catch (ex: MembershipOp.OpException) {
                    rejected[h] =
                        if (ex.failure == MembershipOp.Failure.BAD_SIGNATURE) Reason.BAD_SIGNATURE else Reason.MALFORMED
                    continue
                } catch (_: Throwable) {
                    rejected[h] = Reason.MALFORMED
                    continue
                }
                if (op.user != usr) {
                    rejected[h] = Reason.FOREIGN_USER
                    continue
                }
                dag.add(h, op)
            }
        }

        /**
         * Rule 6. A set of at most [maxOps] well-formed ops is evaluated whole. A larger
         * one keeps only its anchored history — the ops signed by an anchored key and
         * everything they cite, transitively, within the set — and rejects the rest as
         * unanchored; if that history is itself over maxOps the set is refused with
         * [LogTooLargeException]. The walk is iterative.
         */
        @Suppress("LoopWithTooManyJumpStatements")
        fun applyCap(maxOps: Int) {
            val pend = dag.pending()
            if (pend.size <= maxOps) return
            val anchoredKeys = anchorKeys(usr, pend.values)
            val keep = HashSet<String>()
            val stack = ArrayList<String>()
            for ((h, op) in pend) {
                if (op.by in anchoredKeys) stack.add(h)
            }
            while (stack.isNotEmpty()) {
                val h = stack.removeAt(stack.size - 1)
                val op = pend[h] ?: continue
                if (!keep.add(h)) continue
                stack.addAll(op.prev)
            }
            if (keep.size > maxOps) throw LogTooLargeException(keep.size, maxOps)
            val d = newDag()
            for ((h, op) in pend) {
                if (h in keep) d.add(h, op) else rejected[h] = Reason.UNANCHORED
            }
            dag = d
        }

        /** Settle rule 1's second half (prev integrity) for every parsed op, and number the valid ops. */
        fun resolveAll() {
            for (h in dag.resolveAll()) rejected[h] = Reason.BAD_PREV
            ops = dag.valid()
            // The anchored history keeps every add of an anchored key, so the fixpoint over
            // what applyCap kept is the fixpoint over the whole set.
            anchored = anchorKeys(usr, dag.pending().values)
            val n = dag.size()
            list = List(n) { ops.getValue(dag.hash(it)) }
            // Rule 4's causal order is (depth, iat, hash): a total order, so each op's rank
            // in it stands in for the triple wherever two are compared.
            val order = (0 until n).sortedWith { a, b ->
                val x = list[a]
                val y = list[b]
                val dx = dag.depth(x.hash)
                val dy = dag.depth(y.hash)
                when {
                    dx != dy -> dx.compareTo(dy)
                    x.issuedAt != y.issuedAt -> x.issuedAt.compareTo(y.issuedAt)
                    else -> x.hash.compareTo(y.hash)
                }
            }
            okey = IntArray(n)
            byOkey = IntArray(n)
            for ((r, i) in order.withIndex()) {
                okey[i] = r
                byOkey[r] = i
            }
            // Keys by number, so a frame's per-device bookkeeping is keyed by small integers.
            val num = HashMap<String, Int>()
            keyName.clear()
            fun key(k: String): Int = num.getOrPut(k) {
                keyName.add(k)
                keyName.size - 1
            }
            key(usr)
            by = IntArray(n)
            dev = IntArray(n)
            for ((i, op) in list.withIndex()) {
                by[i] = key(op.by)
                dev[i] = key(op.device)
            }
            auth = ByteArray(n)
        }

        /** Rule 2 for op [h] from h's own closure, memoised. */
        fun authorised(h: String): Boolean = authorisedAt(dag.index(h))

        /** [authorised] by topological index. */
        @Suppress("ReturnCount")
        private fun authorisedAt(i: Int): Boolean {
            when (auth[i]) {
                AUTH_YES -> return true
                AUTH_NO, AUTH_SETTLING -> return false
            }
            val op = list[i]
            if (op.genesis) {
                auth[i] = AUTH_YES
                return true
            }
            if (op.by !in anchored) {
                // Rule 6's fixpoint: a signer no anchored key ever added is never a member
                // of any frame, so the frame need not be built to say so.
                auth[i] = AUTH_NO
                return false
            }
            auth[i] = AUTH_SETTLING
            val fr = replay(dag.ancestors(op.hash), strictlyAt(op.issuedAt), by[i])
            val member = fr.members.containsKey(op.by)
            auth[i] = if (member) AUTH_YES else AUTH_NO
            return member
        }

        /**
         * Rule 5's N (ADR-0008): the number of DISTINCT non-genesis devices that can
         * cosign ([canCosign]: Ed25519 keys only, ADR-0018) and that have EVER held an
         * authorised add anywhere in the op set. It counts ADDS ONLY —
         * removes, supersession, expiry and every op's issued-at are ignored — so it is
         * a pure, monotone, order-independent function of the whole set, deliberately
         * STICKY: once it reaches 3, k(N)=2 for every non-genesis remove thereafter,
         * even if the live fleet later shrinks. Because it ignores iat and prev size,
         * neither a minimal-prev nor a backdated-iat remove can shrink the quorum below
         * what the fleet has already reached — that is the downgrade resistance.
         *
         * A remove's authority frame applies rule 5, which reads N — so N depends, in
         * principle, on itself. N is monotone in that dependence, so we take the LEAST
         * FIXPOINT from below: seed N=0 (k=1 everywhere), recount, and repeat until the
         * count is stable. Every pass reads one fixed N (reentrant reads return the
         * pass's current estimate), and the count can only climb, bounded by the device
         * total — so it converges in a handful of passes. Mirrors void-which-binds-go
         * `evaluator.fleetHighWater` byte-for-byte.
         */
        fun fleetHighWater(): Int {
            if (hwReady) return hw
            if (hwComputing) return hw // reentrant read: this pass's fixed estimate
            hwComputing = true
            while (true) {
                // Authority and closure memos depend on N; clear them each pass so they
                // re-settle against this pass's threshold. Structural memos (ancestors,
                // depth, resolution) do not depend on N and are kept.
                auth = ByteArray(list.size)
                closureMem = HashMap()
                warm()
                val devs = HashSet<String>()
                for ((h, op) in ops) {
                    if (op.kind != Kind.ADD || op.device == usr) continue // genesis is never a fleet device
                    // ADR-0018: a passkey (webauthn:) member cannot cosign, so it never raises N.
                    if (!canCosign(op.device)) continue
                    if (authorised(h)) devs.add(op.device)
                }
                if (devs.size == hw) break
                hw = devs.size
            }
            hwComputing = false
            hwReady = true
            return hw
        }

        /**
         * Settle rule 2 (and rule 5's cosigner sets) for every op in topological order,
         * oldest first. Each memo is a function of the op's own closure only, so the
         * order changes no value; it only means that every frame finds its ancestors
         * already settled, so judging a deep history never nests one frame inside another
         * (a long chain cannot overflow the stack).
         */
        private fun warm() {
            for ((i, op) in list.withIndex()) {
                if (authorisedAt(i) && op.kind == Kind.REMOVE && !op.genesis) membersInClosure(i)
            }
        }

        /**
         * The authority frame over [set] with every add's window judged strictly at [at]
         * (no skew; both instants are signer clocks), as the member devices. It is what
         * rule 2 evaluates for an op issued at `at` whose closure is set. Mirrors
         * void-which-binds-go `evaluator.membersAt`.
         */
        fun membersAt(set: OpDag.OpSet, at: Long): Set<String> = frame(set, strictlyAt(at)).members.keys

        /**
         * The device-member set of op [i]'s own prev closure evaluated strictly at op's
         * issued-at — the devices that may VALIDLY co-sign op under rule 5 (a device the
         * op has causally removed is not among them). It no longer drives k — that is the
         * fleet high-water now — but it still decides cosigner validity. Memoised by op.
         * Mirrors void-which-binds-go `evaluator.membersInClosure`.
         */
        private fun membersInClosure(i: Int): Set<String> {
            closureMem[i]?.let { return it }
            val op = list[i]
            val m = frame(dag.ancestors(op.hash), strictlyAt(op.issuedAt)).members.keys.toHashSet()
            closureMem[i] = m
            return m
        }

        /**
         * The count of DISTINCT members of [members] who signed [op]: the primary signer
         * `op.by`, plus every cosig whose `by` is a member and whose signature verifies
         * over op's core under the cosig domain. `op.by` is never double-counted; a cosig
         * by a non-member, a duplicate signer, or with a bad signature adds nothing. Each
         * cosig is verified once per evaluation. Mirrors void-which-binds-go
         * `evaluator.distinctMemberCosigners`.
         */
        private fun distinctMemberCosigners(op: MembershipOp, members: Set<String>): Int {
            val signed = HashSet<String>()
            if (op.by in members) signed.add(op.by)
            if (op.cosig.isEmpty()) return signed.size
            val ok = cosigOK.getOrPut(op.hash) {
                BooleanArray(op.cosig.size) { MembershipOp.verifyCosig(op, op.cosig[it], verifier) }
            }
            for ((j, cs) in op.cosig.withIndex()) {
                if (cs.by !in members) continue // not a member of the op's closure
                if (cs.by in signed) continue // op.by re-signing, or a duplicate cosig
                if (!ok[j]) continue
                signed.add(cs.by)
            }
            return signed.size
        }

        /** An effective add (by topological index) and the removes that killed it. */
        private class Standing(val i: Int) {
            val killedBy = IntList(1)
        }

        /**
         * One frame replay's working memory, pooled: frames are replayed many times over a
         * long history, and nest only shallowly.
         */
        private class Scratch(k: Int) {
            val ops = IntList()
            var order = LongArray(0)
            val stand = ArrayList<Standing>()
            val touched = IntList() // the devices (key numbers) this replay has recorded anything for
            val seen = BooleanArray(k) // by key number: in touched
            val rank = IntArray(k) { NO_RANK } // by key number: okey of the device's earliest authorised add
            val adds = Array(k) { IntList(0) } // by key number: effective adds, as positions in stand
            val removes = Array(k) { IntList(0) } // by key number: effective removes
            val live = Array(k) { IntList(0) } // by key number: adds no remove killed

            fun touch(d: Int) {
                if (!seen[d]) {
                    seen[d] = true
                    touched.add(d)
                }
            }

            fun reset() {
                ops.clear()
                stand.clear()
                touched.forEach { d ->
                    seen[d] = false
                    rank[d] = NO_RANK
                    adds[d].clear()
                    removes[d].clear()
                    live[d].clear()
                }
                touched.clear()
            }
        }

        private fun getScratch(): Scratch =
            if (pool.isNotEmpty()) pool.removeAt(pool.size - 1) else Scratch(keyName.size)

        private fun putScratch(sc: Scratch) {
            sc.reset()
            pool.add(sc)
        }

        /**
         * Rules 2–4 over the ops in [set]: a deterministic REPLAY of the frame's
         * authorised ops in seniority order — every op of the most senior signer, then
         * the next signer's, each signer's own ops in causal (depth, iat, hash) order.
         * [window] decides whether an add is in its validity window for the question
         * being asked (strictly at an op's issued-at for authority; with skew at now
         * for the final view).
         */
        fun frame(set: OpDag.OpSet, window: (MembershipOp) -> String): FrameState = replay(set, window, -1)

        /**
         * [frame]. With [want] ≥ 0 it answers only whether the device numbered want is a
         * member (rule 2's question): members holds at most that device, and removed and
         * ineffective are left empty.
         */
        @Suppress("CyclomaticComplexMethod", "LongMethod", "NestedBlockDepth", "LoopWithTooManyJumpStatements")
        private fun replay(set: OpDag.OpSet, window: (MembershipOp) -> String, want: Int): FrameState {
            val full = want < 0
            val st = FrameState()
            val sc = getScratch()
            try {
                // Rule 2 over the frame; seniority from the authorised adds. An op's rank in
                // rule 4's causal order (okey) stands in for its (depth, iat, hash).
                set.forEachIndex { i ->
                    val op = list[i]
                    if (!authorisedAt(i)) {
                        if (full) st.ineffective[op.hash] = Reason.UNAUTHORISED
                    } else {
                        sc.ops.add(i)
                        if (op.kind == Kind.ADD) {
                            val k = okey[i]
                            val d = dev[i]
                            val cur = sc.rank[d]
                            if (cur == NO_RANK || k < cur) {
                                sc.touch(d)
                                sc.rank[d] = k
                            }
                        }
                    }
                }
                // Genesis is senior to every device. A signer with no authorised add in the
                // frame cannot occur (an authorised op's own closure holds one); it would
                // rank after genesis and before every device.
                fun rankOf(d: Int): Int = when {
                    d == 0 -> GENESIS_RANK
                    sc.rank[d] != NO_RANK -> sc.rank[d]
                    else -> UNRANKED
                }
                if (sc.order.size < sc.ops.size) sc.order = LongArray(maxOf(sc.ops.size, sc.order.size * 2))
                val order = sc.order
                val m = sc.ops.size
                for (x in 0 until m) {
                    val i = sc.ops[x]
                    order[x] = ((rankOf(by[i]) + RANK_BIAS).toLong() shl Int.SIZE_BITS) or okey[i].toLong()
                }
                order.sort(0, m)

                // The replay (rules 3 and 4). Each device's effective adds are tracked with
                // the removes that killed them. An op by a member is allowed iff one of the
                // signer's adds lies in the op's closure and every remove that killed that
                // add had already SEEN the op (the op is in the remove's closure).
                fun allowed(i: Int): Boolean {
                    val mine = sc.adds[by[i]]
                    for (x in 0 until mine.size) {
                        val a = sc.stand[mine[x]]
                        if (!dag.precedesIndex(a.i, i)) continue
                        var seen = true
                        for (y in 0 until a.killedBy.size) {
                            if (!dag.precedesIndex(i, a.killedBy[y])) {
                                seen = false
                                break
                            }
                        }
                        if (seen) return true
                    }
                    return false
                }
                fun ineffective(h: String, r: String) {
                    if (full) st.ineffective[h] = r
                }
                for (x in 0 until m) {
                    val i = byOkey[(order[x] and LOW32).toInt()]
                    val op = list[i]
                    // Rule 5 (ADR-0008): a member's remove needs a quorum of k(N) distinct
                    // member signatures. Cosigner VALIDITY is judged against the op's own
                    // closure (a causally-removed device cannot co-sign); the THRESHOLD k is
                    // driven by the fleet HIGH-WATER, not the closure size, so neither a
                    // minimal prev nor a backdated iat can shrink the quorum. Checked before
                    // seniority so a remove short of quorum is under_threshold, never
                    // outranked. Genesis removes bypass it — the recovery authority needs no
                    // quorum.
                    if (op.kind == Kind.REMOVE && by[i] != 0) {
                        val n = fleetHighWater()
                        if (distinctMemberCosigners(op, membersInClosure(i)) < requiredThreshold(n)) {
                            ineffective(op.hash, Reason.UNDER_THRESHOLD)
                            continue
                        }
                    }
                    if (by[i] != 0 && !allowed(i)) {
                        ineffective(op.hash, if (sc.adds[by[i]].isNotEmpty()) Reason.OUTRANKED else Reason.UNAUTHORISED)
                        continue
                    }
                    val d = dev[i]
                    when (op.kind) {
                        Kind.ADD -> {
                            if (sc.removes[d].isNotEmpty() && (by[i] != 0 || !covers(i, sc.removes[d]))) {
                                ineffective(op.hash, Reason.REMOVED)
                                continue
                            }
                            sc.touch(d)
                            sc.adds[d].add(sc.stand.size)
                            sc.stand.add(Standing(i))
                        }

                        Kind.REMOVE -> {
                            var killed = 0
                            val theirs = sc.adds[d]
                            for (y in 0 until theirs.size) {
                                val a = sc.stand[theirs[y]]
                                if (dag.precedesIndex(i, a.i) && by[a.i] == 0) {
                                    continue // a genesis re-add that already answers this remove
                                }
                                if (a.killedBy.isEmpty()) ineffective(list[a.i].hash, Reason.REMOVED)
                                a.killedBy.add(i)
                                killed++
                            }
                            if (killed == 0 && theirs.isNotEmpty()) {
                                // Every standing add already answers this remove: history, not news.
                                ineffective(op.hash, Reason.SUPERSEDED)
                            }
                            sc.touch(d)
                            sc.removes[d].add(i)
                        }
                    }
                }
                sc.touched.forEach { d ->
                    if (full || d == want) {
                        val theirs = sc.adds[d]
                        for (y in 0 until theirs.size) {
                            val a = sc.stand[theirs[y]]
                            if (a.killedBy.isEmpty()) sc.live[d].add(a.i)
                        }
                    }
                }
                if (full) {
                    sc.touched.forEach { d ->
                        if (sc.live[d].isEmpty() && sc.removes[d].isNotEmpty()) st.removed.add(keyName[d])
                    }
                }

                // Membership: an effective add in window.
                sc.touched.forEach { d ->
                    val l = sc.live[d]
                    var admittedBy = ""
                    var admittedAt = 0L
                    var expires = 0L
                    var firstKey = 0
                    var latestKey = 0
                    var latest: MembershipOp? = null
                    for (y in 0 until l.size) {
                        val i = l[y]
                        val a = list[i]
                        val reason = window(a)
                        if (reason != Reason.OK) {
                            ineffective(a.hash, reason)
                            continue
                        }
                        if (!full) {
                            // Rule 2 asks only whether want is a member.
                            admittedBy = a.hash
                            latest = a
                            break
                        }
                        val k = okey[i]
                        if (admittedBy.isEmpty() || k < firstKey) {
                            admittedBy = a.hash
                            admittedAt = a.issuedAt
                            firstKey = k
                        }
                        if (latest == null || latestKey < k) {
                            latest = a
                            latestKey = k
                        }
                        if (a.expiresAt > expires) expires = a.expiresAt
                    }
                    if (admittedBy.isNotEmpty()) {
                        val device = keyName[d]
                        st.members[device] = Member(
                            device = device,
                            deviceEnc = latest!!.deviceEnc,
                            admittedBy = admittedBy,
                            admittedAt = admittedAt,
                            expiresAt = expires,
                        )
                    }
                }
            } finally {
                putScratch(sc)
            }
            return st
        }

        /**
         * Whether the add numbered [a] causally follows every remove in [tomb] and, if any,
         * is genesis-signed (rule 3).
         */
        @Suppress("ReturnCount")
        private fun covers(a: Int, tomb: IntList): Boolean {
            if (tomb.isEmpty()) return true
            if (by[a] != 0) return false
            for (y in 0 until tomb.size) {
                if (!dag.precedesIndex(tomb[y], a)) return false
            }
            return true
        }

        /** Evaluate the top frame at [now] and assemble the [View]. */
        fun view(now: Long): View {
            val st = frame(dag.all()) { a ->
                // The same skew rule as VerifyCert: skew only ever shortens the window.
                when {
                    now + SKEW_SECONDS < a.issuedAt -> Reason.NOT_YET_VALID
                    now >= a.expiresAt - SKEW_SECONDS -> Reason.EXPIRED
                    else -> Reason.OK
                }
            }
            return View(
                user = usr,
                members = st.members,
                removed = st.removed,
                heads = dag.heads(),
                accepted = HashMap(ops),
                rejected = rejected,
                ineffective = st.ineffective,
            )
        }
    }
}

/**
 * Whether a member key can make a cosig: only an Ed25519 key can (void-which-binds-go
 * ADR-0018, `canCosign`). Any other key kind, such as a `webauthn:` passkey, is still
 * a member, but it does not count toward the high-water N. Mirrors
 * `identity.ParseCanonicalPublicKey` succeeding (#116): exactly `ed25519:` and 64
 * lowercase hex, with no surrounding whitespace.
 */
internal fun canCosign(dev: String): Boolean = try {
    KeyRef.parseCanonicalEd25519(dev)
    true
} catch (_: IllegalArgumentException) {
    false
}
