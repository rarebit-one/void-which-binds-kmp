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
 *
 * The golden vectors in void-which-binds-go's `testvectors/vectors/membership/` are replayed
 * verbatim by `MembershipVectorTest`; a divergence there is a bug in this port,
 * never a "flaky key".
 */
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
     * Compute the [View] of identity [usr] over [tokens] at [now] (unix seconds).
     * Throws only for an unusable [usr] or clock — [usr] must be the identity's one
     * canonical spelling, the same one every op's `usr` carries (#116; void-which-binds-go
     * `ErrNoUser`) — and every problem with an individual
     * op is reported in the view, never fatal, so one junk token can never take an
     * identity's devices offline.
     */
    fun evaluate(
        usr: String,
        tokens: List<String>,
        now: Long,
        verifier: Ed25519Verifier = Ed25519Engine.verifier(),
    ): View {
        try {
            KeyRef.parseCanonicalEd25519(usr)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("an identity (genesis key) is required: ${e.message}")
        }
        require(now > 0) { "a clock is required" }
        val e = Evaluator(usr, verifier)
        e.ingest(tokens)
        e.resolveAll()
        // Settle the fleet high-water (rule 5's N) once, before any frame reads it,
        // so every frame — the authority frames and the top view frame — is judged
        // against the same, final threshold.
        e.fleetHighWater()
        return e.view(now)
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
     * Throws [IllegalArgumentException] for an unusable [usr] or a zero [at], and
     * [MissingContextException] if any head is not a structurally valid op in [ops] or
     * is issued after `at`. Like [evaluate] it is a pure function of the set of ops.
     * Mirrors void-which-binds-go `enrolment.MemberAt` (Phase 3 G1).
     */
    @Suppress("LongParameterList") // Go's MemberAt(usr, dev, ops, heads, at) plus the verifier seam
    fun memberAt(
        usr: String,
        dev: String,
        ops: List<String>,
        heads: List<String>,
        at: Long,
        verifier: Ed25519Verifier = Ed25519Engine.verifier(),
    ): Boolean {
        try {
            KeyRef.parseCanonicalEd25519(usr)
        } catch (e: IllegalArgumentException) {
            throw IllegalArgumentException("an identity (genesis key) is required: ${e.message}")
        }
        require(at != 0L) { "a clock is required" }
        return PersonLog(usr, ops, verifier).memberAt(dev, heads, at)
    }

    /**
     * One person's op set, ingested and resolved once, answering [memberAt] for any
     * (dev, heads, at). Every answer is what a fresh [Membership.memberAt] over the same
     * set would give: the set's structure and its fleet high-water do not depend on the
     * question, and each question builds its own frame. The org roster evaluator keeps
     * one per person so a roster with many signatures does not re-verify the log each time.
     */
    internal class PersonLog(usr: String, ops: List<String>, verifier: Ed25519Verifier) {
        private val e = Evaluator(usr, verifier).also {
            it.ingest(ops)
            it.resolveAll()
        }

        /** [Membership.memberAt] for this set; [usr] must already be canonical. */
        fun memberAt(dev: String, heads: List<String>, at: Long): Boolean {
            val closure = HashSet<String>()
            for (h in heads) {
                if (!e.ops.containsKey(h)) throw MissingContextException()
                closure.add(h)
                closure.addAll(e.ancestors(h))
            }
            for (h in heads) {
                if (e.ops.getValue(h).issuedAt > at) throw MissingContextException()
            }
            e.fleetHighWater()
            return e.membersAt(closure, at).contains(dev)
        }
    }

    // --- the evaluator ------------------------------------------------------------

    /** The total order of rule 4: lower is senior. */
    private data class Seniority(val depth: Int, val iat: Long, val hash: String) : Comparable<Seniority> {
        override fun compareTo(other: Seniority): Int {
            if (depth != other.depth) return depth.compareTo(other.depth)
            if (iat != other.iat) return iat.compareTo(other.iat)
            return hash.compareTo(other.hash)
        }
    }

    private val GENESIS_RANK = Seniority(-1, 0, "")

    /**
     * k(N): how many DISTINCT member signatures a member's remove needs when the
     * identity's fleet high-water is N (ADR-0008 rule 5). Fixed at 2-of-N for
     * N ≥ 3, else 1 — a pure function of N, so evaluation stays order-independent.
     * This is the single seam a future k(N) curve would replace. Mirrors void-which-binds-go
     * `enrolment.requiredThreshold`.
     */
    private fun requiredThreshold(n: Int): Int = if (n >= 3) 2 else 1

    private class FrameState(
        val members: MutableMap<String, Member> = LinkedHashMap(),
        val removed: MutableSet<String> = LinkedHashSet(),
        val ineffective: MutableMap<String, String> = LinkedHashMap(),
    )

    private class Evaluator(val usr: String, val verifier: Ed25519Verifier) {
        val ops = HashMap<String, MembershipOp>() // structurally valid (the dag's valid set, after resolveAll)
        val rejected = LinkedHashMap<String, String>()

        // Rule 1's second half: every prev must be structurally valid and issued no later
        // than the op citing it. A missing prev, an invalid prev, a cycle or a
        // later-issued prev all reject the op as bad_prev. (void-which-binds-go G1 lifted
        // this into internal/opdag; OpDag walks it iteratively.)
        val dag = OpDag<MembershipOp>({ it.prev }, { child, parent -> parent.issuedAt <= child.issuedAt })

        /** The valid ops oldest first (causal depth, then hash): the order memos are settled in. */
        var causalOrder: List<String> = emptyList()
        var auth = HashMap<String, Boolean>()
        var authSeen = HashMap<String, Boolean>()
        var closureMem = HashMap<String, Set<String>>() // rule 5: closure device-members by op hash
        var hw = 0 // rule 5: fleet high-water N (see fleetHighWater)
        var hwReady = false // hw has reached its fixpoint
        var hwComputing = false // a fleetHighWater fixpoint pass is in flight

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

        /** Settle rule 1's second half (prev integrity) for every parsed op. */
        fun resolveAll() {
            for (h in dag.resolveAll()) rejected[h] = Reason.BAD_PREV
            ops.putAll(dag.valid())
            causalOrder = ops.keys.sortedWith(compareBy<String> { dag.depth(it) }.thenBy { it })
        }

        /** The transitive prev closure of [h] (excluding h), memoised. */
        fun ancestors(h: String): Set<String> = dag.ancestors(h)

        /** Rule 2 for op [h] from h's own closure, memoised. */
        fun authorised(h: String): Boolean {
            auth[h]?.let { return it }
            val op = ops.getValue(h)
            if (op.genesis) {
                auth[h] = true
                return true
            }
            if (authSeen[h] == true) return false
            authSeen[h] = true
            val frame = frame(ancestors(h)) { a ->
                // Strictly at X's issued-at: the admitting add must have opened and not
                // yet closed when X was signed. No skew — both instants are signer clocks.
                when {
                    a.issuedAt > op.issuedAt -> Reason.NOT_YET_VALID
                    op.issuedAt >= a.expiresAt -> Reason.EXPIRED
                    else -> Reason.OK
                }
            }
            val member = frame.members.containsKey(op.by)
            auth[h] = member
            return member
        }

        fun opKey(o: MembershipOp): Seniority = Seniority(dag.depth(o.hash), o.issuedAt, o.hash)

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
                auth = HashMap()
                authSeen = HashMap()
                closureMem = HashMap()
                settleInCausalOrder()
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
         * Settle rule 2 and every remove's closure members oldest first, so each frame
         * reads only memos already filled: authority and rule 5 recurse through closures,
         * and in causal order that recursion never goes deeper than one frame (a long
         * chain cannot overflow the stack). Each memo is a function of its op's closure
         * and this pass's N, so the order changes nothing else.
         */
        private fun settleInCausalOrder() {
            for (h in causalOrder) {
                authorised(h)
                val op = ops.getValue(h)
                if (op.kind == Kind.REMOVE && !op.genesis) membersInClosure(op)
            }
        }

        /**
         * The authority frame over [set] with every add's window judged strictly at [at]
         * (no skew; both instants are signer clocks), as the member devices. It is what
         * rule 2 evaluates for an op issued at `at` whose closure is set. Mirrors
         * void-which-binds-go `evaluator.membersAt`.
         */
        fun membersAt(set: Set<String>, at: Long): Set<String> = frame(set) { a ->
            when {
                a.issuedAt > at -> Reason.NOT_YET_VALID
                at >= a.expiresAt -> Reason.EXPIRED
                else -> Reason.OK
            }
        }.members.keys

        /**
         * The device-member set of [op]'s own prev closure evaluated strictly at op's
         * issued-at — the devices that may VALIDLY co-sign op under rule 5 (a device the
         * op has causally removed is not among them). It no longer drives k — that is the
         * fleet high-water now — but it still decides cosigner validity. Memoised by op
         * hash. Mirrors void-which-binds-go `evaluator.membersInClosure`.
         */
        fun membersInClosure(op: MembershipOp): Set<String> {
            closureMem[op.hash]?.let { return it }
            val fr = frame(ancestors(op.hash)) { a ->
                when {
                    a.issuedAt > op.issuedAt -> Reason.NOT_YET_VALID
                    op.issuedAt >= a.expiresAt -> Reason.EXPIRED
                    else -> Reason.OK
                }
            }
            val m = fr.members.keys.toHashSet()
            closureMem[op.hash] = m
            return m
        }

        /**
         * The count of DISTINCT members of [members] who signed [op]: the primary signer
         * `op.by`, plus every cosig whose `by` is a member and whose signature verifies
         * over op's core under the cosig domain. `op.by` is never double-counted; a cosig
         * by a non-member, a duplicate signer, or with a bad signature adds nothing.
         * Mirrors void-which-binds-go `enrolment.distinctMemberCosigners`.
         */
        fun distinctMemberCosigners(op: MembershipOp, members: Set<String>): Int {
            val signed = HashSet<String>()
            if (op.by in members) signed.add(op.by)
            if (op.cosig.isEmpty()) return signed.size
            for (cs in op.cosig) {
                if (cs.by !in members) continue // not a member of the op's closure
                if (cs.by in signed) continue // op.by re-signing, or a duplicate cosig
                if (!MembershipOp.verifyCosig(op, cs, verifier)) continue
                signed.add(cs.by)
            }
            return signed.size
        }

        private class Standing(val op: MembershipOp) {
            val killedBy = ArrayList<MembershipOp>()
        }

        /**
         * Rules 2–4 over the ops in [set]: a deterministic REPLAY of the frame's
         * authorised ops in seniority order — every op of the most senior signer, then
         * the next signer's, each signer's own ops in causal (depth, iat, hash) order.
         * [window] decides whether an add is in its validity window for the question
         * being asked (strictly at an op's issued-at for authority; with skew at now
         * for the final view).
         */
        fun frame(set: Set<String>, window: (MembershipOp) -> String): FrameState {
            val st = FrameState()
            // Rule 2 over the frame; seniority from the authorised adds.
            val list = ArrayList<MembershipOp>()
            val rank = HashMap<String, Seniority>()
            for (h in set) {
                val op = ops.getValue(h)
                if (!authorised(h)) {
                    st.ineffective[h] = Reason.UNAUTHORISED
                    continue
                }
                list.add(op)
                if (op.kind == Kind.ADD) {
                    val k = opKey(op)
                    val cur = rank[op.device]
                    if (cur == null || k < cur) rank[op.device] = k
                }
            }
            fun rankOf(dev: String): Seniority = if (dev == usr) GENESIS_RANK else rank[dev] ?: Seniority(0, 0, "")
            list.sortWith { a, b ->
                val ra = rankOf(a.by)
                val rb = rankOf(b.by)
                if (ra != rb) ra.compareTo(rb) else opKey(a).compareTo(opKey(b))
            }

            // The replay (rules 3 and 4). Each device's effective adds are tracked with
            // the removes that killed them. An op by a member is allowed iff one of the
            // signer's adds lies in the op's closure and every remove that killed that
            // add had already SEEN the op (the op is in the remove's closure).
            val adds = HashMap<String, MutableList<Standing>>()
            val removes = HashMap<String, MutableList<MembershipOp>>()
            fun allowed(op: MembershipOp): Boolean {
                val a = ancestors(op.hash)
                for (s in adds[op.by].orEmpty()) {
                    if (s.op.hash !in a) continue
                    var seen = true
                    for (r in s.killedBy) {
                        if (op.hash !in ancestors(r.hash)) {
                            seen = false
                            break
                        }
                    }
                    if (seen) return true
                }
                return false
            }
            for (op in list) {
                // Rule 5 (ADR-0008): a member's remove needs a quorum of k(N) distinct
                // member signatures. Cosigner VALIDITY is judged against the op's own
                // closure (a causally-removed device cannot co-sign); the THRESHOLD k is
                // driven by the fleet HIGH-WATER, not the closure size, so neither a
                // minimal prev nor a backdated iat can shrink the quorum. Checked before
                // seniority so a remove short of quorum is under_threshold, never
                // outranked. Genesis removes bypass it — the recovery authority needs no
                // quorum.
                if (op.kind == Kind.REMOVE && !op.genesis) {
                    val n = fleetHighWater()
                    if (distinctMemberCosigners(op, membersInClosure(op)) < requiredThreshold(n)) {
                        st.ineffective[op.hash] = Reason.UNDER_THRESHOLD
                        continue
                    }
                }
                if (!op.genesis && !allowed(op)) {
                    st.ineffective[op.hash] =
                        if (adds[op.by].orEmpty().isNotEmpty()) Reason.OUTRANKED else Reason.UNAUTHORISED
                    continue
                }
                val dev = op.device
                when (op.kind) {
                    Kind.ADD -> {
                        val tomb = removes[dev].orEmpty()
                        if (tomb.isNotEmpty() && (!op.genesis || !covers(op, tomb))) {
                            st.ineffective[op.hash] = Reason.REMOVED
                            continue
                        }
                        adds.getOrPut(dev) { ArrayList() }.add(Standing(op))
                    }

                    Kind.REMOVE -> {
                        var killed = 0
                        for (s in adds[dev].orEmpty()) {
                            if (s.op.genesis && op.hash in ancestors(s.op.hash)) {
                                continue // a genesis re-add that already answers this remove
                            }
                            if (s.killedBy.isEmpty()) st.ineffective[s.op.hash] = Reason.REMOVED
                            s.killedBy.add(op)
                            killed++
                        }
                        if (killed == 0 && adds[dev].orEmpty().isNotEmpty()) {
                            // Every standing add already answers this remove: history, not news.
                            st.ineffective[op.hash] = Reason.SUPERSEDED
                        }
                        removes.getOrPut(dev) { ArrayList() }.add(op)
                    }
                }
            }
            val live = HashMap<String, MutableList<MembershipOp>>()
            for ((dev, l) in adds) {
                for (s in l) {
                    if (s.killedBy.isEmpty()) live.getOrPut(dev) { ArrayList() }.add(s.op)
                }
            }
            for ((dev, l) in removes) {
                if (live[dev].orEmpty().isEmpty() && l.isNotEmpty()) st.removed.add(dev)
            }

            // Membership: an effective add in window.
            for ((dev, l) in live) {
                var admittedBy = ""
                var admittedAt = 0L
                var expires = 0L
                var firstKey: Seniority? = null
                var latestKey: Seniority? = null
                var latest: MembershipOp? = null
                for (a in l) {
                    val reason = window(a)
                    if (reason != Reason.OK) {
                        st.ineffective[a.hash] = reason
                        continue
                    }
                    val k = opKey(a)
                    if (admittedBy.isEmpty() || k < firstKey!!) {
                        admittedBy = a.hash
                        admittedAt = a.issuedAt
                        firstKey = k
                    }
                    if (latest == null || latestKey!! < k) {
                        latest = a
                        latestKey = k
                    }
                    if (a.expiresAt > expires) expires = a.expiresAt
                }
                if (admittedBy.isEmpty()) continue
                st.members[dev] = Member(
                    device = dev,
                    deviceEnc = latest!!.deviceEnc,
                    admittedBy = admittedBy,
                    admittedAt = admittedAt,
                    expiresAt = expires,
                )
            }
            return st
        }

        /** Whether add [a] causally follows every remove in [tomb] and, if any, is genesis-signed (rule 3). */
        fun covers(a: MembershipOp, tomb: List<MembershipOp>): Boolean {
            if (tomb.isEmpty()) return true
            if (!a.genesis) return false
            val ancestorsOfA = ancestors(a.hash)
            for (r in tomb) if (r.hash !in ancestorsOfA) return false
            return true
        }

        /** Evaluate the top frame at [now] and assemble the [View]. */
        fun view(now: Long): View {
            val all = ops.keys.toSet()
            val st = frame(all) { a ->
                // The same skew rule as VerifyCert: skew only ever shortens the window.
                when {
                    now + SKEW_SECONDS < a.issuedAt -> Reason.NOT_YET_VALID
                    now >= a.expiresAt - SKEW_SECONDS -> Reason.EXPIRED
                    else -> Reason.OK
                }
            }
            val cited = HashSet<String>()
            for (op in ops.values) cited.addAll(op.prev)
            val heads = ops.keys.filter { it !in cited }.sorted()
            return View(
                user = usr,
                members = st.members,
                removed = st.removed,
                heads = heads,
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
