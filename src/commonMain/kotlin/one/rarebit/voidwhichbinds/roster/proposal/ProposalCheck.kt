package one.rarebit.voidwhichbinds.roster.proposal

import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.Ed25519Verifier
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.roster.OpKind
import one.rarebit.voidwhichbinds.roster.Role
import one.rarebit.voidwhichbinds.roster.Roster
import one.rarebit.voidwhichbinds.roster.RosterDraft
import one.rarebit.voidwhichbinds.roster.RosterException
import one.rarebit.voidwhichbinds.roster.RosterOp
import one.rarebit.voidwhichbinds.roster.RosterReason
import one.rarebit.voidwhichbinds.roster.RosterSignature
import one.rarebit.voidwhichbinds.roster.RosterView
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.BAD_CONTEXT
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.BAD_CORE
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.BAD_COSIG
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.COSIGNER_NOT_COUNTED
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.MALFORMED
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.MISSING_PERSON_CONTEXT
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.MISSING_ROSTER_CONTEXT
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.PROPOSER_NOT_AUTHORISED
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.TOO_LARGE
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.UNEXPECTED_CONTEXT
import one.rarebit.voidwhichbinds.roster.proposal.ProposalReason.WRONG_ORG

/**
 * What a receiver brings to a proposal: the [org] it expects and the [founding] op it
 * pinned (ADR-0016), and optionally its own replica, which [RosterProposal.check] merges
 * with the attachments. With no replica, the proposal alone must suffice (the golden
 * vectors' case). Mirrors Go `proposal.Expect`.
 */
data class Expect(
    val org: String,
    val founding: String,
    /** The receiver's own roster op tokens (any of them; only those in the core's closure are used). */
    val roster: List<String> = emptyList(),
    /** The receiver's own person-op tokens for a sovereign person; null for none. */
    val persons: ((String) -> List<String>)? = null,
)

/**
 * A proposal that passed [RosterProposal.check]: it is safe to show its [draft] to a
 * human and to cosign it, and it carries what [verifyCosig] and [assemble] need.
 * Mirrors Go `proposal.Checked`.
 *
 * The checks, in order after [RosterProposal.decode]'s (ADR-0014, "Proposal transport"):
 *  1. the core's org is the expected org (wrong_org);
 *  2. every attached roster token is a valid op of the org (bad_context);
 *  3. the core's prev, and every op it cites transitively, resolve in the attachments,
 *     the receiver's replica and the founding op (missing_roster_context);
 *  4. every attached person op is a valid op of the person it is listed under
 *     (bad_context), checked over every attachment before any is judged in scope; then
 *     every attached roster op is in the closure, every attached person is named by a
 *     needed signature and every attached person op is in a needed closure
 *     (unexpected_context);
 *  5. [Roster.evaluate] over the closure at the op's iat accepts every op in it
 *     (missing_person_context, else bad_context), and no cited head is issued after the
 *     op (bad_context);
 *  6. the op passes the closure-dependent structural rules ([Roster.checkDraftClosure]),
 *     else bad_core;
 *  7. the proposer would count as the op's primary signer in that view: the view's
 *     authority key in the authority shape (and only it may propose an
 *     [Roster.authorityOnly] kind), else a valid key of its person (missing_person_context
 *     if its bprev does not resolve) who is an admin, a self-remove excepted
 *     (proposer_not_authorised).
 */
@Suppress("LongParameterList")
class Checked private constructor(
    val proposal: Proposal,
    /** The proposed op ([Proposal.draft]). */
    val draft: RosterDraft,
    /** The roster view of the op's closure at its iat: closure(prev) plus the pinned founding op. */
    val view: RosterView,
    private val org: String,
    private val founding: String,
    /** The closure's roster tokens, founding included, in op-hash order. */
    private val closure: List<String>,
    private val persons: (String) -> List<String>,
    private val verifier: Ed25519Verifier,
) {
    /**
     * Make [signer]'s cosig on this proposal, signing for [usr] with [bprev]
     * ([Roster.cosignWith]), and attach the closure of bprev in the cosigner's own person
     * log [ownLog] (merged with what the proposal carried for usr). It refuses, as
     * [verifyCosig] would, a cosig that would not count, so a cosigner never writes back
     * what the proposer must discard. Mirrors Go `Checked.Cosign`.
     */
    fun cosign(
        signer: Ed25519Signer,
        signerPublicKey: ByteArray,
        usr: String,
        bprev: List<String>,
        ownLog: List<String>,
    ): Cosig {
        val entry = Roster.cosignWith(signer, signerPublicKey, draft, usr, bprev, verifier)
        val persons = LinkedHashMap<String, List<String>>()
        if (Closures.needsPersonContext(entry)) {
            val (inn, ok) = Closures.person(usr, entry.bprev, ownLog + this.persons(usr), verifier)
            if (!ok) refuse(MISSING_PERSON_CONTEXT, "the cosigner's own log does not resolve its bprev")
            persons[usr] = RosterProposal.byHash(inn.values)
        }
        val cs = Cosig(entry, persons)
        checkCosig(cs)
        cs.encode()
        return cs
    }

    /**
     * Decode a `cosig` slot payload and check it as the proposer does, in this order
     * after [RosterProposal.decodeCosig]'s: the entry's shape (malformed) and signature
     * over the proposal's core under its usr and bprev (bad_cosig); its person context,
     * judged on its own (#114 item 2): every attached op a valid op of its person
     * (bad_context), then `{}` unless the entry is a sovereign device's with bprev, and
     * otherwise exactly the closure of bprev in that person's log (unexpected_context,
     * missing_person_context); and that the entry would count (cosigner_not_counted): not
     * the primary's key, a valid key of its person at the op's iat, and an admin in the
     * roster view of the op's closure. Mirrors Go `Checked.VerifyCosig`.
     */
    fun verifyCosig(raw: ByteArray): Cosig = RosterProposal.decodeCosig(raw).also { checkCosig(it) }

    @Suppress("ThrowsCount")
    private fun checkCosig(cs: Cosig) {
        val s = cs.entry
        try {
            Roster.verifyDraftCosig(draft, s, verifier)
        } catch (e: RosterException) {
            if (e.failure == RosterException.Failure.COSIG_SIGNATURE) refuse(BAD_COSIG, e.message.orEmpty(), e)
            refuse(MALFORMED, e.message.orEmpty(), e)
        }
        // As in check: every attached person op is validated before any is judged in or out of scope.
        Closures.requireValidPersons(cs.persons, verifier)
        var log = emptyList<String>()
        if (Closures.needsPersonContext(s)) {
            for (usr in cs.persons.keys) {
                if (usr != s.usr) refuse(UNEXPECTED_CONTEXT, "person $usr is not the cosigner's")
            }
            log = cs.persons[s.usr].orEmpty()
            val (inn, ok) = Closures.person(s.usr, s.bprev, log, verifier)
            if (!ok) refuse(MISSING_PERSON_CONTEXT, "the cosig's bprev")
            if (inn.size != log.size) {
                refuse(UNEXPECTED_CONTEXT, "a person op outside the closure of the cosig's bprev")
            }
        } else if (cs.persons.isNotEmpty()) {
            refuse(UNEXPECTED_CONTEXT, "the entry needs no person context")
        }
        if (s.by == draft.by) refuse(COSIGNER_NOT_COUNTED, "the primary's own key")
        if (!validKey(s.by, s.usr, s.bprev, log)) {
            refuse(COSIGNER_NOT_COUNTED, "${s.by} is not a valid key of ${s.usr}")
        }
        if (!Role.isAdmin(view.persons[s.usr]?.role.orEmpty())) refuse(COSIGNER_NOT_COUNTED, "${s.usr} is not an admin")
    }

    /** Check step 7. */
    private fun primaryCounts() {
        val d = draft
        if (d.usr.isEmpty()) {
            if (d.by != view.authority) refuse(PROPOSER_NOT_AUTHORISED, "${d.by} is not the authority key")
            return
        }
        if (Roster.authorityOnly(d.op)) refuse(PROPOSER_NOT_AUTHORISED, "a person cannot sign a ${d.op.wire}")
        if (!validKey(d.by, d.usr, d.bprev, persons(d.usr))) {
            refuse(PROPOSER_NOT_AUTHORISED, "${d.by} is not a valid key of ${d.usr}")
        }
        if (d.op == OpKind.REMOVE && d.mem == d.usr) return // a self-remove needs only a valid key
        if (!Role.isAdmin(view.persons[d.usr]?.role.orEmpty())) {
            refuse(PROPOSER_NOT_AUTHORISED, "${d.usr} is not an admin")
        }
    }

    /**
     * The cross-identity rule's steps 2–3 for one signer, at the op's iat: a sovereign
     * person's genesis, a device in the person's membership as of bprev (over log), or a
     * managed person's live Ed25519 key in the view.
     */
    private fun validKey(by: String, usr: String, bprev: List<String>, log: List<String>): Boolean = when {
        usr.startsWith(Roster.MANAGED_PREFIX) -> view.persons[usr]?.keys?.get(by) == true

        by == usr -> true

        else -> try {
            Membership.memberAt(usr, by, log, bprev, draft.iat, verifier)
        } catch (_: Membership.MissingContextException) {
            refuse(MISSING_PERSON_CONTEXT, "$usr's bprev")
        } catch (e: IllegalArgumentException) {
            refuse(BAD_CONTEXT, e.message.orEmpty(), e)
        }
    }

    /**
     * Mint the op the proposal describes, as the proposer: each cosig is checked again as
     * [verifyCosig] does (duplicate keys dropped, entries in key order, at most
     * [Roster.MAX_COSIGS], else too_large), a re-root's succsig is made by [succ]
     * ([Roster.succSigWith]; ignored for any other op), and [signer] signs the op as `by`
     * ([Roster.signWith]). It then evaluates the op over its closure and returns it with
     * its context and verdict; an op the evaluator rejects is an [IllegalStateException].
     * Mirrors Go `Checked.Assemble`.
     */
    @Suppress("LongParameterList")
    fun assemble(
        signer: Ed25519Signer,
        signerPublicKey: ByteArray,
        cosigs: List<Cosig>,
        succ: Ed25519Signer? = null,
        succPublicKey: ByteArray? = null,
    ): Assembled {
        val byKey = HashMap<String, RosterSignature>()
        val logs = HashMap<String, MutableList<String>>()
        for (cs in cosigs) {
            checkCosig(cs)
            if (byKey.containsKey(cs.entry.by)) continue
            byKey[cs.entry.by] = cs.entry
            for ((usr, l) in cs.persons) logs.getOrPut(usr) { ArrayList() }.addAll(l)
        }
        if (byKey.size > Roster.MAX_COSIGS) refuse(TOO_LARGE, "${byKey.size} cosigs, max ${Roster.MAX_COSIGS}")
        val entries = byKey.keys.sorted().map { byKey.getValue(it) }
        var d = draft
        if (d.op == OpKind.REROOT) {
            require(succ != null && succPublicKey != null) { "proposal: a re-root needs its successor's signer" }
            d = d.copy(succSig = Roster.succSigWith(succ, succPublicKey, d, verifier))
        }
        val tok = Roster.signWith(signer, signerPublicKey, d, entries, verifier)
        val persons = Closures.merged(logs, this.persons)
        val view = Roster.evaluate(org, founding, closure + tok, persons, d.iat, verifier)
        val h = Roster.opHash(tok)
        view.rejected[h]?.let { throw IllegalStateException("proposal: the assembled op is rejected: $it") }
        val op = view.accepted.getValue(h)
        val out = LinkedHashMap<String, List<String>>()
        for ((usr, need) in Closures.personHeads(view.accepted.values, Closures.Sig(op.usr, op.bprev))) {
            val (inn, _) = Closures.person(usr, need, persons(usr), verifier)
            if (inn.isNotEmpty()) out[usr] = RosterProposal.byHash(inn.values)
        }
        return Assembled(tok, h, closure, out, view.ineffective[h].orEmpty())
    }

    internal companion object {
        /** Go `check`: steps 1–7 over a decoded proposal. */
        @Suppress("CyclomaticComplexMethod", "LongMethod", "ThrowsCount")
        fun of(p: Proposal, exp: Expect, verifier: Ed25519Verifier): Checked {
            val d = p.draft
            if (d.org != exp.org) refuse(WRONG_ORG, d.org)
            val founding = RosterProposal.goTrim(exp.founding)
            val fOp = try {
                Roster.verify(founding, verifier)
            } catch (e: RosterException) {
                throw RosterException(RosterException.Failure.FOUNDING, "roster: not a founding op of this org", e)
            }
            if (fOp.org != exp.org) {
                throw RosterException(RosterException.Failure.FOUNDING, "roster: not a founding op of this org")
            }
            val ops = HashMap<String, RosterOp>()
            ops[fOp.hash] = fOp
            for (tok in p.roster) {
                val o = Closures.verifyRoster(tok, verifier)
                if (o == null || o.org != exp.org) refuse(BAD_CONTEXT, "roster op ${Roster.opHash(tok)}")
                ops[o.hash] = o
            }
            for (tok in exp.roster) {
                val h = Roster.opHash(RosterProposal.goTrim(tok))
                if (ops.containsKey(h)) continue
                val o = Closures.verifyRoster(tok, verifier)
                if (o != null && o.org == exp.org) ops[h] = o
            }
            val closure = Closures.roster(ops, d.prev)
            closure.add(fOp.hash)
            // Every attached person op must be valid before any attachment, roster or
            // person, is judged in or out of scope.
            Closures.requireValidPersons(p.persons, verifier)
            for (tok in p.roster) {
                if (Roster.opHash(tok) !in closure) {
                    refuse(UNEXPECTED_CONTEXT, "roster op ${Roster.opHash(tok)} is not in the core's closure")
                }
            }
            val closureOps = closure.map { ops.getValue(it) }.sortedBy { it.hash }
            val closureToks = closureOps.map { it.token }

            val persons = Closures.merged(p.persons, exp.persons)
            val heads = Closures.personHeads(closureOps, Closures.Sig(d.usr, d.bprev))
            for ((usr, list) in p.persons) {
                val need = heads[usr] ?: refuse(UNEXPECTED_CONTEXT, "no signature needs person $usr")
                val (inn, _) = Closures.person(usr, need, persons(usr), verifier)
                for (tok in list) {
                    if (!inn.containsKey(Roster.opHash(tok))) {
                        refuse(UNEXPECTED_CONTEXT, "person op ${Roster.opHash(tok)} is not in a needed closure")
                    }
                }
            }

            val view = Roster.evaluate(exp.org, founding, closureToks, persons, d.iat, verifier)
            contextAccepted(view, closureOps)
            for (h in d.prev) {
                if ((view.accepted[h]?.iat ?: 0L) > d.iat) refuse(BAD_CONTEXT, "head $h is issued after the op")
            }
            try {
                Roster.checkDraftClosure(exp.org, founding, d, closureToks, persons, verifier)
            } catch (e: RosterException) {
                refuse(BAD_CORE, e.message.orEmpty(), e)
            }
            return Checked(p, d, view, exp.org, founding, closureToks, persons, verifier).also { it.primaryCounts() }
        }

        /** Every closure op must be accepted by the evaluator (missing person context wins). */
        private fun contextAccepted(view: RosterView, closure: List<RosterOp>) {
            var bad: String? = null
            for (o in closure) {
                val r = view.rejected[o.hash] ?: continue
                if (r == RosterReason.MISSING_PERSON_CONTEXT) refuse(MISSING_PERSON_CONTEXT, "roster op ${o.hash}")
                if (bad == null) bad = "roster op ${o.hash} is $r"
            }
            bad?.let { refuse(BAD_CONTEXT, it) }
        }
    }
}

/**
 * A minted roster op with everything an RP needs to judge it: its closure's roster ops
 * and the person ops every signature on it and on them names. Mirrors Go
 * `proposal.Assembled`.
 */
data class Assembled(
    val op: String,
    val hash: String,
    /** The closure of the op's prev, founding included, in op-hash order (the op itself excluded). */
    val roster: List<String>,
    /** The closure of every bprev in [roster] and on [op], by person, in op-hash order. */
    val persons: Map<String, List<String>>,
    /**
     * [Roster.evaluate]'s verdict on [op] over [roster] at its iat: "" (effective) or an
     * ineffective [RosterReason]. The op is minted either way.
     */
    val verdict: String,
)

/** The closures and op checks both sides share (Go `check.go`'s helpers). Every walk is iterative. */
internal object Closures {
    /** A signer's person and that person's heads (Go's `sig`, whose key plays no part here). */
    class Sig(val usr: String, val bprev: List<String>)

    /** [Roster.verify], or null for a token that is not a roster op. */
    fun verifyRoster(raw: String, verifier: Ed25519Verifier): RosterOp? {
        // Roster.verify trims with Go's TrimSpace set and reads the body iteratively under
        // Go's nesting limit, so a hostile attachment is refused, never a stack overflow.
        return try {
            Roster.verify(raw, verifier)
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    /** [MembershipOp.verify] (Go `enrolment.VerifyOp`), or null for a token that is not a person op. */
    fun verifyPerson(raw: String, verifier: Ed25519Verifier): MembershipOp? {
        // As verifyRoster: MembershipOp.verify is Go-exact on trimming and nesting.
        return try {
            MembershipOp.verify(raw, verifier)
        } catch (_: IllegalArgumentException) {
            null
        }
    }

    /** Every attached person op must be a valid op of the person it is listed under (bad_context). */
    fun requireValidPersons(persons: Map<String, List<String>>, verifier: Ed25519Verifier) {
        for ((usr, list) in persons) {
            for (tok in list) {
                val o = verifyPerson(tok, verifier)
                if (o == null || o.user != usr) refuse(BAD_CONTEXT, "person op ${Roster.opHash(tok)}")
            }
        }
    }

    /** The prev hashes and every op they cite, transitively, over [ops] (missing_roster_context). */
    fun roster(ops: Map<String, RosterOp>, prev: List<String>): MutableSet<String> {
        val seen = HashSet<String>()
        val stack = ArrayList(prev)
        while (stack.isNotEmpty()) {
            val h = stack.removeAt(stack.size - 1)
            if (h in seen) continue
            val o = ops[h] ?: refuse(MISSING_ROSTER_CONTEXT, h)
            seen.add(h)
            stack.addAll(o.prev)
        }
        return seen
    }

    /**
     * By sovereign person, every bprev hash that the signatures on [ops] (and [extra])
     * name: the heads whose closures an evaluator needs from that person's log, sorted.
     */
    fun personHeads(ops: Collection<RosterOp>, extra: Sig): Map<String, List<String>> {
        val heads = HashMap<String, MutableSet<String>>()
        fun add(usr: String, bprev: List<String>) {
            if (bprev.isEmpty() || usr.isEmpty() || usr.startsWith(Roster.MANAGED_PREFIX)) return
            heads.getOrPut(usr) { HashSet() }.addAll(bprev)
        }
        add(extra.usr, extra.bprev)
        for (o in ops) {
            add(o.usr, o.bprev)
            for (c in o.cosig) add(c.usr, c.bprev)
        }
        return heads.mapValues { it.value.sorted() }
    }

    /**
     * [heads] and every op they cite, transitively, among the valid ops of [usr] in
     * [toks], by hash; the flag is false if a hash does not resolve.
     */
    @Suppress("LoopWithTooManyJumpStatements")
    fun person(
        usr: String,
        heads: List<String>,
        toks: List<String>,
        verifier: Ed25519Verifier,
    ): Pair<Map<String, String>, Boolean> {
        val ops = HashMap<String, MembershipOp>()
        for (t in toks) {
            val o = verifyPerson(RosterProposal.goTrim(t), verifier)
            if (o != null && o.user == usr) ops[o.hash] = o
        }
        val out = HashMap<String, String>()
        val stack = ArrayList(heads)
        var ok = true
        while (stack.isNotEmpty()) {
            val h = stack.removeAt(stack.size - 1)
            if (out.containsKey(h)) continue
            val o = ops[h]
            if (o == null) {
                ok = false
                continue
            }
            out[h] = o.token
            stack.addAll(o.prev)
        }
        return out to ok
    }

    /** Whether a cosig entry carries person context: a sovereign device's signature with bprev. */
    fun needsPersonContext(s: RosterSignature): Boolean =
        s.bprev.isNotEmpty() && s.by != s.usr && !s.usr.startsWith(Roster.MANAGED_PREFIX)

    /** The union of attached person ops and a replica's, memoised per person. */
    fun merged(attached: Map<String, List<String>>, replica: ((String) -> List<String>)?): (String) -> List<String> {
        val memo = HashMap<String, List<String>>()
        return { usr -> memo.getOrPut(usr) { attached[usr].orEmpty() + replica?.invoke(usr).orEmpty() } }
    }
}
