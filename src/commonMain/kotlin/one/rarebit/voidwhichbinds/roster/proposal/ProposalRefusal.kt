package one.rarebit.voidwhichbinds.roster.proposal

/**
 * The machine-readable name of a cosign-transport refusal, spelled exactly as
 * void-which-binds-go `proposal.Reason*` (and the golden vectors in
 * `vectors/roster-proposal/`) spell it.
 */
enum class ProposalReason(val wire: String) {
    /** A slot payload over its byte cap, or a list over its count cap (checked before any token is parsed). */
    TOO_LARGE("too_large"),

    /**
     * Not the canonical encoding of a slot of the expected kind: invalid JSON, another
     * `slot`, a missing, extra or case-variant member, a list out of hash order or with a
     * duplicate, an empty person list, a person key that is not a canonical Ed25519 key,
     * or a cosig entry of the wrong shape.
     */
    MALFORMED("malformed"),

    /** A payload whose `v` is not [RosterProposal.VERSION]. */
    BAD_VERSION("bad_version"),

    /**
     * A `core` that is not the base64url of a well-formed roster op's core, or whose op
     * breaks a structural rule in its closure.
     */
    BAD_CORE("bad_core"),

    /** A core whose `org` is not the org the cosigner expects. */
    WRONG_ORG("wrong_org"),

    /** A restated `usr` or `bprev` that is not the core's own. */
    RESTATEMENT_MISMATCH("restatement_mismatch"),

    /** A `prev` (or an op it cites) that neither the proposal nor the receiver's replica holds (#114 item 1). */
    MISSING_ROSTER_CONTEXT("missing_roster_context"),

    /** A signature whose `bprev` names a person op the payload (and replica) does not hold (#114 item 2). */
    MISSING_PERSON_CONTEXT("missing_person_context"),

    /** An attachment outside the context the op needs. */
    UNEXPECTED_CONTEXT("unexpected_context"),

    /**
     * An attached op that is not a valid op of the org (or person), a context op the
     * evaluator rejects for any reason but missing person context, or a cited head issued
     * after the proposed op.
     */
    BAD_CONTEXT("bad_context"),

    /** A proposer that would not count as the op's primary signer. */
    PROPOSER_NOT_AUTHORISED("proposer_not_authorised"),

    /** A cosig entry whose signature does not verify over the proposal's core. */
    BAD_COSIG("bad_cosig"),

    /** A cosig entry that verifies but would not count toward the op's quorum. */
    COSIGNER_NOT_COUNTED("cosigner_not_counted"),
}

/**
 * A refusal from the cosign transport ([RosterProposal]), with its [reason]. Any other
 * exception from this package is the caller's (an org that is not a key, a founding op
 * that is not the org's, a signer that is not the draft's): Go's errors for which
 * `proposal.ReasonOf` is "".
 */
class ProposalException(val reason: ProposalReason, message: String, cause: Throwable? = null) :
    IllegalArgumentException("proposal: ${reason.wire}: $message", cause) {
    companion object {
        /** The reason of [e] if it is a refusal from this package, else null (Go `proposal.ReasonOf`). */
        fun reasonOf(e: Throwable?): ProposalReason? = (e as? ProposalException)?.reason
    }
}

internal fun refuse(reason: ProposalReason, message: String, cause: Throwable? = null): Nothing =
    throw ProposalException(reason, message, cause)
