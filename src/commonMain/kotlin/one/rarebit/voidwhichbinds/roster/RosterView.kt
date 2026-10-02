package one.rarebit.voidwhichbinds.roster

/**
 * The machine-readable refusals [Roster.evaluate] reports for an op, rendered exactly
 * as void-which-binds-go `roster.Reason*` so the vectors compare as strings. The
 * strings shared with [one.rarebit.voidwhichbinds.Membership.Reason] mean the same in
 * this log.
 */
object RosterReason {
    // Rejected: the op is not part of the state and cannot be cited.
    const val MALFORMED = "malformed"
    const val BAD_SIGNATURE = "bad_signature"
    const val WRONG_TYPE = "wrong_type"

    /** A roster op whose `org` names another org (the ADR-0007 reason for another identity's op). */
    const val FOREIGN_USER = "foreign_usr"
    const val BAD_PREV = "bad_prev"

    /**
     * An op one of whose signatures cites, in `bprev`, a person op the evaluator was not
     * given (or one issued after the roster op): it is judged again when that past arrives.
     */
    const val MISSING_PERSON_CONTEXT = "missing_person_context"

    // Ineffective: the op is in the state, citable, and changes nothing.
    const val UNAUTHORISED = "unauthorised"
    const val UNDER_THRESHOLD = "under_threshold"
    const val OUTRANKED = "outranked"
    const val OWNER_REQUIRED = "owner_required"
    const val LAST_OWNER = "last_owner"

    /**
     * An op signed by an authority key that an effective re-root has retired
     * (ADR-0015), and that is not in that re-root's closure.
     */
    const val RETIRED_AUTHORITY = "retired_authority"

    /**
     * An eligible re-root that did not apply because another eligible re-root of the
     * same key conflicts with it, and any resolve by the authority key that settles no
     * conflict (ADR-0015, amended G3).
     */
    const val REROOT_CONFLICT = "reroot_conflict"
}

/** One person on the evaluated roster. Mirrors void-which-binds-go `roster.Person`. */
data class RosterPerson(
    /** `ed25519:<hex>` or `mp:<hex>`. */
    val id: String,
    val kind: PersonKind,
    val role: String,
    /**
     * A managed person's live enrolled keys (true: an Ed25519 key, which can sign
     * roster ops; false: a live passkey). Null for a sovereign person.
     */
    val keys: Map<String, Boolean>?,
    /** The frontier ops [role] came from, sorted. */
    val assignedBy: List<String>,
    /** The earliest exp among those ops (unix seconds); 0 if none. */
    val expires: Long,
)

/**
 * The evaluated roster: a pure function of (org, founding, the roster op set, the
 * person op sets, now). Mirrors void-which-binds-go `roster.View`.
 */
@Suppress("LongParameterList")
class RosterView(
    /** The org id, the founding genesis. */
    val org: String,
    /**
     * The current authority key (ADR-0015): the org id, or the successor of the last
     * re-root the chain applied. While [frozen] it is the key whose re-roots conflict.
     */
    val authority: String,
    val persons: Map<String, RosterPerson>,
    /** Every person off the roster by an effective remove in their frontier. */
    val removed: Set<String>,
    /** The frontier of the valid roster DAG, sorted: what a new op cites. */
    val heads: List<String>,
    /** H for a new op citing every head (ADR-0014). */
    val adminHighWater: Int,
    /** Each accepted op's own admin high-water H(X), the one rule 3 judged it against. */
    val highWater: Map<String, Int>,
    /**
     * Conflicting re-roots of the authority key (ADR-0015). The roster is still
     * reported, but nothing may authenticate under a frozen view.
     */
    val frozen: Boolean,
    /** The conflicting re-roots' hashes while [frozen], sorted; null otherwise. */
    val conflict: List<String>?,
    /** Every structurally valid op by hash: the state to record. */
    val accepted: Map<String, RosterOp>,
    /** Structurally invalid tokens by hash, with the [RosterReason]. */
    val rejected: Map<String, String>,
    /** Accepted ops that change nothing, with the [RosterReason]. */
    val ineffective: Map<String, String>,
    /**
     * The earliest instant (unix seconds) after the evaluation's now at which the view
     * changes with no new op: the next exp of a role or key it resolved. 0 if none.
     */
    val nextExpiry: Long,
) {
    /** The accepted ops' tokens in hash order: the state to record. */
    fun tokens(): List<String> = accepted.keys.sorted().map { accepted.getValue(it).token }
}
