package one.rarebit.voidwhichbinds.roster

/**
 * What a roster op does (ADR-0014's `op` column; ADR-0015 adds [REROOT] and
 * [RESOLVE]). Mirrors void-which-binds-go `roster.OpKind`.
 */
enum class OpKind(val wire: String) {
    /** Assigns `mem` a role (a grant or a reduction, by the role mem holds in the op's closure). */
    SET("set"),

    /** Takes `mem` off the roster (a reduction to ⊥). */
    REMOVE("remove"),

    /** Enrols `key` for the managed person `mem` (a grant). */
    ENROL("enrol"),

    /** Unenrols `key` from the managed person `mem` (a reduction). */
    UNENROL("unenrol"),

    /** Resets the admin high-water. Authority key only. */
    RESET("reset"),

    /**
     * Moves the authority key to `succ` (ADR-0015): signed by the current authority key
     * as `by`, with an independent admin quorum in `cosig` and succ's own signature in
     * `succsig`.
     */
    REROOT("reroot"),

    /** Settles conflicting re-roots of the authority key by naming one in `pick`. Authority key only. */
    RESOLVE("resolve"),
    ;

    companion object {
        /** The kind spelled [s] on the wire, or null. */
        fun fromWire(s: String): OpKind? = entries.firstOrNull { it.wire == s }
    }
}

/** A roster person's kind (ADR-0014, "Members are persons"). Mirrors void-which-binds-go `roster.Kind`. */
enum class PersonKind(val wire: String) {
    /** A person identified by their own gen2 genesis key, whose devices are in their own membership log. */
    SOVEREIGN("sovereign"),

    /** An org-scoped person (`mp:<hex>`) whose keys the org's admins enrol in the roster. */
    MANAGED("managed"),
}

/**
 * The roles, as the wire spells them, in increasing privilege: ⊥ (not on the roster,
 * the empty string) < viewer < member < admin < owner. Mirrors void-which-binds-go
 * `roster.Role*` (`scope.Role`).
 */
object Role {
    const val VIEWER = "viewer"
    const val MEMBER = "member"
    const val ADMIN = "admin"
    const val OWNER = "owner"

    /**
     * Whether [r] is one of the admin persons' roles (admin or owner): they sign roster
     * ops and count toward the quorum.
     */
    fun isAdmin(r: String): Boolean = r == ADMIN || r == OWNER

    /** The order of [r]; 0 is ⊥ (and any unknown string). */
    @Suppress("MagicNumber")
    internal fun rank(r: String): Int = when (r) {
        VIEWER -> 1
        MEMBER -> 2
        ADMIN -> 3
        OWNER -> 4
        else -> 0
    }

    @Suppress("MagicNumber")
    internal fun ofRank(r: Int): String = when (r) {
        1 -> VIEWER
        2 -> MEMBER
        3 -> ADMIN
        4 -> OWNER
        else -> ""
    }
}

/**
 * One cosig entry (ADR-0014, "Cosigs"): a key, the person it signs for and that
 * person's causal context, and an Ed25519 signature over the cosig preimage of the op's
 * core. Mirrors void-which-binds-go `roster.Signature`.
 */
data class RosterSignature(
    /** The signing key, `ed25519:<hex>`. */
    val by: String,
    /** The person: a sovereign person's genesis key, or a managed person's `mp:` id. */
    val usr: String = "",
    /** That sovereign person's membership heads as the signing device knows them; empty otherwise. */
    val bprev: List<String> = emptyList(),
    /** base64url (no padding) Ed25519 signature. */
    val sig: String,
)

/**
 * A roster op before it is signed: everything but the cosig entries and the primary
 * signature. A proposer builds a Draft, each cosigner signs its [core] with
 * [Roster.cosignWith], and the proposer signs it with [Roster.signWith]. [by], [usr] and
 * [bprev] are the PRIMARY signer's; a re-root's [succSig] is made with
 * [Roster.succSigWith] before [Roster.signWith]. Times are unix seconds; [exp] 0 is no
 * expiry. Mirrors void-which-binds-go `roster.Draft`.
 */
data class RosterDraft(
    val org: String,
    val op: OpKind,
    val mem: String = "",
    val role: String = "",
    val key: String = "",
    val exp: Long = 0,
    val succ: String = "",
    val pick: String = "",
    val by: String,
    val usr: String = "",
    val bprev: List<String> = emptyList(),
    val prev: List<String> = emptyList(),
    val succSig: String = "",
    val iat: Long,
) {
    /**
     * The bytes every cosig covers: the payload with `cosig` and `succsig` omitted.
     * [prev] and [bprev] are sorted and de-duplicated first, as [Roster.signWith] does.
     * Throws [RosterException] ([RosterException.Failure.MALFORMED]) for a draft
     * [Roster.signWith] would refuse.
     */
    @Throws(Exception::class)
    fun core(): ByteArray {
        if (iat == 0L) throw RosterException(RosterException.Failure.MALFORMED, "an issued-at is required")
        val p = payload().copy(succSig = "")
        RosterWire.validate(p)
        return RosterWire.coreOf(p)
    }

    internal fun payload(): RosterWire.Payload = RosterWire.Payload(
        v = Roster.VERSION.toLong(), typ = Roster.TYP, org = org, op = op.wire, mem = mem, role = role, key = key,
        exp = exp, succ = succ, pick = pick, by = by, usr = usr, bprev = RosterWire.normalise(bprev),
        prev = RosterWire.normalise(prev), cosig = emptyList(), succSig = succSig, iat = iat,
    )
}

/**
 * One parsed, signature-checked roster op ([Roster.verify]). Times are unix seconds;
 * [exp] 0 is none. Mirrors void-which-binds-go `roster.Op`.
 */
data class RosterOp(
    /** [Roster.HASH_PREFIX] + hex(sha256([token])). */
    val hash: String,
    val token: String,
    val org: String,
    val kind: OpKind,
    val mem: String,
    val role: String,
    val key: String,
    val exp: Long,
    val succ: String,
    val pick: String,
    val by: String,
    val usr: String,
    val bprev: List<String>,
    val prev: List<String>,
    val cosig: List<RosterSignature>,
    val succSig: String,
    val iat: Long,
) {
    /** The cosig core of this op (its payload without `cosig` and `succsig`). */
    internal val core: ByteArray by lazy { RosterWire.coreOf(draft().payload()) }

    /** The op's draft (everything but its cosigs and signature): the value a cosigner signed. */
    fun draft(): RosterDraft = RosterDraft(
        org = org, op = kind, mem = mem, role = role, key = key, exp = exp, succ = succ, pick = pick,
        by = by, usr = usr, bprev = bprev, prev = prev, succSig = succSig, iat = iat,
    )

    /**
     * Whether the op is signed in the authority shape: a `by` with no person (`usr`
     * absent). Whether `by` IS the authority key is the evaluator's question.
     */
    val authority: Boolean get() = usr.isEmpty()
}

/**
 * A refusal from [Roster.verify], the minters or [Roster.evaluate]. Mirrors
 * void-which-binds-go's `roster.Err*` sentinels.
 */
class RosterException(val failure: Failure, message: String, cause: Throwable? = null) :
    IllegalArgumentException(message, cause) {
    enum class Failure {
        /** `ErrMalformed`: not a well-formed roster op (or draft). */
        MALFORMED,

        /** `ErrWrongType`: a `typ` that is not [Roster.TYP], or none. */
        WRONG_TYPE,

        /** `ErrSignature`: the primary signature does not verify under `by`. */
        BAD_SIGNATURE,

        /** `ErrCosigSignature`: a cosig entry's signature does not verify ([Roster.verifyDraftCosig]). */
        COSIG_SIGNATURE,

        /** `ErrNoOrg`: an org id that is not a canonical Ed25519 key ([Roster.evaluate]). */
        NO_ORG,

        /** `ErrFounding`: a founding op that is not the org's ([Roster.evaluate]). */
        FOUNDING,
    }
}
