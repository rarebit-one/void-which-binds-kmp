package one.rarebit.voidwhichbinds.auth

import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.crypto.GoStrings

/**
 * Why a presented-ops header value was refused, with void-which-binds-go's refusal word
 * (the `rp` sentinel the vectors spell as `reason`).
 */
class RpHeaderException(val failure: Failure, message: String) : IllegalArgumentException(message) {
    /** The refusal kinds a header parse can reach. */
    enum class Failure(val reason: String) {
        /** `rp.ErrMalformed`: not exactly one canonical org id. */
        MALFORMED("malformed"),

        /** `rp.ErrTooManyOps`: over a header's op-count or op-size cap. */
        TOO_MANY_OPS("too_many_ops"),
    }
}

/**
 * The request headers a device presents beside its `Device` credential, with the caps
 * and parsers void-which-binds-go's `rp` package applies to them (ADR-0005, ADR-0016).
 * Format and parse are byte-identical to Go's: a value this formats is exactly the
 * value Go's `Format…Header` renders, and a parse here refuses exactly what Go's
 * `Parse…Header` refuses, with the same [RpHeaderException.Failure].
 *
 * The **org path** (ADR-0016): a request that carries [ORG_HEADER] is judged only by
 * the RP's org roster, never by falling back to its directly pinned users; one
 * without it only by the pins. The person's roster ops ride in [ROSTER_HEADER]; its
 * person ops, and any cosigner's, ride in [MEMBERSHIP_HEADER], routed by their `usr`.
 * [OrgRequest] assembles the set for one org-path request.
 */
object RpHeaders {

    /** `rp.OrgHeader`: selects the org path, one canonical Ed25519 org id per request. */
    const val ORG_HEADER = "Void-Which-Binds-Org"

    /** `rp.RosterHeader`: the roster op tokens a person presents, comma-separated. */
    const val ROSTER_HEADER = "Void-Which-Binds-Roster"

    /** `rp.MembershipHeader`: the person ops presented, comma-separated (see [DeviceCredential]). */
    const val MEMBERSHIP_HEADER = DeviceCredential.MEMBERSHIP_HEADER

    /** `rp.MaxPresentedOps`: the most ops [MEMBERSHIP_HEADER] may carry. */
    const val MAX_PRESENTED_OPS = DeviceCredential.MAX_PRESENTED_OPS

    /** `rp.MaxPresentedOpBytes`: the wire size one person op token is budgeted at. */
    const val MAX_PRESENTED_OP_BYTES = 1 shl 10

    /** `rp.MaxPresentedOpsBodyBytes`: the body cap of a route carrying the person ops in JSON. */
    const val MAX_PRESENTED_OPS_BODY_BYTES = MAX_PRESENTED_OPS * MAX_PRESENTED_OP_BYTES + (32 shl 10)

    /** `rp.MaxPresentedRosterOps`: the most roster ops one request may present. */
    const val MAX_PRESENTED_ROSTER_OPS = 16

    /**
     * `rp.MaxPresentedRosterOpBytes`: the most UTF-8 bytes one presented roster op token
     * may have (four times a person op; 16 × 4 KiB is the membership header's 64 KiB).
     */
    const val MAX_PRESENTED_ROSTER_OP_BYTES = 4 shl 10

    /**
     * `rp.MaxPresentedRosterBodyBytes`: the body cap of an org-path route carrying its
     * presented ops in JSON — the full roster budget plus [MAX_PRESENTED_OPS_BODY_BYTES].
     */
    const val MAX_PRESENTED_ROSTER_BODY_BYTES =
        MAX_PRESENTED_ROSTER_OPS * MAX_PRESENTED_ROSTER_OP_BYTES + MAX_PRESENTED_OPS_BODY_BYTES

    /**
     * `rp.ParseOrgHeader`: exactly one org id, an Ed25519 key in its canonical rendering
     * (surrounding Go whitespace trimmed). Empty, a list, or any other spelling is
     * [RpHeaderException.Failure.MALFORMED].
     */
    fun parseOrgHeader(value: String): String {
        val org = GoStrings.trimSpace(value)
        if (org.isEmpty()) malformed("empty $ORG_HEADER")
        if (org.contains(',')) malformed("$ORG_HEADER names more than one org")
        try {
            KeyRef.parseCanonicalEd25519(org)
        } catch (e: IllegalArgumentException) {
            malformed("$ORG_HEADER: ${e.message}")
        }
        return org
    }

    /**
     * The [ORG_HEADER] value for [org]: the org id itself, which must already be its
     * canonical rendering (the value [parseOrgHeader] returns unchanged). Anything
     * else is [RpHeaderException.Failure.MALFORMED], so a client never sends an org
     * header every RP refuses.
     */
    fun formatOrgHeader(org: String): String {
        if (parseOrgHeader(org) != org) malformed("$ORG_HEADER: '$org' is not trimmed")
        return org
    }

    /**
     * `rp.ParseRosterHeader`: split on `,`, trim each token (Go whitespace), drop
     * empties. More than [MAX_PRESENTED_ROSTER_OPS] tokens, or any token over
     * [MAX_PRESENTED_ROSTER_OP_BYTES] UTF-8 bytes, is
     * [RpHeaderException.Failure.TOO_MANY_OPS]. An empty value is no ops.
     */
    fun parseRosterHeader(value: String): List<String> {
        val ops = splitOps(value) { tok ->
            val n = GoStrings.utf8Length(tok)
            if (n > MAX_PRESENTED_ROSTER_OP_BYTES) {
                tooMany("a roster op of $n bytes > $MAX_PRESENTED_ROSTER_OP_BYTES")
            }
        }
        if (ops.size > MAX_PRESENTED_ROSTER_OPS) tooMany("${ops.size} roster ops > $MAX_PRESENTED_ROSTER_OPS")
        return ops
    }

    /** `rp.FormatRosterHeader`: the tokens joined by `,`, as given. */
    fun formatRosterHeader(ops: List<String>): String = ops.joinToString(",")

    /**
     * `rp.ParseMembershipHeader`: split on `,`, trim each token (Go whitespace), drop
     * empties. More than [MAX_PRESENTED_OPS] is [RpHeaderException.Failure.TOO_MANY_OPS]
     * (Go caps only the count here, not a token's size). An empty value is no ops.
     */
    fun parseMembershipHeader(value: String): List<String> {
        val ops = splitOps(value) {}
        if (ops.size > MAX_PRESENTED_OPS) tooMany("${ops.size} > $MAX_PRESENTED_OPS")
        return ops
    }

    /**
     * `rp.FormatMembershipHeader`: the tokens joined by `,`, as given. (A device's own
     * de-duplicated, hash-ordered, capped value is [DeviceCredential.membershipHeaderValue].)
     */
    fun formatMembershipHeader(ops: List<String>): String = ops.joinToString(",")

    /**
     * Go's `strings.Split(value, ",")` + `TrimSpace` + skip empties, iteratively; [check]
     * sees each kept token as Go's loop does, so a per-token refusal fires before the
     * count is known, in Go's order.
     */
    private inline fun splitOps(value: String, check: (String) -> Unit): List<String> {
        val ops = ArrayList<String>()
        var start = 0
        while (start <= value.length) {
            val comma = value.indexOf(',', start).let { if (it < 0) value.length else it }
            val tok = GoStrings.trimSpace(value.substring(start, comma))
            if (tok.isNotEmpty()) {
                check(tok)
                ops.add(tok)
            }
            start = comma + 1
        }
        return ops
    }

    private fun malformed(why: String): Nothing = throw RpHeaderException(RpHeaderException.Failure.MALFORMED, why)

    private fun tooMany(why: String): Nothing = throw RpHeaderException(RpHeaderException.Failure.TOO_MANY_OPS, why)
}
