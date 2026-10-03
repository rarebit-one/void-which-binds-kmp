package one.rarebit.voidwhichbinds.auth

import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.crypto.GoStrings

/**
 * What a device sends to a relying party on the **org path** (void-which-binds-go
 * ADR-0016): beside its `Device` credential, the org it authenticates under
 * ([RpHeaders.ORG_HEADER]), the roster ops it knows ([RpHeaders.ROSTER_HEADER]) and the
 * person ops — its own and any cosigner's — the RP needs to evaluate them
 * ([RpHeaders.MEMBERSHIP_HEADER]). It is the org-path counterpart of the sovereign
 * request, which is the `Authorization` header plus
 * [DeviceCredential.membershipHeaderValue] (Go `deviceclient.Transport`).
 *
 * The credential is unchanged in shape: a sovereign person's device add, or a managed
 * person's roster `enrol`, joined to a possession proof (`Device <cred>~<proof>`). One
 * org per request — a person in two orgs sends two requests — and a request without
 * the org header is judged on the RP's direct pins instead, never as a fallback.
 *
 * Both op lists are trimmed (Go whitespace), de-duplicated by op hash and put in hash
 * order, as the sovereign membership value is. Unlike that value, nothing is silently
 * dropped: more roster ops than [RpHeaders.MAX_PRESENTED_ROSTER_OPS], a roster op over
 * [RpHeaders.MAX_PRESENTED_ROSTER_OP_BYTES], or more person ops than
 * [RpHeaders.MAX_PRESENTED_OPS] is [RpHeaderException.Failure.TOO_MANY_OPS] here,
 * because any RP refuses that request whole, and which ops to leave out (the
 * person's own `set`, a cosigner's `bprev`) is the caller's call. An org that is not a
 * canonical Ed25519 key is [RpHeaderException.Failure.MALFORMED].
 *
 * Each header value is exactly what Go's `Format…Header` renders for the same lists,
 * and parses back ([RpHeaders]) to them.
 */
class OrgRequest(org: String, rosterOps: List<String> = emptyList(), membershipOps: List<String> = emptyList()) {

    /** The org id, canonical. */
    val org: String = RpHeaders.formatOrgHeader(org)

    /** The roster ops presented, de-duplicated, in op-hash order. */
    val rosterOps: List<String> = byHash(rosterOps)

    /** The person ops presented (of any `usr`), de-duplicated, in op-hash order. */
    val membershipOps: List<String> = byHash(membershipOps)

    init {
        for (tok in this.rosterOps) {
            val n = GoStrings.utf8Length(tok)
            if (n > RpHeaders.MAX_PRESENTED_ROSTER_OP_BYTES) {
                tooMany("a roster op of $n bytes > ${RpHeaders.MAX_PRESENTED_ROSTER_OP_BYTES}")
            }
        }
        if (this.rosterOps.size > RpHeaders.MAX_PRESENTED_ROSTER_OPS) {
            tooMany("${this.rosterOps.size} roster ops > ${RpHeaders.MAX_PRESENTED_ROSTER_OPS}")
        }
        if (this.membershipOps.size > RpHeaders.MAX_PRESENTED_OPS) {
            tooMany("${this.membershipOps.size} person ops > ${RpHeaders.MAX_PRESENTED_OPS}")
        }
    }

    /**
     * The headers beside the credential, in a stable order: the org header always, the
     * roster and membership headers only when they have ops (an empty one is sent as
     * no header, as the sovereign path does). Add these to every attempt a
     * [DeviceAuthPolicy] driver makes; only `Authorization` changes on a re-mint.
     */
    fun presentedHeaders(): Map<String, String> {
        val h = LinkedHashMap<String, String>()
        h[RpHeaders.ORG_HEADER] = org
        if (rosterOps.isNotEmpty()) h[RpHeaders.ROSTER_HEADER] = RpHeaders.formatRosterHeader(rosterOps)
        if (membershipOps.isNotEmpty()) h[RpHeaders.MEMBERSHIP_HEADER] = RpHeaders.formatMembershipHeader(membershipOps)
        return h
    }

    /**
     * Every header of the request: `Authorization` set to [authorization] (a full
     * `Device <cred>~<proof>` value, e.g. [DeviceCredential.Presentation.headerValue]),
     * then [presentedHeaders].
     */
    fun headers(authorization: String): Map<String, String> {
        require(DeviceCredential.isDeviceHeader(authorization)) { "an org-path request needs a Device credential" }
        val h = LinkedHashMap<String, String>()
        h[DeviceCredential.HEADER] = authorization
        h.putAll(presentedHeaders())
        return h
    }

    /** [headers] with [credential]'s live presentation (which may re-mint). */
    fun headers(credential: DeviceCredential): Map<String, String> = headers(credential.headerValue())

    override fun toString(): String =
        "OrgRequest(org=$org, rosterOps=${rosterOps.size}, membershipOps=${membershipOps.size})"

    private companion object {
        fun byHash(toks: List<String>): List<String> {
            val m = HashMap<String, String>()
            for (raw in toks) {
                val t = GoStrings.trimSpace(raw)
                if (t.isNotEmpty()) m[MembershipOp.hash(t)] = t
            }
            return m.keys.sorted().map { m.getValue(it) }
        }

        fun tooMany(why: String): Nothing = throw RpHeaderException(RpHeaderException.Failure.TOO_MANY_OPS, why)
    }
}
