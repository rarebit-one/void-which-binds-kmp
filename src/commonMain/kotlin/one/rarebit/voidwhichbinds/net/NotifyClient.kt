package one.rarebit.voidwhichbinds.net

import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.auth.DeviceCredential
import one.rarebit.voidwhichbinds.crypto.MiniJson

/**
 * Client for Void-Which-Binds's **push/wake notify plane** (void-which-binds-go `notify`): the
 * device side that registers — and later drops — an ntfy / UnifiedPush wake
 * endpoint so a push login can reach this phone without a scanned QR.
 *
 * Wire (byte-identical to void-which-binds-go/notify/handler.go):
 * ```
 * POST   {base}/v1/subscriptions  {cert, possession, channel, endpoint, ops}
 *        -> 200 { user_id, device_key, channel, expires_at }
 * DELETE {base}/v1/subscriptions  {cert, possession, ops}       -> 204
 * ```
 * Both are **cert-authenticated with a possession proof**: the request carries the
 * device's enrolment cert (its admitting op) and a [one.rarebit.voidwhichbinds.auth.PossessionProof]
 * over it, and the plane binds the subscription to the authenticated `(user, device)`
 * — never to fields the client sent. A device can therefore only register or
 * unsubscribe ITSELF. Since void-which-binds-go v0.19.0 (ADR-0022) the plane refuses a
 * bare cert (`ErrPossessionRequired`): a cert is a public token and proves nothing
 * about who sent it. `ops` are the membership ops the device knows (ADR-0007), so a
 * device admitted by another member — not by the user's genesis cert — evaluates on
 * first contact. An un-enrolled device, or one with no proof, is refused (the plane's
 * 401), surfaced here as a thrown [IllegalArgumentException].
 *
 * The plane is a **wake channel, not a crypto path**: registration hands over a
 * public ntfy topic URL and nothing else. This client never sees a private key, a
 * challenge, or a match number — those live in [WebLoginClient] / [WebLogin].
 */
class NotifyClient(private val http: HttpTransport, private val base: String) {
    private fun trimr(s: String) = s.trimEnd('/')
    private fun url() = trimr(base) + "/v1/subscriptions"

    /** The self-hosted ntfy / UnifiedPush wake channel — the only one Void-Which-Binds ships. */
    companion object {
        const val CHANNEL_NTFY = "ntfy"
    }

    /**
     * What the plane recorded for this device: the authenticated [userId] and
     * [deviceKey] it bound the subscription to (both `ed25519:<hex>`, set from the
     * cert — echoed back so a caller can confirm which identity/device registered),
     * the [channel], and the unix-seconds [expiresAt] after which the device must
     * re-register.
     */
    class Subscription(val userId: String, val deviceKey: String, val channel: String, val expiresAt: Long)

    /**
     * Register [endpoint] (this device's ntfy topic URL) as a wake address on
     * [channel] (default [CHANNEL_NTFY]), authenticated by [certToken] and
     * [possession] — a [one.rarebit.voidwhichbinds.auth.PossessionProof] minted over
     * [certToken] by the device key — presenting the membership [ops] the device knows.
     * A subscription is not a credential: it lapses at [Subscription.expiresAt] and the
     * device re-registers before then. Throws if the plane refuses the registration
     * (un-enrolled device, a missing or bad proof, unserved channel, missing endpoint).
     */
    @Throws(Exception::class)
    fun subscribe(
        certToken: String,
        possession: String,
        endpoint: String,
        ops: List<String> = emptyList(),
        channel: String = CHANNEL_NTFY,
    ): Subscription {
        require(certToken.isNotEmpty()) { "notify: a device enrolment cert is required" }
        require(possession.isNotEmpty()) { "notify: a possession proof is required" }
        require(endpoint.isNotEmpty()) { "notify: a wake endpoint is required" }
        val fields = mutableListOf<Pair<String, Any>>(
            "cert" to certToken,
            "possession" to possession,
            "channel" to channel,
            "endpoint" to endpoint,
        )
        presented(ops)?.let { fields += "ops" to it }
        val body = MiniJson.encodeObject(fields).encodeToByteArray()
        val resp = http.post(url(), body, "application/json")
        require(resp.status == 200) { "notify: subscribe refused: HTTP ${resp.status}" }
        val o = MiniJson.parseObject(resp.body.decodeToString())
        return Subscription(
            userId = o["user_id"] as String,
            deviceKey = o["device_key"] as String,
            channel = o["channel"] as String,
            expiresAt = o["expires_at"] as Long,
        )
    }

    /**
     * Drop THIS device's wake subscription, authenticated by [certToken] and
     * [possession] exactly as [subscribe] is — the `(user, device)` to remove comes
     * from the cert, never the client, so a device can only unsubscribe itself. Throws
     * if the plane refuses (a bad/expired cert, a missing or bad proof).
     */
    @Throws(Exception::class)
    fun unsubscribe(certToken: String, possession: String, ops: List<String> = emptyList()) {
        require(certToken.isNotEmpty()) { "notify: a device enrolment cert is required" }
        require(possession.isNotEmpty()) { "notify: a possession proof is required" }
        val fields = mutableListOf<Pair<String, Any>>("cert" to certToken, "possession" to possession)
        presented(ops)?.let { fields += "ops" to it }
        val body = MiniJson.encodeObject(fields).encodeToByteArray()
        val resp = http.delete(url(), body, "application/json")
        require(resp.status == 204) { "notify: unsubscribe refused: HTTP ${resp.status}" }
    }

    /**
     * The `ops` to send: de-duplicated and capped at [DeviceCredential.MAX_PRESENTED_OPS]
     * (Go `rp.MaxPresentedOps` — the plane refuses a longer list outright), or null when
     * there is nothing to present (the field is then omitted, as Go's `omitempty` does).
     */
    private fun presented(ops: List<String>): List<String>? =
        Membership.merge(ops).take(DeviceCredential.MAX_PRESENTED_OPS).takeIf { it.isNotEmpty() }
}
