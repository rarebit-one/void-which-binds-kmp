package one.rarebit.voidwhichbinds.net

import one.rarebit.voidwhichbinds.crypto.MiniJson

/**
 * Client for Void-Which-Binds's **push/wake notify plane** (void-which-binds-go `notify`): the
 * device side that registers — and later drops — an ntfy / UnifiedPush wake
 * endpoint so a push login can reach this phone without a scanned QR.
 *
 * Wire (byte-identical to void-which-binds-go/notify/handler.go):
 * ```
 * POST   {base}/v1/subscriptions  {cert, channel, endpoint}
 *        -> 200 { user_id, device_key, channel, expires_at }
 * DELETE {base}/v1/subscriptions  {cert}                       -> 204
 * ```
 * Both are **cert-authenticated**: the request carries only the device's enrolment
 * cert token, and the plane binds the subscription to the authenticated
 * `(user, device)` the cert names — never to fields the client sent. A device can
 * therefore only register or unsubscribe ITSELF. An un-enrolled device is refused
 * (the plane's 401), surfaced here as a thrown [IllegalStateException].
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
     * [channel] (default [CHANNEL_NTFY]), authenticated by [certToken]. Call it on
     * app open — a subscription is not a credential, so it is short-lived and the
     * device re-registers rather than trusting a stale one. Throws if the plane
     * refuses the registration (un-enrolled device, unserved channel, missing
     * endpoint).
     */
    @Throws(Exception::class)
    fun subscribe(certToken: String, endpoint: String, channel: String = CHANNEL_NTFY): Subscription {
        require(certToken.isNotEmpty()) { "notify: a device enrolment cert is required" }
        require(endpoint.isNotEmpty()) { "notify: a wake endpoint is required" }
        val body = MiniJson.encodeObject(
            listOf("cert" to certToken, "channel" to channel, "endpoint" to endpoint),
        ).encodeToByteArray()
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
     * Drop THIS device's wake subscription, authenticated by [certToken] — the
     * `(user, device)` to remove comes from the cert, never the client, so a device
     * can only unsubscribe itself. Throws if the plane refuses (a bad/expired cert).
     */
    @Throws(Exception::class)
    fun unsubscribe(certToken: String) {
        require(certToken.isNotEmpty()) { "notify: a device enrolment cert is required" }
        val body = MiniJson.encodeObject(listOf("cert" to certToken)).encodeToByteArray()
        val resp = http.delete(url(), body, "application/json")
        require(resp.status == 204) { "notify: unsubscribe refused: HTTP ${resp.status}" }
    }
}
