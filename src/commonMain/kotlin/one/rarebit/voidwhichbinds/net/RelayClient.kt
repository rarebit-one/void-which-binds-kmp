package one.rarebit.voidwhichbinds.net

import one.rarebit.voidwhichbinds.crypto.MiniJson

/**
 * Client for the Void-Which-Binds dumb relay (void-which-binds-go `relay`): an opaque,
 * write-once, blob store addressed by (session, role, message-type) over HTTP.
 *
 * Wire (byte-identical to void-which-binds-go/relay/client.go):
 * ```
 * POST {base}/v1/sessions                       -> { "session_id": "..." }
 * PUT  {base}/v1/sessions/{id}/{role}/{type}      store opaque bytes (204)
 * GET  {base}/v1/sessions/{id}/{role}/{type}      read (200 bytes | 404 not yet)
 * ```
 * A client is bound to one session and its own [role]; [post] writes this role's
 * slot, [fetch] polls the PEER role's slot until it appears. The relay learns
 * nothing: every payload is a public value or ciphertext it cannot open.
 */
class RelayClient(
    private val http: HttpTransport,
    private val base: String,
    val session: String,
    val role: String,
    private val pollIntervalMillis: Long = 150,
    /**
     * How long [fetch] keeps polling an absent peer slot before giving up with
     * [RelayTimeout]. A flow that waits for a HUMAN (an initiator waiting for the new
     * device to join, which may first have to create its key behind a fingerprint)
     * should bound this by the relay's session TTL, not the default.
     */
    private val maxWaitMillis: Long = DEFAULT_MAX_WAIT_MILLIS,
) {
    companion object {
        const val ROLE_INITIATOR = "initiator"
        const val ROLE_RESPONDER = "responder"

        /**
         * The message-slot set of the roster cosign transport (void-which-binds-go
         * `relay.CosignTypes`; ADR-0014 "Proposal transport", payloads in
         * [one.rarebit.voidwhichbinds.roster.proposal.RosterProposal]): the proposer writes
         * `proposal` as the initiator, and the cosigner writes `cosig` back as the
         * responder, one session per cosigner. A relay that carries it is configured with
         * these types and [COSIGN_MAX_MESSAGE_BYTES].
         */
        val COSIGN_TYPES: List<String> = listOf("proposal", "cosig")

        /**
         * The slot bound a cosign relay needs: the largest slot payload the transport
         * accepts (512 KiB, `RosterProposal.MAX_PROPOSAL_BYTES`). Mirrors
         * void-which-binds-go `relay.CosignMaxMessageBytes`.
         */
        const val COSIGN_MAX_MESSAGE_BYTES: Int = 512 shl 10

        /** The historical poll bound (60 s) — fine for a peer already in the handshake. */
        const val DEFAULT_MAX_WAIT_MILLIS: Long = 60_000

        /** Ask the relay to open a session and return its id. */
        fun createSession(http: HttpTransport, base: String): String {
            val resp = http.post(trimr(base) + "/v1/sessions")
            if (resp.status != 200) throw RelayHttpException(resp.status, "create session")
            val id = MiniJson.parseObject(resp.body.decodeToString())["session_id"] as? String
            require(!id.isNullOrEmpty()) { "relay: empty session id" }
            return id
        }

        private fun trimr(s: String) = s.trimEnd('/')
    }

    private fun peer(): String = if (role == ROLE_INITIATOR) ROLE_RESPONDER else ROLE_INITIATOR

    private fun slotUrl(role: String, type: String) = "${trimr(base)}/v1/sessions/$session/$role/$type"

    /** Write this role's [type] slot (write-once at the relay). */
    fun post(type: String, payload: ByteArray) {
        val resp = http.put(slotUrl(role, type), payload, "application/octet-stream")
        if (resp.status != 204) throw RelayHttpException(resp.status, "post $role/$type")
    }

    /** Poll the PEER role's [type] slot until present, returning its bytes. */
    fun fetch(type: String): ByteArray {
        val p = peer()
        var waited = 0L
        while (true) {
            val resp = http.get(slotUrl(p, type))
            when (resp.status) {
                200 -> return resp.body

                404 -> {
                    if (waited >= maxWaitMillis) throw RelayTimeout("relay: timed out waiting for $p/$type")
                    http.sleep(pollIntervalMillis)
                    waited += pollIntervalMillis
                }

                else -> throw RelayHttpException(resp.status, "fetch $p/$type")
            }
        }
    }

    /**
     * Like [fetch], but each poll round also reads the peer's [watch] slot, and hands its
     * bytes to [onWatch] the first time it is present. [onWatch] may throw to end the wait
     * (a verified refusal, void-which-binds-go ADR-0012); if it returns, the slot is write-once, so
     * it is not read again. A [watch] slot the relay does not have (any status but 200 or
     * 404, e.g. a relay that predates the slot answers 400) is dropped silently: the wait
     * then behaves exactly like [fetch].
     */
    fun fetchWatching(type: String, watch: String, onWatch: (ByteArray) -> Unit): ByteArray {
        val p = peer()
        var watching = true
        var waited = 0L
        while (true) {
            val resp = http.get(slotUrl(p, type))
            when (resp.status) {
                200 -> return resp.body

                404 -> {
                    if (watching) watching = pollWatch(slotUrl(p, watch), onWatch)
                    if (waited >= maxWaitMillis) throw RelayTimeout("relay: timed out waiting for $p/$type")
                    http.sleep(pollIntervalMillis)
                    waited += pollIntervalMillis
                }

                else -> throw RelayHttpException(resp.status, "fetch $p/$type")
            }
        }
    }

    /** One read of a watched slot; returns whether to keep watching it. */
    private fun pollWatch(url: String, onWatch: (ByteArray) -> Unit): Boolean {
        val w = http.get(url)
        return when (w.status) {
            200 -> {
                onWatch(w.body)
                false
            }

            404 -> true

            else -> false
        }
    }
}

/** Thrown when [RelayClient.fetch] gives up waiting for a peer slot. */
class RelayTimeout(message: String) : RuntimeException(message)

/**
 * The relay was REACHED but answered a non-success [status] for [op] — a stale or
 * already-used session (404 / 409 on a write-once slot), or a server error. Typed,
 * like [WebLoginHttpException], so a flow can classify "reached but refused" apart
 * from "unreachable" (which arrives as whatever the transport throws).
 */
class RelayHttpException(val status: Int, val op: String) : RuntimeException("relay: $op: HTTP $status")
