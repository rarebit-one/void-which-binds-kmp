package one.rarebit.voidwhichbinds.flow

import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.UserIdentity
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.net.HttpResponse
import one.rarebit.voidwhichbinds.net.HttpTransport
import one.rarebit.voidwhichbinds.net.RelayHttpException
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * `authorise` is retry-safe: it signs the add once, a retry after a failed delivery
 * re-sends the same sealed admission, and the write-once slot's 409 on that retry means
 * an earlier attempt landed. The new device receives the one add either way.
 */
class AuthoriseRetryTest {

    /** An in-memory relay whose first admission write fails: stored or not. */
    private class Relay(private val storeTheFailedWrite: Boolean) : HttpTransport {
        val slots = ConcurrentHashMap<String, ByteArray>()
        private var certWrites = 0

        override fun post(url: String, body: ByteArray?, contentType: String?) = if (url.endsWith("/v1/sessions")) {
            HttpResponse(200, """{"session_id":"s1"}""".encodeToByteArray())
        } else {
            HttpResponse(404, ByteArray(0))
        }

        override fun put(url: String, body: ByteArray, contentType: String?): HttpResponse {
            val key = url.substringAfter("/v1/sessions/")
            val first = key.endsWith("/cert") && ++certWrites == 1
            val status = when {
                first && !storeTheFailedWrite -> 503

                // refused, not stored
                slots.putIfAbsent(key, body) != null -> 409

                first -> 500

                // stored, the reply lost
                else -> 204
            }
            return HttpResponse(status, ByteArray(0))
        }

        override fun get(url: String) =
            slots[url.substringAfter("/v1/sessions/")]?.let { HttpResponse(200, it) } ?: HttpResponse(404, ByteArray(0))

        override fun sleep(millis: Long) = Thread.sleep(millis)
    }

    private val now = 1_724_700_000L

    private class Started(
        val http: Relay,
        val auth: DeviceAuthorization,
        val invitation: DeviceAuthorization.Invitation,
        val pairing: DevicePairing,
        val handshake: DevicePairing.Handshake,
    )

    private fun start(storeTheFailedWrite: Boolean): Started {
        val http = Relay(storeTheFailedWrite)
        val seed = ByteArray(32) { (it + 7).toByte() }
        val enc = DeviceIdentity.generateEncryptionKey()
        val device = DeviceIdentity(Ed25519Group.publicKeyFromSeed(seed), enc.publicKey, enc.privateKey) {
            Ed25519Engine.sign(seed, it)
        }
        val auth = DeviceAuthorization(http, UserIdentity.create(), clock = { now }, pollIntervalMillis = 10)
        val pairing = DevicePairing(http, device, clock = { now }, pollIntervalMillis = 10)
        val invitation = auth.invite("http://relay.test", ByteArray(32) { 1 })
        var handshake: DevicePairing.Handshake? = null
        val joiner = Thread { handshake = pairing.begin(invitation.inviteQr) }.apply { start() }
        auth.handshake(invitation)
        joiner.join(15_000)
        return Started(http, auth, invitation, pairing, handshake!!)
    }

    private fun retried(storeTheFailedWrite: Boolean) {
        val s = start(storeTheFailedWrite)
        val auth = s.auth
        val invitation = s.invitation
        val pairing = s.pairing
        val handshake: DevicePairing.Handshake? = s.handshake

        assertFailsWith<RelayHttpException> { auth.authorise(invitation) }
        val ops = auth.authorise(invitation)
        val admission = pairing.confirm(handshake!!)
        assertTrue(admission.op in ops)
        assertEquals(ops, auth.authorise(invitation), "a further retry signs nothing new")
    }

    @Test
    fun aRetryDoesNotTakeOtherBytesInTheSlotForItsOwn() {
        val s = start(storeTheFailedWrite = false)
        assertFailsWith<RelayHttpException> { s.auth.authorise(s.invitation) }
        // Someone holding the session squats the write-once slot before the retry.
        val slot = s.http.slots.keys.first().substringBefore("/") + "/initiator/cert"
        s.http.slots[slot] = "not the admission".encodeToByteArray()
        val e = assertFailsWith<RelayHttpException> { s.auth.authorise(s.invitation) }
        assertEquals(409, e.status)
    }

    @Test
    fun aRefusedDeliveryIsRetriedWithTheSameAdd() = retried(storeTheFailedWrite = false)

    @Test
    fun aLostReplyIsRecognisedOnRetry() = retried(storeTheFailedWrite = true)
}
