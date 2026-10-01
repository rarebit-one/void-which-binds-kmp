package one.rarebit.voidwhichbinds.flow

import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.PairRefusal
import one.rarebit.voidwhichbinds.UserIdentity
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.net.HttpResponse
import one.rarebit.voidwhichbinds.net.HttpTransport
import one.rarebit.voidwhichbinds.net.PairflowAuthority
import one.rarebit.voidwhichbinds.net.PairflowInitiator
import one.rarebit.voidwhichbinds.net.PairflowResponder
import one.rarebit.voidwhichbinds.net.RelayClient
import one.rarebit.voidwhichbinds.net.RelayHttpException
import one.rarebit.voidwhichbinds.net.RelayTimeout
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * The pairing refusal of void-which-binds-go ADR-0012 (void-which-binds-go#64): an initiator that
 * refuses makes the joiner stop at once instead of waiting out its relay timeout; a
 * refusal nobody but the SAS-bound initiator could have signed is ignored; and a relay
 * or responder that predates the `refuse` slot behaves exactly as before.
 */
class PairingRefusalTest {

    /** An in-memory voidbind relay (write-once slots); [refuseSlot] false = a pre-ADR-0012 relay (400). */
    private class RelayTransport(private val refuseSlot: Boolean = true) : HttpTransport {
        val slots = ConcurrentHashMap<String, ByteArray>()
        private var seq = 0

        private fun unknownSlot(url: String) = !refuseSlot && url.endsWith("/${PairRefusal.SLOT}")

        override fun post(url: String, body: ByteArray?, contentType: String?): HttpResponse =
            if (url.endsWith("/v1/sessions")) {
                HttpResponse(200, """{"session_id":"s${++seq}"}""".encodeToByteArray())
            } else {
                HttpResponse(404, ByteArray(0))
            }

        override fun put(url: String, body: ByteArray, contentType: String?): HttpResponse {
            if (unknownSlot(url)) return HttpResponse(400, ByteArray(0))
            val key = url.substringAfter("/v1/sessions/")
            return HttpResponse(if (slots.putIfAbsent(key, body) != null) 409 else 204, ByteArray(0))
        }

        override fun get(url: String): HttpResponse {
            val v = slots[url.substringAfter("/v1/sessions/")]
            return when {
                unknownSlot(url) -> HttpResponse(400, ByteArray(0))
                v == null -> HttpResponse(404, ByteArray(0))
                else -> HttpResponse(200, v)
            }
        }

        override fun sleep(millis: Long) = Thread.sleep(millis)
    }

    private val relayBase = "http://relay.test"
    private val now = 1_724_700_000L

    private fun softwareDevice(seedByte: Int): DeviceIdentity {
        val seed = ByteArray(32) { (it + seedByte).toByte() }
        val enc = DeviceIdentity.generateEncryptionKey()
        return DeviceIdentity(
            signPublicKey = Ed25519Group.publicKeyFromSeed(seed),
            encPublicKey = enc.publicKey,
            encPrivateKey = enc.privateKey,
            signFn = { msg -> Ed25519Engine.sign(seed, msg) },
        )
    }

    private fun handshakes(
        auth: DeviceAuthorization,
        invitation: DeviceAuthorization.Invitation,
        pairing: DevicePairing,
    ): DevicePairing.Handshake {
        var sas = ""
        var hs: DevicePairing.Handshake? = null
        val a = Thread { sas = auth.handshake(invitation) }
        val b = Thread { hs = pairing.begin(invitation.inviteQr) }
        a.start()
        b.start()
        a.join(15_000)
        b.join(15_000)
        val out = checkNotNull(hs) { "the joiner's handshake did not finish" }
        assertEquals(sas, out.sas, "honest SAS must match")
        return out
    }

    @Test
    fun aRefusedJoinerFailsFastAsRefused() {
        val http = RelayTransport()
        val auth = DeviceAuthorization(http, UserIdentity.create(), clock = { now }, pollIntervalMillis = 10)
        val pairing = DevicePairing(http, softwareDevice(11), clock = { now }, pollIntervalMillis = 10)
        val invitation = auth.invite(relayBase, ByteArray(32) { (it * 3 + 1).toByte() })
        val hs = handshakes(auth, invitation, pairing)

        assertIs<PairingOutcome.Ready<Unit>>(auth.refuseCatching(invitation))
        val started = System.nanoTime()
        val outcome = pairing.confirmCatching(hs)
        val tookMs = (System.nanoTime() - started) / 1_000_000
        val failed = assertIs<PairingOutcome.Failed>(outcome)
        assertEquals(PairingFailureKind.REFUSED, failed.kind)
        assertTrue(tookMs < 5_000, "the refusal took ${tookMs}ms; the relay wait is 60s")
        assertTrue(http.slots.keys.none { it.endsWith("/initiator/cert") }, "a refused pairing wrote a cert")
        assertFailsWith<IllegalStateException> { auth.authorise(invitation) }
    }

    @Test
    fun refuseAfterAuthoriseFails() {
        val http = RelayTransport()
        val auth = DeviceAuthorization(http, UserIdentity.create(), clock = { now }, pollIntervalMillis = 10)
        val pairing = DevicePairing(http, softwareDevice(12), clock = { now }, pollIntervalMillis = 10)
        val invitation = auth.invite(relayBase, ByteArray(32) { (it * 3 + 2).toByte() })
        handshakes(auth, invitation, pairing)
        auth.authorise(invitation)
        assertFailsWith<IllegalStateException> { auth.refuse(invitation) }
    }

    @Test
    fun aForgedRefusalIsIgnoredAndTheHonestAdmissionStillLands() {
        val salt = ByteArray(32) { (it * 3 + 4).toByte() }
        val stranger = Ed25519Engine.generate()
        val user = UserIdentity.create()
        val forgeries = mapOf(
            "a third party's own refusal" to
                PairRefusal.sign({ Ed25519Engine.sign(stranger.privateSeed, it) }, stranger.publicKey, salt),
            "the initiator's refusal of another session" to
                PairRefusal.sign(user.signer(), user.userPublicKey, ByteArray(32) { 9 }),
            "garbage" to "not-a-token",
        )
        for ((name, forged) in forgeries) {
            val http = RelayTransport()
            val auth = DeviceAuthorization(http, user, clock = { now }, pollIntervalMillis = 10)
            val pairing = DevicePairing(http, softwareDevice(13), clock = { now }, pollIntervalMillis = 10)
            val invitation = auth.invite(relayBase, salt)
            val hs = handshakes(auth, invitation, pairing)
            http.slots["${invitation.relaySession}/initiator/${PairRefusal.SLOT}"] = forged.encodeToByteArray()

            var outcome: PairingOutcome<*>? = null
            val joiner = Thread { outcome = pairing.confirmCatching(hs) }
            joiner.start()
            Thread.sleep(100) // the joiner has read the forgery and moved on
            auth.authorise(invitation)
            joiner.join(15_000)
            assertIs<PairingOutcome.Ready<*>>(outcome, "$name: the forgery ended the pairing")
        }
    }

    /** One pairing with explicit relay clients, so the joiner's wait can be short. */
    private fun lowLevel(http: RelayTransport, salt: ByteArray): Pair<PairflowInitiator, PairflowResponder> {
        val user = Ed25519Engine.generate()
        val dev = softwareDevice(14)
        val session = RelayClient.createSession(http, relayBase)
        val init = PairflowInitiator(
            RelayClient(http, relayBase, session, RelayClient.ROLE_INITIATOR, pollIntervalMillis = 10),
            PairflowAuthority.Genesis({ Ed25519Engine.sign(user.privateSeed, it) }, user.publicKey, emptyList(), 0),
            salt,
            now,
        )
        val resp = PairflowResponder(
            RelayClient(
                http,
                relayBase,
                session,
                RelayClient.ROLE_RESPONDER,
                pollIntervalMillis = 10,
                maxWaitMillis = 300,
            ),
            KeyRef.ed25519(user.publicKey).render(),
            dev.signPublicKey,
            dev.encPublicKey,
            salt,
            now,
        )
        val a = Thread { init.handshake() }
        val b = Thread { resp.handshake() }
        a.start()
        b.start()
        a.join(15_000)
        b.join(15_000)
        return init to resp
    }

    @Test
    fun aRelayWithoutTheSlotFallsBackToTheTimeout() {
        val http = RelayTransport(refuseSlot = false)
        val salt = ByteArray(32) { (it * 3 + 5).toByte() }
        val (init, resp) = lowLevel(http, salt)
        assertFailsWith<RelayHttpException> { init.refuse() }
        assertFailsWith<RelayTimeout> { resp.receive(ByteArray(32)) }
    }

    @Test
    fun aJoinerStillEnrolsOverARelayWithoutTheSlot() {
        val http = RelayTransport(refuseSlot = false)
        val auth = DeviceAuthorization(http, UserIdentity.create(), clock = { now }, pollIntervalMillis = 10)
        val pairing = DevicePairing(http, softwareDevice(15), clock = { now }, pollIntervalMillis = 10)
        val invitation = auth.invite(relayBase, ByteArray(32) { (it * 3 + 6).toByte() })
        val hs = handshakes(auth, invitation, pairing)
        auth.authorise(invitation)
        pairing.confirm(hs)
    }

    @Test
    fun aJoinerThatPredatesTheRefusalTimesOutAsBefore() {
        val http = RelayTransport()
        val salt = ByteArray(32) { (it * 3 + 7).toByte() }
        val (init, _) = lowLevel(http, salt)
        init.refuse()
        // The pre-ADR-0012 receive: a single fetch of the cert slot. The refusal does not touch it.
        val old = RelayClient(
            http,
            relayBase,
            "s1",
            RelayClient.ROLE_RESPONDER,
            pollIntervalMillis = 10,
            maxWaitMillis = 200,
        )
        assertFailsWith<RelayTimeout> { old.fetch("cert") }
    }
}
