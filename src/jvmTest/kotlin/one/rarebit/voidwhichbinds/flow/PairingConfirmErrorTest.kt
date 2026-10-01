package one.rarebit.voidwhichbinds.flow

import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.UserIdentity
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.net.HttpResponse
import one.rarebit.voidwhichbinds.net.HttpTransport
import java.util.concurrent.ConcurrentHashMap
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs

/**
 * The POST-handshake pairing steps against a failing transport: after both sides have
 * derived the SAS over an in-memory relay, the network drops (or the relay serves
 * garbage) while the initiator delivers the cert / the responder receives it. Each must
 * resolve to a [PairingOutcome.Failed], never throw out of the coroutine that drives it.
 * JVM-only because the two handshakes must run concurrently (threads).
 */
class PairingConfirmErrorTest {

    /** The CoordinatorPairingTest relay with a kill switch + a tamper hook. */
    private class RelayTransport : HttpTransport {
        private val slots = ConcurrentHashMap<String, ByteArray>()

        @Volatile var down = false

        @Volatile var status: Int? = null

        /** Skip the poll sleeps so the relay's 60s wait elapses instantly (a timeout test). */
        @Volatile var instantSleep = false

        private fun gate() {
            if (down) throw RuntimeException("failed to connect to /192.168.16.224 (port 7777)")
        }

        override fun post(url: String, body: ByteArray?, contentType: String?): HttpResponse {
            gate()
            return HttpResponse(200, """{"session_id":"s1"}""".encodeToByteArray())
        }
        override fun put(url: String, body: ByteArray, contentType: String?): HttpResponse {
            gate()
            status?.let { return HttpResponse(it, ByteArray(0)) }
            val key = url.substringAfter("/v1/sessions/")
            return if (slots.putIfAbsent(key, body) != null) {
                HttpResponse(409, ByteArray(0))
            } else {
                HttpResponse(204, ByteArray(0))
            }
        }
        override fun get(url: String): HttpResponse {
            gate()
            status?.let { return HttpResponse(it, ByteArray(0)) }
            val key = url.substringAfter("/v1/sessions/")
            val v = slots[key] ?: return HttpResponse(404, ByteArray(0))
            return HttpResponse(200, v)
        }
        override fun sleep(millis: Long) {
            if (!instantSleep) Thread.sleep(millis)
        }

        fun tamper(key: String, bytes: ByteArray) {
            slots[key] = bytes
        }
    }

    private fun device(): DeviceIdentity {
        val seed = ByteArray(32) { (it + 11).toByte() }
        val enc = DeviceIdentity.generateEncryptionKey()
        return DeviceIdentity(Ed25519Group.publicKeyFromSeed(seed), enc.publicKey, enc.privateKey) {
            Ed25519Engine.sign(seed, it)
        }
    }

    private class Handshook(
        val http: RelayTransport,
        val auth: DeviceAuthorization,
        val invitation: DeviceAuthorization.Invitation,
        val pairing: DevicePairing,
        val handshake: DevicePairing.Handshake,
    )

    private fun handshook(): Handshook {
        val http = RelayTransport()
        val auth = DeviceAuthorization(http, UserIdentity.create(), { 1_724_700_000L }, pollIntervalMillis = 10)
        val pairing = DevicePairing(http, device(), { 1_724_700_000L }, pollIntervalMillis = 10)
        val invitation = assertIs<PairingOutcome.Ready<DeviceAuthorization.Invitation>>(
            auth.inviteCatching("http://192.168.16.224:7777"),
        ).value
        var initiator: PairingOutcome<String>? = null
        var responder: PairingOutcome<DevicePairing.Handshake>? = null
        val tA = Thread { initiator = auth.handshakeCatching(invitation) }
        val tB = Thread { responder = pairing.beginCatching(invitation.inviteQr) }
        tA.start()
        tB.start()
        tA.join(15_000)
        tB.join(15_000)
        val sas = assertIs<PairingOutcome.Ready<String>>(initiator).value
        val handshake = assertIs<PairingOutcome.Ready<DevicePairing.Handshake>>(responder).value
        assertEquals(sas, handshake.sas, "the catching handshakes must agree on the SAS like the throwing ones")
        return Handshook(http, auth, invitation, pairing, handshake)
    }

    @Test
    fun authoriseWhenTheNetworkDropsIsUnreachableNotACrash() {
        val h = handshook()
        h.http.down = true
        val failed = assertIs<PairingOutcome.Failed>(h.auth.authoriseCatching(h.invitation))
        assertEquals(PairingFailureKind.UNREACHABLE, failed.kind)
        assertEquals("192.168.16.224:7777", failed.relayHost)
    }

    @Test
    fun authoriseWhenTheRelayRefusesIsRejected() {
        val h = handshook()
        h.http.status = 409 // the write-once cert slot is already taken
        val failed = assertIs<PairingOutcome.Failed>(h.auth.authoriseCatching(h.invitation))
        assertEquals(PairingFailureKind.REJECTED, failed.kind)
    }

    @Test
    fun confirmWhenTheNetworkDropsIsUnreachableNotACrash() {
        val h = handshook()
        h.http.down = true
        val failed = assertIs<PairingOutcome.Failed>(h.pairing.confirmCatching(h.handshake))
        assertEquals(PairingFailureKind.UNREACHABLE, failed.kind)
        assertEquals("192.168.16.224:7777", failed.relayHost)
    }

    @Test
    fun confirmWhenTheCertNeverArrivesIsATimeout() {
        val h = handshook()
        // The initiator never authorises → no cert slot ever appears → the responder's
        // receive polls until the relay wait elapses (sleeps skipped) and gives up.
        h.http.instantSleep = true
        val failed = assertIs<PairingOutcome.Failed>(h.pairing.confirmCatching(h.handshake))
        assertEquals(PairingFailureKind.TIMEOUT, failed.kind)
    }

    @Test
    fun confirmOfATamperedCertIsProtocolNotACrash() {
        val h = handshook()
        h.http.tamper("s1/initiator/cert", """{"wrapped":"AAAA","cipher":"AAAA"}""".encodeToByteArray())
        val failed = assertIs<PairingOutcome.Failed>(h.pairing.confirmCatching(h.handshake))
        assertEquals(PairingFailureKind.PROTOCOL, failed.kind)
    }

    @Test
    fun theHappyPathStillDeliversAVerifiedCert() {
        val h = handshook()
        val ops = assertIs<PairingOutcome.Ready<List<String>>>(h.auth.authoriseCatching(h.invitation)).value
        assertEquals(1, ops.size, "genesis held no ops; after authorising it holds the one add")
        val admission = assertIs<PairingOutcome.Ready<one.rarebit.voidwhichbinds.net.Admission>>(
            h.pairing.confirmCatching(h.handshake),
        ).value
        assertEquals(ops, admission.ops)
        assertEquals(true, one.rarebit.voidwhichbinds.MembershipOp.verify(admission.op).genesis)
    }
}
