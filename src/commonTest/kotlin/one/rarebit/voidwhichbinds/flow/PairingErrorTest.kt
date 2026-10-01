package one.rarebit.voidwhichbinds.flow

import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.Invite
import one.rarebit.voidwhichbinds.UserIdentity
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.net.HttpResponse
import one.rarebit.voidwhichbinds.net.HttpTransport
import one.rarebit.voidwhichbinds.net.RelayClient
import one.rarebit.voidwhichbinds.net.RelayHttpException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Regression for the on-device crash: joining a `voidbind:pair?…` invite while the phone
 * had no route to the relay threw `SocketTimeoutException` out of the blocking
 * transport, through [DevicePairing.begin], and killed the app (FATAL EXCEPTION main).
 * Every network-touching pairing step must instead resolve to a [PairingOutcome.Failed]
 * with a message that says what to do — never throw. Covers the transport throwing
 * (no route / refused / TLS / timeout / cleartext all arrive this way), a reached relay
 * refusing, a peer that never joins, and a malformed invite, for the responder's join
 * and the initiator's invite + handshake. The post-handshake steps (confirm/authorise)
 * need two threads over a relay and live in jvmTest (`PairingConfirmErrorTest`).
 */
class PairingErrorTest {

    private val relay = "http://192.168.16.224:7777/pair"
    private val invite = Invite.Parsed(
        relay,
        "deadbeef",
        ByteArray(32) {
            7
        },
        "ed25519:f947b10c8089aa8fed2d435fae069d0ca1513b33691955ae963dfe8bc5b398c4",
    )

    private fun device(): DeviceIdentity {
        val enc = DeviceIdentity.generateEncryptionKey()
        val pub = Ed25519Group.publicKeyFromSeed(ByteArray(32) { 1 })
        return DeviceIdentity(pub, enc.publicKey, enc.privateKey) { ByteArray(64) }
    }

    /** Every call blows up the way OkHttp does with no route to the relay. */
    private class ThrowingTransport(private val boom: () -> Throwable) : HttpTransport {
        override fun get(url: String): HttpResponse = throw boom()
        override fun post(url: String, body: ByteArray?, contentType: String?): HttpResponse = throw boom()
        override fun put(url: String, body: ByteArray, contentType: String?): HttpResponse = throw boom()
        override fun sleep(millis: Long) {}
    }

    /** Reaches the relay; every call answers [status]. */
    private class StatusTransport(private val status: Int) : HttpTransport {
        override fun get(url: String) = HttpResponse(status, ByteArray(0))
        override fun post(url: String, body: ByteArray?, contentType: String?) = HttpResponse(status, ByteArray(0))
        override fun put(url: String, body: ByteArray, contentType: String?) = HttpResponse(status, ByteArray(0))
        override fun sleep(millis: Long) {}
    }

    /** Session opens and writes land, but the peer's slot never appears (404 forever). */
    private class LonelyTransport : HttpTransport {
        override fun get(url: String) = HttpResponse(404, ByteArray(0))
        override fun post(url: String, body: ByteArray?, contentType: String?) =
            HttpResponse(200, """{"session_id":"s1"}""".encodeToByteArray())
        override fun put(url: String, body: ByteArray, contentType: String?) = HttpResponse(204, ByteArray(0))
        override fun sleep(millis: Long) {}
    }

    /** Session opens, then the network drops: every later call throws. */
    private class DropAfterSessionTransport : HttpTransport {
        override fun get(url: String): HttpResponse = throw RuntimeException("failed to connect")
        override fun post(url: String, body: ByteArray?, contentType: String?) =
            HttpResponse(200, """{"session_id":"s1"}""".encodeToByteArray())
        override fun put(url: String, body: ByteArray, contentType: String?): HttpResponse =
            throw RuntimeException("failed to connect")
        override fun sleep(millis: Long) {}
    }

    // --- responder: joinPairInvite → DevicePairing.beginCatching -------------------

    @Test
    fun joinWithNoRouteToTheRelayIsUnreachableNotACrash() {
        // Mirrors the captured SocketTimeoutException("failed to connect to /192.168.16.224 (port 7777)").
        val pairing =
            DevicePairing(
                ThrowingTransport {
                    RuntimeException("failed to connect to /192.168.16.224 (port 7777)")
                },
                device(),
                { 1L },
            )
        val outcome = pairing.beginCatching(invite) // must NOT throw
        val failed = assertIs<PairingOutcome.Failed>(outcome)
        assertEquals(PairingFailureKind.UNREACHABLE, failed.kind)
        assertEquals("192.168.16.224:7777", failed.relayHost)
        assertEquals(
            "Can't reach the relay at 192.168.16.224:7777. Check Wi-Fi or your VPN and try again.",
            failed.message,
        )
        assertTrue(
            "SocketTimeout" !in failed.message && "failed to connect" !in failed.message,
            "no raw exception text",
        )
    }

    @Test
    fun joinWhenTheRelayRefusesIsRejectedNotACrash() {
        for (status in listOf(404, 409, 500)) {
            val pairing = DevicePairing(StatusTransport(status), device(), { 1L })
            val failed = assertIs<PairingOutcome.Failed>(pairing.beginCatching(invite), "HTTP $status must not throw")
            assertEquals(PairingFailureKind.REJECTED, failed.kind, "HTTP $status should be REJECTED")
            assertTrue(failed.message.contains("HTTP $status"))
        }
    }

    @Test
    fun joinWhenTheInitiatorNeverShowsUpIsATimeout() {
        // A single poll step above the 60s relay wait so the test does not spin.
        val pairing = DevicePairing(LonelyTransport(), device(), { 1L }, pollIntervalMillis = 120_000)
        val failed = assertIs<PairingOutcome.Failed>(pairing.beginCatching(invite))
        assertEquals(PairingFailureKind.TIMEOUT, failed.kind)
        assertTrue(failed.message.contains("fresh invite"))
    }

    @Test
    fun joinFromAMalformedInviteStringIsProtocolNotACrash() {
        val pairing = DevicePairing(ThrowingTransport { RuntimeException("never reached") }, device(), { 1L })
        val failed = assertIs<PairingOutcome.Failed>(pairing.beginCatching("voidbind:pair?relay=&session="))
        assertEquals(PairingFailureKind.PROTOCOL, failed.kind)
        val failed2 = assertIs<PairingOutcome.Failed>(pairing.beginCatching("not a voidbind uri at all"))
        assertEquals(PairingFailureKind.PROTOCOL, failed2.kind)
    }

    @Test
    fun theThrowingBeginStillThrowsForCallersThatCatch() {
        val pairing = DevicePairing(ThrowingTransport { RuntimeException("boom") }, device(), { 1L })
        assertFailsWith<RuntimeException> { pairing.begin(invite) }
    }

    // --- initiator: startPairInvite → DeviceAuthorization.inviteCatching -----------

    @Test
    fun inviteWithNoRouteToTheRelayIsUnreachableNotACrash() {
        val auth =
            DeviceAuthorization(
                ThrowingTransport {
                    RuntimeException("failed to connect")
                },
                UserIdentity.create(),
                { 1L },
            )
        val failed = assertIs<PairingOutcome.Failed>(auth.inviteCatching("https://relay.thesim.family"))
        assertEquals(PairingFailureKind.UNREACHABLE, failed.kind)
        assertEquals("relay.thesim.family", failed.relayHost)
        assertTrue(failed.message.contains("relay.thesim.family"))
    }

    @Test
    fun inviteWhenTheRelayRefusesASessionIsRejected() {
        val auth = DeviceAuthorization(StatusTransport(503), UserIdentity.create(), { 1L })
        val failed = assertIs<PairingOutcome.Failed>(auth.inviteCatching(relay))
        assertEquals(PairingFailureKind.REJECTED, failed.kind)
    }

    // --- initiator: awaitPairHandshake → DeviceAuthorization.handshakeCatching -----

    @Test
    fun handshakeWhenTheNetworkDropsAfterTheInviteIsUnreachable() {
        val auth = DeviceAuthorization(DropAfterSessionTransport(), UserIdentity.create(), { 1L })
        val invitation = assertIs<PairingOutcome.Ready<DeviceAuthorization.Invitation>>(
            auth.inviteCatching(relay),
        ).value
        val failed = assertIs<PairingOutcome.Failed>(auth.handshakeCatching(invitation))
        assertEquals(PairingFailureKind.UNREACHABLE, failed.kind)
        assertEquals("192.168.16.224:7777", failed.relayHost)
    }

    @Test
    fun handshakeWhenNoDeviceJoinsIsATimeout() {
        val auth = DeviceAuthorization(LonelyTransport(), UserIdentity.create(), { 1L }, pollIntervalMillis = 120_000)
        val invitation = assertIs<PairingOutcome.Ready<DeviceAuthorization.Invitation>>(
            auth.inviteCatching(relay),
        ).value
        val failed = assertIs<PairingOutcome.Failed>(auth.handshakeCatching(invitation))
        assertEquals(PairingFailureKind.TIMEOUT, failed.kind)
    }

    // --- the layer beneath + the classifier ---------------------------------------

    @Test
    fun relayClientThrowsTypedExceptionOnNonSuccess() {
        val e = assertFailsWith<RelayHttpException> { RelayClient.createSession(StatusTransport(500), relay) }
        assertEquals(500, e.status)
        val client = RelayClient(StatusTransport(409), relay, "s", RelayClient.ROLE_RESPONDER)
        assertEquals(409, assertFailsWith<RelayHttpException> { client.post("commit", ByteArray(1)) }.status)
    }

    @Test
    fun hostOfRendersHostAndPortWithoutPathOrScheme() {
        assertEquals("192.168.16.224:7777", PairingFailures.hostOf("http://192.168.16.224:7777/pair"))
        assertEquals("relay.thesim.family", PairingFailures.hostOf("https://relay.thesim.family"))
        assertEquals("relay.thesim.family", PairingFailures.hostOf("https://relay.thesim.family/"))
        assertEquals("host:1", PairingFailures.hostOf("http://user@host:1/x?y#z"))
        assertEquals("the relay", PairingFailures.hostOf(""))
    }
}
