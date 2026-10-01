package one.rarebit.voidwhichbinds.flow

import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.LoginQr
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.net.HttpResponse
import one.rarebit.voidwhichbinds.net.HttpTransport
import one.rarebit.voidwhichbinds.net.WebLoginClient
import one.rarebit.voidwhichbinds.net.WebLoginHttpException
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * Regression for the on-device crash (issue #20): a failed login-challenge fetch must
 * resolve to an [LoginApproval.Outcome.Failed] the UI can render, NOT propagate as an
 * uncaught throw. Covers every failure shape — the transport throwing (an unreachable
 * RP / TLS error / timeout / cleartext-blocked URL all arrive this way) and a non-2xx
 * from a reached RP — plus the happy path still returning [LoginApproval.Outcome.Ready].
 */
class LoginApprovalErrorTest {

    // A device is required to construct LoginApproval but is never touched by begin()/
    // beginCatching() — only fetchChallenge runs — so dummy key material is fine here.
    private fun dummyDevice(): DeviceIdentity {
        val enc = DeviceIdentity.generateEncryptionKey()
        val pub = Ed25519Group.publicKeyFromSeed(ByteArray(32) { 1 })
        return DeviceIdentity(pub, enc.publicKey, enc.privateKey) { ByteArray(64) }
    }

    /** A transport whose GET blows up the way OkHttp does for a cleartext/TLS/timeout failure. */
    private class ThrowingTransport(private val boom: () -> Throwable) : HttpTransport {
        override fun get(url: String): HttpResponse = throw boom()
        override fun post(url: String, body: ByteArray?, contentType: String?) = HttpResponse(500, ByteArray(0))
        override fun put(url: String, body: ByteArray, contentType: String?) = HttpResponse(500, ByteArray(0))
        override fun sleep(millis: Long) {}
    }

    /** A transport that reaches the RP but gets back a non-success status. */
    private class StatusTransport(private val status: Int) : HttpTransport {
        override fun get(url: String) = HttpResponse(status, ByteArray(0))
        override fun post(url: String, body: ByteArray?, contentType: String?) = HttpResponse(status, ByteArray(0))
        override fun put(url: String, body: ByteArray, contentType: String?) = HttpResponse(status, ByteArray(0))
        override fun sleep(millis: Long) {}
    }

    /** A transport that returns a well-formed v1 challenge — the happy path. */
    private class OkTransport : HttpTransport {
        override fun get(url: String): HttpResponse {
            val id = url.substringAfterLast("/login/").substringBefore("/challenge")
            val json = MiniJson.encodeObject(
                listOf(
                    "id" to id,
                    "nonce" to Base64Url.encode(ByteArray(32) { 0x5A }),
                    "audience" to "https://homelab.example:8443",
                    "expires_at" to 4_102_444_800L,
                ),
            ).encodeToByteArray()
            return HttpResponse(200, json)
        }
        override fun post(url: String, body: ByteArray?, contentType: String?) = HttpResponse(204, ByteArray(0))
        override fun put(url: String, body: ByteArray, contentType: String?) = HttpResponse(405, ByteArray(0))
        override fun sleep(millis: Long) {}
    }

    private val parsed = LoginQr.Parsed(rp = "http://rp.invalid", id = "L42")

    @Test
    fun transportThrowResolvesToUnreachableFailureNotACrash() {
        // Mirrors the captured UnknownServiceException (cleartext blocked) and any IOException.
        val flow = LoginApproval(
            ThrowingTransport { RuntimeException("CLEARTEXT communication not permitted") },
            dummyDevice(),
            "cert-unused",
        )
        val outcome = flow.beginCatching(parsed) // must NOT throw
        val failed = assertIs<LoginApproval.Outcome.Failed>(outcome)
        assertEquals(LoginApproval.FailureKind.UNREACHABLE, failed.kind)
        assertTrue(failed.message.isNotBlank())
    }

    @Test
    fun nonSuccessStatusResolvesToRejectedFailureNotACrash() {
        // A genuine refusal (a 4xx that is not 404/410, or a 5xx) is REJECTED — not EXPIRED.
        for (status in listOf(401, 403, 500, 503)) {
            val flow = LoginApproval(StatusTransport(status), dummyDevice(), "cert-unused")
            val outcome = flow.beginCatching(parsed) // must NOT throw
            val failed = assertIs<LoginApproval.Outcome.Failed>(outcome)
            assertEquals(LoginApproval.FailureKind.REJECTED, failed.kind, "HTTP $status should be REJECTED")
        }
    }

    @Test
    fun expiredOrNotFoundStatusResolvesToExpiredFailureNotRejected() {
        // A 404 (not found) or 410 (gone) on the challenge fetch means the short-lived login id
        // expired or was lost (the RP restarted) — its own EXPIRED kind, distinct from REJECTED,
        // so the user is told to scan a fresh code rather than "the site refused".
        for (status in listOf(404, 410)) {
            val flow = LoginApproval(StatusTransport(status), dummyDevice(), "cert-unused")
            val outcome = flow.beginCatching(parsed) // must NOT throw
            val failed = assertIs<LoginApproval.Outcome.Failed>(outcome)
            assertEquals(LoginApproval.FailureKind.EXPIRED, failed.kind, "HTTP $status should be EXPIRED")
            assertTrue(failed.message.isNotBlank())
        }
    }

    @Test
    fun aReachableRpStillReturnsReady() {
        val flow = LoginApproval(OkTransport(), dummyDevice(), "cert-unused")
        val outcome = flow.beginCatching(parsed)
        val ready = assertIs<LoginApproval.Outcome.Ready>(outcome)
        assertEquals("L42", ready.request.loginId)
        assertEquals("https://homelab.example:8443", ready.request.audience)
    }

    @Test
    fun webLoginClientThrowsTypedExceptionOnNonSuccess() {
        // The layer beneath the flow signals a reached-but-refused RP with the typed
        // exception, so beginCatching can classify it REJECTED rather than UNREACHABLE.
        val client = WebLoginClient(StatusTransport(404), "http://rp.invalid")
        val e = assertFailsWith<WebLoginHttpException> { client.fetchChallenge("L42") }
        assertEquals(404, e.status)
    }
}
