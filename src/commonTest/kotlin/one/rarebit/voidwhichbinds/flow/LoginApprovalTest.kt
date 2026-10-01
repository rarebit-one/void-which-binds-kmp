package one.rarebit.voidwhichbinds.flow

import one.rarebit.voidwhichbinds.Cert
import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Enrolment
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.UserIdentity
import one.rarebit.voidwhichbinds.WebLogin
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.net.HttpResponse
import one.rarebit.voidwhichbinds.net.HttpTransport
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Drives [LoginApproval] against an in-memory RP that VERIFIES the assertion the
 * way void-which-binds-go's `weblogin.Verify` does (pinned user key + the device key that
 * cert names must sign THIS challenge, unexpired). So a green test proves the
 * coordinator produced an assertion a real void-which-binds-go RP would accept — and that
 * an un-pinned device is refused.
 */
class LoginApprovalTest {

    // A device: a software signing key + a self-enrolled cert under some user identity.
    private class TestDevice(val user: UserIdentity, seedByte: Int) {
        val seed = ByteArray(32) { (it + seedByte).toByte() }
        val enc = DeviceIdentity.generateEncryptionKey()
        val identity = DeviceIdentity(
            signPublicKey = Ed25519Group.publicKeyFromSeed(seed),
            encPublicKey = enc.publicKey,
            encPrivateKey = enc.privateKey,
            signFn = { msg -> Ed25519Engine.sign(seed, msg) },
        )
        val cert = Enrolment.selfEnrol(user, identity, issuedAt = 1_000_000_000L, lifetimeSeconds = 999_999_999L)
    }

    /** An in-memory RP pinning [pinnedUser], faithful to void-which-binds-go weblogin.Verify. */
    private class FakeRp(private val pinnedUser: ByteArray) : HttpTransport {
        val nonce = ByteArray(32) { 0x5A }
        val audience = "https://homelab.example:8443"
        val expiresAt = 4_102_444_800L // year 2100 — never expired in-test
        var approvedToken: String? = null

        private fun challengeJson(id: String) = MiniJson.encodeObject(
            listOf(
                "id" to id,
                "nonce" to Base64Url.encode(nonce),
                "audience" to audience,
                "expires_at" to expiresAt,
            ),
        ).encodeToByteArray()

        override fun get(url: String): HttpResponse {
            // .../login/{id}/challenge
            val id = url.substringAfterLast("/login/").substringBefore("/challenge")
            return HttpResponse(200, challengeJson(id))
        }

        override fun post(url: String, body: ByteArray?, contentType: String?): HttpResponse {
            if (!url.endsWith("/approve")) return HttpResponse(404, ByteArray(0))
            val id = url.substringAfterLast("/login/").substringBefore("/approve")
            val o = MiniJson.parseObject(body!!.decodeToString())
            val certToken = o["cert"] as String
            val sig = Base64Url.decode(o["sig"] as String)
            // void-which-binds-go weblogin.Verify, faithfully:
            val parsed = Cert.parse(certToken)
            val verifier = Ed25519Engine.verifier()
            val certOk = parsed.verify(verifier) && parsed.cert.user.bytes.contentEquals(pinnedUser)
            val challenge = WebLogin.Challenge(id, nonce, audience, expiresAt)
            val sigOk = verifier.verify(parsed.cert.device.bytes, WebLogin.signingBytes(challenge), sig)
            return if (certOk && sigOk) {
                approvedToken = "token-for-$id"
                HttpResponse(204, ByteArray(0))
            } else {
                HttpResponse(401, ByteArray(0))
            }
        }

        override fun put(url: String, body: ByteArray, contentType: String?) = HttpResponse(405, ByteArray(0))
        override fun sleep(millis: Long) {}
    }

    @Test
    fun pinnedDeviceApprovesAndTheRpAcceptsTheAssertion() {
        val user = UserIdentity.create()
        val device = TestDevice(user, seedByte = 7)
        val rp = FakeRp(user.userPublicKey)

        val flow = LoginApproval(rp, device.identity, device.cert)
        val request = flow.begin(LoginQrRp)
        assertEquals("https://homelab.example:8443", request.audience)
        assertEquals("L42", request.loginId)

        flow.approve(request)
        assertEquals("token-for-L42", rp.approvedToken, "a pinned device's assertion must be accepted")
    }

    @Test
    fun anUnpinnedDeviceIsRefused() {
        val pinned = UserIdentity.create()
        val stranger = UserIdentity.create() // NOT pinned by the RP
        val device = TestDevice(stranger, seedByte = 9)
        val rp = FakeRp(pinned.userPublicKey)

        val flow = LoginApproval(rp, device.identity, device.cert)
        val request = flow.begin(LoginQrRp)
        assertFailsWith<IllegalArgumentException> { flow.approve(request) } // WebLoginClient.approve refuses non-204
        assertTrue(rp.approvedToken == null)
    }

    private companion object {
        // The scanned QR points the coordinator at the fake RP (base is ignored by
        // the fake transport, which routes on path) with login id "L42".
        val LoginQrRp = one.rarebit.voidwhichbinds.LoginQr.decode("void-which-binds:login?id=L42&rp=http%3A%2F%2Frp")
    }
}
