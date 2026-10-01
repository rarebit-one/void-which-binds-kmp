package one.rarebit.voidwhichbinds.flow

import one.rarebit.voidwhichbinds.Cert
import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Enrolment
import one.rarebit.voidwhichbinds.LoginQr
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
 * Drives the **number-matching (v2)** path of [LoginApproval] against an in-memory
 * RP that verifies exactly the way void-which-binds-go's `weblogin.Verify` does for a v2
 * challenge: the chosen number must equal the challenge's true match (its
 * `ErrNumberMismatch` gate) AND the device key the cert names must have signed the
 * v2 preimage bound to that chosen number. So a green test proves the coordinator's
 * selection→sign logic produces an approval a real void-which-binds-go RP accepts — and that
 * tapping a decoy is refused, which is the whole anti-phishing point of the plane.
 */
class NumberMatchApprovalTest {

    private class TestDevice(user: UserIdentity, seedByte: Int) {
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

    /**
     * A faithful v2 RP: it holds the TRUE match number server-side, shows only the
     * shuffled candidate set to the phone, and on approve enforces both the equality
     * gate and the signature-over-chosen binding.
     */
    private class FakeV2Rp(private val pinnedUser: ByteArray, private val trueNumber: Int) : HttpTransport {
        val nonce = ByteArray(32) { 0x5A }
        val audience = "https://homelab.example:8443"
        val expiresAt = 4_102_444_800L
        val candidates = listOf(11, trueNumber, 73) // shuffled display set; includes the true match
        var approvedToken: String? = null

        private fun challengeJson(id: String): ByteArray {
            // Built by hand because the wire carries a `candidates` ARRAY and the true
            // number is DELIBERATELY absent (the phone must not learn which is right).
            val cands = candidates.joinToString(",")
            return (
                """{"id":"$id","nonce":"${Base64Url.encode(nonce)}",""" +
                    """"audience":"$audience","expires_at":$expiresAt,"candidates":[$cands]}"""
                ).encodeToByteArray()
        }

        override fun get(url: String): HttpResponse {
            val id = url.substringAfterLast("/login/").substringBefore("/challenge")
            return HttpResponse(200, challengeJson(id))
        }

        override fun post(url: String, body: ByteArray?, contentType: String?): HttpResponse {
            if (!url.endsWith("/approve")) return HttpResponse(404, ByteArray(0))
            val id = url.substringAfterLast("/login/").substringBefore("/approve")
            val o = MiniJson.parseObject(body!!.decodeToString())
            val certToken = o["cert"] as String
            val sig = Base64Url.decode(o["sig"] as String)
            val chosen = (o["match_number"] as Long).toInt()

            // Gate 1 — the equality check (void-which-binds-go's ErrNumberMismatch).
            if (chosen != trueNumber) return HttpResponse(401, ByteArray(0))

            // Gate 2 — cert pinned to the user, device key signed the v2 binding.
            val parsed = Cert.parse(certToken)
            val verifier = Ed25519Engine.verifier()
            val certOk = parsed.verify(verifier) && parsed.cert.user.bytes.contentEquals(pinnedUser)
            val challenge = WebLogin.Challenge(id, nonce, audience, expiresAt, candidates)
            val sigOk = verifier.verify(parsed.cert.device.bytes, WebLogin.signingBytesV2(challenge, chosen), sig)
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
    fun tappingTheTrueNumberApprovesAndTheRpAcceptsIt() {
        val user = UserIdentity.create()
        val device = TestDevice(user, seedByte = 7)
        val trueNumber = 42
        val rp = FakeV2Rp(user.userPublicKey, trueNumber)

        val flow = LoginApproval(rp, device.identity, device.cert)
        val request = flow.begin(PushLoginQr)
        assertTrue(request.isNumberMatch, "a v2 login must surface as number-matching")
        assertEquals(listOf(11, 42, 73), request.candidates)

        flow.approve(request, trueNumber) // the human taps the match
        assertEquals("token-for-L9", rp.approvedToken, "the true-number tap must be accepted")
    }

    @Test
    fun tappingADecoyIsRefused_noLogin() {
        val user = UserIdentity.create()
        val device = TestDevice(user, seedByte = 3)
        val trueNumber = 42
        val rp = FakeV2Rp(user.userPublicKey, trueNumber)

        val flow = LoginApproval(rp, device.identity, device.cert)
        val request = flow.begin(PushLoginQr)

        // 11 and 73 are decoys; tapping one binds the wrong number → RP refuses (401).
        assertFailsWith<IllegalArgumentException> { flow.approve(request, 11) }
        assertTrue(rp.approvedToken == null, "a decoy tap must not authenticate")
    }

    @Test
    fun aNumberOutsideTheCandidateSetIsRejectedBeforeAnySignature() {
        val user = UserIdentity.create()
        val device = TestDevice(user, seedByte = 5)
        val rp = FakeV2Rp(user.userPublicKey, 42)
        val flow = LoginApproval(rp, device.identity, device.cert)
        val request = flow.begin(PushLoginQr)
        // 99 was never shown — refused locally, so the device never signs a stray number.
        assertFailsWith<IllegalArgumentException> { flow.approve(request, 99) }
    }

    @Test
    fun aV2RequestCannotBeApprovedByTheV1Path() {
        val user = UserIdentity.create()
        val device = TestDevice(user, seedByte = 8)
        val rp = FakeV2Rp(user.userPublicKey, 42)
        val flow = LoginApproval(rp, device.identity, device.cert)
        val request = flow.begin(PushLoginQr)
        // The no-number overload must refuse a number-matching request (no silent v1).
        assertFailsWith<IllegalArgumentException> { flow.approve(request) }
    }

    private companion object {
        val PushLoginQr = LoginQr.decode("void-which-binds:login?id=L9&rp=http%3A%2F%2Frp")
    }
}
