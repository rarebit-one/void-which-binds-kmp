package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * Golden vector CAPTURED FROM void-which-binds-go's `weblogin.SignAssertion` (gen2
 * domain `void-which-binds/weblogin/challenge/v1`, void-which-binds-go v0.19.0): a device
 * key from seed 0x44×32 signing the challenge {id="abc123", nonce=0x55×32,
 * audience="https://homelab.example", exp=1800000000}. The JDK's Ed25519 is
 * deterministic, so on JVM/Android the kmp device signer must reproduce the exact
 * base64url signature. That proves the challenge preimage framing and the signing
 * match, i.e. void-which-binds-go's weblogin.Verify accepts an assertion produced here
 * unchanged. On iOS (randomized CryptoKit Ed25519), Go's signature must verify over
 * our preimage and ours must verify too (see [assertMatchesGoSignature]).
 */
class WebLoginTest {

    private fun rep(b: Int) = ByteArray(32) { b.toByte() }

    private val deviceSeed = rep(0x44)
    private val challenge = WebLogin.Challenge(
        id = "abc123",
        nonce = rep(0x55),
        audience = "https://homelab.example",
        expiresAt = 1_800_000_000L,
    )
    private val goldenSig = "gTs0YNCOgytOhb8DBp2seqyRUup_vr4pEuNHqSebQ8FlRpzrgeN0-kFBzQoG5_BFFu5c3mJskw-YMnkyZmSqAQ"

    @Test
    fun assertionMatchesVoidbindGo() {
        val a = WebLogin.signAssertion(challenge, "CERT.TOKEN") { msg ->
            Ed25519Engine.sign(deviceSeed, msg)
        }
        assertEquals("CERT.TOKEN", a.cert)
        assertMatchesGoSignature(
            goldenSig,
            a.sig,
            Ed25519Group.publicKeyFromSeed(deviceSeed),
            WebLogin.signingBytes(challenge),
            "the assertion signature must match void-which-binds-go byte-for-byte",
        )
    }

    @Test
    fun bindsTheChallengeSoADifferentExpiryDoesNotVerify() {
        val a1 = WebLogin.signAssertion(challenge, "c") { Ed25519Engine.sign(deviceSeed, it) }
        val tampered = WebLogin.Challenge(challenge.id, challenge.nonce, challenge.audience, challenge.expiresAt + 1)
        val a2 = WebLogin.signAssertion(tampered, "c") { Ed25519Engine.sign(deviceSeed, it) }
        assertNotEquals(a1.sig, a2.sig, "a one-second expiry change changes the signature (framing binds it)")
    }

    /**
     * void-which-binds-go `TestGen1DomainSignatureDoesNotVerify` (ADR-0022): both preimages
     * start with the framed gen2 domain, so an approval signed under a gen1
     * `voidbind/weblogin/challenge/…` domain is not a signature over the gen2 preimage.
     */
    @Test
    fun aGen1DomainSignatureDoesNotVerify() {
        fun frame(p: String): ByteArray {
            val b = p.encodeToByteArray()
            val n = ByteArray(8) { i -> (b.size.toLong() ushr (8 * (7 - i))).toByte() }
            return n + b
        }
        val pub = Ed25519Group.publicKeyFromSeed(deviceSeed)
        val cases = listOf(
            Triple(WebLogin.signingBytes(challenge), WebLogin.ASSERTION_DOMAIN, "voidbind/weblogin/challenge/v1"),
            Triple(
                WebLogin.signingBytesV2(challenge, 42),
                WebLogin.ASSERTION_DOMAIN_V2,
                "voidbind/weblogin/challenge/v2",
            ),
        )
        for ((pre, gen2, gen1) in cases) {
            val head = frame(gen2)
            assertContentEquals(head, pre.copyOfRange(0, head.size), "preimage starts with the framed $gen2")
            val gen1Pre = frame(gen1) + pre.copyOfRange(head.size, pre.size)
            assertFalse(Ed25519Engine.verify(pub, pre, Ed25519Engine.sign(deviceSeed, gen1Pre)), "$gen1 verified")
            assertTrue(Ed25519Engine.verify(pub, pre, Ed25519Engine.sign(deviceSeed, pre)))
        }
    }

    @Test
    fun refusesAnEmptyCert() {
        assertFailsWith<IllegalArgumentException> {
            WebLogin.signAssertion(challenge, "") { Ed25519Engine.sign(deviceSeed, it) }
        }
    }
}
