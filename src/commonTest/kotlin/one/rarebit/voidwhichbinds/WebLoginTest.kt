package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals

/**
 * Golden vector CAPTURED FROM void-which-binds-go's `weblogin.SignAssertion`: a device
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
    private val goldenSig = "9rs7DTivz1svj6Dr517N-bIdQgQuPo0sjNf9UdtLV1ukpiJyswsvfXGYheihtuHL5sfJaFKbD1QWzc0ty-s7BQ"

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
            "the assertion signature must match voidbind-go byte-for-byte",
        )
    }

    @Test
    fun bindsTheChallengeSoADifferentExpiryDoesNotVerify() {
        val a1 = WebLogin.signAssertion(challenge, "c") { Ed25519Engine.sign(deviceSeed, it) }
        val tampered = WebLogin.Challenge(challenge.id, challenge.nonce, challenge.audience, challenge.expiresAt + 1)
        val a2 = WebLogin.signAssertion(tampered, "c") { Ed25519Engine.sign(deviceSeed, it) }
        assertNotEquals(a1.sig, a2.sig, "a one-second expiry change changes the signature (framing binds it)")
    }

    @Test
    fun refusesAnEmptyCert() {
        assertFailsWith<IllegalArgumentException> {
            WebLogin.signAssertion(challenge, "") { Ed25519Engine.sign(deviceSeed, it) }
        }
    }
}
