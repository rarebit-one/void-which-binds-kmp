package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Base64Url
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertTrue

/**
 * The number-matching (v2) preimage + assertion, ported byte-for-byte from
 * void-which-binds-go's `weblogin` (ADR-0006). An INDEPENDENT framer here is the oracle:
 * it reconstructs the exact length-framed bytes the Go side signs, so a green test
 * proves [WebLogin.signingBytesV2] matches the wire — and [WebLoginV2GoInteropTest]
 * (jvmTest, when `go` is present) proves a live Go RP accepts what this signs.
 */
class WebLoginV2Test {

    private val challenge = WebLogin.Challenge(
        id = "abc123",
        nonce = ByteArray(WebLogin.NONCE_LEN) { (it * 3 + 1).toByte() },
        audience = "allthing",
        expiresAt = 1_724_700_000L,
        candidates = listOf(42, 7, 88),
    )

    /** Independent length-framer: 8-byte big-endian length prefix, then bytes. */
    private fun frame(parts: List<ByteArray>): ByteArray {
        val out = ArrayList<Byte>()
        for (p in parts) {
            val n = p.size.toLong()
            for (shift in 56 downTo 0 step 8) out.add((n ushr shift).toByte())
            out.addAll(p.toList())
        }
        return out.toByteArray()
    }

    private fun be64(v: Long): ByteArray {
        val out = ByteArray(8)
        var e = v
        for (i in 7 downTo 0) {
            out[i] = (e and 0xFF).toByte()
            e = e ushr 8
        }
        return out
    }

    @Test
    fun v2SigningBytesMatchTheIndependentlyFramedPreimage() {
        val chosen = 42
        val expected = frame(
            listOf(
                "voidbind/weblogin/challenge/v2".encodeToByteArray(),
                challenge.id.encodeToByteArray(),
                challenge.nonce,
                challenge.audience.encodeToByteArray(),
                be64(challenge.expiresAt),
                be64(chosen.toLong()),
            ),
        )
        assertContentEquals(expected, WebLogin.signingBytesV2(challenge, chosen))
    }

    @Test
    fun v2DomainAndTrailingMatchNumberDistinguishItFromV1() {
        val v1 = WebLogin.signingBytes(challenge)
        val v2 = WebLogin.signingBytesV2(challenge, 42)
        // Different domain string → different bytes from the very start; and v2 is
        // longer by the framed 8-byte match number (8-byte length prefix + 8 bytes).
        assertFalse(v1.contentEquals(v2), "v1 and v2 preimages must never coincide")
        assertEquals(v1.size + 16, v2.size, "v2 appends a framed 8-byte match number")
        assertTrue(v2.decodeToString().contains("voidbind/weblogin/challenge/v2"))
    }

    @Test
    fun theChosenNumberIsCryptographicallyBoundIntoThePreimage() {
        // Tapping a different number yields a different preimage → a different signature.
        val a = WebLogin.signingBytesV2(challenge, 42)
        val b = WebLogin.signingBytesV2(challenge, 7)
        assertFalse(a.contentEquals(b), "the match number must change the signed bytes")
    }

    @Test
    fun signAssertionV2CarriesTheChosenNumberAndSignsThatBinding() {
        val dev = Ed25519Engine.generate()
        val chosen = 88
        val assertion = WebLogin.signAssertionV2(challenge, chosen, "CERT.TOKEN") {
            Ed25519Engine.sign(dev.privateSeed, it)
        }
        assertNotNull(assertion.matchNumber)
        assertEquals(chosen, assertion.matchNumber)

        // The signature verifies against the v2 preimage bound to the chosen number…
        val verifier = Ed25519Engine.verifier()
        val sig = Base64Url.decode(assertion.sig)
        assertTrue(
            verifier.verify(dev.publicKey, WebLogin.signingBytesV2(challenge, chosen), sig),
            "the assertion must sign the chosen-number binding",
        )
        // …and NOT against a different number's preimage (the anti-phishing binding).
        assertFalse(
            verifier.verify(dev.publicKey, WebLogin.signingBytesV2(challenge, 42), sig),
            "a v2 signature must not verify for a number the user did not choose",
        )
    }

    @Test
    fun candidatesDriveTheIsNumberMatchFlag() {
        assertTrue(challenge.isNumberMatch)
        val v1 = WebLogin.Challenge("x", ByteArray(32), "aud", 1L)
        assertFalse(v1.isNumberMatch)
        assertTrue(v1.candidates.isEmpty())
    }
}
