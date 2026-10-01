package one.rarebit.voidwhichbinds

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * A deterministic, NON-cryptographic signer/verifier pair used only to exercise
 * the cert token's encode/parse/verify plumbing without pulling a real Ed25519
 * backend into `commonTest`. The signature is a fixed-length keyed digest of the
 * payload — enough to prove the token structure and that a tampered payload fails.
 */
private object FakeEd {
    private fun digest(message: ByteArray): ByteArray {
        val out = ByteArray(64)
        var h = -0x340d631b7bdddcdbL // arbitrary FNV-ish seed
        for (b in message) {
            h = h xor (b.toLong() and 0xFF)
            h *= 0x100000001b3L
        }
        for (i in out.indices) {
            h = h xor (i.toLong() * 0x2545F4914F6CDD1DL)
            h *= 0x100000001b3L
            out[i] = (h ushr ((i % 8) * 8)).toByte()
        }
        return out
    }

    val signer = Ed25519Signer { message -> digest(message) }
    val verifier = Ed25519Verifier { _, message, signature -> digest(message).contentEquals(signature) }
}

class CertTest {

    private fun sampleCert(): Cert = Cert(
        version = Labels.CERT_VERSION,
        user = KeyRef.ed25519(ByteArray(32) { (it + 1).toByte() }),
        device = KeyRef.ed25519(ByteArray(32) { (it * 2 + 1).toByte() }),
        deviceEnc = KeyRef.x25519(ByteArray(32) { (it * 3 + 7).toByte() }),
        issuedAt = 1_724_700_000L,
        expiresAt = 1_756_236_000L,
    )

    @Test
    fun encodeParseRoundTrips() {
        val cert = sampleCert()
        val token = cert.encode(FakeEd.signer)

        assertTrue(token.contains('.'), "token must be payload.sig")
        val parsed = Cert.parse(token)
        assertEquals(cert, parsed.cert, "parsed cert must equal original")
        assertTrue(parsed.payload.contentEquals(cert.signingBytes()), "payload bytes must match")

        // Re-encoding the parsed cert yields the identical token (canonical form).
        assertEquals(token, parsed.cert.encode(FakeEd.signer))
    }

    @Test
    fun signatureVerifies() {
        val cert = sampleCert()
        val token = cert.encode(FakeEd.signer)
        assertTrue(cert.verify(token, FakeEd.verifier))
        assertTrue(Cert.parse(token).verify(FakeEd.verifier))
    }

    @Test
    fun tamperedPayloadFailsVerification() {
        val cert = sampleCert()
        val token = cert.encode(FakeEd.signer)
        val forged = cert.copy(expiresAt = cert.expiresAt + 1)
        // Splice the forged payload in front of the original signature.
        val forgedToken = forged.encode(FakeEd.signer).substringBefore('.') +
            "." + token.substringAfter('.')
        assertFalse(forged.verify(forgedToken, FakeEd.verifier))
    }

    @Test
    fun keyRefRendersWithAlgPrefix() {
        val k = KeyRef.ed25519(byteArrayOf(0x0a, 0x0b.toByte(), 0xff.toByte()))
        assertEquals("ed25519:0a0bff", k.render())
        assertEquals(k, KeyRef.parse("ed25519:0a0bff"))
        assertEquals("x25519", KeyRef.x25519(ByteArray(1)).alg)
    }

    @Test
    fun payloadFieldOrderIsCanonical() {
        // Wire contract: fields in order v,usr,dev,denc,iat,exp.
        val json = sampleCert().signingBytes().decodeToString()
        val vi = json.indexOf("\"v\"")
        val usr = json.indexOf("\"usr\"")
        val dev = json.indexOf("\"dev\"")
        val denc = json.indexOf("\"denc\"")
        val iat = json.indexOf("\"iat\"")
        val exp = json.indexOf("\"exp\"")
        assertTrue(
            vi in 0 until usr && usr < dev && dev < denc && denc < iat && iat < exp,
            "unexpected field order in $json",
        )
    }
}
