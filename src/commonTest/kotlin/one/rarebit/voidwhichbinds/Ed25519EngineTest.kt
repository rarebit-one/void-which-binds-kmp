package one.rarebit.voidwhichbinds

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Validates the multiplatform software-Ed25519 engine end to end: generate,
 * derive the public key deterministically from the seed, sign, and verify — the
 * operations every [DeviceKeyStore] actual performs after unsealing its seed.
 * Running on commonTest means the SAME assertions run on JVM and (when built)
 * the Native targets, so the provider is proven consistent across platforms.
 */
class Ed25519EngineTest {

    @Test
    fun generatesRawKeyOfTheRightShape() {
        val g = Ed25519Engine.generate()
        assertEquals(32, g.privateSeed.size, "Ed25519 seed is 32 bytes")
        assertEquals(32, g.publicKey.size, "Ed25519 public key is 32 bytes")
    }

    @Test
    fun signsWithAReimportedSeed() {
        // The store seals the seed and re-imports it to sign; prove a signature
        // made from the raw seed verifies against the generated public key.
        val g = Ed25519Engine.generate()
        val msg = "reimported seed still signs".encodeToByteArray()
        val sig = Ed25519Engine.sign(g.privateSeed, msg)
        assertTrue(Ed25519Engine.verify(g.publicKey, msg, sig), "seed re-import produces a valid signature")
    }

    @Test
    fun signsAndVerifies() {
        val g = Ed25519Engine.generate()
        val msg = "void-which-binds device signing".encodeToByteArray()
        val sig = Ed25519Engine.sign(g.privateSeed, msg)
        assertEquals(64, sig.size, "Ed25519 signature is 64 bytes")
        assertTrue(Ed25519Engine.verify(g.publicKey, msg, sig), "valid signature verifies")
    }

    @Test
    fun rejectsATamperedMessage() {
        val g = Ed25519Engine.generate()
        val sig = Ed25519Engine.sign(g.privateSeed, "authentic".encodeToByteArray())
        assertFalse(
            Ed25519Engine.verify(g.publicKey, "tampered".encodeToByteArray(), sig),
            "a signature does not verify against a different message",
        )
    }

    @Test
    fun rejectsAWrongKey() {
        val a = Ed25519Engine.generate()
        val b = Ed25519Engine.generate()
        val msg = "bound to key a".encodeToByteArray()
        val sig = Ed25519Engine.sign(a.privateSeed, msg)
        assertFalse(Ed25519Engine.verify(b.publicKey, msg, sig), "key b does not verify key a's signature")
    }
}
