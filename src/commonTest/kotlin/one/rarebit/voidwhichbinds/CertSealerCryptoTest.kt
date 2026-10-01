package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.VoidbindEncryption
import one.rarebit.voidwhichbinds.crypto.X25519
import one.rarebit.voidwhichbinds.crypto.XChaCha20Poly1305
import one.rarebit.voidwhichbinds.net.SealedCert
import one.rarebit.voidwhichbinds.net.VoidbindCertSealer
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull

/**
 * Pins the cert-delivery crypto byte-for-byte against void-which-binds-go. The decisive
 * test is [goSealKat]: a blob SEALED by live void-which-binds-go must unwrap+decrypt to
 * the exact plaintext here — a Go→Kotlin proof that runs in CI with no Go.
 */
class CertSealerCryptoTest {

    // --- X25519 (RFC 7748 §5.2) ---
    @Test
    fun x25519Rfc7748Vector() {
        val scalar = Hex.decode("a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4")
        val point = Hex.decode("e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c")
        val expected = "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552"
        assertEquals(expected, Hex.encode(X25519.scalarMult(scalar, point)))
    }

    // The KAT recipient seed must derive the KAT recipient public key — this alone
    // proves the pure X25519 base-point mult matches Go's crypto/ecdh.
    @Test
    fun x25519BaseMatchesGo() {
        val seed = Hex.decode(KAT_RECIPIENT_SEED)
        assertEquals(KAT_RECIPIENT_PUB, Hex.encode(X25519.scalarMultBase(seed)))
    }

    // --- XChaCha20-Poly1305 self round-trip (exercises HChaCha20 + the AEAD) ---
    @Test
    fun xchachaRoundTrip() {
        val key = ByteArray(32) { (it + 1).toByte() }
        val nonce = ByteArray(24) { (100 - it).toByte() }
        val aad = "associated".encodeToByteArray()
        val pt = "the quick brown fox".encodeToByteArray()
        val ct = XChaCha20Poly1305.encrypt(key, nonce, aad, pt)
        assertContentEquals(pt, XChaCha20Poly1305.decrypt(key, nonce, aad, ct))
    }

    // --- The decisive Go→Kotlin KAT ---
    @Test
    fun goSealKat() {
        val seed = Hex.decode(KAT_RECIPIENT_SEED)
        // 1. Kotlin unwraps a blob that live void-which-binds-go sealed to this recipient.
        val spaceKey = VoidbindEncryption.unwrap(Hex.decode(KAT_WRAPPED_BLOB), seed)
        assertEquals(32, spaceKey.size)
        // 2. and decrypts the content Go encrypted under that same (opaque) key.
        val plaintext = VoidbindEncryption.decryptChange(spaceKey, Hex.decode(KAT_CONTENT_CT))
        assertEquals(KAT_PLAINTEXT, plaintext.decodeToString())
    }

    // --- Kotlin round-trips (seal↔unwrap, encryptChange↔decryptChange) ---
    @Test
    fun sealUnwrapRoundTrip() {
        val recipientSeed = ByteArray(32) { (it * 7 + 3).toByte() }
        val recipientPub = X25519.scalarMultBase(recipientSeed)
        val spaceKey = VoidbindEncryption.newSpaceKey()
        val wrapped = VoidbindEncryption.seal(spaceKey, recipientPub)
        assertEquals(104, wrapped.size)
        assertContentEquals(spaceKey, VoidbindEncryption.unwrap(wrapped, recipientSeed))

        val payload = "an enrolment cert token".encodeToByteArray()
        val blob = VoidbindEncryption.encryptChange(spaceKey, payload)
        assertContentEquals(payload, VoidbindEncryption.decryptChange(spaceKey, blob))
    }

    // --- Regression: reusing a (key,nonce) across consecutive AEAD ops ---
    // Before the fresh-Cipher fix, cryptography-kotlin's pooled JDK cipher made
    // SunJCE throw InvalidKeyException ("Matching key and nonce from previous
    // initialization") on the SECOND op with the same (key,nonce): a round-trip
    // encrypt→decrypt or decrypting the same blob twice. These fail on JVM before
    // the fix and pass after; on Android/iOS they always passed.
    @Test
    fun xchachaDecryptTwiceSameBlob() {
        val key = ByteArray(32) { (it + 1).toByte() }
        val nonce = ByteArray(24) { (100 - it).toByte() }
        val aad = "associated".encodeToByteArray()
        val pt = "decrypt me twice".encodeToByteArray()
        val ct = XChaCha20Poly1305.encrypt(key, nonce, aad, pt)
        // Decrypt the SAME ciphertext twice — the second op reuses (key,nonce).
        assertContentEquals(pt, XChaCha20Poly1305.decrypt(key, nonce, aad, ct))
        assertContentEquals(pt, XChaCha20Poly1305.decrypt(key, nonce, aad, ct))
    }

    @Test
    fun voidbindDecryptChangeTwice() {
        val spaceKey = ByteArray(32) { (it * 3 + 1).toByte() }
        val payload = "a change payload".encodeToByteArray()
        val blob = VoidbindEncryption.encryptChange(spaceKey, payload)
        // Decrypt the SAME blob twice (encrypt already used the nonce once).
        assertContentEquals(payload, VoidbindEncryption.decryptChange(spaceKey, blob))
        assertContentEquals(payload, VoidbindEncryption.decryptChange(spaceKey, blob))
    }

    @Test
    fun voidbindUnwrapTwice() {
        val recipientSeed = ByteArray(32) { (it * 7 + 3).toByte() }
        val recipientPub = X25519.scalarMultBase(recipientSeed)
        val spaceKey = VoidbindEncryption.newSpaceKey()
        val wrapped = VoidbindEncryption.seal(spaceKey, recipientPub)
        // Unwrap the SAME wrapped blob twice.
        assertContentEquals(spaceKey, VoidbindEncryption.unwrap(wrapped, recipientSeed))
        assertContentEquals(spaceKey, VoidbindEncryption.unwrap(wrapped, recipientSeed))
    }

    // --- The full CertSealer (what Pairflow uses) ---
    @Test
    fun certSealerRoundTrip() {
        val encSeed = ByteArray(32) { (255 - it).toByte() }
        val encPub = X25519.scalarMultBase(encSeed)
        val cert = "eyJ2IjoyfQ.c2ln" // any token; the sealer treats it opaquely
        val sealed: SealedCert = VoidbindCertSealer.seal(cert, encPub)
        assertNotNull(sealed)
        assertEquals(cert, VoidbindCertSealer.open(sealed, encSeed))
    }

    private companion object {
        // Generated from live void-which-binds-go (encryption.Seal / EncryptChange).
        const val KAT_RECIPIENT_SEED = "0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20"
        const val KAT_RECIPIENT_PUB = "07a37cbc142093c8b755dc1b10e86cb426374ad16aa853ed0bdfc0b2b86d1c7c"
        const val KAT_WRAPPED_BLOB =
            "81412bb18d31a79dcf33c1da25e7aa8aa6ece0295108a332af8325c820a2b04e" +
                "51dfe48e692daf26a4f748f7bcc8e8c016f0338ca367db4d83ea9c5a5e454e765" +
                "dc4d3dcda054c80723063a08dabc07b59903dc31fc1e85cec20a4be4e5d5f5c9a" +
                "7dcab6d613e3e0"
        const val KAT_CONTENT_CT =
            "237e4cc8cb17477e4d0eb141bc809cda72b272f1c4e368ede9e6cbfe2694230b" +
                "45e317720f78feb9072bdbe5438df96799ffd3837b45e894fd3c129a83243825" +
                "fddf64bf4cb797ecdc789891acb8e6b4138f7cd526402104e76a04b62298c86c" +
                "2743fb2fcaea3b3fbb39180aa3aa016d6e953139c7498fd5eb5d3f51dd91"
        const val KAT_PLAINTEXT =
            "voidbind cert delivery KAT — the initiator seals the enrolment cert to the responder"
    }
}
