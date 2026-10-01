package one.rarebit.voidwhichbinds.crypto

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.HKDF
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.random.CryptographyRandom

/**
 * The X25519 space-key wrap + content AEAD, byte-identical to
 * void-which-binds-go/encryption (`Seal`/`Unwrap`/`EncryptChange`/`DecryptChange`). This
 * is the crypto behind the pairing cert delivery: the initiator wraps a fresh
 * space key to the responder's X25519 key and encrypts the enrolment cert under
 * it; only the responder can unwrap and read it (the relay ferries ciphertext).
 *
 * Construction (void-which-binds-go ADR-0049, `wrap.go`/`content.go`):
 *  - shared  = X25519(ephemeralPriv, recipientPub)
 *  - wrapKey = HKDF-SHA256(ikm=shared, salt=ephPub‖recipientPub,
 *              info="heyarr/space-key-wrap/v1", len=32)
 *  - wrapped = ephPub(32) ‖ nonce(24) ‖ XChaCha20Poly1305.seal(wrapKey, nonce,
 *              aad=ephPub‖recipientPub, plaintext=spaceKey)   → 104 bytes
 *  - content = nonce(24) ‖ XChaCha20Poly1305.seal(spaceKey, nonce, aad=∅, plaintext)
 *
 * X25519 is pure Kotlin ([X25519]) so `unwrap` can derive the recipient's public
 * key from its private seed (which the JDK X25519 provider will not do); HKDF and
 * the AEAD are the vetted cryptography-kotlin primitives. Verified against a
 * live-voidbind-go KAT.
 *
 * This object is PUBLIC because a relying-party app that holds device-side
 * encrypted personal state (heyarr-mobile, ADR-0049) needs these same four
 * raw-byte operations `void-which-binds-go/encryption` exposes — `seal`/`unwrap` a space
 * key and `encryptChange`/`decryptChange` a change — to fold and MINT M9 CRDT
 * changes on the device, without re-deriving the wrap/AEAD wire format (the
 * one-copy rule the consuming apps are told to keep). Only these ByteArray-in,
 * ByteArray-out entry points are the surface; the primitives it builds on
 * ([X25519], [XChaCha20Poly1305]) stay internal.
 */
public object VoidbindEncryption {
    private const val WRAP_INFO = "heyarr/space-key-wrap/v1"
    const val SPACE_KEY_SIZE = 32
    private const val EPH_PUB_LEN = 32
    private const val WRAP_NONCE_LEN = 24
    private const val WRAP_OVERHEAD = EPH_PUB_LEN + WRAP_NONCE_LEN + SPACE_KEY_SIZE + XChaCha20Poly1305.TAG_SIZE // 104

    private val hkdf = CryptographyProvider.Default.get(HKDF)

    /** A fresh 32-byte space key from the platform CSPRNG. */
    fun newSpaceKey(): ByteArray = CryptographyRandom.Default.nextBytes(SPACE_KEY_SIZE)

    /** Seal [spaceKey] to a recipient's raw 32-byte X25519 public key. */
    fun seal(spaceKey: ByteArray, recipientPub: ByteArray): ByteArray {
        require(spaceKey.size == SPACE_KEY_SIZE) { "seal: space key must be 32 bytes" }
        require(recipientPub.size == 32) { "seal: recipient public key must be 32 bytes" }
        val ephSeed = CryptographyRandom.Default.nextBytes(32)
        val ephPub = X25519.scalarMultBase(ephSeed)
        val shared = X25519.scalarMult(ephSeed, recipientPub)
        val salt = ephPub + recipientPub
        val wrapKey = hkdf32(shared, salt)
        val nonce = CryptographyRandom.Default.nextBytes(WRAP_NONCE_LEN)
        val sealed = XChaCha20Poly1305.encrypt(wrapKey, nonce, salt, spaceKey)
        return ephPub + nonce + sealed
    }

    /** Unwrap a 104-byte blob with the recipient's raw 32-byte X25519 seed. */
    fun unwrap(wrapped: ByteArray, recipientSeed: ByteArray): ByteArray {
        require(wrapped.size == WRAP_OVERHEAD) {
            "unwrap: wrapped key must be $WRAP_OVERHEAD bytes, got ${wrapped.size}"
        }
        require(recipientSeed.size == 32) { "unwrap: recipient seed must be 32 bytes" }
        val ephPub = wrapped.copyOfRange(0, EPH_PUB_LEN)
        val nonce = wrapped.copyOfRange(EPH_PUB_LEN, EPH_PUB_LEN + WRAP_NONCE_LEN)
        val sealed = wrapped.copyOfRange(EPH_PUB_LEN + WRAP_NONCE_LEN, wrapped.size)
        val recipientPub = X25519.scalarMultBase(recipientSeed)
        val shared = X25519.scalarMult(recipientSeed, ephPub)
        val salt = ephPub + recipientPub
        val wrapKey = hkdf32(shared, salt)
        return XChaCha20Poly1305.decrypt(wrapKey, nonce, salt, sealed)
    }

    /** Encrypt a payload under a space key: nonce(24) ‖ ciphertext‖tag (no aad). */
    fun encryptChange(spaceKey: ByteArray, plaintext: ByteArray): ByteArray {
        require(spaceKey.size == SPACE_KEY_SIZE) { "encryptChange: space key must be 32 bytes" }
        val nonce = CryptographyRandom.Default.nextBytes(WRAP_NONCE_LEN)
        val ct = XChaCha20Poly1305.encrypt(spaceKey, nonce, EMPTY, plaintext)
        return nonce + ct
    }

    /** Reverse of [encryptChange]. */
    fun decryptChange(spaceKey: ByteArray, blob: ByteArray): ByteArray {
        require(spaceKey.size == SPACE_KEY_SIZE) { "decryptChange: space key must be 32 bytes" }
        require(blob.size >= WRAP_NONCE_LEN + XChaCha20Poly1305.TAG_SIZE) { "decryptChange: ciphertext too short" }
        val nonce = blob.copyOfRange(0, WRAP_NONCE_LEN)
        val ct = blob.copyOfRange(WRAP_NONCE_LEN, blob.size)
        return XChaCha20Poly1305.decrypt(spaceKey, nonce, EMPTY, ct)
    }

    private val EMPTY = ByteArray(0)

    private fun hkdf32(ikm: ByteArray, salt: ByteArray): ByteArray =
        hkdf.secretDerivation(SHA256, 32.bytes, salt, WRAP_INFO.encodeToByteArray())
            .deriveSecretToByteArrayBlocking(ikm)
}
