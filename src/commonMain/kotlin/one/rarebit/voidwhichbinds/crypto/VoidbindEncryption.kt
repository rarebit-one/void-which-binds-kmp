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
 *              info="void-which-binds/space-key-wrap/v1", len=32)
 *  - wrapped = ephPub(32) ‖ nonce(24) ‖ XChaCha20Poly1305.seal(wrapKey, nonce,
 *              aad=ephPub‖recipientPub, plaintext=spaceKey)   → 104 bytes
 *  - content = nonce(24) ‖ XChaCha20Poly1305.seal(spaceKey, nonce, aad=∅, plaintext)
 *  - chain   = nonce(24) ‖ XChaCha20Poly1305.seal(sealingKey, nonce,
 *              aad="void-which-binds/space-key-chain/v1", plaintext=spaceKey) → 72 bytes
 *              (`chain.go`, heyarr ADR-0103: one link of a space-key history)
 *
 * X25519 is pure Kotlin ([X25519]) so `unwrap` can derive the recipient's public
 * key from its private seed (which the JDK X25519 provider will not do); HKDF and
 * the AEAD are the vetted cryptography-kotlin primitives. Verified against a
 * live void-which-binds-go KAT.
 *
 * This object is PUBLIC because a relying-party app that holds device-side
 * encrypted personal state (heyarr-mobile, ADR-0049) needs these same four
 * raw-byte operations `void-which-binds-go/encryption` exposes — `seal`/`unwrap` a space
 * key and `encryptChange`/`decryptChange` a change — to fold and MINT M9 CRDT
 * changes on the device, without re-deriving the wrap/AEAD wire format (the
 * one-copy rule the consuming apps are told to keep), and `sealSpaceKey`/`openSpaceKey`
 * a link of a rotated space's key history. Only these ByteArray-in,
 * ByteArray-out entry points are the surface; the primitives it builds on
 * ([X25519], [XChaCha20Poly1305]) stay internal.
 */
public object VoidbindEncryption {
    private const val WRAP_INFO = "void-which-binds/space-key-wrap/v1"
    const val SPACE_KEY_SIZE = 32
    private const val EPH_PUB_LEN = 32
    private const val WRAP_NONCE_LEN = 24
    private const val WRAP_OVERHEAD = EPH_PUB_LEN + WRAP_NONCE_LEN + SPACE_KEY_SIZE + XChaCha20Poly1305.TAG_SIZE // 104

    // The associated data of a sealed space key (void-which-binds-go `chainLabel`). An
    // identity-defining constant: changing it is a total break, not a tidy-up. It is
    // what keeps a sealed key and an encrypted change (aad = ∅) from ever opening as
    // each other, even under the same space key.
    private const val CHAIN_LABEL = "void-which-binds/space-key-chain/v1"

    /** The length of a [sealSpaceKey] output: nonce(24) ‖ key(32) ‖ tag(16) (Go `SealedSpaceKeySize`). */
    const val SEALED_SPACE_KEY_SIZE = WRAP_NONCE_LEN + SPACE_KEY_SIZE + XChaCha20Poly1305.TAG_SIZE // 72

    /**
     * A sealed space key that did not open (void-which-binds-go `ErrUnwrap`): the wrong
     * sealing key, a corrupt or truncated blob, or bytes that were not sealed as a space
     * key (an encrypted change, for one). Deliberately one opaque error with no cause, so
     * a caller cannot tell which; a holder of several keys just tries the next one.
     */
    public class UnwrapException : Exception("encryption: could not unwrap the space key")

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

    /**
     * Seal [spaceKey] under [sealingKey] (void-which-binds-go `encryption.SealSpaceKey`):
     * in a key history (heyarr ADR-0103), the previous epoch's key under the next one.
     * A fresh random nonce each call, so sealing the same pair twice yields two blobs.
     * Throws [IllegalArgumentException] for a key that is not 32 bytes (Go `ErrWrongLength`).
     */
    @Throws(Exception::class)
    fun sealSpaceKey(sealingKey: ByteArray, spaceKey: ByteArray): ByteArray =
        sealSpaceKeyWithNonce(sealingKey, spaceKey, CryptographyRandom.Default.nextBytes(WRAP_NONCE_LEN))

    /** [sealSpaceKey] with a caller-chosen nonce: the golden-vector seam (Go `sealSpaceKeyWithNonce`). */
    internal fun sealSpaceKeyWithNonce(sealingKey: ByteArray, spaceKey: ByteArray, nonce: ByteArray): ByteArray {
        require(sealingKey.size == SPACE_KEY_SIZE) { "sealSpaceKey: sealing key must be 32 bytes" }
        require(spaceKey.size == SPACE_KEY_SIZE) { "sealSpaceKey: space key must be 32 bytes" }
        require(nonce.size == WRAP_NONCE_LEN) { "sealSpaceKey: nonce must be $WRAP_NONCE_LEN bytes" }
        return nonce + XChaCha20Poly1305.encrypt(sealingKey, nonce, CHAIN_LABEL.encodeToByteArray(), spaceKey)
    }

    /**
     * Reverse [sealSpaceKey] with the sealing key (void-which-binds-go
     * `encryption.OpenSpaceKey`), returning the 32-byte sealed key. Every failure of
     * the blob (wrong key, corrupt, truncated, not exactly [SEALED_SPACE_KEY_SIZE]
     * bytes, an encrypted change) is the one opaque [UnwrapException]; only a
     * [sealingKey] that is not 32 bytes is an [IllegalArgumentException] (Go
     * `ErrWrongLength`), a caller bug rather than bad data.
     */
    @Throws(Exception::class)
    fun openSpaceKey(sealingKey: ByteArray, sealed: ByteArray): ByteArray {
        require(sealingKey.size == SPACE_KEY_SIZE) { "openSpaceKey: sealing key must be 32 bytes" }
        val key = if (sealed.size == SEALED_SPACE_KEY_SIZE) openChainOrNull(sealingKey, sealed) else null
        // No cause attached: Go's ErrUnwrap carries none either, and a holder of several keys
        // must not learn which part of the blob failed.
        return key ?: throw UnwrapException()
    }

    /** The AEAD open of a 72-byte sealed key, or null on any failure (collapsed by [openSpaceKey]). */
    private fun openChainOrNull(sealingKey: ByteArray, sealed: ByteArray): ByteArray? = runCatching {
        val nonce = sealed.copyOfRange(0, WRAP_NONCE_LEN)
        val ct = sealed.copyOfRange(WRAP_NONCE_LEN, sealed.size)
        XChaCha20Poly1305.decrypt(sealingKey, nonce, CHAIN_LABEL.encodeToByteArray(), ct)
    }.getOrNull()?.takeIf { it.size == SPACE_KEY_SIZE }

    private val EMPTY = ByteArray(0)

    private fun hkdf32(ikm: ByteArray, salt: ByteArray): ByteArray =
        hkdf.secretDerivation(SHA256, 32.bytes, salt, WRAP_INFO.encodeToByteArray())
            .deriveSecretToByteArrayBlocking(ikm)
}
