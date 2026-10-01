package one.rarebit.voidwhichbinds

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA256

/**
 * Short-Authentication-String pairing with **commit-before-reveal**, ported
 * **byte-for-byte from void-which-binds-go's v2 transcript** (`pairing/pairing.go` +
 * `pairing/commitment.go`, ADR-0022/0038/0049 §41). This must interoperate with a
 * live backend, so every hashed byte matches the Go side exactly:
 *
 * - domains `void-which-binds/pairing/commit/v2` and `void-which-binds/pairing/sas/v2`;
 * - the commitment binds a device's **both** keys — Ed25519 signing + X25519
 *   encryption (v2's whole point: a relay that swapped only the encryption key is
 *   caught too);
 * - every field is **length-framed with an 8-byte big-endian count** so no byte
 *   can migrate across a boundary, and an empty encryption key is bound by its
 *   framed absence;
 * - the SAS is `SHA-256(...) mod 10^7`, rendered as 7 fixed-width decimal digits.
 *
 * The full digest is reduced modulo 10^7 byte-by-byte (Horner over base-256), which
 * equals `bigint(digest) mod 10^7` without needing a multiplatform big integer, and
 * keeps the modulo bias mathematically nil.
 */
object Pairing {

    /** Folded into the domain labels; a bump reshapes every string. */
    const val VERSION = 2

    const val COMMIT_DOMAIN = "void-which-binds/pairing/commit/v2"
    const val SAS_DOMAIN = "void-which-binds/pairing/sas/v2"

    /** Decimal length of the SAS (a security parameter — ~23 bits). */
    const val DIGITS = 7
    private const val SPACE = 10_000_000L

    /** A commitment is a full SHA-256 digest. */
    const val COMMITMENT_LEN = 32

    const val ED25519_PUBLIC_KEY_SIZE = 32
    const val ENC_KEY_SIZE = 32

    /** Freshly generated salt length; the smallest [deriveSas] accepts. */
    const val SALT_LEN = 32
    const val MIN_SALT_LEN = 16

    private val sha256 = CryptographyProvider.Default.get(SHA256).hasher()

    /**
     * One device's two public keys the SAS/commitment bind: its Ed25519 [sign]ing
     * key and its X25519 [enc]ryption key. [enc] may be empty (a v1-shaped device
     * with no encryption key) and is then bound by its framed absence; a non-empty
     * [enc] must be exactly [ENC_KEY_SIZE].
     */
    class Keys(val sign: ByteArray, val enc: ByteArray = ByteArray(0)) {
        internal fun validate(role: String) {
            require(sign.size == ED25519_PUBLIC_KEY_SIZE) {
                "pairing: $role signing key is ${sign.size} bytes, want $ED25519_PUBLIC_KEY_SIZE"
            }
            require(enc.isEmpty() || enc.size == ENC_KEY_SIZE) {
                "pairing: $role encryption key is ${enc.size} bytes, want $ENC_KEY_SIZE or 0"
            }
        }
    }

    /**
     * The commitment a device broadcasts to BOTH its keys before either side
     * reveals a key. [enc] is committed as-is (empty or its raw bytes). Refuses a
     * signing key that is not exactly [ED25519_PUBLIC_KEY_SIZE].
     */
    fun commit(signPub: ByteArray, enc: ByteArray = ByteArray(0)): ByteArray {
        require(signPub.size == ED25519_PUBLIC_KEY_SIZE) {
            "pairing: key is ${signPub.size} bytes, want $ED25519_PUBLIC_KEY_SIZE"
        }
        return sha256.hashBlocking(frame(listOf(COMMIT_DOMAIN.encodeToByteArray(), signPub, enc)))
    }

    /**
     * Whether [signPub] + [enc] open [commitment] — the check the transport MUST
     * run on a peer's revealed keys before deriving the SAS. Refuses a commitment
     * of the wrong length.
     */
    fun opens(commitment: ByteArray, signPub: ByteArray, enc: ByteArray = ByteArray(0)): Boolean {
        require(commitment.size == COMMITMENT_LEN) {
            "pairing: commitment is ${commitment.size} bytes, want $COMMITMENT_LEN"
        }
        return commitment.contentEquals(commit(signPub, enc))
    }

    /**
     * Derive the SAS binding both devices' key sets and the session [salt]. Both
     * sides run it; they get the same 7-digit string iff they hashed the same keys
     * in the same roles under the same salt. [initiator] is the authorising
     * (existing) device, [responder] the new one.
     */
    fun deriveSas(initiator: Keys, responder: Keys, salt: ByteArray): String {
        initiator.validate("initiator")
        responder.validate("responder")
        require(salt.size >= MIN_SALT_LEN) {
            "pairing: session salt is ${salt.size} bytes, want at least $MIN_SALT_LEN"
        }
        val digest = sha256.hashBlocking(
            frame(
                listOf(
                    SAS_DOMAIN.encodeToByteArray(),
                    initiator.sign,
                    initiator.enc,
                    responder.sign,
                    responder.enc,
                    salt,
                ),
            ),
        )
        // digest mod 10^7, computed byte-by-byte (Horner, base 256). SPACE*256 fits
        // in a Long, so this never overflows and equals bigint(digest) mod 10^7.
        var acc = 0L
        for (b in digest) {
            acc = (acc * 256 + (b.toLong() and 0xFF)) % SPACE
        }
        return acc.toString().padStart(DIGITS, '0')
    }

    /**
     * Length-framed preimage: each part preceded by its length as an **8-byte
     * big-endian** count, matching void-which-binds-go's `writeField`. The boundary
     * between fields is itself hashed, so no byte can shift across it and an empty
     * field is bound by its zero length.
     */
    private fun frame(parts: List<ByteArray>): ByteArray {
        var size = 0
        for (p in parts) size += 8 + p.size
        val out = ByteArray(size)
        var i = 0
        for (p in parts) {
            val n = p.size.toLong()
            for (shift in 56 downTo 0 step 8) {
                out[i++] = (n ushr shift).toByte()
            }
            p.copyInto(out, i)
            i += p.size
        }
        return out
    }
}
