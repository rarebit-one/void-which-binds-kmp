package one.rarebit.voidwhichbinds.slip39

import dev.whyoleg.cryptography.BinarySize.Companion.bytes
import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.PBKDF2
import dev.whyoleg.cryptography.algorithms.SHA256

/**
 * The SLIP-39 master-secret encryption: a four-round Feistel network (Luby-Rackoff)
 * whose round function is PBKDF2-HMAC-SHA256. L and R are the halves of the secret;
 * each round is (L, R) ← (R, L ⊕ F(i, R)), and the result is R ‖ L. Ported from
 * void-which-binds-go `recovery/slip39/cipher.go`.
 *
 * PBKDF2 is the cryptography-kotlin provider's (JDK `PBKDF2WithHmacSHA256` on
 * JVM/Android, CommonCrypto on Apple), pinned by `Pbkdf2Test`'s RFC 7914 known
 * answers and, end to end, by Trezor's vectors. Its password is `i ‖ passphrase`:
 * one round byte (0..3) and printable ASCII, which the JDK's char-based password
 * API carries unchanged.
 */
internal object Feistel {
    /** The total PBKDF2 iterations at exponent 0, spread evenly over the rounds. */
    private const val BASE_ITERATIONS = 10000
    private const val ROUNDS = 4
    private const val BYTE_BITS = 8

    /**
     * The salt prefix of a non-extendable backup, followed by the identifier as two
     * big-endian bytes. An extendable backup uses no salt prefix, so its encryption
     * does not depend on the identifier.
     */
    private const val SALT_PREFIX = "shamir"

    private val pbkdf2 = CryptographyProvider.Default.get(PBKDF2)

    fun encrypt(secret: ByteArray, passphrase: ByteArray, params: SplitParams): ByteArray {
        val forward = 0 until ROUNDS
        return run(secret, passphrase, params, forward)
    }

    /** [encrypt] inverted: the same network with the rounds in reverse. */
    fun decrypt(encrypted: ByteArray, passphrase: ByteArray, params: SplitParams): ByteArray {
        val reversed = (ROUNDS - 1) downTo 0
        return run(encrypted, passphrase, params, reversed)
    }

    private fun run(input: ByteArray, passphrase: ByteArray, params: SplitParams, order: IntProgression): ByteArray {
        val half = input.size / 2
        var l = input.copyOfRange(0, half)
        var r = input.copyOfRange(half, input.size)
        val salt = if (params.extendable) {
            ByteArray(0)
        } else {
            SALT_PREFIX.encodeToByteArray() + byteArrayOf((params.id ushr BYTE_BITS).toByte(), params.id.toByte())
        }
        val iterations = (BASE_ITERATIONS / ROUNDS) shl params.iterationExponent
        for (i in order) {
            // F(i, R) = PBKDF2(HMAC-SHA256, password = i ‖ passphrase, salt = salt ‖ R, iterations, n/2 bytes)
            val f = pbkdf2
                .secretDerivation(digest = SHA256, iterations = iterations, outputSize = half.bytes, salt = salt + r)
                .deriveSecretToByteArrayBlocking(byteArrayOf(i.toByte()) + passphrase)
            val next = ByteArray(half) { k -> (l[k].toInt() xor f[k].toInt()).toByte() }
            l = r
            r = next
        }
        return r + l
    }
}
