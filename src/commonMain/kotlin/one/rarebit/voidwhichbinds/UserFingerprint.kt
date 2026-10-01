package one.rarebit.voidwhichbinds

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA256

/**
 * A short, human-comparable fingerprint of a user identity's public key, for
 * checking a written recovery secret against the identity it should derive
 * (void-which-binds-go ADR-0010). Byte-identical to void-which-binds-go `recovery.Fingerprint`:
 *
 *     base32(SHA-256("void-which-binds/user-fingerprint/v1" ‖ 0x00 ‖ userPublicKey)[:10])
 *
 * RFC 4648 base32 without padding (A–Z and 2–7, so no digit can be misread as an O,
 * I or B), 16 characters grouped four by four: `PYJI XGNZ K7ZH XHEJ`. Pinned by
 * void-which-binds-go's `testvectors/vectors/recovery/` known answers.
 */
object UserFingerprint {
    /** The domain-separation label; part of the recovery format. Never rename. */
    const val LABEL = "void-which-binds/user-fingerprint/v1"

    private const val KEY_LEN = 32
    private const val BYTES = 10
    private const val GROUP = 4
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567"
    private const val BYTE_BITS = 8
    private const val BYTE_MASK = 0xFF
    private const val SYMBOL_BITS = 5
    private const val SYMBOL_MASK = 0x1F

    private val sha256 = CryptographyProvider.Default.get(SHA256).hasher()

    /** The fingerprint of [userPublicKey], or "" for a key that is not 32 bytes. */
    fun of(userPublicKey: ByteArray): String {
        if (userPublicKey.size != KEY_LEN) return ""
        val digest = sha256.hashBlocking(LABEL.encodeToByteArray() + byteArrayOf(0) + userPublicKey)
        return base32(digest.copyOf(BYTES)).chunked(GROUP).joinToString(" ")
    }

    /** RFC 4648 base32, no padding. */
    private fun base32(bytes: ByteArray): String {
        val out = StringBuilder()
        var buffer = 0
        var bits = 0
        for (b in bytes) {
            buffer = (buffer shl BYTE_BITS) or (b.toInt() and BYTE_MASK)
            bits += BYTE_BITS
            while (bits >= SYMBOL_BITS) {
                out.append(ALPHABET[(buffer ushr (bits - SYMBOL_BITS)) and SYMBOL_MASK])
                bits -= SYMBOL_BITS
            }
        }
        if (bits > 0) out.append(ALPHABET[(buffer shl (SYMBOL_BITS - bits)) and SYMBOL_MASK])
        return out.toString()
    }
}
