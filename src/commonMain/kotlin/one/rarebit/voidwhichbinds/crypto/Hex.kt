package one.rarebit.voidwhichbinds.crypto

/**
 * Lowercase hex codec. Pure Kotlin, no platform APIs.
 *
 * Keys on the wire are rendered as `<alg>:<hex>` (see [one.rarebit.voidwhichbinds.KeyRef]);
 * this is the hex half of that rendering.
 */
object Hex {
    private const val DIGITS = "0123456789abcdef"

    fun encode(bytes: ByteArray): String {
        val sb = StringBuilder(bytes.size * 2)
        for (b in bytes) {
            val v = b.toInt() and 0xFF
            sb.append(DIGITS[v ushr 4])
            sb.append(DIGITS[v and 0x0F])
        }
        return sb.toString()
    }

    fun decode(hex: String): ByteArray {
        require(hex.length % 2 == 0) { "hex string must have even length, got ${hex.length}" }
        val out = ByteArray(hex.length / 2)
        var i = 0
        while (i < hex.length) {
            val hi = nibble(hex[i])
            val lo = nibble(hex[i + 1])
            out[i / 2] = ((hi shl 4) or lo).toByte()
            i += 2
        }
        return out
    }

    private fun nibble(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("invalid hex character: '$c'")
    }
}
