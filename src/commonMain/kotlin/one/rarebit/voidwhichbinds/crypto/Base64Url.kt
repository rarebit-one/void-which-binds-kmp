package one.rarebit.voidwhichbinds.crypto

/**
 * URL-safe Base64 **without padding** (RFC 4648 §5, no `=`).
 *
 * This is the encoding used on both halves of the enrolment cert token:
 * `base64url(json payload) + "." + base64url(ed25519 sig)`. It must match
 * void-which-binds-go's `base64.RawURLEncoding` byte-for-byte.
 */
object Base64Url {
    private const val ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_"
    private val INVERSE = IntArray(128) { -1 }.also { inv ->
        for (i in ALPHABET.indices) inv[ALPHABET[i].code] = i
    }

    fun encode(bytes: ByteArray): String {
        if (bytes.isEmpty()) return ""
        val sb = StringBuilder((bytes.size * 4 + 2) / 3)
        var i = 0
        while (i + 3 <= bytes.size) {
            val n = ((bytes[i].toInt() and 0xFF) shl 16) or
                ((bytes[i + 1].toInt() and 0xFF) shl 8) or
                (bytes[i + 2].toInt() and 0xFF)
            sb.append(ALPHABET[(n ushr 18) and 0x3F])
            sb.append(ALPHABET[(n ushr 12) and 0x3F])
            sb.append(ALPHABET[(n ushr 6) and 0x3F])
            sb.append(ALPHABET[n and 0x3F])
            i += 3
        }
        when (bytes.size - i) {
            1 -> {
                val n = (bytes[i].toInt() and 0xFF) shl 16
                sb.append(ALPHABET[(n ushr 18) and 0x3F])
                sb.append(ALPHABET[(n ushr 12) and 0x3F])
            }

            2 -> {
                val n = ((bytes[i].toInt() and 0xFF) shl 16) or
                    ((bytes[i + 1].toInt() and 0xFF) shl 8)
                sb.append(ALPHABET[(n ushr 18) and 0x3F])
                sb.append(ALPHABET[(n ushr 12) and 0x3F])
                sb.append(ALPHABET[(n ushr 6) and 0x3F])
            }
        }
        return sb.toString()
    }

    fun decode(s: String): ByteArray {
        if (s.isEmpty()) return ByteArray(0)
        require(s.length % 4 != 1) { "invalid base64url length: ${s.length}" }
        val fullGroups = s.length / 4
        val rem = s.length % 4
        val outLen = fullGroups * 3 + when (rem) {
            2 -> 1
            3 -> 2
            else -> 0
        }
        val out = ByteArray(outLen)
        var si = 0
        var oi = 0
        repeat(fullGroups) {
            val n = (sym(s[si]) shl 18) or (sym(s[si + 1]) shl 12) or
                (sym(s[si + 2]) shl 6) or sym(s[si + 3])
            out[oi] = (n ushr 16).toByte()
            out[oi + 1] = (n ushr 8).toByte()
            out[oi + 2] = n.toByte()
            si += 4
            oi += 3
        }
        when (rem) {
            2 -> {
                val n = (sym(s[si]) shl 18) or (sym(s[si + 1]) shl 12)
                out[oi] = (n ushr 16).toByte()
            }

            3 -> {
                val n = (sym(s[si]) shl 18) or (sym(s[si + 1]) shl 12) or (sym(s[si + 2]) shl 6)
                out[oi] = (n ushr 16).toByte()
                out[oi + 1] = (n ushr 8).toByte()
            }
        }
        return out
    }

    private fun sym(c: Char): Int {
        val v = if (c.code < 128) INVERSE[c.code] else -1
        require(v >= 0) { "invalid base64url character: '$c'" }
        return v
    }
}
