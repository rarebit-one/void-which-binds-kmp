package one.rarebit.voidwhichbinds.crypto

/**
 * Bech32m codec (BIP-350). Pure Kotlin, no platform APIs.
 *
 * Void-Which-Binds uses bech32m — **not** bech32 — for the human-facing recovery secret
 * (see [one.rarebit.voidwhichbinds.RecoverySecret], HRP `heyarr`). The two differ only
 * in the checksum constant; using the wrong one silently produces strings that
 * a correct decoder rejects, so this is a wire-contract detail, not a cosmetic one.
 */
object Bech32m {
    /** Checksum constant that distinguishes bech32m from bech32 (0x01). */
    private const val CONST = 0x2bc830a3

    private const val CHARSET = "qpzry9x8gf2tvdw0s3jn54khce6mua7l"
    private val REVERSE = IntArray(128) { -1 }.also { rev ->
        for (i in CHARSET.indices) rev[CHARSET[i].code] = i
    }

    private val GENERATOR = intArrayOf(0x3b6a57b2, 0x26508e6d, 0x1ea119fa, 0x3d4233dd, 0x2a1462b3)

    /** Encode 5-bit groups [data] under [hrp] into a bech32m string. */
    fun encode(hrp: String, data: IntArray): String {
        require(hrp.isNotEmpty()) { "empty HRP" }
        val checksum = createChecksum(hrp, data)
        val sb = StringBuilder(hrp.length + 1 + data.size + checksum.size)
        sb.append(hrp).append('1')
        for (d in data) sb.append(CHARSET[d])
        for (c in checksum) sb.append(CHARSET[c])
        return sb.toString()
    }

    /** Decoded parts of a bech32m string: the HRP and the raw 5-bit data (no checksum). */
    data class Decoded(val hrp: String, val data: IntArray) {
        override fun equals(other: Any?): Boolean =
            other is Decoded && hrp == other.hrp && data.contentEquals(other.data)

        override fun hashCode(): Int = 31 * hrp.hashCode() + data.contentHashCode()
    }

    /** Decode and verify a bech32m string. Throws on any structural or checksum error. */
    fun decode(s: String): Decoded {
        require(s.length in 8..90) { "bech32m string length out of range: ${s.length}" }
        val lower = s.lowercase()
        val upper = s.uppercase()
        require(s == lower || s == upper) { "bech32m must not be mixed case" }
        val norm = lower
        val sep = norm.lastIndexOf('1')
        require(sep >= 1) { "missing/invalid HRP separator" }
        require(norm.length - sep - 1 >= 6) { "data part too short for checksum" }
        val hrp = norm.substring(0, sep)
        val dataChars = norm.substring(sep + 1)
        val values = IntArray(dataChars.length)
        for (i in dataChars.indices) {
            val v = if (dataChars[i].code < 128) REVERSE[dataChars[i].code] else -1
            require(v >= 0) { "invalid bech32m data character: '${dataChars[i]}'" }
            values[i] = v
        }
        require(verifyChecksum(hrp, values)) { "bech32m checksum mismatch" }
        return Decoded(hrp, values.copyOfRange(0, values.size - 6))
    }

    private fun polymod(values: IntArray): Int {
        var chk = 1
        for (v in values) {
            val b = chk ushr 25
            chk = ((chk and 0x1ffffff) shl 5) xor v
            for (i in 0 until 5) {
                if (((b ushr i) and 1) != 0) chk = chk xor GENERATOR[i]
            }
        }
        return chk
    }

    private fun hrpExpand(hrp: String): IntArray {
        val out = IntArray(hrp.length * 2 + 1)
        for (i in hrp.indices) out[i] = hrp[i].code ushr 5
        out[hrp.length] = 0
        for (i in hrp.indices) out[hrp.length + 1 + i] = hrp[i].code and 31
        return out
    }

    private fun createChecksum(hrp: String, data: IntArray): IntArray {
        val values = hrpExpand(hrp) + data + intArrayOf(0, 0, 0, 0, 0, 0)
        val mod = polymod(values) xor CONST
        return IntArray(6) { (mod ushr (5 * (5 - it))) and 31 }
    }

    private fun verifyChecksum(hrp: String, data: IntArray): Boolean = polymod(hrpExpand(hrp) + data) == CONST

    /**
     * General power-of-two base conversion (RFC-style `convertbits`).
     * Used to pack raw bytes (8-bit) into 5-bit groups and back.
     */
    fun convertBits(data: IntArray, fromBits: Int, toBits: Int, pad: Boolean): IntArray {
        var acc = 0
        var bits = 0
        val out = ArrayList<Int>()
        val maxv = (1 shl toBits) - 1
        val maxAcc = (1 shl (fromBits + toBits - 1)) - 1
        for (value in data) {
            require(value >= 0 && (value ushr fromBits) == 0) { "input value out of range: $value" }
            acc = ((acc shl fromBits) or value) and maxAcc
            bits += fromBits
            while (bits >= toBits) {
                bits -= toBits
                out.add((acc ushr bits) and maxv)
            }
        }
        if (pad) {
            if (bits > 0) out.add((acc shl (toBits - bits)) and maxv)
        } else {
            require(bits < fromBits) { "excess padding" }
            require(((acc shl (toBits - bits)) and maxv) == 0) { "non-zero padding" }
        }
        return out.toIntArray()
    }

    fun bytesToInts(bytes: ByteArray): IntArray = IntArray(bytes.size) { bytes[it].toInt() and 0xFF }

    fun intsToBytes(ints: IntArray): ByteArray = ByteArray(ints.size) { ints[it].toByte() }
}
