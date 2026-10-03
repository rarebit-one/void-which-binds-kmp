package one.rarebit.voidwhichbinds.slip39

import one.rarebit.voidwhichbinds.crypto.GoStrings

/**
 * What every share of one split agrees on: the random identifier, the extendable
 * flag, the iteration exponent, and the group threshold and count (real values;
 * the mnemonic stores each of the last two minus one).
 */
internal data class SplitParams(
    val id: Int,
    val extendable: Boolean,
    val iterationExponent: Int,
    val groupThreshold: Int,
    val groupCount: Int,
)

/** One decoded mnemonic: its split's [params], its place in the split, and its share [value]. */
internal class Share(
    val params: SplitParams,
    val groupIndex: Int,
    val memberIndex: Int,
    val memberThreshold: Int,
    val value: ByteArray,
) {
    /** Encode as the space-separated mnemonic (see the spec's "Format of the share mnemonic"). */
    fun mnemonic(): String {
        val ext = if (params.extendable) 1 else 0
        val idExp = (params.id shl (1 + ITER_EXP_BITS)) or (ext shl ITER_EXP_BITS) or params.iterationExponent
        val groupParams = (groupIndex shl GROUP_INDEX_SHIFT) or
            ((params.groupThreshold - 1) shl GROUP_THRESHOLD_SHIFT) or
            ((params.groupCount - 1) shl GROUP_COUNT_SHIFT) or
            (memberIndex shl MEMBER_INDEX_SHIFT) or
            (memberThreshold - 1)
        val header = intArrayOf(
            idExp ushr RADIX_BITS,
            idExp and WORD_MASK,
            groupParams ushr RADIX_BITS,
            groupParams and WORD_MASK,
        )
        val data = header + valueToWords(value)
        val words = data + Rs1024.checksum(params.extendable, data)
        return words.joinToString(" ") { Slip39Wordlist.words[it] }
    }

    companion object {
        /** The width of one word: log2(1024). */
        const val RADIX_BITS = 10
        private const val WORD_MASK = 0x3ff
        private const val BYTE_BITS = 8
        private const val BYTE_MASK = 0xff
        private const val UNIT_BITS = 16
        private const val MAX_PADDING_BITS = 8

        /** The identifier's width; the extendable flag and the 4-bit exponent follow it. */
        const val ID_BITS = 15
        private const val ITER_EXP_BITS = 4
        private const val NIBBLE = 0xf
        private const val GROUP_INDEX_SHIFT = 16
        private const val GROUP_THRESHOLD_SHIFT = 12
        private const val GROUP_COUNT_SHIFT = 8
        private const val MEMBER_INDEX_SHIFT = 4

        // Layout, in words: id+ext+e (2), GI+Gt+g+I+t (2), value, checksum (3).
        private const val ID_EXP_WORDS = 2
        private const val PARAM_WORDS = 2
        private const val HEADER_WORDS = ID_EXP_WORDS + PARAM_WORDS
        private const val METADATA_WORDS = HEADER_WORDS + Rs1024.CHECKSUM_WORDS

        /** A 128-bit secret's share: the shortest there is (33 words for 256 bits). */
        const val MIN_WORDS = 20

        /**
         * Decode and validate one mnemonic: every word known, the length possible, the
         * checksum good, the padding zero and the metadata consistent. Words are split
         * on any whitespace and matched case-insensitively, like void-which-binds-go `parseShare`.
         */
        fun parse(mnemonic: String): Share {
            val words = toWords(mnemonic)
            if (words.size < MIN_WORDS) {
                refuse(Slip39Error.INVALID_LENGTH, "${words.size} words, a share has at least $MIN_WORDS")
            }
            if (paddingBits(words.size - METADATA_WORDS) > MAX_PADDING_BITS) {
                refuse(Slip39Error.INVALID_LENGTH, "${words.size} words cannot hold a whole secret")
            }
            val idExp = (words[0] shl RADIX_BITS) or words[1]
            val extendable = (idExp ushr ITER_EXP_BITS) and 1 == 1
            if (!Rs1024.verifies(extendable, words)) refuse(Slip39Error.CHECKSUM)

            val p = (words[2] shl RADIX_BITS) or words[HEADER_WORDS - 1]
            val params = SplitParams(
                id = idExp ushr (1 + ITER_EXP_BITS),
                extendable = extendable,
                iterationExponent = idExp and NIBBLE,
                groupThreshold = ((p ushr GROUP_THRESHOLD_SHIFT) and NIBBLE) + 1,
                groupCount = ((p ushr GROUP_COUNT_SHIFT) and NIBBLE) + 1,
            )
            if (params.groupThreshold > params.groupCount) {
                refuse(
                    Slip39Error.MALFORMED_SHARE,
                    "group threshold ${params.groupThreshold} is greater than the group count ${params.groupCount}",
                )
            }
            return Share(
                params = params,
                groupIndex = (p ushr GROUP_INDEX_SHIFT) and NIBBLE,
                memberIndex = (p ushr MEMBER_INDEX_SHIFT) and NIBBLE,
                memberThreshold = (p and NIBBLE) + 1,
                value = wordsToValue(words.copyOfRange(HEADER_WORDS, words.size - Rs1024.CHECKSUM_WORDS)),
            )
        }

        private fun toWords(mnemonic: String): IntArray {
            // Go `strings.Fields(strings.ToLower(mnemonic))` (#107): split on unicode.IsSpace,
            // lower-cased rune by rune (simple case mapping: U+0130 is "i", not "i̇").
            val fields = GoStrings.fields(GoStrings.toLower(mnemonic))
            return IntArray(fields.size) { i ->
                val word = fields[i]
                Slip39Wordlist.indexOf(word)
                    ?: refuse(Slip39Error.UNKNOWN_WORD, "word ${i + 1}, \"$word\", is not in the SLIP-39 wordlist")
            }
        }

        /** The leading zero bits that pad [valueWords] words to whole 16-bit units. */
        private fun paddingBits(valueWords: Int): Int = (RADIX_BITS * valueWords) % UNIT_BITS

        /** Render [value] as big-endian 10-bit words, left-padded with zero bits. */
        fun valueToWords(value: ByteArray): IntArray {
            val n = (value.size * BYTE_BITS + RADIX_BITS - 1) / RADIX_BITS
            val out = IntArray(n)
            var next = 0
            var acc = 0
            var bits = n * RADIX_BITS - value.size * BYTE_BITS // the padding: leading zero bits
            for (b in value) {
                acc = (acc shl BYTE_BITS) or (b.toInt() and BYTE_MASK)
                bits += BYTE_BITS
                while (bits >= RADIX_BITS) {
                    bits -= RADIX_BITS
                    out[next++] = (acc ushr bits) and WORD_MASK
                    acc = acc and ((1 shl bits) - 1)
                }
            }
            return out
        }

        /** [valueToWords]' inverse; a non-zero padding bit is refused. */
        fun wordsToValue(words: IntArray): ByteArray {
            val padding = paddingBits(words.size)
            val out = ByteArray((words.size * RADIX_BITS - padding) / BYTE_BITS)
            var next = 0
            var acc = 0
            var bits = -padding
            for ((i, w) in words.withIndex()) {
                acc = (acc shl RADIX_BITS) or w
                bits += RADIX_BITS
                // The first word carries the padding: its top `padding` bits must be zero.
                if (i == 0 && acc ushr bits != 0) refuse(Slip39Error.PADDING)
                while (bits >= BYTE_BITS) {
                    bits -= BYTE_BITS
                    out[next++] = (acc ushr bits).toByte()
                    acc = acc and ((1 shl bits) - 1)
                }
            }
            return out
        }
    }
}
