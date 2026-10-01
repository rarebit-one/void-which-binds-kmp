package one.rarebit.voidwhichbinds.slip39

/**
 * RS1024, the SLIP-39 checksum: a Reed-Solomon code over GF(1024) that detects any
 * error in up to three words. Ported from void-which-binds-go `rs1024Polymod`, itself the
 * spec's reference. The customization string keys the checksum to the extendable
 * flag (`shamir` or `shamir_extendable`), so the flag cannot be flipped unnoticed.
 */
internal object Rs1024 {
    /** Three checksum words at the end of every mnemonic. */
    const val CHECKSUM_WORDS = 3

    private const val CUSTOMIZATION = "shamir"
    private const val CUSTOMIZATION_EXTENDABLE = "shamir_extendable"

    private const val WORD_BITS = 10
    private const val WORD_MASK = 0x3ff
    private const val TOP_SHIFT = 20
    private const val LOW_MASK = 0xfffff

    // The generator, from the spec; ten 30-bit values.
    private const val G0 = 0xe0e040
    private const val G1 = 0x1c1c080
    private const val G2 = 0x3838100
    private const val G3 = 0x7070200
    private const val G4 = 0xe0e0009
    private const val G5 = 0x1c0c2412
    private const val G6 = 0x38086c24
    private const val G7 = 0x3090fc48
    private const val G8 = 0x21b1f890
    private const val G9 = 0x3f3f120
    private val generator = intArrayOf(G0, G1, G2, G3, G4, G5, G6, G7, G8, G9)

    private fun customization(extendable: Boolean) = if (extendable) CUSTOMIZATION_EXTENDABLE else CUSTOMIZATION

    /** The spec's `rs1024_polymod` over the customization string's bytes, then [words]. */
    private fun polymod(extendable: Boolean, words: IntArray): Int {
        var chk = 1
        fun step(v: Int) {
            val b = chk ushr TOP_SHIFT
            chk = ((chk and LOW_MASK) shl WORD_BITS) xor v
            for (i in generator.indices) {
                if ((b ushr i) and 1 == 1) chk = chk xor generator[i]
            }
        }
        customization(extendable).forEach { step(it.code) }
        words.forEach { step(it) }
        return chk
    }

    /** Whether [words] (data then checksum) carry a valid checksum. */
    fun verifies(extendable: Boolean, words: IntArray): Boolean = polymod(extendable, words) == 1

    /** The three checksum words for [data]. */
    fun checksum(extendable: Boolean, data: IntArray): IntArray {
        val pm = polymod(extendable, data + IntArray(CHECKSUM_WORDS)) xor 1
        return IntArray(CHECKSUM_WORDS) { i -> (pm ushr (WORD_BITS * (CHECKSUM_WORDS - 1 - i))) and WORD_MASK }
    }
}
