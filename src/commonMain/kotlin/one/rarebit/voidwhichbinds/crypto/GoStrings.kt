package one.rarebit.voidwhichbinds.crypto

/**
 * The Go string semantics a header, slot or recovery parser must reproduce exactly, where
 * Kotlin's own differ: `strings.TrimSpace`/`strings.Fields`'s whitespace set,
 * `strings.ToLower`'s simple case mapping, and `len` of a string (UTF-8 bytes, not
 * UTF-16 units).
 */
internal object GoStrings {

    /**
     * Go's `strings.TrimSpace`. Its whitespace is `unicode.IsSpace`, which differs from
     * Kotlin's `trim()`: Go trims U+0085 and does not trim U+001C..U+001F.
     */
    fun trimSpace(s: String): String = s.trim(::isSpace)

    /** Go's `strings.Fields`: the runs of [s] between [isSpace] characters, none empty. */
    fun fields(s: String): List<String> {
        val out = ArrayList<String>()
        var start = -1
        for (i in 0..s.length) {
            val space = i == s.length || isSpace(s[i])
            if (space && start >= 0) {
                out += s.substring(start, i)
                start = -1
            } else if (!space && start < 0) {
                start = i
            }
        }
        return out
    }

    /**
     * Go's `strings.ToLower`: each rune through `unicode.ToLower`, the one-to-one simple
     * case mapping. Kotlin's `lowercase()` applies the full mapping instead, which turns
     * U+0130 into two characters where Go writes `i`.
     */
    fun toLower(s: String): String {
        val sb = StringBuilder(s.length)
        var i = 0
        while (i < s.length) {
            val c = s[i]
            if (c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate()) {
                // No supplementary character has a multi-character lowercase, so the full
                // mapping of a surrogate pair is its simple one.
                sb.append(s.substring(i, i + 2).lowercase())
                i += 2
            } else {
                sb.append(c.lowercaseChar())
                i++
            }
        }
        return sb.toString()
    }

    /** Go's `unicode.IsSpace` over a UTF-16 unit (every Go space is in the BMP). */
    fun isSpace(c: Char): Boolean = when (c) {
        '\t', '\n', '\u000B', '\u000C', '\r', ' ', '\u0085', ' ', ' ',
        ' ', ' ', ' ', ' ', '　',
        -> true

        in ' '..' ' -> true

        else -> false
    }

    /**
     * Go's `len(s)` for the UTF-8 encoding of [s], without allocating it. A lone
     * surrogate counts as the 3-byte U+FFFD Kotlin's encoder writes for it.
     */
    fun utf8Length(s: String): Int {
        var n = 0
        var i = 0
        while (i < s.length) {
            val c = s[i]
            n += when {
                c.code < ONE_BYTE_LIMIT -> 1

                c.code < TWO_BYTE_LIMIT -> 2

                c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate() -> {
                    i++
                    SUPPLEMENTARY_BYTES
                }

                else -> BMP_BYTES
            }
            i++
        }
        return n
    }

    private const val ONE_BYTE_LIMIT = 0x80
    private const val TWO_BYTE_LIMIT = 0x800
    private const val BMP_BYTES = 3
    private const val SUPPLEMENTARY_BYTES = 4
}
