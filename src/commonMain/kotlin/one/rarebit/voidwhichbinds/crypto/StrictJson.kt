package one.rarebit.voidwhichbinds.crypto

/**
 * The strict JSON-object reader ADR-0018's WebAuthn checks need: a port of
 * void-which-binds-go `identity.strictObject` (its `json.Valid` + `walkJSON` pair),
 * working on raw bytes.
 *
 * [read] tells apart the two outcomes Go tells apart:
 *
 * - [Outcome.Invalid] — not exactly one syntactically valid JSON object (RFC 8259
 *   grammar, as Go's `json.Valid`: whitespace is space/tab/LF/CR, no control
 *   characters inside strings, only the standard escapes), or trailing data.
 * - [Outcome.Refused] — a valid JSON object that breaks the strict rules: a
 *   duplicate key at any depth (compared after unescaping), nesting deeper than
 *   [MAX_DEPTH], or a number that overflows a float64 (Go's `Decoder.Token`
 *   decodes numbers to float64 and errors on overflow).
 * - [Outcome.Ok] — the top-level members, with their names exactly as decoded.
 *
 * Strings are decoded as Go's `encoding/json` decodes them: an invalid UTF-8 byte
 * becomes U+FFFD (one per byte, as `utf8.DecodeRune` reports it), and a `\u`
 * surrogate that does not pair becomes U+FFFD.
 *
 * Iterative (an explicit container stack), so a deeply nested but bounded input
 * cannot overflow the call stack before the depth rule refuses it.
 */
internal object StrictJson {

    /** Go `identity.maxJSONDepth`: a value nested deeper than this is refused. */
    const val MAX_DEPTH = 16

    /** A top-level member's value, reduced to what the WebAuthn checks read. */
    sealed interface Value {
        /** A JSON string, decoded. */
        class Str(val value: String) : Value

        /** The literal `true`. */
        object True : Value

        /** The literal `false`. */
        object False : Value

        /** Any other value (number, null, array, object). */
        object Other : Value
    }

    sealed interface Outcome {
        class Invalid(val reason: String) : Outcome
        class Refused(val reason: String) : Outcome
        class Ok(val members: Map<String, Value>) : Outcome
    }

    fun read(bytes: ByteArray): Outcome = Reader(bytes).run()

    /**
     * Whether [b] is valid UTF-8 under Go's `utf8.Valid` rules (no overlong forms,
     * no surrogates, nothing above U+10FFFF).
     */
    fun isValidUtf8(b: ByteArray): Boolean {
        var i = 0
        while (i < b.size) {
            val n = runeLen(b, i)
            if (n < 0) return false
            i += n
        }
        return true
    }

    private const val REPLACEMENT = 0xFFFD
    private const val ASCII_MAX = 0x7F
    private const val CONTROL_MAX = 0x1F
    private const val LOW6 = 0x3F
    private const val SURR_HI_MIN = 0xD800
    private const val SURR_HI_MAX = 0xDBFF
    private const val SURR_LO_MIN = 0xDC00
    private const val SURR_LO_MAX = 0xDFFF
    private const val SURR_BASE = 0x10000
    private const val HEX_DIGITS = 4
    private const val HEX_RADIX = 16
    private const val SURR_SHIFT = 10
    private const val SURR_LOW_MASK = 0x3FF
    private const val BYTE_MASK = 0xFF

    /**
     * The byte length of the valid UTF-8 sequence at [i], or -1 if it is invalid
     * (Go `utf8.DecodeRune`'s acceptance ranges).
     */
    @Suppress("MagicNumber", "ReturnCount", "CyclomaticComplexMethod")
    private fun runeLen(b: ByteArray, i: Int): Int {
        val c0 = b[i].toInt() and BYTE_MASK
        if (c0 <= ASCII_MAX) return 1
        fun cont(k: Int, lo: Int = 0x80, hi: Int = 0xBF): Boolean {
            if (i + k >= b.size) return false
            val c = b[i + k].toInt() and BYTE_MASK
            return c in lo..hi
        }
        return when (c0) {
            in 0xC2..0xDF -> if (cont(1)) 2 else -1
            0xE0 -> if (cont(1, 0xA0) && cont(2)) 3 else -1
            in 0xE1..0xEC, 0xEE, 0xEF -> if (cont(1) && cont(2)) 3 else -1
            0xED -> if (cont(1, 0x80, 0x9F) && cont(2)) 3 else -1
            0xF0 -> if (cont(1, 0x90) && cont(2) && cont(3)) 4 else -1
            in 0xF1..0xF3 -> if (cont(1) && cont(2) && cont(3)) 4 else -1
            0xF4 -> if (cont(1, 0x80, 0x8F) && cont(2) && cont(3)) 4 else -1
            else -> -1
        }
    }

    /** The code point of the valid sequence of length [n] at [i]. */
    @Suppress("MagicNumber")
    private fun decodeRune(b: ByteArray, i: Int, n: Int): Int {
        val c0 = b[i].toInt() and BYTE_MASK
        var cp = when (n) {
            1 -> return c0
            2 -> c0 and 0x1F
            3 -> c0 and 0x0F
            else -> c0 and 0x07
        }
        for (k in 1 until n) cp = (cp shl 6) or (b[i + k].toInt() and LOW6)
        return cp
    }

    private fun StringBuilder.appendCodePoint(cp: Int) {
        if (cp < SURR_BASE) {
            append(cp.toChar())
        } else {
            val v = cp - SURR_BASE
            append((SURR_HI_MIN + (v shr SURR_SHIFT)).toChar())
            append((SURR_LO_MIN + (v and SURR_LOW_MASK)).toChar())
        }
    }

    private class Syntax(message: String) : Exception(message)

    private class Frame(val isObject: Boolean) {
        val keys = HashSet<String>()
    }

    private enum class State { VALUE, OBJ_FIRST, OBJ_KEY, ARR_FIRST, AFTER, DONE }

    /** Go's JSON number grammar (RFC 8259 §6). */
    private val NUMBER = Regex("-?(0|[1-9][0-9]*)(\\.[0-9]+)?([eE][+-]?[0-9]+)?")

    private const val NUMBER_CHARS = "+-.eE0123456789"

    @Suppress("TooManyFunctions") // one small function per grammar production
    private class Reader(val b: ByteArray) {
        var i = 0
        val stack = ArrayList<Frame>()
        val members = LinkedHashMap<String, Value>()
        var pendingKey: String? = null
        var strict: String? = null

        fun run(): Outcome = try {
            parse()
            strict?.let { Outcome.Refused(it) } ?: Outcome.Ok(members)
        } catch (e: Syntax) {
            Outcome.Invalid(e.message ?: "invalid JSON")
        }

        fun syntax(why: String): Nothing = throw Syntax(why)

        fun refuse(reason: String) {
            if (strict == null) strict = reason
        }

        fun byteAt(k: Int): Int = b[k].toInt() and BYTE_MASK

        fun skipWs() {
            while (i < b.size && byteAt(i).toChar() in " \t\n\r") i++
        }

        fun peek(): Char = if (i < b.size) byteAt(i).toChar() else syntax("unexpected end of JSON")

        fun next(): Char = peek().also { i++ }

        fun parse() {
            skipWs()
            if (peek() != '{') syntax("not a JSON object")
            var state = State.VALUE
            while (state != State.DONE) {
                skipWs()
                state = when (state) {
                    State.VALUE -> value()
                    State.OBJ_FIRST -> if (peek() == '}') close() else State.OBJ_KEY
                    State.OBJ_KEY -> key()
                    State.ARR_FIRST -> if (peek() == ']') close() else State.VALUE
                    State.AFTER -> after()
                    State.DONE -> State.DONE
                }
            }
        }

        fun value(): State {
            if (stack.size > MAX_DEPTH) refuse("nested too deeply")
            return when (peek()) {
                '{' -> open(isObject = true)

                '[' -> open(isObject = false)

                else -> {
                    complete(scalar())
                    State.AFTER
                }
            }
        }

        fun open(isObject: Boolean): State {
            i++
            stack.add(Frame(isObject))
            return if (isObject) State.OBJ_FIRST else State.ARR_FIRST
        }

        /** Consume the closer at [i] and finish the innermost container. */
        fun close(): State {
            i++
            stack.removeAt(stack.size - 1)
            complete(Value.Other)
            return State.AFTER
        }

        fun key(): State {
            if (peek() != '"') syntax("object key is not a string")
            val key = string()
            if (!stack.last().keys.add(key)) refuse("duplicate key \"$key\"")
            skipWs()
            if (next() != ':') syntax("expected ':' after an object key")
            if (stack.size == 1) pendingKey = key
            return State.VALUE
        }

        fun after(): State {
            if (stack.isEmpty()) {
                if (i != b.size) syntax("trailing data after the object")
                return State.DONE
            }
            val isObject = stack.last().isObject
            return when (peek()) {
                ',' -> {
                    i++
                    if (isObject) State.OBJ_KEY else State.VALUE
                }

                if (isObject) '}' else ']' -> close()

                else -> syntax("unexpected '${peek()}'")
            }
        }

        /** Record [v] if it is the value of a top-level member. */
        fun complete(v: Value) {
            if (stack.size == 1) {
                pendingKey?.let { members[it] = v }
                pendingKey = null
            }
        }

        fun scalar(): Value = when (peek()) {
            '"' -> Value.Str(string())
            't' -> literal("true", Value.True)
            'f' -> literal("false", Value.False)
            'n' -> literal("null", Value.Other)
            else -> number()
        }

        fun literal(word: String, v: Value): Value {
            for (ch in word) if (i < b.size && byteAt(i).toChar() == ch) i++ else syntax("invalid literal")
            return v
        }

        /**
         * A number: the maximal run of number characters must match the grammar (a
         * valid number is never followed by another number character), and must not
         * overflow a float64.
         */
        fun number(): Value {
            val start = i
            while (i < b.size && byteAt(i).toChar() in NUMBER_CHARS) i++
            val text = b.copyOfRange(start, i).decodeToString()
            if (!NUMBER.matches(text)) syntax("invalid number")
            if (text.toDouble().isInfinite()) refuse("number $text overflows a float64")
            return Value.Other
        }

        /** The `\uXXXX` code unit at [at] (pointing at the backslash), or -1. */
        fun u4(at: Int): Int {
            val ok = at + 2 + HEX_DIGITS <= b.size && byteAt(at) == '\\'.code && byteAt(at + 1) == 'u'.code
            var v = if (ok) 0 else -1
            for (k in 0 until HEX_DIGITS) {
                if (v < 0) break
                val d = byteAt(at + 2 + k).toChar().digitToIntOrNull(HEX_RADIX)
                v = if (d == null) -1 else v * HEX_RADIX + d
            }
            return v
        }

        fun string(): String {
            i++ // the opening quote
            val sb = StringBuilder()
            while (true) {
                if (i >= b.size) syntax("unterminated string")
                val c = byteAt(i)
                when {
                    c == '"'.code -> {
                        i++
                        return sb.toString()
                    }

                    c == '\\'.code -> escape(sb)

                    c <= CONTROL_MAX -> syntax("control character in string")

                    c <= ASCII_MAX -> {
                        sb.append(c.toChar())
                        i++
                    }

                    else -> {
                        // Go: an invalid UTF-8 byte decodes to U+FFFD, one byte at a time.
                        val n = runeLen(b, i)
                        sb.appendCodePoint(if (n < 0) REPLACEMENT else decodeRune(b, i, n))
                        i += maxOf(n, 1)
                    }
                }
            }
        }

        /** The character a one-letter escape `\\[e]` stands for, or null if [e] is not one. */
        fun simpleEscape(e: Char): Char? = when (e) {
            '"', '\\', '/' -> e
            'b' -> '\b'
            'f' -> '\u000C'
            'n' -> '\n'
            'r' -> '\r'
            't' -> '\t'
            else -> null
        }

        /** The escape at [i] (pointing at the backslash). */
        fun escape(sb: StringBuilder) {
            if (i + 1 >= b.size) syntax("unterminated escape")
            val e = byteAt(i + 1).toChar()
            val simple = if (e == 'u') null else simpleEscape(e) ?: syntax("invalid escape '\\$e'")
            if (simple != null) {
                sb.append(simple)
                i += 2
                return
            }
            val r = u4(i)
            if (r < 0) syntax("invalid \\u escape")
            i += 2 + HEX_DIGITS
            if (r !in SURR_HI_MIN..SURR_LO_MAX) {
                sb.appendCodePoint(r)
                return
            }
            // Go unquote: pair a high surrogate with a following low one; anything
            // else is U+FFFD (and a following escape is read on its own).
            val r2 = u4(i)
            if (r <= SURR_HI_MAX && r2 in SURR_LO_MIN..SURR_LO_MAX) {
                i += 2 + HEX_DIGITS
                sb.appendCodePoint(SURR_BASE + ((r - SURR_HI_MIN) shl SURR_SHIFT) + (r2 - SURR_LO_MIN))
            } else {
                sb.appendCodePoint(REPLACEMENT)
            }
        }
    }
}
