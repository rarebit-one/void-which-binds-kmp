@file:Suppress("MagicNumber", "ReturnCount", "CyclomaticComplexMethod", "LongMethod", "ComplexCondition")

package one.rarebit.voidwhichbinds.crypto

/**
 * A JSON reader and string encoder that behave as Go's `encoding/json` does, for the
 * payloads whose refusal ORDER depends on how Go reads non-canonical input (the roster
 * cosign transport's slots, `roster.ParseCore`). [MiniJson] is laxer than Go; this
 * reader is not:
 *
 * - [parse] accepts exactly what Go's scanner (`checkValid`) accepts: RFC 8259 syntax,
 *   whitespace limited to space, tab, CR and LF, and at most [MAX_DEPTH] nested arrays
 *   and objects. It is iterative, so no input exhausts the stack. Strings are unquoted
 *   as Go unquotes them (a lone or broken surrogate escape becomes U+FFFD).
 * - [foldsTo] is Go's case-insensitive struct-field match (`foldName`), which is how a
 *   case-variant member such as `"V"` still sets a struct's `v`.
 * - [appendString] is Go's `json.Marshal` string encoding (HTML-escaped: `<`, `>` and
 *   `&` as `<…`, U+2028/U+2029 escaped, `\b`/`\f` short forms).
 * - [compareUtf8] is Go's map-key order (byte order of the UTF-8 encoding).
 */
internal object GoJson {
    /** Go's `maxNestingDepth`: the scanner refuses a deeper document. */
    const val MAX_DEPTH = 10000

    /** A parsed JSON value. Members and items keep their document order (duplicates included). */
    sealed interface Node

    class Str(val value: String) : Node

    /** A number, kept as its literal text (Go decodes it per target type). */
    class Num(val text: String) : Node

    class Bool(val value: Boolean) : Node

    object Null : Node

    class Arr(val items: MutableList<Node> = ArrayList()) : Node

    class Obj(val members: MutableList<Pair<String, Node>> = ArrayList()) : Node

    /** Parse [s] as one JSON document, or null where Go's scanner reports a syntax error. */
    fun parse(s: String): Node? = try {
        Parser(s).run()
    } catch (_: Invalid) {
        null
    }

    /**
     * Whether a JSON member [key] sets the struct field named [field] (an ASCII name) in
     * Go: an exact match, or equal under Go's `foldName` (ASCII upper-casing, and the two
     * non-ASCII runes whose simple-fold orbit holds an ASCII letter: U+017F `ſ` → `S`,
     * U+212A KELVIN SIGN → `K`).
     */
    fun foldsTo(key: String, field: String): Boolean {
        if (key == field) return true
        if (key.length != field.length) return false
        for (i in key.indices) {
            if (fold(key[i]) != fold(field[i])) return false
        }
        return true
    }

    private fun fold(c: Char): Char = when (c) {
        in 'a'..'z' -> c - ('a' - 'A')
        'ſ' -> 'S'
        'K' -> 'K'
        else -> c
    }

    /** Append [s] as Go's `json.Marshal` renders a string. */
    fun appendString(sb: StringBuilder, s: String) {
        sb.append('"')
        var i = 0
        while (i < s.length) {
            val c = s[i]
            when {
                c == '"' || c == '\\' -> sb.append('\\').append(c)

                c == '\b' -> sb.append("\\b")

                c == '\u000C' -> sb.append("\\f")

                c == '\n' -> sb.append("\\n")

                c == '\r' -> sb.append("\\r")

                c == '\t' -> sb.append("\\t")

                c < ' ' || c == '<' || c == '>' || c == '&' -> {
                    sb.append("\\u00").append(HEX[c.code shr 4]).append(HEX[c.code and 0xF])
                }

                c == ' ' || c == ' ' -> sb.append("\\u202").append(HEX[c.code and 0xF])

                c.isHighSurrogate() && i + 1 < s.length && s[i + 1].isLowSurrogate() -> {
                    sb.append(c).append(s[i + 1])
                    i++
                }

                // A lone surrogate is invalid UTF-8 in Go's terms, which it renders as U+FFFD.
                c.isSurrogate() -> sb.append("\\ufffd")

                else -> sb.append(c)
            }
            i++
        }
        sb.append('"')
    }

    /** Go's string order: the byte order of the UTF-8 encodings. */
    fun compareUtf8(a: String, b: String): Int {
        val x = a.encodeToByteArray()
        val y = b.encodeToByteArray()
        for (i in 0 until minOf(x.size, y.size)) {
            val d = (x[i].toInt() and 0xFF) - (y[i].toInt() and 0xFF)
            if (d != 0) return d
        }
        return x.size - y.size
    }

    private const val HEX = "0123456789abcdef"

    private class Invalid : Exception()

    /** An open container while parsing: the container and, for an object, the member key awaiting its value. */
    private class Frame(val node: Node, var key: String? = null)

    @Suppress("TooManyFunctions")
    private class Parser(val s: String) {
        var i = 0
        val stack = ArrayList<Frame>()

        fun fail(): Nothing = throw Invalid()

        fun skipWs() {
            while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
        }

        fun peek(): Char = if (i < s.length) s[i] else fail()

        @Suppress("CyclomaticComplexMethod", "LoopWithTooManyJumpStatements", "NestedBlockDepth")
        fun run(): Node {
            var root: Node? = null
            skipWs()
            value@ while (true) {
                // Read one value; a container is pushed and its first member read next.
                var v: Node? = when (peek()) {
                    '{' -> {
                        i++
                        push(Obj())
                        skipWs()
                        if (peek() == '}') {
                            i++
                            stack.removeAt(stack.size - 1).node
                        } else {
                            readKey()
                            continue@value
                        }
                    }

                    '[' -> {
                        i++
                        push(Arr())
                        skipWs()
                        if (peek() == ']') {
                            i++
                            stack.removeAt(stack.size - 1).node
                        } else {
                            continue@value
                        }
                    }

                    '"' -> Str(readString())

                    't' -> literal("true", Bool(true))

                    'f' -> literal("false", Bool(false))

                    'n' -> literal("null", Null)

                    else -> Num(readNumber())
                }
                // Attach the finished value, closing every container it completes.
                while (v != null) {
                    if (stack.isEmpty()) {
                        root = v
                        break@value
                    }
                    val top = stack.last()
                    when (val n = top.node) {
                        is Arr -> n.items.add(v)
                        is Obj -> n.members.add(top.key!! to v)
                        else -> fail()
                    }
                    skipWs()
                    val c = peek()
                    i++
                    v = when {
                        c == ',' -> {
                            skipWs()
                            if (top.node is Obj) readKey()
                            continue@value
                        }

                        c == ']' && top.node is Arr -> stack.removeAt(stack.size - 1).node

                        c == '}' && top.node is Obj -> stack.removeAt(stack.size - 1).node

                        else -> fail()
                    }
                }
            }
            skipWs()
            if (i != s.length) fail()
            return root!!
        }

        fun push(n: Node) {
            stack.add(Frame(n))
            if (stack.size > MAX_DEPTH) fail()
        }

        /** Read `"key"` `:` for the open object, leaving the parser at its value. */
        fun readKey() {
            if (peek() != '"') fail()
            stack.last().key = readString()
            skipWs()
            if (peek() != ':') fail()
            i++
            skipWs()
        }

        fun literal(word: String, n: Node): Node {
            if (!s.startsWith(word, i)) fail()
            i += word.length
            return n
        }

        fun readNumber(): String {
            val start = i
            if (i < s.length && s[i] == '-') i++
            when {
                i < s.length && s[i] == '0' -> i++
                i < s.length && s[i] in '1'..'9' -> while (i < s.length && s[i] in '0'..'9') i++
                else -> fail()
            }
            if (i < s.length && s[i] == '.') {
                i++
                digits()
            }
            if (i < s.length && (s[i] == 'e' || s[i] == 'E')) {
                i++
                if (i < s.length && (s[i] == '+' || s[i] == '-')) i++
                digits()
            }
            return s.substring(start, i)
        }

        fun digits() {
            val start = i
            while (i < s.length && s[i] in '0'..'9') i++
            if (i == start) fail()
        }

        @Suppress("CyclomaticComplexMethod")
        fun readString(): String {
            i++ // the opening quote
            val sb = StringBuilder()
            while (true) {
                val c = peek()
                i++
                when {
                    c == '"' -> return sb.toString()

                    c < ' ' -> fail()

                    c != '\\' -> sb.append(c)

                    else -> when (peek().also { i++ }) {
                        '"' -> sb.append('"')
                        '\\' -> sb.append('\\')
                        '/' -> sb.append('/')
                        'b' -> sb.append('\b')
                        'f' -> sb.append('\u000C')
                        'n' -> sb.append('\n')
                        'r' -> sb.append('\r')
                        't' -> sb.append('\t')
                        'u' -> unicodeEscape(sb)
                        else -> fail()
                    }
                }
            }
        }

        /** After `\u`: Go's `unquote`, pairing a surrogate escape with the next or writing U+FFFD. */
        fun unicodeEscape(sb: StringBuilder) {
            val r = hex4(i) ?: fail()
            i += 4
            val c = r.toChar()
            if (!c.isSurrogate()) {
                sb.append(c)
                return
            }
            if (c.isHighSurrogate() && s.startsWith("\\u", i)) {
                val r2 = hex4(i + 2)
                if (r2 != null && r2.toChar().isLowSurrogate()) {
                    sb.append(c).append(r2.toChar())
                    i += 6
                    return
                }
            }
            sb.append('�')
        }

        fun hex4(at: Int): Int? {
            if (at + 4 > s.length) return null
            var r = 0
            for (k in at until at + 4) {
                val d = when (val h = s[k]) {
                    in '0'..'9' -> h - '0'
                    in 'a'..'f' -> h - 'a' + 10
                    in 'A'..'F' -> h - 'A' + 10
                    else -> return null
                }
                r = r * 16 + d
            }
            return r
        }
    }
}
