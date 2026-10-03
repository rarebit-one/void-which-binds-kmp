package one.rarebit.voidwhichbinds.crypto

/**
 * Tiny, dependency-free JSON codec for the wire-shaped payloads this library
 * signs and reads (the cert / membership-op payload, the relay envelopes, the
 * weblogin bodies, the golden-vector files). Deliberately not a general JSON
 * library — it carries exactly the value kinds those shapes need.
 *
 * The encoder emits **compact** JSON (no insignificant whitespace) with fields
 * in insertion order, matching Go's `encoding/json` `Marshal` of a struct
 * (which emits fields in declaration order). Because the enrolment cert and the
 * membership op sign the exact payload bytes, this byte layout is part of the
 * wire contract: fields must be listed in the same order void-which-binds-go declares
 * them (`v, usr, dev, denc, iat, exp` for a cert; `v, usr, op, dev, denc, by,
 * prev, cosig, iat, exp` for an op).
 */
object MiniJson {

    /**
     * Encode an ordered list of (key, value) pairs. Values are `String`, `Int`,
     * `Long`, `Boolean`, a `List` of those (or of nested objects), or a nested
     * object given as another ordered `List<Pair<String, Any>>`.
     */
    fun encodeObject(fields: List<Pair<String, Any>>): String {
        val sb = StringBuilder()
        encodeObjectInto(sb, fields)
        return sb.toString()
    }

    private fun encodeObjectInto(sb: StringBuilder, fields: List<Pair<String, Any>>) {
        sb.append('{')
        for ((i, field) in fields.withIndex()) {
            if (i > 0) sb.append(',')
            encodeString(sb, field.first)
            sb.append(':')
            encodeValue(sb, field.second)
        }
        sb.append('}')
    }

    @Suppress("UNCHECKED_CAST")
    private fun encodeValue(sb: StringBuilder, v: Any) {
        when (v) {
            is String -> encodeString(sb, v)

            is Int -> sb.append(v.toString())

            is Long -> sb.append(v.toString())

            is Boolean -> sb.append(if (v) "true" else "false")

            is List<*> -> {
                // A list of pairs is a nested OBJECT (ordered fields); anything else is an array.
                if (v.isNotEmpty() && v.all { it is Pair<*, *> && (it as Pair<*, *>).first is String }) {
                    encodeObjectInto(sb, v as List<Pair<String, Any>>)
                } else {
                    sb.append('[')
                    for ((i, e) in v.withIndex()) {
                        if (i > 0) sb.append(',')
                        encodeValue(sb, e ?: throw IllegalArgumentException("null JSON array element"))
                    }
                    sb.append(']')
                }
            }

            else -> throw IllegalArgumentException("unsupported JSON value type: ${v::class}")
        }
    }

    private fun encodeString(sb: StringBuilder, s: String) {
        sb.append('"')
        for (c in s) {
            when (c) {
                '"' -> sb.append("\\\"")

                '\\' -> sb.append("\\\\")

                '\n' -> sb.append("\\n")

                '\r' -> sb.append("\\r")

                '\t' -> sb.append("\\t")

                else -> if (c.code < 0x20) {
                    sb.append("\\u")
                    val hex = c.code.toString(16)
                    repeat(4 - hex.length) { sb.append('0') }
                    sb.append(hex)
                } else {
                    sb.append(c)
                }
            }
        }
        sb.append('"')
    }

    /**
     * A parsed object. Values are [String], [Long], [Boolean], `null`-free — a JSON
     * `null` is represented by [Null] — a `List<Any>` for an array (so weblogin v2's
     * integer `candidates` reads as a list of [Long]), or a nested
     * `Map<String, Any>` for an object.
     */
    fun parseObject(json: String): Map<String, Any> {
        val p = Parser(json)
        p.skipWs()
        val out = p.parseObject()
        p.skipWs()
        require(p.atEnd()) { "trailing content after JSON object" }
        return out
    }

    /** The JSON `null` marker inside a parsed structure. */
    object Null

    private class Parser(val s: String) {
        var i = 0

        fun atEnd(): Boolean = i >= s.length
        fun peek(): Char = if (i < s.length) s[i] else throw IllegalArgumentException("unexpected end of JSON")
        fun next(): Char = peek().also { i++ }
        fun expect(c: Char) {
            val n = next()
            require(n == c) { "expected '$c', got '$n'" }
        }

        fun skipWs() {
            while (i < s.length && (s[i] == ' ' || s[i] == '\t' || s[i] == '\n' || s[i] == '\r')) i++
        }

        /** An open array or object, and for an object the member key awaiting its value. */
        private class Frame(val obj: LinkedHashMap<String, Any>?, val arr: ArrayList<Any>?) {
            var key: String = ""
            val value: Any get() = obj ?: arr!!
        }

        private val stack = ArrayList<Frame>()

        /** A top-level object (the only top-level value this codec reads). */
        @Suppress("UNCHECKED_CAST")
        fun parseObject(): Map<String, Any> {
            if (peek() != '{') expect('{')
            return parseValue() as Map<String, Any>
        }

        /**
         * One JSON value. Iterative, with Go's nesting limit ([GoJson.MAX_DEPTH] arrays
         * and objects, `encoding/json`'s `maxNestingDepth`): a deeper document is refused
         * with [IllegalArgumentException], never a stack overflow (which Kotlin/Native
         * cannot catch).
         */
        @Suppress("CyclomaticComplexMethod", "LoopWithTooManyJumpStatements", "NestedBlockDepth")
        fun parseValue(): Any {
            value@ while (true) {
                // Read one value; a container is opened and its first member read next.
                var v: Any? = when (val c = peek()) {
                    '{' -> {
                        next()
                        push(Frame(LinkedHashMap(), null))
                        skipWs()
                        if (peek() == '}') {
                            next()
                            pop()
                        } else {
                            readKey()
                            null
                        }
                    }

                    '[' -> {
                        next()
                        push(Frame(null, ArrayList()))
                        skipWs()
                        if (peek() == ']') {
                            next()
                            pop()
                        } else {
                            null
                        }
                    }

                    else -> scalar(c)
                }
                // Attach the finished value, closing every container it completes.
                while (v != null) {
                    if (stack.isEmpty()) return v
                    val top = stack.last()
                    if (top.obj != null) top.obj[top.key] = v else top.arr!!.add(v)
                    skipWs()
                    val c = next()
                    v = when {
                        c == ',' -> {
                            skipWs()
                            if (top.obj != null) readKey()
                            continue@value
                        }

                        top.obj != null && c == '}' -> pop()

                        top.arr != null && c == ']' -> pop()

                        top.obj != null -> throw IllegalArgumentException("expected ',' or '}', got '$c'")

                        else -> throw IllegalArgumentException("expected ',' or ']', got '$c'")
                    }
                }
            }
        }

        private fun push(f: Frame) {
            stack.add(f)
            require(stack.size <= GoJson.MAX_DEPTH) { "JSON nested too deeply" }
        }

        private fun pop(): Any = stack.removeAt(stack.size - 1).value

        /** Read `"key"` `:` for the open object, leaving the parser at its value. */
        private fun readKey() {
            skipWs()
            stack.last().key = parseString()
            skipWs()
            expect(':')
            skipWs()
        }

        private fun scalar(c: Char): Any = when (c) {
            '"' -> parseString()

            't' -> {
                literal("true")
                true
            }

            'f' -> {
                literal("false")
                false
            }

            'n' -> {
                literal("null")
                Null
            }

            else -> if (c == '-' || c in '0'..'9') {
                parseNumber()
            } else {
                throw IllegalArgumentException("unsupported JSON value starting with '$c'")
            }
        }

        private fun literal(word: String) {
            require(s.startsWith(word, i)) { "invalid JSON literal at $i" }
            i += word.length
        }

        fun parseString(): String {
            expect('"')
            val sb = StringBuilder()
            while (true) {
                when (val c = next()) {
                    '"' -> return sb.toString()

                    '\\' -> when (val e = next()) {
                        '"' -> sb.append('"')

                        '\\' -> sb.append('\\')

                        '/' -> sb.append('/')

                        'n' -> sb.append('\n')

                        'r' -> sb.append('\r')

                        't' -> sb.append('\t')

                        'b' -> sb.append('\b')

                        'f' -> sb.append('\u000C')

                        'u' -> {
                            require(i + 4 <= s.length) { "truncated \\u escape" }
                            val hex = s.substring(i, i + 4)
                            i += 4
                            sb.append(hex.toInt(16).toChar())
                        }

                        else -> throw IllegalArgumentException("bad escape '\\$e'")
                    }

                    else -> sb.append(c)
                }
            }
        }

        fun parseNumber(): Long {
            val start = i
            if (peek() == '-') i++
            while (i < s.length && s[i] in '0'..'9') i++
            // This codec only carries integer fields; reject fractions/exponents.
            require(i > start && !(i - start == 1 && s[start] == '-')) { "invalid number" }
            if (i < s.length && (s[i] == '.' || s[i] == 'e' || s[i] == 'E')) {
                throw IllegalArgumentException("non-integer JSON number")
            }
            return s.substring(start, i).toLong()
        }
    }
}
