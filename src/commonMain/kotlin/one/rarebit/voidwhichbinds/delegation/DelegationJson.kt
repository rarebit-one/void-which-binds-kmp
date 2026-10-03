package one.rarebit.voidwhichbinds.delegation

import one.rarebit.voidwhichbinds.crypto.GoJson

/**
 * The JSON a delegation token needs, with Go `encoding/json` semantics: [obj] renders a
 * struct as `json.Marshal` does (compact, fields in the given order, strings
 * HTML-escaped by [GoJson.appendString], a nil slice as `null`), [parse] reads with Go's
 * scanner, and [checkTyp] is void-which-binds-go `sigtoken.CheckTyp`.
 */
internal object DelegationJson {

    /** Values are `String`, `Long`, or a `List<String>` (null renders `null`, as a nil Go slice). */
    fun obj(vararg fields: Pair<String, Any?>): ByteArray {
        val sb = StringBuilder()
        sb.append('{')
        for ((i, f) in fields.withIndex()) {
            if (i > 0) sb.append(',')
            GoJson.appendString(sb, f.first)
            sb.append(':')
            appendValue(sb, f.second)
        }
        sb.append('}')
        return sb.toString().encodeToByteArray()
    }

    private fun appendValue(sb: StringBuilder, v: Any?) {
        when (v) {
            null -> sb.append("null")

            is String -> GoJson.appendString(sb, v)

            is Long -> sb.append(v)

            is List<*> -> {
                sb.append('[')
                v.forEachIndexed { j, e ->
                    if (j > 0) sb.append(',')
                    GoJson.appendString(sb, e as String)
                }
                sb.append(']')
            }

            else -> error("unsupported JSON value ${v::class}")
        }
    }

    /** A member whose JSON type is not the struct field's (Go's `UnmarshalTypeError`). */
    class WrongType : Exception()

    /** A string field: absent is `""`; any non-string value (`null` included) is [WrongType]. */
    fun string(m: Map<String, GoJson.Node>, k: String): String = when (val n = m[k]) {
        null -> ""
        is GoJson.Str -> n.value
        else -> throw WrongType()
    }

    /** An integer field: absent is 0; anything but an integer literal that fits a Long is [WrongType]. */
    fun long(m: Map<String, GoJson.Node>, k: String): Long = when (val n = m[k]) {
        null -> 0L
        is GoJson.Num -> n.text.toLongOrNull() ?: throw WrongType()
        else -> throw WrongType()
    }

    /** A string-slice field: absent or `null` is a nil slice (null); an element that is not a string is [WrongType]. */
    fun strings(m: Map<String, GoJson.Node>, k: String): List<String>? = when (val n = m[k]) {
        null, GoJson.Null -> null
        is GoJson.Arr -> n.items.map { (it as? GoJson.Str)?.value ?: throw WrongType() }
        else -> throw WrongType()
    }

    /** One JSON document as Go's scanner reads it, or null for a syntax error. */
    fun parse(body: ByteArray): GoJson.Node? = GoJson.parse(body.decodeToString())

    /**
     * Go `sigtoken.CheckTyp` over a parsed body: null when `typ` is [want], or when the
     * body is not a JSON object at all (not a type question; the caller's own parse
     * refuses it); [Delegation.Failure.MALFORMED] for a `typ` that is not a string or a
     * case-variant key; else [Delegation.Failure.WRONG_TYPE], absent included. As Go
     * decodes into a map, the last of duplicate members wins.
     */
    @Suppress("ReturnCount")
    fun checkTyp(node: GoJson.Node?, want: String): Delegation.Failure? {
        val members = (node as? GoJson.Obj)?.members?.toMap() ?: return null
        var typ: String? = null
        for ((k, v) in members) {
            if (k == "typ") {
                typ = (v as? GoJson.Str)?.value ?: return Delegation.Failure.MALFORMED
            } else if (k.equals("typ", ignoreCase = true)) {
                return Delegation.Failure.MALFORMED
            }
        }
        return if (typ == want) null else Delegation.Failure.WRONG_TYPE
    }
}
