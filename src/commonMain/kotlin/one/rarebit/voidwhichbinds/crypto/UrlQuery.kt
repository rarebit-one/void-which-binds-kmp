package one.rarebit.voidwhichbinds.crypto

/**
 * A tiny reproduction of Go's `net/url` query encoding, so a KMP-rendered
 * `void-which-binds:` QR is byte-identical to a void-which-binds-go-rendered one. [encode] matches
 * `url.Values.Encode()` (keys sorted, values query-escaped); [escape]/[unescape]
 * match `url.QueryEscape`/`QueryUnescape` (query-component mode: unreserved
 * `A-Za-z0-9-_.~` kept, space as `+`, everything else uppercase `%XX` over UTF-8).
 *
 * This is the same contract [one.rarebit.voidwhichbinds.Invite] encodes inline for the
 * pairing invite; it lives here so the login QR shares one vetted implementation.
 */
internal object UrlQuery {

    /** Encode key/value pairs as Go's `url.Values.Encode()` does: keys sorted, `k=v&…`. */
    fun encode(params: List<Pair<String, String>>): String = params.sortedBy { it.first }
        .joinToString("&") { (k, v) -> "${escape(k)}=${escape(v)}" }

    /** Parse a `k=v&k=v` query into a map, tolerant of key order and `+`/`%XX`. */
    fun decode(query: String): Map<String, String> {
        val fields = HashMap<String, String>()
        if (query.isEmpty()) return fields
        for (pair in query.split("&")) {
            if (pair.isEmpty()) continue
            val eq = pair.indexOf('=')
            if (eq < 0) {
                fields[unescape(pair)] = ""
            } else {
                fields[unescape(pair.substring(0, eq))] = unescape(pair.substring(eq + 1))
            }
        }
        return fields
    }

    /** Reproduce Go's `url.QueryEscape` (query-component mode). */
    fun escape(s: String): String {
        val bytes = s.encodeToByteArray()
        val out = StringBuilder(bytes.size)
        for (b in bytes) {
            val c = b.toInt() and 0xFF
            when {
                c.toChar() in 'A'..'Z' || c.toChar() in 'a'..'z' || c.toChar() in '0'..'9' ||
                    c.toChar() == '-' || c.toChar() == '_' || c.toChar() == '.' || c.toChar() == '~' ->
                    out.append(c.toChar())

                c == ' '.code -> out.append('+')

                else -> {
                    out.append('%')
                    out.append(HEX[c ushr 4])
                    out.append(HEX[c and 0x0F])
                }
            }
        }
        return out.toString()
    }

    /** Reverse [escape]: `+` → space, `%XX` → byte, decoded as UTF-8. */
    fun unescape(s: String): String {
        val out = ArrayList<Byte>(s.length)
        var i = 0
        while (i < s.length) {
            when (val c = s[i]) {
                '+' -> {
                    out.add(' '.code.toByte())
                    i++
                }

                '%' -> {
                    require(i + 2 < s.length) { "truncated percent-escape" }
                    val hi = hexVal(s[i + 1])
                    val lo = hexVal(s[i + 2])
                    out.add(((hi shl 4) or lo).toByte())
                    i += 3
                }

                else -> {
                    out.add(c.code.toByte())
                    i++
                }
            }
        }
        return out.toByteArray().decodeToString()
    }

    private val HEX = "0123456789ABCDEF".toCharArray()

    private fun hexVal(c: Char): Int = when (c) {
        in '0'..'9' -> c - '0'
        in 'a'..'f' -> c - 'a' + 10
        in 'A'..'F' -> c - 'A' + 10
        else -> throw IllegalArgumentException("invalid percent-escape digit '$c'")
    }
}
