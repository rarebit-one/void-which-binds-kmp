package one.rarebit.voidwhichbinds.crypto

/**
 * Go's `json.Unmarshal` into a struct, over a [GoJson] tree: the decode a void-which-binds-go
 * verifier runs on a signed token body (`enrolment.VerifyOp`, `VerifyCert`,
 * `VerifyPossession`, …). It reproduces what decides a verdict:
 *
 * - [parse] is `json.Unmarshal`'s syntax check: anything Go's scanner refuses is null,
 *   and anything it accepts parses, a fraction or exponent in an unknown member included.
 * - [members] matches a member to a field by its exact name, else by Go's case-folded
 *   name ([GoJson.foldsTo]: `"USR"` and `"uſr"` set `usr`, `"ıat"` sets nothing). Members
 *   are applied in document order, so of duplicates the last wins. Unknown members are
 *   ignored whatever they hold.
 * - [str] and [long] decode a scalar field: `null` leaves the field as it was, and a value
 *   of another JSON type, or a number that is not an int64 literal (`1.0`, `1e3`, one
 *   past int64), is a [TypeError], which fails the whole decode as Go's
 *   `UnmarshalTypeError` does.
 * - [Slice] is a slice field, including how Go reuses a slice's elements when a member
 *   repeats.
 */
internal object GoStruct {

    /** A value of the wrong JSON type for its field (Go's `UnmarshalTypeError`): the decode fails. */
    class TypeError : Exception()

    /** [body] as `json.Unmarshal` scans it (invalid UTF-8 in a string read as U+FFFD), or null for a syntax error. */
    fun parse(body: ByteArray): GoJson.Node? = GoJson.parse(GoJson.decodeUtf8(body))

    /**
     * Decode [node] into a struct with the ASCII field names [fields]: `null` is a no-op,
     * an object's members go to the field named exactly, else to the one it folds to, else
     * nowhere; any other value is [TypeError].
     */
    fun members(node: GoJson.Node, fields: List<String>, set: (String, GoJson.Node) -> Unit) {
        when (node) {
            GoJson.Null -> Unit

            is GoJson.Obj -> for ((k, v) in node.members) {
                val f = fields.firstOrNull { it == k } ?: fields.firstOrNull { GoJson.foldsTo(k, it) }
                if (f != null) set(f, v)
            }

            else -> throw TypeError()
        }
    }

    /** A string field: `null` keeps [cur]. */
    fun str(node: GoJson.Node, cur: String): String = when (node) {
        is GoJson.Str -> node.value
        GoJson.Null -> cur
        else -> throw TypeError()
    }

    /** An `int`/`int64` field (Go's `strconv.ParseInt` of the literal, 64-bit): `null` keeps [cur]. */
    fun long(node: GoJson.Node, cur: Long): Long = when (node) {
        is GoJson.Num -> node.text.toLongOrNull() ?: throw TypeError()
        GoJson.Null -> cur
        else -> throw TypeError()
    }

    /**
     * A Go slice field, decoded member by member as Go's `decodeState.array` does. `null`
     * makes it nil and `[]` makes it empty, each dropping what it held. Any other array is
     * decoded INTO the slice's existing backing elements: Go only resets the length, so an
     * element that is `null`, or an object that omits a field, keeps what an earlier
     * duplicate member wrote at that index (`"prev":["a","b"],"prev":[null]` is `["a"]`).
     * The backing array keeps every element ever written, as Go's does: Go's growth never
     * drops an element below the length it copies.
     */
    class Slice<T>(private val zero: () -> T) {
        private val backing = ArrayList<T>()
        private var len = 0
        private var nil = true

        /** Decode [node] into the slice, each element through [element] (the element's JSON, its current value). */
        fun decode(node: GoJson.Node, element: (GoJson.Node, T) -> T) {
            when (node) {
                GoJson.Null -> reset(nil = true)

                is GoJson.Arr -> if (node.items.isEmpty()) {
                    reset(nil = false)
                } else {
                    node.items.forEachIndexed { i, item ->
                        if (i == backing.size) backing.add(zero())
                        backing[i] = element(item, backing[i])
                    }
                    len = node.items.size
                    nil = false
                }

                else -> throw TypeError()
            }
        }

        private fun reset(nil: Boolean) {
            backing.clear()
            len = 0
            this.nil = nil
        }

        /** The slice: null when nil. */
        fun value(): List<T>? = if (nil) null else backing.subList(0, len).toList()
    }
}
