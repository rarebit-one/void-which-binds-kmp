package one.rarebit.voidwhichbinds.scope

/** A scope or scope list outside the grammar. Every scope refusal is ADR-0017's `malformed`. */
class ScopeException(message: String) : IllegalArgumentException(message)

/**
 * The scope vocabulary shared by delegation (void-which-binds-go ADR-0017) and action
 * approval (ADR-0019): the grammar of one scope and the canonical form of a scope
 * list. A port of the minter- and verifier-side half of void-which-binds-go `scope`
 * (`Validate`, `Canonical`, `CanonicalList`, `ValidateList`, `Contains`); the broker's
 * intersection rule (`Allowed`, `Intersect`, `Subset`) is server-side and not ported.
 *
 * A scope is `<ns>:<path>`:
 *
 *     ns    [a-z][a-z0-9-]{0,31}         1–32 bytes
 *     path  [a-z0-9][a-z0-9._/-]{0,127}  1–128 bytes
 *
 * compared byte for byte, with no wildcards and no implication. Nothing is normalised:
 * a string outside the grammar is refused, never folded into one inside it. A scope
 * LIST is canonical when it is sorted by byte order, de-duplicated and holds
 * 1–[MAX_SCOPES] entries. `vectors/scope/` is replayed by `ScopeVectorTest`.
 */
object Scope {
    /** The longest namespace, in bytes. */
    const val MAX_NAMESPACE_LEN = 32

    /** The longest path, in bytes. */
    const val MAX_PATH_LEN = 128

    /** The longest scope: namespace, colon and path. */
    const val MAX_LEN = MAX_NAMESPACE_LEN + 1 + MAX_PATH_LEN

    /** The most entries a scope list may hold (ADR-0017, the `scp` rule). */
    const val MAX_SCOPES = 32

    /** Refuses [s] unless it is one well-formed scope, naming the first rule it breaks. Go `scope.Validate`. */
    fun validate(s: String) {
        val len = s.encodeToByteArray().size
        val colon = s.indexOf(':')
        val why = when {
            len > MAX_LEN -> "$len bytes, longer than $MAX_LEN"
            colon < 0 -> "\"$s\" has no ':' between namespace and path"
            else -> (checkNamespace(s.substring(0, colon)) ?: checkPath(s.substring(colon + 1)))?.let { "\"$s\": $it" }
        }
        if (why != null) throw ScopeException("scope: malformed: $why")
    }

    /** Whether [s] is one well-formed scope. */
    fun isValid(s: String): Boolean = runCatching { validate(s) }.isSuccess

    /**
     * The minter's rule for a scope list (ADR-0017, `scp`): every entry must be a valid
     * scope, and the result is sorted by byte order, de-duplicated, and holds
     * 1–[MAX_SCOPES] entries. Go `scope.CanonicalList`.
     */
    fun canonicalList(scopes: List<String>): List<String> {
        val out = LinkedHashSet<String>()
        for (s in scopes) {
            validate(s)
            out += s
        }
        if (out.isEmpty() || out.size > MAX_SCOPES) {
            throw ScopeException("scope: malformed: a scope list holds 1 to $MAX_SCOPES scopes: ${out.size} distinct")
        }
        // Valid scopes are ASCII, so String order is byte order.
        return out.sorted()
    }

    /**
     * The verifier's rule for a scope list: 1–[MAX_SCOPES] entries, each a valid scope,
     * in strictly ascending byte order. It refuses rather than repairs. Go
     * `scope.ValidateList`.
     */
    fun validateList(scopes: List<String>) {
        if (scopes.isEmpty() || scopes.size > MAX_SCOPES) {
            throw ScopeException("scope: malformed: a scope list holds 1 to $MAX_SCOPES scopes: ${scopes.size}")
        }
        for ((i, s) in scopes.withIndex()) {
            validate(s)
            if (i > 0 && scopes[i - 1] >= s) {
                throw ScopeException(
                    "scope: malformed: a scope list is not sorted and de-duplicated: \"$s\" after \"${scopes[i - 1]}\"",
                )
            }
        }
    }

    private fun isLower(c: Char) = c in 'a'..'z'

    private fun isDigit(c: Char) = c in '0'..'9'

    private fun checkNamespace(ns: String): String? = when {
        ns.isEmpty() -> "empty namespace"
        ns.length > MAX_NAMESPACE_LEN -> "namespace is longer than $MAX_NAMESPACE_LEN bytes"
        !isLower(ns[0]) -> "namespace does not start with a-z"
        ns.drop(1).any { !isLower(it) && !isDigit(it) && it != '-' } -> "namespace is not a-z, 0-9 or '-'"
        else -> null
    }

    private fun checkPath(path: String): String? = when {
        path.isEmpty() -> "empty path"

        path.length > MAX_PATH_LEN -> "path is longer than $MAX_PATH_LEN bytes"

        !isLower(path[0]) && !isDigit(path[0]) -> "path does not start with a-z or 0-9"

        path.drop(1).any {
            !isLower(it) && !isDigit(it) && it !in "._/-"
        } -> "path is not a-z, 0-9, '.', '_', '/' or '-'"

        else -> null
    }
}
