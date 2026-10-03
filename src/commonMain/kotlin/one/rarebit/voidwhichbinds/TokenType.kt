package one.rarebit.voidwhichbinds

/**
 * The token-type claim of void-which-binds-go ADR-0009: every signed token names its kind in
 * a `typ` member, placed **second** in the body, right after `v`. It is a byte-exact
 * port of void-which-binds-go `internal/sigtoken.Typ` / `CheckTyp`.
 *
 * Gen2 is **typed-only** (void-which-binds-go ADR-0022): every minter emits `typ`
 * ([MembershipOp.sign] `void-which-binds.op`,
 * [one.rarebit.voidwhichbinds.auth.PossessionProof.mint] `void-which-binds.possession`,
 * [Cert] `void-which-binds.cert`), and every verifier refuses a body without one, or
 * with a gen1 `voidbind.*` value, as [Failure.WRONG_TYPE]. There is no generation to
 * dispatch on: a gen1 `typ` is simply foreign. `void-which-binds.roster`
 * ([one.rarebit.voidwhichbinds.roster.Roster]) and `void-which-binds.delegation` /
 * `void-which-binds.delegation-pop` ([one.rarebit.voidwhichbinds.delegation.Delegation])
 * are checked by their own packages, not here.
 *
 * Values are dotted, not slashed, so no JSON encoder ever escapes them, and they
 * are compared byte-for-byte.
 */
object TokenType {
    const val GRANT = "void-which-binds.grant"
    const val CERT = "void-which-binds.cert"
    const val POSSESSION = "void-which-binds.possession"
    const val OP = "void-which-binds.op"

    /** The pairing refusal (void-which-binds-go ADR-0012), typed from its first version; see [PairRefusal]. */
    const val PAIR_REFUSAL = PairRefusal.TYP

    /** Why a `typ` claim was refused. */
    enum class Failure {
        /** An absent `typ`, or one that names a kind this verifier does not accept. */
        WRONG_TYPE,

        /** A `typ` that is not a JSON string (`null` included), or a case-variant key such as `"Typ"`. */
        MALFORMED,
    }

    /** Thrown by [check]. */
    class TypeException(val failure: Failure, message: String) : IllegalArgumentException(message)

    /**
     * Apply the typed-only rule (ADR-0009, ADR-0022) to a parsed body [obj] for a
     * verifier that accepts the kinds in [allowed]. Returns the `typ`. Throws
     * [TypeException] for an absent `typ` or one outside [allowed]
     * ([Failure.WRONG_TYPE]), or a malformed one ([Failure.MALFORMED]). Mirrors
     * void-which-binds-go `sigtoken.CheckTyp`.
     *
     * It reads an unauthenticated claim, but it can only REFUSE, so every verifier
     * runs it straight after splitting the token, before the signature, as Go does.
     */
    fun check(obj: Map<String, Any>, vararg allowed: String): String {
        val caseVariant = obj.keys.any { it != "typ" && it.equals("typ", ignoreCase = true) }
        val raw = obj["typ"]
        val refusal = when {
            caseVariant || (raw != null && raw !is String) ->
                TypeException(Failure.MALFORMED, "typ is not a string, or its key is a case variant")

            raw == null -> TypeException(Failure.WRONG_TYPE, "token type is absent (gen2 is typed-only)")

            raw !in allowed ->
                TypeException(Failure.WRONG_TYPE, "token type \"$raw\" is not ${allowed.joinToString(" or ")}")

            else -> null
        }
        if (refusal != null) throw refusal
        return raw as String
    }

    /**
     * Whether a body's `v` is one its kind has (void-which-binds-go `typedVersionOK`):
     * a cert is v1 or v2 and an op is v3. [check] has already refused every other `typ`.
     */
    fun versionOk(typ: String, v: Int): Boolean = when (typ) {
        CERT -> v in 1..Labels.CERT_VERSION
        OP -> v == MembershipOp.VERSION
        else -> false
    }
}
