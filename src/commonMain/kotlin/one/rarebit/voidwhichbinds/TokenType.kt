package one.rarebit.voidwhichbinds

/**
 * The token-type claim of void-which-binds-go ADR-0009: every signed token names its kind in
 * a `typ` member, placed **second** in the body, right after `v`. It is a byte-exact
 * port of void-which-binds-go `internal/sigtoken.Typ` / `CheckTyp`.
 *
 * Verifiers check `typ` when a token carries it and still accept an untyped token
 * under the legacy rules; that is phase 1, and it stays true until phase 3. Since phase
 * 2 ("emit") every minter emits it: [MembershipOp.sign] (`voidbind.op`),
 * [one.rarebit.voidwhichbinds.auth.PossessionProof.mint] (`voidbind.possession`), and a
 * new [Cert] (`voidbind.cert`, its default [Cert.typ]). The typed mint paths take
 * `""` only for legacy fixtures.
 *
 * Values are dotted, not slashed, so no JSON encoder ever escapes them, and they
 * are compared byte-for-byte.
 */
object TokenType {
    const val GRANT = "voidbind.grant"
    const val CERT = "voidbind.cert"
    const val POSSESSION = "voidbind.possession"
    const val OP = "voidbind.op"

    /** The pairing refusal (void-which-binds-go ADR-0012), typed from its first version; see [PairRefusal]. */
    const val PAIR_REFUSAL = PairRefusal.TYP

    /** Why a `typ` claim was refused. */
    enum class Failure {
        /** A present `typ` that names a kind this verifier does not accept. */
        WRONG_TYPE,

        /** A `typ` that is not a JSON string (`null` included), or a case-variant key such as `"Typ"`. */
        MALFORMED,
    }

    /** Thrown by [check]. */
    class TypeException(val failure: Failure, message: String) : IllegalArgumentException(message)

    /**
     * Apply the phase-1 rule to a parsed body [obj] for a verifier that accepts the
     * kinds in [allowed]. Returns the present `typ`, or `""` for an untyped (legacy)
     * body. Throws [TypeException] for a present `typ` outside [allowed]
     * ([Failure.WRONG_TYPE]) or a malformed one ([Failure.MALFORMED]).
     *
     * It reads an unauthenticated claim, but it can only REFUSE, so every verifier
     * runs it straight after splitting the token, before the signature, as Go does.
     */
    fun check(obj: Map<String, Any>, vararg allowed: String): String {
        val caseVariant = obj.keys.any { it != "typ" && it.equals("typ", ignoreCase = true) }
        val raw = obj["typ"]
        if (caseVariant || (raw != null && raw !is String)) {
            throw TypeException(Failure.MALFORMED, "typ is not a string, or its key is a case variant")
        }
        val typ: String = raw ?: return ""
        if (typ !in allowed) {
            throw TypeException(Failure.WRONG_TYPE, "token type \"$typ\" is not ${allowed.joinToString(" or ")}")
        }
        return typ
    }

    /**
     * Whether a typed body's `v` is one its kind has (void-which-binds-go `typedVersionOK`).
     * A typed cert is v1 or v2 and a typed op is v3. An untyped body is left to the
     * legacy rules.
     */
    fun versionOk(typ: String, v: Int): Boolean = when (typ) {
        CERT -> v in 1..Labels.CERT_VERSION
        OP -> v == MembershipOp.VERSION
        else -> true
    }
}
