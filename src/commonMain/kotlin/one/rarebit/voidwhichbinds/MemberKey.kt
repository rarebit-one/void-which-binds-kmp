package one.rarebit.voidwhichbinds

import dev.whyoleg.cryptography.algorithms.ECDSA
import one.rarebit.voidwhichbinds.crypto.Es256
import one.rarebit.voidwhichbinds.crypto.GoStrings
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.P256

/**
 * Why a member key or a member-key signature was refused (void-which-binds-go
 * ADR-0018). Each entry is one of Go's sentinel errors (`ErrMalformedPublicKey`,
 * `ErrInvalidDomain`, `ErrAssertionMalformed`, `ErrWrongCeremony`, …); [word] is
 * ADR-0018's refusal word, exactly as Go's `identity.MemberKeyReason` names it.
 */
enum class MemberKeyFailure(val word: String) {
    /** Go `ErrMalformedPublicKey`: the key string does not parse. */
    MALFORMED_PUBLIC_KEY("malformed"),

    /** Go `ErrInvalidDomain`: a caller error (empty domain, or one containing NUL). */
    INVALID_DOMAIN("malformed"),

    /** Go `ErrAssertionMalformed`: envelope, clientDataJSON or authenticatorData breaks the strict rules. */
    ASSERTION_MALFORMED("malformed"),

    /** Go `ErrWrongCeremony`: clientDataJSON `type` is not `webauthn.get`. */
    WRONG_CEREMONY("wrong_ceremony"),

    /** Go `ErrChallengeMismatch`: the assertion is over another body or another domain. */
    CHALLENGE_MISMATCH("challenge_mismatch"),

    /** Go `ErrOriginNotAllowed`: origin outside the policy, `crossOrigin` true, or `topOrigin` present. */
    ORIGIN_NOT_ALLOWED("origin_not_allowed"),

    /** Go `ErrRPIDMismatch`: rpIdHash is not SHA-256 of an RP ID paired with the origin. */
    RP_ID_MISMATCH("rp_id_mismatch"),

    /** Go `ErrUserNotPresent`: UP clear. */
    USER_NOT_PRESENT("user_not_present"),

    /** Go `ErrUserNotVerified`: UV clear (always required: this key signs authority). */
    USER_NOT_VERIFIED("user_not_verified"),

    /** Go `ErrSyncedNotAllowed`: a backup-eligible (BE=1) passkey under a policy that does not allow synced ones. */
    SYNCED_NOT_ALLOWED("synced_not_allowed"),

    /** Go `ErrBadSignature`: forgery, wrong key, non-DER ECDSA, or the other scheme's signature segment. */
    BAD_SIGNATURE("bad_signature"),
}

/** A refused member key or member-key signature; [failure] says which rule refused it. */
class MemberKeyException(val failure: MemberKeyFailure, message: String) : Exception(message) {
    /** ADR-0018's refusal word. */
    val reason: String get() = failure.word
}

/**
 * A parsed member key of either ADR-0018 kind: the key a person's member signs
 * delegations (ADR-0017) and action approvals (ADR-0019) with. Port of
 * void-which-binds-go `identity.MemberKey`. It can only come from [parse], which has
 * already checked the key string.
 */
class MemberKey private constructor(
    /** The key's algorithm prefix. */
    val kind: Kind,
    private val text: String,
    private val ed25519: ByteArray?,
    private val es256: ECDSA.PublicKey?,
) {
    /** The member-key kinds [parse] accepts; any other prefix is refused (fail closed). */
    enum class Kind(val prefix: String) {
        /** `ed25519:<64 lowercase hex>` — the only kind that can sign ops, cosign, or prove possession. */
        ED25519("ed25519"),

        /** `webauthn:es256:<130 lowercase hex>` — an ES256 passkey, signing only through a WebAuthn assertion. */
        WEBAUTHN("webauthn"),
    }

    /** The canonical rendering, byte-identical to the string it was parsed from. */
    override fun toString(): String = text

    override fun equals(other: Any?): Boolean = other is MemberKey && other.text == text

    override fun hashCode(): Int = text.hashCode()

    /**
     * Verifies [sig] as this key's signature over [body] for domain [domain]; throws
     * [MemberKeyException] on refusal. The scheme is chosen by the key's kind, never
     * by the shape of [sig] (ADR-0018):
     *
     * - Ed25519: [sig] is the raw 64-byte signature over [body]; [domain] and
     *   [policy] are not used.
     * - WebAuthn: [sig] is the assertion envelope
     *   `{"ad":<b64url authenticatorData>,"cd":<b64url clientDataJSON>,"sig":<b64url DER>}`
     *   (the token's signature segment, base64url-decoded). The assertion must be over
     *   [WebAuthn.challenge]`(domain, body)` and satisfy [policy]; checks run in
     *   ADR-0018 §7.2 order.
     *
     * Mirrors void-which-binds-go `MemberKey.VerifyBody`.
     */
    @Throws(Exception::class)
    fun verifyBody(domain: String, body: ByteArray, sig: ByteArray, policy: WebAuthnPolicy) {
        when (kind) {
            Kind.ED25519 -> {
                val pub = checkNotNull(ed25519)
                val ok = sig.size == ED25519_SIG_LEN &&
                    runCatching { Ed25519Engine.verify(pub, body, sig) }.getOrDefault(false)
                if (!ok) {
                    throw MemberKeyException(
                        MemberKeyFailure.BAD_SIGNATURE,
                        "not an ed25519 signature by $text over this body",
                    )
                }
            }

            Kind.WEBAUTHN -> {
                WebAuthn.checkDomain(domain)
                verifyWebAuthnChallenge(WebAuthn.challenge(domain, body), sig, policy)
            }
        }
    }

    /**
     * The `webauthn:` checks against a raw [challenge] (Go's test-only
     * `VerifyWebAuthnChallenge`), for the WebAuthn L3 §16 conformance vectors.
     */
    internal fun verifyWebAuthnChallenge(challenge: ByteArray, sig: ByteArray, policy: WebAuthnPolicy) {
        check(kind == Kind.WEBAUTHN) { "not a webauthn key" }
        WebAuthn.verify(checkNotNull(es256), text, challenge, sig, policy)
    }

    companion object {
        private const val ED25519_SIG_LEN = 64

        /** The only sub-algorithm a `webauthn:` key may name today (COSE −7). */
        private const val WEBAUTHN_ES256 = "es256"

        /** Hex length of a 65-byte SEC1 uncompressed point. */
        private const val POINT_HEX_LEN = 2 * P256.UNCOMPRESSED_LEN

        /**
         * Parses a member-key string of any kind ADR-0018 defines, cutting on the
         * first `:` and dispatching on the prefix:
         *
         * - `ed25519:<64 lowercase hex>` ([KeyRef.parseCanonicalEd25519]);
         * - `webauthn:es256:<130 lowercase hex>`, a 65-byte SEC1 uncompressed P-256
         *   point that must be on the curve ([P256.isValidUncompressedPoint]).
         *
         * Anything else, an unknown prefix or surrounding whitespace included, throws
         * [MemberKeyException] ([MemberKeyFailure.MALFORMED_PUBLIC_KEY]). Mirrors
         * void-which-binds-go `identity.ParseMemberKey`.
         */
        @Throws(Exception::class)
        fun parse(s: String): MemberKey {
            if (s.isEmpty()) malformed("the member key is empty")
            if (GoStrings.trimSpace(s) != s) malformed("\"$s\" has surrounding whitespace")
            val colon = s.indexOf(':')
            if (colon < 0) malformed("\"$s\" has no key-kind prefix")
            return when (val prefix = s.substring(0, colon)) {
                Kind.ED25519.prefix -> {
                    val raw = try {
                        KeyRef.parseCanonicalEd25519(s)
                    } catch (e: IllegalArgumentException) {
                        malformed(e.message ?: "\"$s\" is not a canonical ed25519 key")
                    }
                    MemberKey(Kind.ED25519, s, raw, null)
                }

                Kind.WEBAUTHN.prefix -> MemberKey(Kind.WEBAUTHN, s, null, parseWebAuthnEs256(s, s.substring(colon + 1)))

                else -> malformed(
                    "\"$s\" names key kind \"$prefix\"; a member key is \"${Kind.ED25519.prefix}\" or " +
                        "\"${Kind.WEBAUTHN.prefix}\" (ADR-0018)",
                )
            }
        }

        private fun malformed(why: String): Nothing =
            throw MemberKeyException(MemberKeyFailure.MALFORMED_PUBLIC_KEY, why)

        /** The part of a `webauthn:` key [s] after the prefix ([rest]). Go `parseWebAuthnES256`. */
        private fun parseWebAuthnEs256(s: String, rest: String): ECDSA.PublicKey {
            val sub = rest.indexOf(':')
            if (sub < 0 || rest.substring(0, sub) != WEBAUTHN_ES256) {
                malformed("\"$s\" is a webauthn key without the \"$WEBAUTHN_ES256\" sub-algorithm (ADR-0018)")
            }
            val hexed = rest.substring(sub + 1)
            if (hexed.length != POINT_HEX_LEN) {
                malformed("\"$s\" has ${hexed.length} hex characters, and a webauthn:es256 key has $POINT_HEX_LEN")
            }
            if (hexed.lowercase() != hexed) malformed("\"$s\" is not lowercase hex")
            val raw = try {
                Hex.decode(hexed)
            } catch (_: IllegalArgumentException) {
                malformed("\"$s\" is not hex")
            }
            // ADR-0018: on the curve and not the identity (Go checks it through crypto/ecdh).
            if (!P256.isValidUncompressedPoint(raw)) malformed("\"$s\" is not a valid P-256 point")
            // The provider's own decode: unreachable once the on-curve gate passed, kept
            // so the two can never disagree silently (as Go keeps ecdsa's parse).
            return Es256.publicKeyOrNull(raw) ?: malformed("\"$s\" is not a valid P-256 point")
        }

        /**
         * Renders a 65-byte SEC1 uncompressed P-256 point as a `webauthn:es256:`
         * member-key string. It does not validate the point; [parse] the result to do
         * that. Mirrors void-which-binds-go `identity.FormatWebAuthnES256`.
         */
        fun formatWebAuthnEs256(point: ByteArray): String =
            "${Kind.WEBAUTHN.prefix}:$WEBAUTHN_ES256:${Hex.encode(point)}"

        /**
         * ADR-0018's refusal word for the outcome of [parse] / [verifyBody]: `"ok"` for
         * null, the [MemberKeyFailure.word] of a [MemberKeyException], and `"malformed"`
         * for anything else. Mirrors void-which-binds-go `identity.MemberKeyReason`.
         */
        fun reason(error: Throwable?): String = when (error) {
            null -> "ok"
            is MemberKeyException -> error.reason
            else -> "malformed"
        }
    }
}
