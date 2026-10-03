package one.rarebit.voidwhichbinds.delegation

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA256
import dev.whyoleg.cryptography.random.CryptographyRandom
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.Ed25519Verifier
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.MemberKey
import one.rarebit.voidwhichbinds.MemberKeyException
import one.rarebit.voidwhichbinds.WebAuthn
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.GoJson
import one.rarebit.voidwhichbinds.roster.Roster
import one.rarebit.voidwhichbinds.scope.Scope
import one.rarebit.voidwhichbinds.scope.ScopeException
import kotlin.random.Random

/**
 * The delegation grant of void-which-binds-go ADR-0017 (G8): a person's member key
 * lends a scoped, expiring authority to an agent key, at one broker, for one org.
 * This is the **minting** side, a byte-exact port of void-which-binds-go `delegation`
 * (`Body`, `SignWith`, `Challenge`, `AssembleWebAuthn`, `BodyHash`, `SignProofWith`,
 * `Parse`, `NewJTI`/`NewNonce`). The broker's `Verify` is server-only and not ported.
 *
 * A [user] (`usr`) is `ed25519:<genesis>` (sovereign) or `mp:<32 hex>` (org-managed);
 * the [issuer] (`iss`) is one of that person's member keys, `ed25519:<hex>` or
 * `webauthn:es256:<hex>` (ADR-0018); the [principal] (`prn`) is the agent's
 * `ed25519:<hex>`; [audience] (`aud`) the broker, [org] its org genesis key. [jti] is
 * 16 random bytes ([newJti]) and [nonce] (`non`) the broker's 32-byte nonce, both
 * unpadded base64url. [issuedAt]/[expiresAt] are unix seconds, `exp − iat ≤`
 * [MAX_TTL_SECONDS]. [scopes] are as the minter was handed them; [body] sorts and
 * de-duplicates them.
 *
 * Minting paths:
 * - an **Ed25519** member key (a device key, a custody signer): [signWith];
 * - a **`webauthn:` passkey**: take [body], assert over [challenge]`(body)` with
 *   `userVerification: "required"`, then [assembleWebAuthn] (with [webAuthnEnvelope]);
 * - the **agent** then proves possession on every request: [signProofWith].
 */
data class Delegation(
    val user: String,
    val org: String,
    val issuer: String,
    val principal: String,
    val audience: String,
    val scopes: List<String>,
    val jti: String,
    val nonce: String,
    val issuedAt: Long,
    val expiresAt: Long,
) {
    /**
     * Checks this delegation and renders its signed body: the bytes an Ed25519 issuer
     * signs and a `webauthn:` issuer asserts over ([challenge]). The body is exactly Go's
     * `json.Marshal` of the payload — fields `v, typ, usr, org, iss, prn, aud, scp, jti,
     * non, iat, exp`, compact, with `<`, `>`, `&` escaped as `<`, `>`, `&`.
     *
     * Refusals, in Go's order: [Failure.INCOMPLETE] (an empty binding, an unset or empty
     * window), [Failure.MALFORMED_SCOPE], [Failure.PRINCIPAL_IS_ISSUER] (prn is iss, usr
     * or org), [Failure.ISSUER_MISMATCH] (iss is usr or org: a genesis key is never a
     * member key), then the claim grammar: [Failure.MALFORMED] naming the field,
     * [Failure.INCOMPLETE] (iat ≤ 0 or exp ≤ iat), [Failure.TTL_TOO_LONG]. Go `Body`.
     */
    fun body(): ByteArray {
        if (listOf(user, org, issuer, principal, audience, jti, nonce).any { it.isEmpty() }) {
            fail(Failure.INCOMPLETE, "a binding is empty")
        }
        if (issuedAt == 0L || expiresAt == 0L) {
            fail(Failure.INCOMPLETE, "a delegation needs an issued-at and an expiry")
        }
        val scp = try {
            Scope.canonicalList(scopes)
        } catch (e: ScopeException) {
            fail(Failure.MALFORMED_SCOPE, "scp: ${e.message}")
        }
        val p = Payload(VERSION, TYP, user, org, issuer, principal, audience, scp, jti, nonce, issuedAt, expiresAt)
        if (p.principal == p.issuer || p.principal == p.user || p.principal == p.org) {
            fail(Failure.PRINCIPAL_IS_ISSUER, "prn ${p.principal}")
        }
        if (p.issuer == p.user || p.issuer == p.org) {
            fail(Failure.ISSUER_MISMATCH, "iss ${p.issuer} is a genesis key, never a member key")
        }
        p.check(mint = true)
        return p.encode()
    }

    /** Why a mint or a parse was refused. Mint-side failures are not wire reasons. */
    enum class Failure {
        /** ADR-0017 `malformed`: a claim outside its grammar, or a body that is not the canonical encoding. */
        MALFORMED,

        /** ADR-0017 `wrong_type`: a body whose `typ` is not [TYP] (absent included). */
        WRONG_TYPE,

        /** Mint: a scope list outside the grammar (Go wraps `scope.ErrMalformed`). */
        MALFORMED_SCOPE,

        /** Mint: an empty binding or an empty window (Go `ErrIncomplete`). */
        INCOMPLETE,

        /** Mint: `exp − iat` over [MAX_TTL_SECONDS], or a proof ttl over [POSSESSION_TTL_SECONDS] (`ErrTTLTooLong`). */
        TTL_TOO_LONG,

        /**
         * Mint: the stated iss (or a proof's prn) is not the signing key, or iss is a genesis
         * key (Go `ErrIssuerMismatch`).
         */
        ISSUER_MISMATCH,

        /** Mint: prn is iss, usr or org (Go `ErrPrincipalIsIssuer`). */
        PRINCIPAL_IS_ISSUER,
    }

    /** A refused mint or parse. */
    class DelegationException(val failure: Failure, message: String) : IllegalArgumentException(message)

    /**
     * ADR-0017's refusal words, as a broker reports them for a delegation request.
     * Minting never produces these except [MALFORMED] and [WRONG_TYPE] from [parse].
     */
    enum class Reason(val word: String) {
        OK("ok"),
        MALFORMED("malformed"),
        WRONG_TYPE("wrong_type"),
        POP_INVALID("pop_invalid"),
        UNKNOWN_USER("unknown_user"),
        ISSUER_NOT_MEMBER("issuer_not_member"),
        ISSUER_REMOVED("issuer_removed"),
        PRINCIPAL_IS_MEMBER("principal_is_member"),
        BAD_SIGNATURE("bad_signature"),
        AUDIENCE_MISMATCH("audience_mismatch"),
        NOT_YET_VALID("not_yet_valid"),
        EXPIRED("expired"),
        NONCE_INVALID("nonce_invalid"),
        NONCE_REUSED("nonce_reused"),
        SCOPE_DENIED("scope_denied"),
        SCOPE_EXCEEDS_ROLE("scope_exceeds_role"),
        ;

        companion object {
            /** The reason for [word], or null for a word ADR-0017 does not define. */
            fun of(word: String): Reason? = entries.firstOrNull { it.word == word }
        }
    }

    /** The signed body, in ADR-0017's fixed field order (Go's unexported `payload`). */
    private data class Payload(
        val v: Int,
        val typ: String,
        val user: String,
        val org: String,
        val issuer: String,
        val principal: String,
        val audience: String,
        val scopes: List<String>?,
        val jti: String,
        val nonce: String,
        val issuedAt: Long,
        val expiresAt: Long,
    ) {
        fun encode(): ByteArray = DelegationJson.obj(
            "v" to v.toLong(),
            "typ" to typ,
            "usr" to user,
            "org" to org,
            "iss" to issuer,
            "prn" to principal,
            "aud" to audience,
            "scp" to scopes,
            "jti" to jti,
            "non" to nonce,
            "iat" to issuedAt,
            "exp" to expiresAt,
        )

        fun toDelegation() = Delegation(
            user, org, issuer, principal, audience, scopes.orEmpty(), jti, nonce, issuedAt, expiresAt,
        )

        /**
         * The claim grammar shared by mint and parse (Go `payload.check`). At mint an
         * empty window is [Failure.INCOMPLETE] and an over-long one [Failure.TTL_TOO_LONG];
         * at parse every refusal is [Failure.MALFORMED].
         */
        @Suppress("CyclomaticComplexMethod")
        fun check(mint: Boolean) {
            if (user.startsWith(Roster.MANAGED_PREFIX)) {
                if (!validManagedId(user)) fail(Failure.MALFORMED, "usr \"$user\" is not an mp:<32 hex> id")
            } else {
                canonicalEd25519(user, "usr")
            }
            canonicalEd25519(org, "org")
            try {
                MemberKey.parse(issuer)
            } catch (e: MemberKeyException) {
                fail(Failure.MALFORMED, "iss: ${e.message}")
            }
            canonicalEd25519(principal, "prn")
            if (audience.isEmpty()) fail(Failure.MALFORMED, "empty aud")
            randomClaim(jti, JTI_LEN, "jti")
            randomClaim(nonce, NONCE_LEN, "non")
            if (issuedAt <= 0 || expiresAt <= issuedAt) {
                fail(
                    if (mint) Failure.INCOMPLETE else Failure.MALFORMED,
                    "the window is empty: iat $issuedAt, exp $expiresAt",
                )
            }
            // Both are positive here, so the difference cannot overflow.
            if (expiresAt - issuedAt > MAX_TTL_SECONDS) {
                fail(
                    if (mint) Failure.TTL_TOO_LONG else Failure.MALFORMED,
                    "exp − iat exceeds MaxTTL: ${expiresAt - issuedAt}s > ${MAX_TTL_SECONDS}s",
                )
            }
        }
    }

    @Suppress("TooManyFunctions") // one function per Go entry point, plus the claim-grammar helpers
    companion object {
        /** The `v` of both token kinds. */
        const val VERSION = 1

        /** A delegation's `typ` (ADR-0017 registers it in ADR-0013's gen2 table). */
        const val TYP = "void-which-binds.delegation"

        /** An agent's proof-of-possession token's `typ`. */
        const val TYP_PROOF = "void-which-binds.delegation-pop"

        /** The ADR-0018 challenge domain a `webauthn:` issuer asserts a body under. */
        const val DOMAIN = TYP

        /** `exp − iat` bound, enforced at mint and at verify (Go `grant.MaxTTL`, 24 h). */
        const val MAX_TTL_SECONDS = 24L * 60 * 60

        /** The broker's skew margin, which only shortens a delegation's window (Go `grant.SkewMargin`). */
        const val SKEW_MARGIN_SECONDS = 5L * 60

        /** How long after the broker issued a nonce a delegation may still be minted from it. */
        const val NONCE_TTL_SECONDS = 5L * 60

        /** A proof's maximum (and default) `exp − iat` (Go `enrolment.PossessionTTL`). */
        const val POSSESSION_TTL_SECONDS = 2L * 60

        /** The clock tolerance on a proof's not-yet-valid side only (Go `enrolment.PossessionSkew`). */
        const val POSSESSION_SKEW_SECONDS = 30L

        /** The jti's random bytes: 22 unpadded base64url characters. */
        const val JTI_LEN = 16

        /** The broker nonce's random bytes: 43 unpadded base64url characters. */
        const val NONCE_LEN = 32

        /** The request header carrying the delegation (ADR-0017, "Transport"). */
        const val HEADER = "Void-Which-Binds-Delegation"

        /** The request header carrying the agent's proof of possession. */
        const val PROOF_HEADER = "Void-Which-Binds-Delegation-Proof"

        private const val SIGNATURE_LEN = 64
        private const val MANAGED_HEX_LEN = 32

        private val sha256 = CryptographyProvider.Default.get(SHA256).hasher()

        private fun fail(failure: Failure, why: String): Nothing =
            throw DelegationException(failure, "delegation: ${failure.name.lowercase()}: $why")

        /** A fresh jti: [JTI_LEN] random bytes, unpadded base64url. Go `NewJTI`. */
        fun newJti(random: Random = CryptographyRandom.Default): String = Base64Url.encode(random.nextBytes(JTI_LEN))

        /** A fresh broker nonce: [NONCE_LEN] random bytes (a broker records it as it issues it). Go `NewNonce`. */
        fun newNonce(random: Random = CryptographyRandom.Default): String =
            Base64Url.encode(random.nextBytes(NONCE_LEN))

        /**
         * Mints [d] under an Ed25519 member key reached through [signer] (a hardware device
         * key, a custody signer), whose 32-byte public key is [signerPublicKey]. `d.issuer`
         * must be that key's `ed25519:<hex>` ([Failure.ISSUER_MISMATCH] otherwise, and
         * always for a `webauthn:` issuer), and [d] must pass [body]'s checks. The
         * signature is checked under [signerPublicKey] before it is returned. Ed25519 is
         * deterministic, so the same key and delegation mint the same token. Go `SignWith`.
         */
        fun signWith(
            signer: Ed25519Signer,
            signerPublicKey: ByteArray,
            d: Delegation,
            verifier: Ed25519Verifier = Ed25519Engine.verifier(),
        ): String {
            val self = KeyRef.ed25519(signerPublicKey).render()
            if (d.issuer != self) fail(Failure.ISSUER_MISMATCH, "delegation names \"${d.issuer}\", key is \"$self\"")
            val body = d.body()
            return Base64Url.encode(body) + "." + Base64Url.encode(signature(signer, signerPublicKey, body, verifier))
        }

        /**
         * The 32-byte WebAuthn challenge a `webauthn:` issuer asserts over to sign [body]
         * (ADR-0018): [WebAuthn.challenge]`(`[DOMAIN]`, body)`. Pass it as
         * `PublicKeyCredentialRequestOptions.challenge` with `userVerification: "required"`.
         */
        fun challenge(body: ByteArray): ByteArray = WebAuthn.challenge(DOMAIN, body)

        /**
         * ADR-0018's assertion envelope `{"ad":…,"cd":…,"sig":…}` (each unpadded base64url)
         * from a platform assertion: the raw authenticatorData, clientDataJSON and DER
         * ECDSA signature, exactly as the authenticator returned them.
         */
        fun webAuthnEnvelope(authenticatorData: ByteArray, clientDataJson: ByteArray, signature: ByteArray): ByteArray =
            DelegationJson.obj(
                "ad" to Base64Url.encode(authenticatorData),
                "cd" to Base64Url.encode(clientDataJson),
                "sig" to Base64Url.encode(signature),
            )

        /**
         * Joins a delegation [body] and the assertion [envelope] a `webauthn:` issuer's
         * authenticator produced over [challenge]`(body)` into a token,
         * `base64url(body) "." base64url(envelope)`. It checks that [body] is a
         * well-formed delegation whose iss is a `webauthn:` key
         * ([Failure.ISSUER_MISMATCH] otherwise) and that [envelope] is non-empty
         * ([Failure.INCOMPLETE]); it does not verify the assertion. Go `AssembleWebAuthn`.
         */
        fun assembleWebAuthn(body: ByteArray, envelope: ByteArray): String {
            val p = parseBody(body)
            val kind = runCatching { MemberKey.parse(p.issuer).kind }.getOrNull()
            if (kind !=
                MemberKey.Kind.WEBAUTHN
            ) {
                fail(Failure.ISSUER_MISMATCH, "iss \"${p.issuer}\" is not a webauthn key")
            }
            if (envelope.isEmpty()) fail(Failure.INCOMPLETE, "no assertion envelope")
            return Base64Url.encode(body) + "." + Base64Url.encode(envelope)
        }

        /**
         * The proof's `dlg` for a delegation [token]: unpadded base64url of sha256 of the
         * token's BODY bytes (it binds the body, not the malleable signature). Go `BodyHash`.
         */
        fun bodyHash(token: String): String {
            val body = tokenBody(token.trim()) ?: fail(Failure.MALFORMED, "the delegation token")
            return bodyHashOf(body)
        }

        private fun bodyHashOf(body: ByteArray): String = Base64Url.encode(sha256.hashBlocking(body))

        /**
         * Mints the agent's proof of possession for [delegationToken] at the broker [aud],
         * valid from [now] (unix seconds) for [ttlSeconds] (non-positive:
         * [POSSESSION_TTL_SECONDS]; at most that). [signer] is the agent key, whose public
         * key [signerPublicKey] must be the delegation's prn ([Failure.ISSUER_MISMATCH]
         * otherwise), read from the token's body unverified. Body
         * `{"v":1,"typ":"void-which-binds.delegation-pop","dlg":…,"aud":…,"iat":…,"exp":…}`.
         * Go `SignProofWith`.
         */
        @Suppress("LongParameterList")
        fun signProofWith(
            signer: Ed25519Signer,
            signerPublicKey: ByteArray,
            delegationToken: String,
            aud: String,
            now: Long,
            ttlSeconds: Long = 0,
            verifier: Ed25519Verifier = Ed25519Engine.verifier(),
        ): String {
            val body = tokenBody(delegationToken.trim()) ?: fail(Failure.MALFORMED, "the delegation token")
            val p = parseBody(body)
            val self = KeyRef.ed25519(signerPublicKey).render()
            if (p.principal != self) {
                fail(Failure.ISSUER_MISMATCH, "delegation prn is \"${p.principal}\", key is \"$self\"")
            }
            if (aud.isEmpty() || now == 0L) fail(Failure.INCOMPLETE, "a proof needs an audience and a clock")
            val ttl = if (ttlSeconds <= 0) POSSESSION_TTL_SECONDS else ttlSeconds
            if (ttl > POSSESSION_TTL_SECONDS) {
                fail(Failure.TTL_TOO_LONG, "proof ttl ${ttl}s > ${POSSESSION_TTL_SECONDS}s")
            }
            val pb = DelegationJson.obj(
                "v" to VERSION.toLong(),
                "typ" to TYP_PROOF,
                "dlg" to bodyHashOf(body),
                "aud" to aud,
                "iat" to now,
                "exp" to now + ttl,
            )
            return Base64Url.encode(pb) + "." + Base64Url.encode(signature(signer, signerPublicKey, pb, verifier))
        }

        /**
         * Reads a delegation token's body without verifying anything but its shape: the
         * typ ([Failure.WRONG_TYPE]), then [Failure.MALFORMED] for a body that is not the
         * exact canonical encoding of its claims, a `v` other than [VERSION], a
         * non-canonical scope list, or any claim outside its grammar. For logging and for
         * a minter checking what it holds; it authenticates nothing. Go `Parse`.
         */
        fun parse(token: String): Delegation {
            val t = token.trim()
            val dot = t.indexOf('.')
            if (dot < 0) fail(Failure.MALFORMED, "not <body>.<signature>")
            val body = goDecode(t.substring(0, dot)) ?: fail(Failure.MALFORMED, "the body is not base64url")
            goDecode(t.substring(dot + 1)) ?: fail(Failure.MALFORMED, "the signature is not base64url")
            return parseBody(body).toDelegation()
        }

        private fun tokenBody(token: String): ByteArray? {
            val dot = token.indexOf('.')
            return if (dot < 0) null else goDecode(token.substring(0, dot))
        }

        /** Go's `base64.RawURLEncoding.DecodeString`: CR and LF are skipped. */
        private fun goDecode(s: String): ByteArray? =
            runCatching { Base64Url.decode(s.filter { it != '\r' && it != '\n' }) }.getOrNull()

        private fun signature(
            signer: Ed25519Signer,
            publicKey: ByteArray,
            msg: ByteArray,
            verifier: Ed25519Verifier,
        ): ByteArray {
            val sig = signer.sign(msg)
            val ok =
                sig.size == SIGNATURE_LEN && runCatching { verifier.verify(publicKey, msg, sig) }.getOrDefault(false)
            check(ok) { "delegation: the signer returned a signature that does not verify under its public key" }
            return sig
        }

        /** Go `parseBody`: typ first (wrong_type), then the exact canonical encoding and every claim (malformed). */
        private fun parseBody(body: ByteArray): Payload {
            val node = DelegationJson.parse(body)
            DelegationJson.checkTyp(node, TYP)?.let { fail(it, "token type is not $TYP") }
            val p = decode(node) ?: fail(Failure.MALFORMED, "the body does not decode as a delegation")
            if (!p.encode().contentEquals(body)) {
                fail(Failure.MALFORMED, "the body is not the canonical encoding of its claims")
            }
            if (p.v != VERSION) fail(Failure.MALFORMED, "v is ${p.v}")
            try {
                Scope.validateList(p.scopes.orEmpty())
            } catch (e: ScopeException) {
                fail(Failure.MALFORMED, "scp: ${e.message}")
            }
            p.check(mint = false)
            return p
        }

        /**
         * The payload read from exactly-named members, or null where a value has the wrong
         * JSON type. Any other difference from Go's case-folding struct decode (a folded
         * key, a duplicate, a `null`) re-encodes differently, so [parseBody]'s canonical
         * comparison refuses it as `malformed` exactly as Go does.
         */
        private fun decode(node: GoJson.Node?): Payload? {
            val m = (node as? GoJson.Obj)?.members?.toMap() ?: return null
            return try {
                val v = DelegationJson.long(m, "v")
                if (v !in Int.MIN_VALUE..Int.MAX_VALUE) throw DelegationJson.WrongType()
                Payload(
                    v = v.toInt(),
                    typ = DelegationJson.string(m, "typ"),
                    user = DelegationJson.string(m, "usr"),
                    org = DelegationJson.string(m, "org"),
                    issuer = DelegationJson.string(m, "iss"),
                    principal = DelegationJson.string(m, "prn"),
                    audience = DelegationJson.string(m, "aud"),
                    scopes = DelegationJson.strings(m, "scp"),
                    jti = DelegationJson.string(m, "jti"),
                    nonce = DelegationJson.string(m, "non"),
                    issuedAt = DelegationJson.long(m, "iat"),
                    expiresAt = DelegationJson.long(m, "exp"),
                )
            } catch (_: DelegationJson.WrongType) {
                null
            }
        }

        private fun canonicalEd25519(s: String, field: String) {
            try {
                KeyRef.parseCanonicalEd25519(s)
            } catch (e: IllegalArgumentException) {
                fail(Failure.MALFORMED, "$field: ${e.message}")
            }
        }

        /**
         * [s] must be exactly [n] bytes in unpadded base64url, in its one canonical
         * spelling (Go's strict `RawURLEncoding`, which still skips CR and LF).
         */
        private fun randomClaim(s: String, n: Int, field: String) {
            val stripped = s.filter { it != '\r' && it != '\n' }
            val b = runCatching { Base64Url.decode(stripped) }.getOrNull()
            when {
                b == null || Base64Url.encode(b) != stripped -> fail(Failure.MALFORMED, "$field: not strict base64url")
                b.size != n -> fail(Failure.MALFORMED, "$field: ${b.size} bytes, want $n")
            }
        }

        private fun validManagedId(s: String): Boolean {
            val h = s.removePrefix(Roster.MANAGED_PREFIX)
            return h.length == MANAGED_HEX_LEN && h.all { it in '0'..'9' || it in 'a'..'f' }
        }
    }
}
