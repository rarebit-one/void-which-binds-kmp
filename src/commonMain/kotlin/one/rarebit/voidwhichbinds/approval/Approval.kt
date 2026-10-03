package one.rarebit.voidwhichbinds.approval

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.Ed25519Verifier
import one.rarebit.voidwhichbinds.LoginQr
import one.rarebit.voidwhichbinds.WebAuthn
import one.rarebit.voidwhichbinds.auth.OrgRequest
import one.rarebit.voidwhichbinds.crypto.Base64Url

/**
 * The approver's side of the action-approval challenge (void-which-binds-go `approval`,
 * G9a, ADR-0019): what Cruciform does when an `approve` wake arrives. A byte-exact port
 * of the parts of Go's byte layer an approver runs:
 *
 * 1. the wake: [parseApprove] reads `void-which-binds:approve?h=<handle>` (an exact
 *    match) into a [Handle] — the tuple names no rp, no challenge and nothing about the
 *    action, so the approver sends the fetch to the broker it holds standing at, from its
 *    own enrolment;
 * 2. the authenticated fetch ([one.rarebit.voidwhichbinds.net.ApprovalClient]): a
 *    [FetchNonce] from the broker, a proof over [fetchPreimage] bound to the broker's
 *    audience ([signFetchProofWith] for an Ed25519 device key; [fetchPasskeyChallenge]
 *    then [encodeEnvelope] for a passkey), the [FetchRequest], and [FetchResponse.open],
 *    which recomputes the action digest over the fetched bytes (no canonicalisation) and
 *    refuses an action that does not match the challenge;
 * 3. the approval: the person picks a number among [Challenge.candidates]; then
 *    [signAssertionWith] (Ed25519) or [passkeyChallenge] + [webAuthnAssertion] (passkey)
 *    builds the [Assertion] body `{credential, ops, roster, sig, match_number}`.
 *
 * The broker (challenge and handle stores, `CheckOrg`, the authority check, the commit,
 * consumption, rate limits, and the verifier's `CheckAssertion`/`VerifyAssertion`/
 * `VerifyFetchProof`) is server-only (G9b) and not ported. Every frame is
 * `uint64be(len(p)) ‖ p`; the three domains share nothing with weblogin's or a
 * delegation's, so no signature made for one verifies as another.
 */
@Suppress("TooManyFunctions") // one function per Go entry point an approver uses
object Approval {
    /** Frames the approval preimage, and is the ADR-0018 domain a passkey approval asserts under. */
    const val DOMAIN_CHALLENGE = "void-which-binds/approval/challenge/v1"

    /** Frames the action digest. */
    const val DOMAIN_ACTION = "void-which-binds/approval/action/v1"

    /** Frames the fetch proof preimage, and is the ADR-0018 domain a passkey fetch proof asserts under. */
    const val DOMAIN_FETCH = "void-which-binds/approval/fetch/v1"

    /** A challenge's own window (`expires_at − issued_at`), weblogin's 2 minutes. */
    const val CHALLENGE_TTL_SECONDS = 120L

    /** The longest approval lifetime a challenge may carry (Go `MaxApprovalTTL`, 1 h). */
    const val MAX_APPROVAL_TTL_SECONDS = 3600L

    /** How long a fetch nonce is usable after the broker issues it. */
    const val FETCH_NONCE_TTL_SECONDS = 120L

    /** The random bytes behind a challenge id (32 lowercase hex characters). */
    const val ID_LEN = 16

    /** The challenge's per-ceremony RP nonce. */
    const val NONCE_LEN = 32

    /** The `approve` tuple's opaque handle. */
    const val HANDLE_LEN = 32

    /** The authenticated fetch's nonce. */
    const val FETCH_NONCE_LEN = 32

    /** The action digest (SHA-256). */
    const val DIGEST_LEN = 32

    /** The longest action kind, in bytes. */
    const val MAX_KIND_LEN = 32

    /** The longest action summary, in bytes of UTF-8. */
    const val MAX_SUMMARY_LEN = 1024

    /** The longest action params, in bytes. */
    const val MAX_PARAMS_LEN = 64 shl 10

    /** How many numbers the phone shows (ADR-0006). */
    const val MATCH_CANDIDATE_COUNT = 3

    /** The exclusive upper bound of a match number (ADR-0006). */
    const val MATCH_NUMBER_BOUND = 100

    /** Everything in an `approve` tuple before the handle. Go `ApproveTuplePrefix`. */
    const val APPROVE_TUPLE_PREFIX = "${LoginQr.SCHEME}:approve?h="

    /** The status every fetch refusal answers with (Go `FetchRefusalStatus`). */
    const val FETCH_REFUSAL_STATUS = 404

    /** The exact body of every fetch refusal, no trailing newline (Go `FetchRefusalBody`). */
    const val FETCH_REFUSAL_BODY = """{"error":"not_found"}"""

    /** The unpadded base64url length of 32 bytes. */
    private const val B64_32_LEN = 43
    private const val SIGNATURE_LEN = 64

    /** Why the approver's side refused. [word] is ADR-0019's refusal word for the case. */
    enum class Failure(val word: String) {
        /** A challenge, action, value or body outside the rules (Go `ErrMalformed`). */
        MALFORMED("malformed"),

        /** A ttl over [MAX_APPROVAL_TTL_SECONDS] (Go wraps both `ErrMalformed` and `ErrTTLTooLong`). */
        TTL_TOO_LONG("malformed"),

        /**
         * The fetched action does not recompute to the challenge's digest: the approver
         * must not sign it (Go `ErrActionMismatch` wrapping `ErrDigestMismatch`).
         */
        DIGEST_MISMATCH("digest_mismatch"),

        /** The fetched action names another resource (Go `ErrActionMismatch` wrapping `ErrResourceMismatch`). */
        RESOURCE_MISMATCH("resource_mismatch"),

        /** A tuple or handle that is not one handle (Go `ErrUnknownHandle`). */
        UNKNOWN_HANDLE("unknown_handle"),

        /** A fetch nonce that is not 32 canonical non-zero bytes (Go `ErrFetchNonceSpent`). */
        FETCH_NONCE_SPENT("fetch_nonce_spent"),
    }

    /** A refusal on the approver's side; [failure] says which rule refused. */
    class ApprovalException(val failure: Failure, message: String) : IllegalArgumentException(message) {
        /** ADR-0019's refusal word. */
        val reason: String get() = failure.word
    }

    internal fun fail(failure: Failure, why: String): Nothing =
        throw ApprovalException(failure, "approval: ${failure.word}: $why")

    // --- the handle and the approve tuple ------------------------------------------

    /**
     * Decodes [s] as unpadded base64url in its one canonical spelling: Go's strict
     * `RawURLEncoding` then a re-encode comparison, so padding, CR/LF (which Go's decoder
     * would skip), any other character, and non-zero trailing bits are refused. Null on
     * refusal. Go `decodeCanonical`.
     */
    internal fun decodeCanonical(s: String): ByteArray? {
        val raw = runCatching { Base64Url.decode(s) }.getOrNull() ?: return null
        return raw.takeIf { Base64Url.encode(it) == s }
    }

    /** Go `parse32`: exactly 43 characters of canonical unpadded base64url, 32 bytes, not all zero. */
    @Suppress("ReturnCount")
    private fun parse32(s: String): ByteArray? {
        if (s.length != B64_32_LEN) return null
        val b = decodeCanonical(s) ?: return null
        return b.takeIf { it.size == HANDLE_LEN && !it.all { x -> x == 0.toByte() } }
    }

    /** Parses a handle's unpadded base64url; anything else is [Failure.UNKNOWN_HANDLE]. Go `ParseHandle`. */
    @Throws(Exception::class)
    fun parseHandle(s: String): Handle =
        Handle(parse32(s) ?: fail(Failure.UNKNOWN_HANDLE, "not 32 bytes of canonical unpadded base64url"))

    /**
     * Parses a fetch nonce's unpadded base64url; anything else is [Failure.FETCH_NONCE_SPENT].
     * Go `ParseFetchNonce`.
     */
    @Throws(Exception::class)
    fun parseFetchNonce(s: String): FetchNonce =
        FetchNonce(parse32(s) ?: fail(Failure.FETCH_NONCE_SPENT, "not 32 bytes of canonical unpadded base64url"))

    /** Renders the `approve` tuple `void-which-binds:approve?h=<handle>`. Go `EncodeApprove`. */
    fun encodeApprove(h: Handle): String = APPROVE_TUPLE_PREFIX + h

    /**
     * Parses an `approve` tuple. It is an exact match, not a URI parse: [APPROVE_TUPLE_PREFIX]
     * followed by exactly a handle's 43 characters — no other parameter, percent-encoding,
     * padding, fragment, case variant or surrounding whitespace. Anything else is
     * [Failure.UNKNOWN_HANDLE]. Go `ParseApprove`.
     */
    @Throws(Exception::class)
    fun parseApprove(tuple: String): Handle {
        if (!tuple.startsWith(APPROVE_TUPLE_PREFIX)) fail(Failure.UNKNOWN_HANDLE, "not an approve tuple")
        return parseHandle(tuple.substring(APPROVE_TUPLE_PREFIX.length))
    }

    /** Non-throwing [parseApprove]: null for anything that is not an `approve` tuple. */
    fun parseApproveOrNull(tuple: String): Handle? = try {
        parseApprove(tuple)
    } catch (_: ApprovalException) {
        null
    }

    // --- the fetch proof ----------------------------------------------------------

    /**
     * The bytes an approver signs to fetch a challenge:
     *
     *     frame(DOMAIN_FETCH) frame(audience) frame(handle) frame(nonce)
     *
     * with the handle and nonce as their raw 32 bytes. [audience] is the broker's origin
     * and must not be empty ([Failure.MALFORMED]). Go `FetchPreimage`.
     */
    @Throws(Exception::class)
    fun fetchPreimage(audience: String, h: Handle, n: FetchNonce): ByteArray {
        if (audience.isEmpty()) fail(Failure.MALFORMED, "empty audience")
        return Frames()
            .add(DOMAIN_FETCH.encodeToByteArray())
            .add(audience.encodeToByteArray())
            .add(h.bytes)
            .add(n.bytes)
            .bytes()
    }

    /**
     * An Ed25519 approver's fetch proof: unpadded base64url of its signature over
     * [fetchPreimage]. [signer] is the member key (a hardware device key), whose public key
     * [signerPublicKey] the signature is checked under before it is returned. Ed25519 is
     * deterministic, so the same key and inputs give the same proof. Go `SignFetchProofWith`.
     */
    @Suppress("LongParameterList")
    @Throws(Exception::class)
    fun signFetchProofWith(
        signer: Ed25519Signer,
        signerPublicKey: ByteArray,
        audience: String,
        h: Handle,
        n: FetchNonce,
        verifier: Ed25519Verifier = Ed25519Engine.verifier(),
    ): String = Base64Url.encode(signature(signer, signerPublicKey, fetchPreimage(audience, h, n), verifier))

    /**
     * The 32-byte WebAuthn challenge a passkey approver asserts over for a fetch proof:
     * [WebAuthn.challenge]`(`[DOMAIN_FETCH]`, `[fetchPreimage]`)`. Pass it as
     * `PublicKeyCredentialRequestOptions.challenge` with `userVerification: "required"`;
     * the proof is then [encodeEnvelope] of the assertion. Go `FetchPasskeyChallenge`.
     */
    @Throws(Exception::class)
    fun fetchPasskeyChallenge(audience: String, h: Handle, n: FetchNonce): ByteArray =
        WebAuthn.challenge(DOMAIN_FETCH, fetchPreimage(audience, h, n))

    /**
     * ADR-0018's assertion envelope `{"ad":…,"cd":…,"sig":…}` (each unpadded base64url)
     * from a platform assertion's raw authenticatorData, clientDataJSON and DER signature.
     */
    fun webAuthnEnvelope(authenticatorData: ByteArray, clientDataJson: ByteArray, signature: ByteArray): ByteArray =
        ApprovalJson.obj(
            "ad" to Base64Url.encode(authenticatorData),
            "cd" to Base64Url.encode(clientDataJson),
            "sig" to Base64Url.encode(signature),
        )

    /** A passkey envelope as a `sig` or `proof` value: its unpadded base64url. Go `EncodeEnvelope`. */
    fun encodeEnvelope(envelope: ByteArray): String = Base64Url.encode(envelope)

    // --- the approval -------------------------------------------------------------

    /**
     * [c]'s preimage bound to the person's [chosen] number, after checking that [fetched]
     * is the action [c] was minted for ([Failure.DIGEST_MISMATCH] /
     * [Failure.RESOURCE_MISMATCH]; a malformed action is [Failure.MALFORMED]) and that
     * [chosen] is one of [c]'s candidates ([Failure.MALFORMED]): the approver signs only
     * what it displayed. Go `bound`; the candidate check is this client's own, since the
     * UI only ever offers the candidates.
     */
    private fun bound(c: Challenge, fetched: Action, chosen: Int): ByteArray {
        c.requireMatches(fetched)
        val pre = c.withMatchNumber(chosen).preimage()
        if (chosen !in c.candidates) fail(Failure.MALFORMED, "$chosen is not one of the candidates ${c.candidates}")
        return pre
    }

    /**
     * The approver's assertion under an Ed25519 member key reached through [signer] (the
     * hardware device key), whose public key is [signerPublicKey]: it refuses as [bound]
     * does, then signs [c]'s preimage bound to [chosen]. [credential] is the admitting op
     * token (a sovereign device's add, or the roster `enrol` op of a managed person's key;
     * an empty one is [Failure.MALFORMED]); [presented] supplies the presented person ops
     * (`ops`) and roster ops (`roster`) the broker evaluates through `CheckOrg` — the same
     * de-duplicated, hash-ordered lists an org-path request carries in its headers.
     * Ed25519 is deterministic: the same key, challenge and number give the same
     * signature. Go `SignAssertionWith`.
     */
    @Suppress("LongParameterList")
    @Throws(Exception::class)
    fun signAssertionWith(
        signer: Ed25519Signer,
        signerPublicKey: ByteArray,
        c: Challenge,
        fetched: Action,
        chosen: Int,
        credential: String,
        presented: OrgRequest? = null,
        verifier: Ed25519Verifier = Ed25519Engine.verifier(),
    ): Assertion {
        if (credential.isEmpty()) fail(Failure.MALFORMED, "no credential")
        val pre = bound(c, fetched, chosen)
        val sig = signature(signer, signerPublicKey, pre, verifier)
        return Assertion(
            credential,
            presented?.membershipOps.orEmpty(),
            presented?.rosterOps.orEmpty(),
            Base64Url.encode(sig),
            chosen,
        )
    }

    /**
     * The 32-byte WebAuthn challenge a passkey approver asserts over:
     * [WebAuthn.challenge]`(`[DOMAIN_CHALLENGE]`, B)`, B being [c]'s preimage bound to
     * [chosen]. Refuses as [signAssertionWith] does. Go `PasskeyChallenge`.
     */
    @Throws(Exception::class)
    fun passkeyChallenge(c: Challenge, fetched: Action, chosen: Int): ByteArray =
        WebAuthn.challenge(DOMAIN_CHALLENGE, bound(c, fetched, chosen))

    /**
     * A passkey approver's assertion from the [envelope] its authenticator produced over
     * [passkeyChallenge] (see [webAuthnEnvelope]). It does not verify it; an empty
     * [credential] or [envelope] is [Failure.MALFORMED]. Go `WebAuthnAssertion`.
     */
    @Throws(Exception::class)
    fun webAuthnAssertion(
        credential: String,
        chosen: Int,
        envelope: ByteArray,
        presented: OrgRequest? = null,
    ): Assertion {
        if (credential.isEmpty() ||
            envelope.isEmpty()
        ) {
            fail(Failure.MALFORMED, "a credential and an envelope are required")
        }
        return Assertion(
            credential,
            presented?.membershipOps.orEmpty(),
            presented?.rosterOps.orEmpty(),
            encodeEnvelope(envelope),
            chosen,
        )
    }

    /** Go `sigtoken.SignatureWith`: sign, then check the signature verifies under the public key. */
    private fun signature(
        signer: Ed25519Signer,
        publicKey: ByteArray,
        msg: ByteArray,
        verifier: Ed25519Verifier,
    ): ByteArray {
        val sig = signer.sign(msg)
        val ok = sig.size == SIGNATURE_LEN && runCatching { verifier.verify(publicKey, msg, sig) }.getOrDefault(false)
        check(ok) { "approval: the signer returned a signature that does not verify under its public key" }
        return sig
    }
}

/** The opaque pointer an `approve` wake carries: 32 random bytes, never all zero. Go `approval.Handle`. */
class Handle internal constructor(raw: ByteArray) {
    private val b = raw.copyOf()

    /** A copy of the 32 bytes. */
    val bytes: ByteArray get() = b.copyOf()

    /** The handle as unpadded base64url (43 characters). */
    override fun toString(): String = Base64Url.encode(b)

    override fun equals(other: Any?): Boolean = other is Handle && other.b.contentEquals(b)

    override fun hashCode(): Int = b.contentHashCode()
}

/** The authenticated fetch's single-use nonce: 32 bytes, never all zero. Go `approval.FetchNonce`. */
class FetchNonce internal constructor(raw: ByteArray) {
    private val b = raw.copyOf()

    /** A copy of the 32 bytes. */
    val bytes: ByteArray get() = b.copyOf()

    /** The nonce as unpadded base64url (43 characters). */
    override fun toString(): String = Base64Url.encode(b)

    override fun equals(other: Any?): Boolean = other is FetchNonce && other.b.contentEquals(b)

    override fun hashCode(): Int = b.contentHashCode()
}
