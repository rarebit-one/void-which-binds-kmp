package one.rarebit.voidwhichbinds

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.SHA256
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Es256
import one.rarebit.voidwhichbinds.crypto.StrictJson

/**
 * One relying party a deployment accepts assertions for: an RP ID and the exact
 * origins that may assert for it (ADR-0018 pins the RP ID per deployment, not in the
 * key string). Go `identity.WebAuthnRP`.
 */
data class WebAuthnRp(val rpId: String, val origins: List<String>)

/**
 * What a verifier accepts from a `webauthn:` key. Go `identity.WebAuthnPolicy`.
 *
 * @property rps the allow-list of {RP ID, origins} pairs. `clientDataJSON.origin` must
 *   exactly equal one listed origin, and authenticatorData's rpIdHash must be SHA-256
 *   of an RP ID that lists that origin. An empty list refuses every assertion.
 * @property allowSynced admits a backup-eligible (BE=1, synced) passkey; set it only
 *   for an org-managed person in an org deployment (ADR-0018, fail closed).
 */
data class WebAuthnPolicy(val rps: List<WebAuthnRp> = emptyList(), val allowSynced: Boolean = false)

/**
 * ADR-0018's WebAuthn relying-party checks, a port of void-which-binds-go
 * `identity/webauthn.go`.
 */
object WebAuthn {

    /** The label ADR-0018's challenge derivation starts with. Go `WebAuthnChallengeLabel`. */
    const val CHALLENGE_LABEL: String = "void-which-binds/webauthn/challenge/v1"

    private val sha256 = CryptographyProvider.Default.get(SHA256).hasher()

    /**
     * The challenge a `webauthn:` member key asserts over to sign [body] under [domain]:
     *
     *     SHA-256( "void-which-binds/webauthn/challenge/v1" ‖ 0x00 ‖ domain ‖ 0x00 ‖ body )
     *
     * The client passes these 32 bytes as `PublicKeyCredentialRequestOptions.challenge`
     * with `userVerification: "required"`. [domain] must not contain NUL;
     * [MemberKey.verifyBody] refuses one that does. Go `identity.WebAuthnChallenge`.
     */
    fun challenge(domain: String, body: ByteArray): ByteArray =
        sha256.hashBlocking(CHALLENGE_LABEL.encodeToByteArray() + NUL + domain.encodeToByteArray() + NUL + body)

    private val NUL = byteArrayOf(0)

    // authenticatorData flag bits (WebAuthn L3 §6.1).
    private const val FLAG_UP = 0x01
    private const val FLAG_UV = 0x04
    private const val FLAG_BE = 0x08
    private const val FLAG_BS = 0x10
    private const val FLAG_AT = 0x40
    private const val FLAG_ED = 0x80

    /** rpIdHash (32) ‖ flags (1) ‖ signCount (4). */
    private const val AUTH_DATA_MIN_LEN = 37
    private const val RP_ID_HASH_LEN = 32
    private const val BYTE_MASK = 0xFF

    /** Bound on the envelope before any parsing (Go `maxEnvelopeLen`, 16 KiB). */
    private const val MAX_ENVELOPE_LEN = 16 shl 10

    private val BOM = byteArrayOf(0xEF.toByte(), 0xBB.toByte(), 0xBF.toByte())

    private fun fail(failure: MemberKeyFailure, why: String): Nothing = throw MemberKeyException(failure, why)

    /** Go `checkDomain`: an empty domain, or one containing NUL, cannot be framed unambiguously. */
    internal fun checkDomain(domain: String) {
        if (domain.isEmpty() || domain.contains('\u0000')) {
            fail(MemberKeyFailure.INVALID_DOMAIN, "the webauthn challenge domain \"$domain\" is empty or contains NUL")
        }
    }

    private class Envelope(val authData: ByteArray, val clientData: ByteArray, val sig: ByteArray)

    private class ClientData(
        val type: String,
        val challenge: String,
        val origin: String,
        val crossOrigin: Boolean,
        val hasTopOrigin: Boolean,
    )

    /**
     * ADR-0018's checks for an assertion over [challenge]. Structural problems are
     * found first (envelope, then §7.2 steps 7–9, then the authenticatorData layout);
     * the semantic checks then run in §7.2 order, signature last. Go
     * `MemberKey.verifyWebAuthn`.
     */
    @Suppress("CyclomaticComplexMethod", "ThrowsCount")
    internal fun verify(
        key: ECDSA.PublicKey,
        keyText: String,
        challenge: ByteArray,
        seg: ByteArray,
        policy: WebAuthnPolicy,
    ) {
        val env = parseEnvelope(seg)
        val cd = parseClientData(env.clientData)
        val ad = env.authData
        checkAuthDataLayout(ad)
        val flags = ad[RP_ID_HASH_LEN].toInt() and BYTE_MASK

        // §7.2 step 10.
        if (cd.type != "webauthn.get") fail(MemberKeyFailure.WRONG_CEREMONY, "type is \"${cd.type}\"")
        // Step 11.
        val want = Base64Url.encode(challenge)
        if (cd.challenge != want) {
            fail(MemberKeyFailure.CHALLENGE_MISMATCH, "clientDataJSON names \"${cd.challenge}\", want \"$want\"")
        }
        // Step 12: exact string match against the allow-list (§13.4.9).
        val rpIds = policy.rps.filter { cd.origin in it.origins }.map { it.rpId }
        if (rpIds.isEmpty()) fail(MemberKeyFailure.ORIGIN_NOT_ALLOWED, "\"${cd.origin}\"")
        // Steps 13–14: Phase 1 has no iframe embedding.
        if (cd.crossOrigin) fail(MemberKeyFailure.ORIGIN_NOT_ALLOWED, "crossOrigin is true")
        if (cd.hasTopOrigin) fail(MemberKeyFailure.ORIGIN_NOT_ALLOWED, "topOrigin is present")
        // Step 15.
        val rpIdHash = ad.copyOfRange(0, RP_ID_HASH_LEN)
        if (rpIds.none { sha256.hashBlocking(it.encodeToByteArray()).contentEquals(rpIdHash) }) {
            fail(MemberKeyFailure.RP_ID_MISMATCH, "origin \"${cd.origin}\"")
        }
        // Steps 16–17.
        if (flags and FLAG_UP == 0) fail(MemberKeyFailure.USER_NOT_PRESENT, "webauthn assertion without user presence")
        if (flags and FLAG_UV ==
            0
        ) {
            fail(MemberKeyFailure.USER_NOT_VERIFIED, "webauthn assertion without user verification")
        }
        // Steps 18–19 (§6.1.3).
        if (flags and FLAG_BE == 0 && flags and FLAG_BS != 0) {
            fail(MemberKeyFailure.ASSERTION_MALFORMED, "BS is set without BE")
        }
        if (flags and FLAG_BE != 0 && !policy.allowSynced) {
            fail(MemberKeyFailure.SYNCED_NOT_ALLOWED, "synced (backup-eligible) passkey not allowed for this person")
        }
        // Steps 20–21: ES256 over authData ‖ SHA-256(clientDataJSON), DER only. Step 22
        // (signCount) is deliberately ignored (ADR-0018).
        val message = ad + sha256.hashBlocking(env.clientData)
        if (!Es256.verify(key, message, env.sig)) {
            fail(MemberKeyFailure.BAD_SIGNATURE, "ES256 assertion by $keyText does not verify")
        }
    }

    /**
     * Decodes `{"ad":…,"cd":…,"sig":…}`. A segment that is not a JSON object at all is
     * the other scheme's signature (`bad_signature`); a JSON object that breaks the
     * envelope's rules is malformed. Go `parseEnvelope`.
     */
    @Suppress("ThrowsCount")
    private fun parseEnvelope(seg: ByteArray): Envelope {
        // The size bound comes first, so no parser ever scans an oversized segment.
        if (seg.size > MAX_ENVELOPE_LEN) {
            fail(MemberKeyFailure.ASSERTION_MALFORMED, "the envelope is ${seg.size} bytes, over $MAX_ENVELOPE_LEN")
        }
        val members = when (val r = StrictJson.read(seg)) {
            is StrictJson.Outcome.Invalid ->
                fail(MemberKeyFailure.BAD_SIGNATURE, "the signature segment is not a webauthn assertion envelope")

            is StrictJson.Outcome.Refused -> fail(MemberKeyFailure.ASSERTION_MALFORMED, "envelope: ${r.reason}")

            is StrictJson.Outcome.Ok -> r.members
        }
        if (members.size != ENVELOPE_FIELDS.size) {
            fail(MemberKeyFailure.ASSERTION_MALFORMED, "the envelope must have exactly ad, cd and sig")
        }
        val decoded = ENVELOPE_FIELDS.map { name ->
            val v = members[name] ?: fail(MemberKeyFailure.ASSERTION_MALFORMED, "the envelope has no \"$name\"")
            if (v !is StrictJson.Value.Str) {
                fail(
                    MemberKeyFailure.ASSERTION_MALFORMED,
                    "envelope \"$name\" is not a string",
                )
            }
            strictBase64Url(v.value)?.takeIf { it.isNotEmpty() }
                ?: fail(MemberKeyFailure.ASSERTION_MALFORMED, "envelope \"$name\" is not unpadded base64url")
        }
        return Envelope(decoded[0], decoded[1], decoded[2])
    }

    private val ENVELOPE_FIELDS = listOf("ad", "cd", "sig")

    /**
     * Unpadded base64url under Go's `RawURLEncoding.Strict()` (and refusing CR/LF,
     * which Go's decoder would otherwise skip): the canonical encoding only, so a
     * string whose unused trailing bits are not zero is refused. Null if invalid.
     */
    private fun strictBase64Url(s: String): ByteArray? {
        val b = try {
            Base64Url.decode(s)
        } catch (_: IllegalArgumentException) {
            return null
        }
        return if (Base64Url.encode(b) == s) b else null
    }

    /**
     * §7.2 steps 7–9: strip one leading UTF-8 BOM, then parse strictly. Duplicate keys
     * at any depth, invalid UTF-8, trailing data, and a missing or non-string `type`,
     * `challenge` or `origin` are malformed; so is a `crossOrigin` that is present and
     * not a boolean. Other members are allowed and ignored. Go `parseClientData`.
     */
    @Suppress("ThrowsCount")
    private fun parseClientData(raw: ByteArray): ClientData {
        val bytes = if (raw.size >= BOM.size && raw.copyOfRange(0, BOM.size).contentEquals(BOM)) {
            raw.copyOfRange(BOM.size, raw.size)
        } else {
            raw
        }
        if (!StrictJson.isValidUtf8(bytes)) fail(MemberKeyFailure.ASSERTION_MALFORMED, "clientDataJSON is not UTF-8")
        val members = when (val r = StrictJson.read(bytes)) {
            is StrictJson.Outcome.Invalid -> fail(MemberKeyFailure.ASSERTION_MALFORMED, "clientDataJSON: ${r.reason}")
            is StrictJson.Outcome.Refused -> fail(MemberKeyFailure.ASSERTION_MALFORMED, "clientDataJSON: ${r.reason}")
            is StrictJson.Outcome.Ok -> r.members
        }
        fun str(name: String): String = (members[name] as? StrictJson.Value.Str)?.value
            ?: fail(MemberKeyFailure.ASSERTION_MALFORMED, "clientDataJSON \"$name\" is missing or not a string")
        val type = str("type")
        val challenge = str("challenge")
        val origin = str("origin")
        val crossOrigin = when (members["crossOrigin"]) {
            null, StrictJson.Value.False -> false
            StrictJson.Value.True -> true
            else -> fail(MemberKeyFailure.ASSERTION_MALFORMED, "clientDataJSON crossOrigin is not a boolean")
        }
        return ClientData(type, challenge, origin, crossOrigin, hasTopOrigin = "topOrigin" in members)
    }

    /**
     * rpIdHash ‖ flags ‖ signCount, exactly 37 bytes, unless ED is set, when extension
     * CBOR follows (not parsed, but covered by the signature). AT on an assertion is
     * malformed. Go `checkAuthDataLayout`.
     */
    private fun checkAuthDataLayout(ad: ByteArray) {
        if (ad.size < AUTH_DATA_MIN_LEN) {
            fail(
                MemberKeyFailure.ASSERTION_MALFORMED,
                "authenticatorData is ${ad.size} bytes, under $AUTH_DATA_MIN_LEN",
            )
        }
        val flags = ad[RP_ID_HASH_LEN].toInt() and BYTE_MASK
        if (flags and FLAG_AT != 0) {
            fail(MemberKeyFailure.ASSERTION_MALFORMED, "AT (attested credential data) is set on an assertion")
        }
        if (flags and FLAG_ED == 0 && ad.size != AUTH_DATA_MIN_LEN) {
            fail(
                MemberKeyFailure.ASSERTION_MALFORMED,
                "authenticatorData has ${ad.size - AUTH_DATA_MIN_LEN} trailing bytes and no ED flag",
            )
        }
        if (flags and FLAG_ED != 0 && ad.size == AUTH_DATA_MIN_LEN) {
            fail(MemberKeyFailure.ASSERTION_MALFORMED, "ED is set and no extension data follows")
        }
    }
}
