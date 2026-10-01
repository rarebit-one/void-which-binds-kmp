package one.rarebit.voidwhichbinds.auth

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA256
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.Ed25519Verifier
import one.rarebit.voidwhichbinds.TokenType
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.MiniJson

/**
 * The **possession proof** half of a `Device` credential — a byte-exact port of
 * void-which-binds-go's `enrolment.SignPossession` / `VerifyPossession` (v0.5.0, what
 * heyarr-core and every other relying party vendor).
 *
 * A cert says a user vouches for a device key; it does not prove the caller HOLDS
 * that key — anyone who saw a cert could otherwise replay it and be its device. A
 * possession proof closes that: the device signs, with its hardware-sealed private
 * key, a short-lived assertion bound to the very cert it is presenting.
 *
 * Wire (Go `encoding/json`, struct field order, compact — the JSON body IS the
 * signed message, there is no domain label):
 * ```
 * body  = {"v":2,"typ":"void-which-binds.possession",
 *          "crt":"<base64url(sha256(cert token bytes))>","iat":<unix s>,"exp":<unix s>}
 * proof = base64url(body) + "." + base64url(ed25519(deviceKey, body))
 * ```
 * `base64url` is RFC 4648 §5 **without padding** (Go's `RawURLEncoding`). `crt` hashes
 * the cert token *as presented* (the whole `payload.sig` string), so a proof cannot be
 * lifted onto a different presentation.
 *
 * The proof is stateless — no server nonce, no round trip — and the price is a replay
 * WINDOW of [DEFAULT_TTL_SECONDS], deliberately tiny. Validity, in the server's check
 * order (`VerifyPossession`): signature, then `v == 2`, then the cert hash, then time —
 * **not-yet-valid tolerates [SKEW_SECONDS] of a device clock running ahead; expiry is
 * strict, zero grace** (void-which-binds-go `PossessionSkew`). A relying party answers every
 * refusal with an undifferentiated `401`, so the client strategy is "re-mint once and
 * retry" — see [DeviceAuthPolicy].
 */
object PossessionProof {

    /** `enrolment.Version` — the cert/proof payload version. */
    const val VERSION = 2

    /** `enrolment.PossessionTTL` — the default proof lifetime (2 minutes). */
    const val DEFAULT_TTL_SECONDS = 120L

    /** `enrolment.PossessionSkew` — how far ahead a device clock may run and still be honoured. */
    const val SKEW_SECONDS = 30L

    /** Why a proof was refused, in the server's check order. */
    enum class Reason { MALFORMED, BAD_SIGNATURE, WRONG_CERT, NOT_YET_VALID, EXPIRED, WRONG_TYPE }

    /** A refused proof, carrying the server-side [reason]. */
    class Refused(val reason: Reason, message: String, cause: Throwable? = null) :
        IllegalArgumentException(message, cause)

    /** The parsed, NOT-yet-verified payload of a proof. Times are unix seconds. */
    data class Payload(
        val version: Int,
        val certHash: String,
        val issuedAt: Long,
        val expiresAt: Long,
        /** ADR-0009 `typ` as read; [verify] only returns a proof whose `typ` is [TokenType.POSSESSION]. */
        val typ: String = "",
    )

    private val sha256 = CryptographyProvider.Default.get(SHA256).hasher()

    /** `base64url(sha256(certToken))` — the `crt` field, computed over the token's UTF-8 bytes. */
    fun certHash(certToken: String): String = Base64Url.encode(sha256.hashBlocking(certToken.encodeToByteArray()))

    /**
     * The exact JSON bytes the device signs:
     * `{"v":2,"typ":"void-which-binds.possession","crt":…,"iat":…,"exp":…}` (ADR-0009:
     * `typ` second, after `v`; gen2 always emits it).
     */
    fun signingBytes(certToken: String, issuedAt: Long, expiresAt: Long): ByteArray {
        val fields = listOf(
            "v" to VERSION,
            "typ" to TokenType.POSSESSION,
            "crt" to certHash(certToken),
            "iat" to issuedAt,
            "exp" to expiresAt,
        )
        return MiniJson.encodeObject(fields).encodeToByteArray()
    }

    /**
     * Mint a proof over [certToken] issued at [now] (unix seconds) for [ttlSeconds],
     * signed by the device key via [signer] — on a phone the hardware-sealed
     * `DeviceKeyStore.asSigner()`, which may block on user presence. A non-positive
     * ttl means [DEFAULT_TTL_SECONDS], as in Go.
     */
    fun mint(certToken: String, signer: Ed25519Signer, now: Long, ttlSeconds: Long = DEFAULT_TTL_SECONDS): String {
        require(certToken.isNotEmpty()) { "possession proof needs a cert token to bind to" }
        val ttl = if (ttlSeconds <= 0) DEFAULT_TTL_SECONDS else ttlSeconds
        val body = signingBytes(certToken, now, now + ttl)
        val sig = signer.sign(body)
        require(sig.size == 64) { "device signer returned ${sig.size} bytes, want a 64-byte Ed25519 signature" }
        return Base64Url.encode(body) + "." + Base64Url.encode(sig)
    }

    /**
     * ADR-0009/ADR-0022: `typ` must be present and say possession (an untyped or
     * gen1-typed proof is [Reason.WRONG_TYPE]). It can only refuse, so, as in
     * void-which-binds-go, [verify] reads it before the signature. A cert or op this device key
     * signed is not a possession proof, whatever fields it carries.
     */
    private fun checkTyp(body: ByteArray) {
        // A body that is not a JSON object is not a type question: leave it to the
        // checks below, so a body corrupted in flight is still BAD_SIGNATURE (Go's
        // sigtoken.CheckTyp does the same).
        val obj = runCatching { MiniJson.parseObject(body.decodeToString()) }.getOrNull() ?: return
        try {
            TokenType.check(obj, TokenType.POSSESSION)
        } catch (e: TokenType.TypeException) {
            val r = when (e.failure) {
                TokenType.Failure.WRONG_TYPE -> Reason.WRONG_TYPE
                TokenType.Failure.MALFORMED -> Reason.MALFORMED
            }
            throw Refused(r, e.message ?: "bad typ", e)
        }
    }

    /** Split and decode a proof WITHOUT verifying it (a client-side freshness read). */
    fun parse(proof: String): Payload = try {
        val dot = proof.indexOf('.')
        require(dot > 0 && dot < proof.length - 1) { "possession proof is not <body>.<sig>" }
        val obj = MiniJson.parseObject(Base64Url.decode(proof.substring(0, dot)).decodeToString())
        Payload(
            version = (obj["v"] as Long).toInt(),
            certHash = obj["crt"] as String,
            issuedAt = obj["iat"] as Long,
            expiresAt = obj["exp"] as Long,
            typ = obj["typ"] as? String ?: "",
        )
    } catch (e: Refused) {
        throw e
    } catch (e: Exception) {
        throw Refused(Reason.MALFORMED, "malformed possession proof: ${e.message}")
    }

    /**
     * Verify [proof] exactly as a relying party does (`enrolment.VerifyPossession`):
     * the device's 32-byte [devicePublicKey] signed it, it is v[VERSION], it names
     * [certToken], and [now] (unix seconds) lies inside its window with the skew
     * asymmetry above. Throws [Refused] with the server's reason, else returns the payload.
     */
    fun verify(
        proof: String,
        devicePublicKey: ByteArray,
        certToken: String,
        now: Long,
        verifier: Ed25519Verifier,
    ): Payload {
        if (devicePublicKey.size != 32) throw Refused(Reason.BAD_SIGNATURE, "no 32-byte device key to check against")
        val dot = proof.indexOf('.')
        if (dot <= 0 || dot >= proof.length - 1) throw Refused(Reason.MALFORMED, "possession proof is not <body>.<sig>")
        val body: ByteArray
        val sig: ByteArray
        try {
            body = Base64Url.decode(proof.substring(0, dot))
            sig = Base64Url.decode(proof.substring(dot + 1))
        } catch (e: IllegalArgumentException) {
            throw Refused(Reason.MALFORMED, "possession proof is not base64url: ${e.message}")
        }
        checkTyp(body)
        if (sig.size != 64 || !verifier.verify(devicePublicKey, body, sig)) {
            throw Refused(Reason.BAD_SIGNATURE, "possession proof is not signed by the device key")
        }
        val p = parse(proof)
        if (p.version != VERSION || p.certHash.isEmpty()) {
            throw Refused(Reason.MALFORMED, "possession proof payload is not v$VERSION")
        }
        if (p.certHash != certHash(certToken)) {
            throw Refused(Reason.WRONG_CERT, "possession proof is bound to a different cert")
        }
        if (now + SKEW_SECONDS < p.issuedAt) {
            throw Refused(Reason.NOT_YET_VALID, "possession proof valid from ${p.issuedAt}, now $now")
        }
        if (now >= p.expiresAt) {
            throw Refused(Reason.EXPIRED, "possession proof expired at ${p.expiresAt}, now $now")
        }
        return p
    }
}
