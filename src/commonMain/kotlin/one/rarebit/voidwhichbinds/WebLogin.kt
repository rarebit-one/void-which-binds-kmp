package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Base64Url

/**
 * The device side of Void-Which-Binds's **web QR-login** (WhatsApp-Web pattern), ported
 * byte-for-byte from void-which-binds-go's `weblogin` package. A relying party (All Thing,
 * a homelab web app) shows a QR `voidbind:login?rp=<base>&id=<id>`; the device
 * fetches the challenge, **signs it with its hardware device key**, and posts the
 * assertion; the RP verifies it offline against the pinned user key (via
 * void-which-binds-go/rp) and issues a short-lived session token.
 *
 * This object is the crypto half — the exact preimage the device signs and the
 * assertion it returns. The HTTP fetch/approve calls and the QR scanning live in
 * the app. Every hashed/signed byte matches void-which-binds-go, so an assertion produced
 * here is accepted by void-which-binds-go's `weblogin.Verify` unchanged.
 */
object WebLogin {

    /** Domain separation for the signed challenge preimage (matches void-which-binds-go). */
    const val ASSERTION_DOMAIN = "voidbind/weblogin/challenge/v1"

    /**
     * Domain separation for a **number-matching (v2)** challenge preimage (ADR-0006).
     * A v2 preimage folds in the match number, so it carries its own version — a v1
     * signature can never be replayed as a v2 approval, or a v2 as a v1. Matches
     * void-which-binds-go's `assertionDomainV2`.
     */
    const val ASSERTION_DOMAIN_V2 = "voidbind/weblogin/challenge/v2"

    /** Challenge nonce length — 256 bits of freshness (anti-replay). */
    const val NONCE_LEN = 32

    /**
     * A login challenge the RP issues and the device signs. [expiresAt] is unix
     * seconds. [issuedAt] is not part of the signed preimage (void-which-binds-go binds
     * id, nonce, audience, expiry) so it is omitted here.
     *
     * [candidates] is the **display-only** set a number-matching (v2) challenge
     * shows on the phone (the true match plus decoys, shuffled). It is NOT part of
     * [signingBytes] and does NOT reveal the true number — that stays with the RP,
     * and the human bridges it from the initiating surface. Empty for a v1 challenge.
     */
    class Challenge(
        val id: String,
        val nonce: ByteArray,
        val audience: String,
        val expiresAt: Long,
        val candidates: List<Int> = emptyList(),
    ) {
        /** True when this is a v2 (number-matching) challenge — the phone shows candidates. */
        val isNumberMatch: Boolean get() = candidates.isNotEmpty()
    }

    /**
     * A device's approval of a challenge: its enrolment [cert] token and the
     * base64url [sig]nature by its device key over the challenge preimage. This is
     * the JSON the device POSTs to the RP's approve endpoint (`{"cert":...,"sig":...}`).
     *
     * [matchNumber], when non-null, is the number the human tapped for a v2
     * (number-matching) approval — the signature binds THIS number, and the RP
     * refuses the approval unless it equals the challenge's true match. Serialised as
     * `match_number`, omitted for a v1 approval (matches void-which-binds-go's
     * `Assertion.MatchNumber` with `omitempty`).
     *
     * [ops] are the membership ops the device knows (ADR-0005; at most
     * [MAX_PRESENTED_OPS]), so an RP that has never met the member that admitted this
     * device can evaluate the admission. Serialised as `ops`, omitted when empty; not
     * part of the signed assertion because each op is signed on its own. [cert] is the
     * device's ADMITTING op — a v3 add, or a v1/v2 cert, which is one.
     */
    data class Assertion(
        val cert: String,
        val sig: String,
        val matchNumber: Int? = null,
        val ops: List<String> = emptyList(),
    )

    /** The most membership ops an RP accepts beside a credential (void-which-binds-go `rp.MaxPresentedOps`). */
    const val MAX_PRESENTED_OPS = 64

    /**
     * The exact, domain-separated, 8-byte-big-endian length-framed preimage the
     * device signs and the RP verifies — matching void-which-binds-go's
     * `Challenge.signingBytes`. Framing every field means the signature binds
     * precisely (id, nonce, audience, expiry) and nothing else.
     *
     * This is the v1 preimage; [signingBytesV2] appends the framed match number.
     */
    fun signingBytes(challenge: Challenge): ByteArray = frame(
        listOf(
            ASSERTION_DOMAIN.encodeToByteArray(),
            challenge.id.encodeToByteArray(),
            challenge.nonce,
            challenge.audience.encodeToByteArray(),
            be64(challenge.expiresAt),
        ),
    )

    /**
     * The v2 (number-matching) preimage: the v1 fields under the v2 domain, plus the
     * [chosen] match number framed as an 8-byte big-endian value at the end —
     * matching void-which-binds-go's `Challenge.signingBytes` when `MatchNumber` is set. The
     * signature over this binds the approval to the number the human tapped, so
     * tapping a decoy yields a signature that cannot verify against the true
     * challenge (the binding holds even if the equality gate were bypassed).
     */
    fun signingBytesV2(challenge: Challenge, chosen: Int): ByteArray = frame(
        listOf(
            ASSERTION_DOMAIN_V2.encodeToByteArray(),
            challenge.id.encodeToByteArray(),
            challenge.nonce,
            challenge.audience.encodeToByteArray(),
            be64(challenge.expiresAt),
            be64(chosen.toLong()),
        ),
    )

    /**
     * Sign [challenge] with the device key and return the assertion to POST. [sign]
     * is the device signer — in production `deviceKeyStore::sign` (hardware,
     * biometric-gated); in tests a software signer over a known seed. [certToken]
     * is the device's enrolment cert; the signing key must be the one that cert
     * names, or the RP's `weblogin.Verify` refuses the assertion.
     */
    fun signAssertion(
        challenge: Challenge,
        certToken: String,
        ops: List<String> = emptyList(),
        sign: (ByteArray) -> ByteArray,
    ): Assertion {
        require(certToken.isNotEmpty()) { "weblogin: a device enrolment cert is required" }
        val sig = sign(signingBytes(challenge))
        return Assertion(cert = certToken, sig = Base64Url.encode(sig), ops = presentable(ops))
    }

    /**
     * Sign a **number-matching (v2)** approval: the device signs [challenge] bound to
     * the number the human [chosen] (tapped), and returns an assertion carrying that
     * number. The device only ever knows the candidate set (from the RP's challenge);
     * it does not learn the true match, so it signs whatever the human picked — the RP
     * then refuses the approval unless the chosen number equals its stored true match
     * (its `ErrNumberMismatch`), restoring the origin-binding a scanned QR gave for
     * free. Matches void-which-binds-go's `SignAssertionV2`.
     */
    fun signAssertionV2(
        challenge: Challenge,
        chosen: Int,
        certToken: String,
        ops: List<String> = emptyList(),
        sign: (ByteArray) -> ByteArray,
    ): Assertion {
        require(certToken.isNotEmpty()) { "weblogin: a device enrolment cert is required" }
        val sig = sign(signingBytesV2(challenge, chosen))
        return Assertion(cert = certToken, sig = Base64Url.encode(sig), matchNumber = chosen, ops = presentable(ops))
    }

    /**
     * The ops a device presents beside its credential: de-duplicated by hash, in hash
     * order, capped at [MAX_PRESENTED_OPS] (an RP refuses more). A replica that has
     * outgrown the cap presents its first 64 in hash order — deterministic, and the
     * RP already holds what it has seen before.
     */
    fun presentable(ops: List<String>): List<String> = Membership.merge(ops).take(MAX_PRESENTED_OPS)

    /** 8-byte big-endian encoding of [v] (unsigned), matching Go's `binary.BigEndian`. */
    private fun be64(v: Long): ByteArray {
        val out = ByteArray(8)
        var e = v
        for (i in 7 downTo 0) {
            out[i] = (e and 0xFF).toByte()
            e = e ushr 8
        }
        return out
    }

    /** 8-byte big-endian length-framed preimage, matching void-which-binds-go's `writeField`. */
    private fun frame(parts: List<ByteArray>): ByteArray {
        var size = 0
        for (p in parts) size += 8 + p.size
        val out = ByteArray(size)
        var i = 0
        for (p in parts) {
            val n = p.size.toLong()
            for (shift in 56 downTo 0 step 8) {
                out[i++] = (n ushr shift).toByte()
            }
            p.copyInto(out, i)
            i += p.size
        }
        return out
    }
}
