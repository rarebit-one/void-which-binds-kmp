package one.rarebit.voidwhichbinds

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.SHA256
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.MiniJson

/**
 * The pairing refusal of void-which-binds-go ADR-0012 (`pairflow/refusal.go`), byte for byte.
 * It lets an initiator tell the joining device "no" when a human rejects the SAS or
 * cancels, so the joiner stops at once instead of waiting out its relay timeout.
 *
 * It is a compact signed token (`base64url(body).base64url(sig)`), typed from its
 * first version (ADR-0009), posted to the initiator's [SLOT] relay slot:
 *
 *     {"v":1,"typ":"void-which-binds.pair-refusal","by":"ed25519:<hex>","ses":"<b64url>"}
 *
 * `by` is the initiator's signing key (the key the responder bound into the SAS) and
 * the token is signed by it, so nobody else on the relay can make a joiner give up.
 * `ses` binds it to one pairing:
 * `base64url(SHA-256("void-which-binds/pairflow/refusal/session/v1" ‖ 0x00 ‖ salt))`.
 *
 * Pinned by void-which-binds-go's `testvectors/vectors/pair-refusal-vector.json`
 * (`PairRefusalVectorTest`).
 */
object PairRefusal {
    /** The relay slot a refusal is posted to (void-which-binds-go `pairflow.MsgRefuse`). */
    const val SLOT = "refuse"

    /** The ADR-0009 `typ` claim (void-which-binds-go `pairflow.RefusalTyp`). */
    const val TYP = "void-which-binds.pair-refusal"

    /** `v` within [TYP]. */
    const val VERSION = 1

    /** Domain-separates the session binding. Part of the wire; never rename. */
    const val SESSION_LABEL = "void-which-binds/pairflow/refusal/session/v1"

    private const val KEY_LEN = 32
    private const val SIG_LEN = 64

    private val sha256 = CryptographyProvider.Default.get(SHA256).hasher()

    /** The `ses` claim for a session [salt] (void-which-binds-go `pairflow.RefusalSession`). */
    fun session(salt: ByteArray): String =
        Base64Url.encode(sha256.hashBlocking(SESSION_LABEL.encodeToByteArray() + byteArrayOf(0) + salt))

    /**
     * Mint a refusal of the pairing under [salt], signed by [signer] whose public key is
     * [signPublicKey] (a member device's key, or genesis's). Mirrors void-which-binds-go
     * `pairflow.SignRefusal`.
     */
    fun sign(signer: Ed25519Signer, signPublicKey: ByteArray, salt: ByteArray): String {
        require(signPublicKey.size == KEY_LEN) { "pairflow: a 32-byte ed25519 key is required" }
        val body = MiniJson.encodeObject(
            listOf(
                "v" to VERSION,
                "typ" to TYP,
                "by" to KeyRef.ed25519(signPublicKey).render(),
                "ses" to session(salt),
            ),
        ).encodeToByteArray()
        return Base64Url.encode(body) + "." + Base64Url.encode(signer.sign(body))
    }

    /**
     * Whether [token] is a refusal of the pairing under [salt], signed by [initiator]
     * (the SAS-bound initiator key). Anything else is `false`, and a responder ignores
     * it. Mirrors void-which-binds-go `pairflow.VerifyRefusal`: the signature is checked first,
     * then `typ` must be present and exactly [TYP] (no case-variant key), `v` must be
     * [VERSION], `by` the initiator and `ses` this session's binding.
     */
    fun verify(
        token: String,
        initiator: ByteArray,
        salt: ByteArray,
        verifier: Ed25519Verifier = Ed25519Engine.verifier(),
    ): Boolean = runCatching {
        require(initiator.size == KEY_LEN)
        val parts = token.split('.', limit = 2)
        require(parts.size == 2)
        val body = decodeStrict(parts[0])
        val sig = decodeStrict(parts[1])
        require(sig.size == SIG_LEN && verifier.verify(initiator, body, sig))
        val obj = MiniJson.parseObject(body.decodeToString())
        // A refusal is typed from its first version: typ must be present, and exactly TYP.
        TokenType.check(obj, TYP) == TYP &&
            obj["v"] == VERSION.toLong() &&
            obj["by"] == KeyRef.ed25519(initiator).render() &&
            obj["ses"] == session(salt)
    }.getOrDefault(false)

    private fun decodeStrict(s: String): ByteArray {
        require(!s.contains('=') && !s.contains('+') && !s.contains('/'))
        return Base64Url.decode(s)
    }
}

/**
 * The initiator the SAS bound refused the pairing (void-which-binds-go `pairflow.ErrRefused`):
 * nothing was admitted. Thrown by [one.rarebit.voidwhichbinds.net.PairflowResponder.receive].
 */
class PairingRefusedException : RuntimeException("pairflow: the initiator refused the pairing")
