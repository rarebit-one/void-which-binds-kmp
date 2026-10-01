package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Base64Url
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * Whether [Ed25519Engine] signs deterministically (RFC 8032) on this target.
 *
 * `true` on JVM/Android: the JDK provider signs deterministically, so a signature
 * over a Go vector's preimage must equal Go's signature byte-for-byte. `false` on
 * Apple: CryptoKit signs with randomized (hedged) Ed25519, so the bytes differ on
 * every call. Such a signature is still a valid Ed25519 signature that void-which-binds-go
 * verifies.
 */
internal expect val ed25519SigningIsDeterministic: Boolean

/**
 * Assert that [actual], a `base64url(payload).base64url(sig)` token minted here,
 * matches void-which-binds-go's [expected] token for the same inputs.
 *
 * On a deterministic target the whole token must be byte-identical. On a randomized
 * one (iOS) the PAYLOAD must still be byte-identical, because it is the signed wire
 * encoding. Our signature must verify under [signerPublicKey], and so must Go's
 * signature, which proves both halves agree on the key and the preimage.
 */
internal fun assertMatchesGoToken(
    expected: String,
    actual: String,
    signerPublicKey: ByteArray,
    message: String? = null,
) {
    if (ed25519SigningIsDeterministic) {
        assertEquals(expected, actual, message)
        return
    }
    val (expPayload, expSig) = expected.splitToken()
    val (actPayload, actSig) = actual.splitToken()
    assertEquals(expPayload, actPayload, "${message ?: "token"}: payload must match void-which-binds-go byte-for-byte")
    val signed = Base64Url.decode(actPayload)
    assertGoSignatureVerifies(expSig, actSig, signerPublicKey, signed, message)
}

/**
 * Assert that [actualSig] (base64url), a signature over [signed] made here, matches
 * void-which-binds-go's [expectedSig]. The bytes must be equal on a deterministic target. On
 * a randomized one, both signatures must verify under [signerPublicKey].
 */
internal fun assertMatchesGoSignature(
    expectedSig: String,
    actualSig: String,
    signerPublicKey: ByteArray,
    signed: ByteArray,
    message: String? = null,
) {
    if (ed25519SigningIsDeterministic) {
        assertEquals(expectedSig, actualSig, message)
        return
    }
    assertGoSignatureVerifies(expectedSig, actualSig, signerPublicKey, signed, message)
}

private fun assertGoSignatureVerifies(
    expectedSig: String,
    actualSig: String,
    signerPublicKey: ByteArray,
    signed: ByteArray,
    message: String?,
) {
    val what = message ?: "signature"
    assertTrue(
        Ed25519Engine.verify(signerPublicKey, signed, Base64Url.decode(actualSig)),
        "$what: our signature must verify under the signer's public key",
    )
    assertTrue(
        Ed25519Engine.verify(signerPublicKey, signed, Base64Url.decode(expectedSig)),
        "$what: void-which-binds-go's signature must verify under our public key over our preimage",
    )
}

private fun String.splitToken(): Pair<String, String> {
    val dot = indexOf('.')
    require(dot > 0 && dot < length - 1) { "not a <payload>.<sig> token: $this" }
    return substring(0, dot) to substring(dot + 1)
}
