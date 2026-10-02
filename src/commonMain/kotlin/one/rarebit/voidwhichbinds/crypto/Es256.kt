package one.rarebit.voidwhichbinds.crypto

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EC
import dev.whyoleg.cryptography.algorithms.ECDSA
import dev.whyoleg.cryptography.algorithms.SHA256

/**
 * ES256 (ECDSA over P-256 with SHA-256) signature verification, via
 * cryptography-kotlin's ECDSA — the JDK provider (`SHA256withECDSA`) on
 * JVM/Android and CryptoKit (`P256.Signing`) on Apple. Signature verification is
 * not hand-rolled; only the public-point validation ([P256]) is, because that is
 * the one check whose behaviour must not vary by provider.
 *
 * The signature is a DER `Ecdsa-Sig-Value` (WebAuthn's form, and what Go's
 * `ecdsa.VerifyASN1` takes). A non-DER signature, one with trailing bytes, or a
 * provider exception is "does not verify".
 */
internal object Es256 {

    private val ecdsa = CryptographyProvider.Default.get(ECDSA)
    private val publicDecoder = ecdsa.publicKeyDecoder(EC.Curve.P256)

    /** The provider's key for a SEC1 uncompressed [point]; null if it refuses it. */
    fun publicKeyOrNull(point: ByteArray): ECDSA.PublicKey? = try {
        if (!P256.isValidUncompressedPoint(point)) {
            null
        } else {
            publicDecoder.decodeFromByteArrayBlocking(EC.PublicKey.Format.RAW, point)
        }
    } catch (@Suppress("TooGenericExceptionCaught") _: Exception) {
        null
    }

    /** Whether [der] is a valid ES256 signature by [key] over [message] (hashed with SHA-256 here). */
    fun verify(key: ECDSA.PublicKey, message: ByteArray, der: ByteArray): Boolean = try {
        key.signatureVerifier(SHA256, ECDSA.SignatureFormat.DER).tryVerifySignatureBlocking(message, der)
    } catch (@Suppress("TooGenericExceptionCaught") _: Exception) {
        false
    }
}
