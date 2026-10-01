package one.rarebit.voidwhichbinds

import java.security.KeyFactory
import java.security.KeyPair
import java.security.KeyPairGenerator
import java.security.PrivateKey
import java.security.PublicKey
import java.security.Signature
import java.security.spec.X509EncodedKeySpec

/**
 * JVM software Ed25519, built on the JDK's own provider (Ed25519 is standard from
 * JDK 15+; this project targets JDK 21). Test-only: it lives in jvmTest and backs
 * the real-Ed25519 checks in JvmDeviceKeyStoreTest. The keys are ordinary in-heap
 * software keys, NOT hardware-backed. Production signing on a
 * device must go through the iOS Secure Enclave / Android StrongBox `actual`s.
 */
internal object JvmEd25519 {

    fun generate(): KeyPair = KeyPairGenerator.getInstance("Ed25519").genKeyPair()

    /**
     * Raw 32-byte Ed25519 public key. The JDK encodes an Ed25519 public key as a
     * 44-byte X.509 SubjectPublicKeyInfo whose trailing 32 bytes are exactly the
     * raw key, so we slice those off.
     */
    fun rawPublicKey(pub: PublicKey): ByteArray {
        val x509 = pub.encoded
        require(x509.size >= 32) { "unexpected Ed25519 public key encoding (${x509.size} bytes)" }
        return x509.copyOfRange(x509.size - 32, x509.size)
    }

    /** Rebuild a [PublicKey] from raw 32 bytes by prefixing the fixed X.509 header. */
    fun publicKeyFromRaw(raw: ByteArray): PublicKey {
        require(raw.size == 32) { "Ed25519 public key must be 32 bytes, got ${raw.size}" }
        // Fixed SubjectPublicKeyInfo prefix for Ed25519 (RFC 8410).
        val header = byteArrayOf(
            0x30, 0x2a, 0x30, 0x05, 0x06, 0x03, 0x2b, 0x65, 0x70, 0x03, 0x21, 0x00,
        )
        val spki = header + raw
        return KeyFactory.getInstance("Ed25519").generatePublic(X509EncodedKeySpec(spki))
    }

    fun sign(priv: PrivateKey, message: ByteArray): ByteArray {
        val s = Signature.getInstance("Ed25519")
        s.initSign(priv)
        s.update(message)
        return s.sign()
    }

    fun verify(rawPublicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean = try {
        val s = Signature.getInstance("Ed25519")
        s.initVerify(publicKeyFromRaw(rawPublicKey))
        s.update(message)
        s.verify(signature)
    } catch (_: Exception) {
        false
    }

    /** An [Ed25519Verifier] backed by the JDK provider — usable from tests. */
    fun verifier(): Ed25519Verifier = Ed25519Verifier(::verify)
}
