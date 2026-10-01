package one.rarebit.voidwhichbinds

import dev.whyoleg.cryptography.CryptographyProvider
import dev.whyoleg.cryptography.algorithms.EdDSA

/**
 * Software Ed25519, multiplatform, via cryptography-kotlin — the JDK provider on
 * JVM/Android and CryptoKit on Apple. It operates on **RAW 32-byte seeds** and
 * **RAW 32-byte public keys** on purpose: the [DeviceKeyStore] actuals seal the
 * private seed with a hardware wrapping key at rest, and re-import it here only
 * transiently to sign.
 *
 * This is deliberately the **software** half of the device key. Non-extractability
 * comes from the platform seal around the seed (StrongBox AES-GCM / Secure-Enclave
 * ECIES); see docs/adr/0001-hardware-keystore-mechanism.md. Ed25519 itself is not
 * hand-rolled — it is the vetted provider's implementation.
 */
internal object Ed25519Engine {

    private val eddsa = CryptographyProvider.Default.get(EdDSA)
    private val generator = eddsa.keyPairGenerator(EdDSA.Curve.Ed25519)
    private val privateDecoder = eddsa.privateKeyDecoder(EdDSA.Curve.Ed25519)
    private val publicDecoder = eddsa.publicKeyDecoder(EdDSA.Curve.Ed25519)

    /** A freshly generated device key, as raw bytes ready to seal. */
    class Generated(val privateSeed: ByteArray, val publicKey: ByteArray)

    /** Generate a new Ed25519 key; returns the RAW 32-byte seed + 32-byte public key. */
    fun generate(): Generated {
        val pair = generator.generateKeyBlocking()
        val seed = pair.privateKey.encodeToByteArrayBlocking(EdDSA.PrivateKey.Format.RAW)
        val pub = pair.publicKey.encodeToByteArrayBlocking(EdDSA.PublicKey.Format.RAW)
        return Generated(seed, pub)
    }

    // Note: deriving the public key FROM a private seed is intentionally not
    // offered — the JDK provider cannot do it without BouncyCastle, and the
    // keystore has no need: [generate] returns the public key, and every store
    // persists it (it is not secret) alongside the sealed seed. So publicKey() on
    // a DeviceKeyStore is a stored-bytes lookup, never a re-derivation.

    /** Sign [message] with a RAW 32-byte private [seed]; returns a 64-byte signature. */
    fun sign(seed: ByteArray, message: ByteArray): ByteArray {
        val priv = privateDecoder.decodeFromByteArrayBlocking(EdDSA.PrivateKey.Format.RAW, seed)
        return priv.signatureGenerator().generateSignatureBlocking(message)
    }

    /** Verify a 64-byte [signature] over [message] against a RAW 32-byte [publicKey]. */
    fun verify(publicKey: ByteArray, message: ByteArray, signature: ByteArray): Boolean {
        val pub = publicDecoder.decodeFromByteArrayBlocking(EdDSA.PublicKey.Format.RAW, publicKey)
        return pub.signatureVerifier().tryVerifySignatureBlocking(message, signature)
    }

    /** An [Ed25519Verifier] backed by the provider — usable from common tests. */
    fun verifier(): Ed25519Verifier = Ed25519Verifier(::verify)
}
