package one.rarebit.voidwhichbinds

import dev.whyoleg.cryptography.random.CryptographyRandom
import one.rarebit.voidwhichbinds.crypto.X25519

/**
 * This device's own key material, used by every device-side flow (pairing,
 * web-login, self-enrolment). Two keys:
 *
 *  - the **Ed25519 signing key** — held in the platform secure element
 *    ([DeviceKeyStore]: StrongBox / Secure Enclave), exposed here only as a public
 *    key and a [sign] function (never the private half). This is the key a cert
 *    binds as `dev` and the key that signs a web-login assertion.
 *  - the **X25519 encryption key** — a raw keypair. It CANNOT live in StrongBox/SE
 *    (those hold no curve25519 agreement key), so the app persists it sealed at
 *    rest by the same hardware wrapping key that seals the signing seed (ADR-0001).
 *    It is bound as a cert's `denc` and is what unseals a cert delivered over the
 *    relay ([net.PairflowResponder.receive]).
 *
 * The app constructs one per session from its [DeviceKeyStore] (for [signPublicKey]
 * + [sign]) and its stored [EncryptionKey]; this library never persists anything.
 */
class DeviceIdentity(
    /** The device's 32-byte Ed25519 public signing key. */
    val signPublicKey: ByteArray,
    /** The device's 32-byte X25519 public encryption key (cert `denc`). */
    val encPublicKey: ByteArray,
    /** The device's 32-byte X25519 private encryption scalar (unseals delivered certs). */
    val encPrivateKey: ByteArray,
    private val signFn: (ByteArray) -> ByteArray,
) {
    /** Sign [message] with the hardware device key (biometric-gated on-device). */
    fun sign(message: ByteArray): ByteArray = signFn(message)

    /** The device signing key as an [Ed25519Signer]. */
    fun asSigner(): Ed25519Signer = Ed25519Signer { signFn(it) }

    /** `ed25519:<hex>` for the device signing key. */
    val deviceId: KeyRef get() = KeyRef.ed25519(signPublicKey)

    /** `x25519:<hex>` for the device encryption key. */
    val deviceEncId: KeyRef get() = KeyRef.x25519(encPublicKey)

    /** A freshly generated X25519 device encryption keypair. */
    class EncryptionKey(val privateKey: ByteArray, val publicKey: ByteArray)

    companion object {
        /**
         * Generate a new device X25519 encryption keypair. The app calls this ONCE
         * when provisioning a device, seals [EncryptionKey.privateKey] at rest, and
         * reuses it across sessions. (Software curve25519 — hardware elements do not
         * hold an agreement key; the seal-at-rest is the protection, ADR-0001.)
         */
        fun generateEncryptionKey(): EncryptionKey {
            val priv = CryptographyRandom.Default.nextBytes(32)
            return EncryptionKey(priv, X25519.scalarMultBase(priv))
        }
    }
}
