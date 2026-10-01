package one.rarebit.voidwhichbinds

import kotlin.concurrent.Volatile

/**
 * The Secure Enclave operations the iOS [DeviceKeyStore] needs, implemented in
 * **Swift** in the app and injected here. The Secure Enclave holds a P-256 key
 * (it cannot hold Ed25519); this seals the software Ed25519 seed to that SE key
 * via ECIES and unseals it behind a biometric gate. Keeping the SE + Keychain
 * calls in Swift (CryptoKit / Security) avoids fragile Kotlin/Native interop and
 * uses the idiomatic, well-supported platform APIs.
 *
 * Implementations MUST make the SE private key non-extractable
 * (`kSecAttrTokenIDSecureEnclave`) and gate [unsealSeed] on user presence
 * (`.privateKeyUsage` + `.biometryCurrentSet` / `.userPresence`), so the seed
 * cannot be recovered from device storage and no signature is produced without a
 * fresh biometric/passcode check. See docs/adr/0001-hardware-keystore-mechanism.md.
 */
interface SecureEnclaveSealer {

    /** Whether a sealed key already exists for [alias]. */
    fun sealExists(alias: String): Boolean

    /** The stored Ed25519 public key (RAW 32 bytes) for a provisioned [alias]. */
    fun loadPublicKey(alias: String): ByteArray

    /**
     * Provision [alias]: create the non-extractable Secure-Enclave P-256 key,
     * ECIES-seal [ed25519Seed] (RAW 32 bytes) to it, and persist the ciphertext
     * alongside [ed25519PublicKey]. The seed must not be retained after sealing.
     */
    fun provision(alias: String, ed25519PublicKey: ByteArray, ed25519Seed: ByteArray)

    /**
     * Unseal and return the RAW 32-byte Ed25519 seed for [alias]. This triggers
     * the Secure Enclave + the system biometric prompt; the caller uses the seed
     * transiently to sign and zeroizes it immediately.
     */
    fun unsealSeed(alias: String): ByteArray
}

/**
 * Holds the app-provided [SecureEnclaveSealer]. The iOS app calls [init] once at
 * startup before using [DeviceKeyStore].
 */
object VoidbindIos {

    @Volatile
    private var sealerRef: SecureEnclaveSealer? = null

    fun init(sealer: SecureEnclaveSealer) {
        sealerRef = sealer
    }

    internal fun requireSealer(): SecureEnclaveSealer = sealerRef ?: throw DeviceKeyStoreException(
        "VoidbindIos.init(sealer) must be called before using DeviceKeyStore on iOS",
    )
}
