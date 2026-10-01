package one.rarebit.voidwhichbinds

/** Base type for [DeviceKeyStore] failures across platforms. */
open class DeviceKeyStoreException(message: String, cause: Throwable? = null) : Exception(message, cause)

/**
 * A signing operation needs a fresh user-presence authentication (biometric /
 * device credential) that is not currently valid.
 *
 * On **iOS** the Secure Enclave shows the system biometric prompt itself during
 * the unseal, so this is rarely surfaced. On **Android** the StrongBox wrapping
 * key is bound to a short post-authentication validity window; when it has
 * lapsed, [DeviceKeyStore.sign] throws this and the app must run its
 * `BiometricPrompt` and retry within the window. The hardware never signs
 * without a recent user-presence check — that refusal is this exception.
 */
class AuthenticationRequiredException(message: String, cause: Throwable? = null) :
    DeviceKeyStoreException(message, cause)
