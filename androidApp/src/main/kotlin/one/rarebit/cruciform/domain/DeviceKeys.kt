package one.rarebit.cruciform.domain

import one.rarebit.voidwhichbinds.DeviceKeyStore

/**
 * The device signing key as [DeviceVoidbindEngine] uses it: a public key, a signature,
 * and the hardware tier backing it. Never the private half.
 *
 * A seam over the library's [DeviceKeyStore] (an `expect class` bound to the
 * AndroidKeyStore on this target), so the engine's own logic runs in a plain JVM unit
 * test against a software key. Production always goes through [HardwareDeviceKeys].
 */
interface DeviceSigningKey {
    /** The 32-byte Ed25519 public signing key. */
    val publicKey: ByteArray

    /**
     * Sign [message] with the device key. On hardware this can throw
     * [one.rarebit.voidwhichbinds.AuthenticationRequiredException] when the post-authentication
     * window has lapsed.
     */
    fun sign(message: ByteArray): ByteArray

    /** The REAL tier holding the key's wrapping key, queried rather than assumed. */
    fun backing(): HardwareBacking
}

/**
 * Loads (or, the first time, provisions) this device's signing key. Can throw
 * [one.rarebit.voidwhichbinds.AuthenticationRequiredException] on hardware; the engine's
 * `withDeviceAuth` prompts and retries.
 */
fun interface DeviceKeys {
    fun getOrCreate(): DeviceSigningKey
}

/** Production [DeviceKeys]: the StrongBox/TEE-sealed [DeviceKeyStore] key under [alias]. */
class HardwareDeviceKeys(private val alias: String = DEFAULT_ALIAS) : DeviceKeys {

    override fun getOrCreate(): DeviceSigningKey {
        val ks = DeviceKeyStore.getOrCreate(alias)
        return object : DeviceSigningKey {
            override val publicKey: ByteArray get() = ks.publicKey().bytes

            override fun sign(message: ByteArray): ByteArray = ks.sign(message)

            override fun backing(): HardwareBacking = when (ks.securityLevel()) {
                DeviceKeyStore.SecurityLevel.STRONGBOX -> HardwareBacking.STRONGBOX
                DeviceKeyStore.SecurityLevel.TEE -> HardwareBacking.TEE
                DeviceKeyStore.SecurityLevel.SOFTWARE -> HardwareBacking.SOFTWARE
            }
        }
    }

    companion object {
        /** The alias the engine has always provisioned the device key under. Changing it orphans the key. */
        const val DEFAULT_ALIAS = "device"
    }
}
