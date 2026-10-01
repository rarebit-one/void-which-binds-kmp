package one.rarebit.voidwhichbinds

/**
 * iOS `actual` for [DeviceKeyStore] — **hardware-backed**.
 *
 * The device signing key is a software Ed25519 seed ([Ed25519Engine]) sealed at
 * rest by a **Secure-Enclave P-256 key** (the Enclave cannot hold Ed25519). The
 * Secure Enclave + Keychain work is done by the app-provided [SecureEnclaveSealer]
 * (Swift/CryptoKit); this class owns the Ed25519 signing and the store contract.
 * The seed is unsealed only transiently — behind the Enclave's biometric gate —
 * to produce one signature, then zeroized. See
 * docs/adr/0001-hardware-keystore-mechanism.md.
 */
actual class DeviceKeyStore private constructor(private val alias: String, private val publicKeyBytes: ByteArray) {

    actual val isHardwareBacked: Boolean = true

    actual fun publicKey(): KeyRef = KeyRef.ed25519(publicKeyBytes)

    actual fun sign(message: ByteArray): ByteArray {
        // Unseal is Enclave-gated (biometric); the seed is used once and wiped.
        val seed = VoidbindIos.requireSealer().unsealSeed(alias)
        try {
            return Ed25519Engine.sign(seed, message)
        } finally {
            seed.fill(0)
        }
    }

    actual companion object {
        /**
         * [userAuthValiditySeconds] is the intended post-authentication reuse window. iOS has no
         * per-key seconds window like Android's `setUserAuthenticationParameters`; the closest
         * primitive is `LAContext.touchIDAuthenticationAllowableReuseDuration`, which the platform
         * **caps at 10 min** (`LATouchIDAuthenticationMaximumAllowableReuseDuration = 600`), so the
         * effective iOS reuse is `min(userAuthValiditySeconds, 600)`. That reuse is applied by the
         * app-side [SecureEnclaveSealer] (Swift/CryptoKit), which owns the `LAContext`; this seam
         * only threads the requested window through. iOS apps are not shipping yet, so the cap is
         * acceptable — a distinct `*.authorising` alias still amortises biometrics up to 10 min,
         * versus a fresh prompt per proof. See [getOrCreate] and ADR-0001.
         */
        actual fun getOrCreate(alias: String, userAuthValiditySeconds: Int): DeviceKeyStore {
            val sealer = VoidbindIos.requireSealer()
            if (sealer.sealExists(alias)) {
                return DeviceKeyStore(alias, sealer.loadPublicKey(alias))
            }
            val generated = Ed25519Engine.generate()
            try {
                sealer.provision(alias, generated.publicKey, generated.privateSeed)
            } finally {
                generated.privateSeed.fill(0)
            }
            return DeviceKeyStore(alias, generated.publicKey)
        }
    }
}
