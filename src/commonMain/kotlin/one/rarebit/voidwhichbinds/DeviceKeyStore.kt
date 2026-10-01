package one.rarebit.voidwhichbinds

/**
 * The **whole point** of void-which-binds-kmp: a device's signing key must live in
 * hardware and never leave it. This is the platform seam for that key.
 *
 * The `actual` for each target binds to the platform secure element:
 * - **iOS** → Secure Enclave (`kSecAttrTokenIDSecureEnclave`), key non-extractable.
 * - **Android** → StrongBox / TEE-backed AndroidKeyStore, `setIsStrongBoxBacked(true)`.
 * - **JVM** → software key only (dev/test); [isHardwareBacked] is `false`. NOT for production.
 *
 * The key is Ed25519 (identity/signing). The store exposes the public key as a
 * [KeyRef] and can [sign] via [asSigner], but never exposes private key material.
 */
expect class DeviceKeyStore {

    /** True only when the private key is held in a hardware secure element. */
    val isHardwareBacked: Boolean

    /** The device signing public key, rendered as `ed25519:<hex>`. */
    fun publicKey(): KeyRef

    /** Sign [message] with the non-extractable device key; returns a 64-byte Ed25519 signature. */
    fun sign(message: ByteArray): ByteArray

    companion object {
        /**
         * Create or load the device signing key under [alias]. On iOS/Android this
         * provisions a hardware-backed, non-extractable key on first use.
         *
         * [userAuthValiditySeconds] is how long **one** user authentication (biometric /
         * device credential) authorises this key's use before the platform demands a fresh
         * one — the Android `setUserAuthenticationParameters` window. The default of **30 s**
         * is the strict, per-use posture that fits "authorise as you go" acts (enrol, add a
         * device), where a biometric per operation is wanted; existing callers that pass only
         * [alias] keep exactly that behaviour.
         *
         * **Possession proofs are different** (see [one.rarebit.voidwhichbinds.auth.PossessionProof]):
         * a proof's TTL is short (≤ 10 min) but proofs are minted repeatedly, so a 30 s window
         * would force a biometric roughly every half-minute. For that, provision a **separate
         * alias** — the wrapping key is namespaced per [alias], so a distinct alias gets its own
         * hardware key — with a longer window, e.g.:
         *
         * ```kotlin
         * // one biometric authorises an hour of short-proof signing:
         * DeviceKeyStore.getOrCreate("$base.authorising", userAuthValiditySeconds = 3600)
         * ```
         *
         * so a single biometric covers an hour of proof minting while each minted proof stays
         * short. The proof's own TTL ([one.rarebit.voidwhichbinds.auth.PossessionProof.DEFAULT_TTL_SECONDS])
         * is unchanged and independent of this window.
         *
         * Platform mapping: **Android** passes this straight to `setUserAuthenticationParameters`.
         * **iOS** maps it to `LAContext.touchIDAuthenticationAllowableReuseDuration`, which the
         * platform caps at 10 min, so the effective iOS reuse is `min(window, 600)`. **JVM** is
         * software-only and ignores it.
         */
        fun getOrCreate(alias: String, userAuthValiditySeconds: Int = 30): DeviceKeyStore
    }
}

/** Adapt a [DeviceKeyStore] to the pure [Ed25519Signer] seam used by [Cert.encode]. */
fun DeviceKeyStore.asSigner(): Ed25519Signer = Ed25519Signer { message -> sign(message) }
