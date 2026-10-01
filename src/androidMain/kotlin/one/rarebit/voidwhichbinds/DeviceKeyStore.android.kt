package one.rarebit.voidwhichbinds

import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyInfo
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import android.security.keystore.UserNotAuthenticatedException
import java.io.File
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.SecretKeyFactory
import javax.crypto.spec.GCMParameterSpec

/**
 * Android `actual` for [DeviceKeyStore] — **hardware-backed**.
 *
 * The device signing key is a software Ed25519 seed ([Ed25519Engine]) whose 32
 * bytes are sealed at rest by an **AES-256-GCM wrapping key held in the
 * AndroidKeyStore, StrongBox-backed where the device has a StrongBox secure
 * element** (TEE-backed otherwise). The wrapping key is non-extractable and
 * requires a recent user authentication; the seed is unsealed only transiently
 * to sign and zeroized immediately after. See
 * docs/adr/0001-hardware-keystore-mechanism.md.
 *
 * Authentication: the wrapping key is bound to a short post-authentication
 * validity window. When the app has not authenticated recently,
 * [getOrCreate] (on first provisioning) and [sign] throw
 * [AuthenticationRequiredException]; the app runs a `BiometricPrompt` and
 * retries within the window.
 */
actual class DeviceKeyStore private constructor(private val alias: String, private val publicKeyBytes: ByteArray) {

    actual val isHardwareBacked: Boolean = true

    /** The AndroidKeyStore security tier actually backing this device's wrapping key. */
    enum class SecurityLevel { STRONGBOX, TEE, SOFTWARE }

    /**
     * The REAL security tier of the wrapping key. [createWrapKey] falls back to TEE on
     * devices without a StrongBox secure element, so we must query the level rather than
     * assume StrongBox — the UI must never over-state hardware backing.
     */
    fun securityLevel(): SecurityLevel {
        val key = loadWrapKey(alias) ?: return SecurityLevel.SOFTWARE
        return try {
            val factory = SecretKeyFactory.getInstance(key.algorithm, KEYSTORE)
            val info = factory.getKeySpec(key, KeyInfo::class.java) as KeyInfo
            when (info.securityLevel) {
                KeyProperties.SECURITY_LEVEL_STRONGBOX -> SecurityLevel.STRONGBOX
                KeyProperties.SECURITY_LEVEL_TRUSTED_ENVIRONMENT -> SecurityLevel.TEE
                else -> SecurityLevel.SOFTWARE
            }
        } catch (_: Exception) {
            // Can't read the tier (older HAL / unknown): the key is still in the
            // AndroidKeyStore and non-extractable — report TEE conservatively, never StrongBox.
            SecurityLevel.TEE
        }
    }

    actual fun publicKey(): KeyRef = KeyRef.ed25519(publicKeyBytes)

    actual fun sign(message: ByteArray): ByteArray {
        val sealed = readSealed(alias)
        val key = loadWrapKey(alias)
            ?: throw DeviceKeyStoreException("wrapping key missing for alias '$alias'")
        val seed = try {
            Cipher.getInstance(TRANSFORMATION).run {
                init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, sealed.iv))
                doFinal(sealed.ciphertext)
            }
        } catch (e: UserNotAuthenticatedException) {
            throw AuthenticationRequiredException("device authentication required to sign", e)
        }
        try {
            return Ed25519Engine.sign(seed, message)
        } finally {
            seed.fill(0)
        }
    }

    actual companion object {
        private const val TRANSFORMATION = "AES/GCM/NoPadding"
        private const val KEYSTORE = "AndroidKeyStore"
        private const val GCM_TAG_BITS = 128
        private const val WRAP_KEY_BITS = 256

        actual fun getOrCreate(alias: String, userAuthValiditySeconds: Int): DeviceKeyStore {
            val existing = readSealedOrNull(alias)
            if (existing != null && loadWrapKey(alias) != null) {
                return DeviceKeyStore(alias, existing.publicKey)
            }
            // First provisioning: generate the Ed25519 seed, create the hardware
            // wrapping key, seal the seed, persist. The seal (encrypt) is itself
            // user-auth-gated, so this surfaces AuthenticationRequiredException the
            // same way sign() does.
            val generated = Ed25519Engine.generate()
            val wrapKey = createWrapKey(alias, userAuthValiditySeconds)
            val sealed = try {
                Cipher.getInstance(TRANSFORMATION).run {
                    init(Cipher.ENCRYPT_MODE, wrapKey)
                    val ciphertext = doFinal(generated.privateSeed)
                    Sealed(generated.publicKey, iv, ciphertext)
                }
            } catch (e: UserNotAuthenticatedException) {
                throw AuthenticationRequiredException(
                    "device authentication required to provision the device key",
                    e,
                )
            } finally {
                generated.privateSeed.fill(0)
            }
            writeSealed(alias, sealed)
            return DeviceKeyStore(alias, sealed.publicKey)
        }

        // --- hardware wrapping key -----------------------------------------

        private fun wrapKeyAlias(alias: String) = "voidbind.wrap.$alias"

        /**
         * Create the AES-GCM wrapping key, StrongBox-backed where available.
         *
         * [userAuthValiditySeconds] is the post-authentication validity window — how long one
         * biometric / device-credential authorises this wrapping key before the platform demands
         * a fresh one. A short window (the 30 s default) is the strict per-use posture for
         * enrol/authorise acts; a long window (e.g. 3600 s under a distinct `*.authorising` alias)
         * lets one biometric cover an hour of short possession-proof signing. See [getOrCreate].
         */
        private fun createWrapKey(alias: String, userAuthValiditySeconds: Int): SecretKey {
            fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
                wrapKeyAlias(alias),
                KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
            )
                .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
                .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
                .setKeySize(WRAP_KEY_BITS)
                .setUnlockedDeviceRequired(true)
                .setUserAuthenticationRequired(true)
                .setUserAuthenticationParameters(
                    userAuthValiditySeconds,
                    KeyProperties.AUTH_BIOMETRIC_STRONG or KeyProperties.AUTH_DEVICE_CREDENTIAL,
                )
                .setIsStrongBoxBacked(strongBox)
                .build()

            val generator = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
            return try {
                generator.init(spec(strongBox = true))
                generator.generateKey()
            } catch (_: StrongBoxUnavailableException) {
                // No StrongBox secure element on this device — fall back to the
                // TEE-backed AndroidKeyStore, still non-extractable.
                generator.init(spec(strongBox = false))
                generator.generateKey()
            }
        }

        private fun loadWrapKey(alias: String): SecretKey? {
            val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
            return ks.getKey(wrapKeyAlias(alias), null) as? SecretKey
        }

        // --- sealed-seed storage (public key is not secret) -----------------

        private class Sealed(val publicKey: ByteArray, val iv: ByteArray, val ciphertext: ByteArray)

        private fun keyFile(alias: String): File {
            val dir = File(VoidbindAndroid.requireContext().filesDir, "voidbind").apply { mkdirs() }
            return File(dir, "$alias.key")
        }

        private fun writeSealed(alias: String, sealed: Sealed) {
            // length-prefixed: [pubLen][pub][ivLen][iv][ctLen][ct]
            val out = ArrayList<Byte>()
            fun put(b: ByteArray) {
                val n = b.size
                out.add((n ushr 24).toByte())
                out.add((n ushr 16).toByte())
                out.add((n ushr 8).toByte())
                out.add(n.toByte())
                b.forEach { out.add(it) }
            }
            put(sealed.publicKey)
            put(sealed.iv)
            put(sealed.ciphertext)
            keyFile(alias).writeBytes(out.toByteArray())
        }

        private fun readSealedOrNull(alias: String): Sealed? {
            val f = keyFile(alias)
            if (!f.exists()) return null
            return try {
                readSealed(alias)
            } catch (_: Exception) {
                null
            }
        }

        private fun readSealed(alias: String): Sealed {
            val bytes = keyFile(alias).readBytes()
            var i = 0
            fun take(): ByteArray {
                val n = ((bytes[i].toInt() and 0xFF) shl 24) or ((bytes[i + 1].toInt() and 0xFF) shl 16) or
                    ((bytes[i + 2].toInt() and 0xFF) shl 8) or (bytes[i + 3].toInt() and 0xFF)
                i += 4
                val slice = bytes.copyOfRange(i, i + n)
                i += n
                return slice
            }
            return Sealed(take(), take(), take())
        }
    }
}
