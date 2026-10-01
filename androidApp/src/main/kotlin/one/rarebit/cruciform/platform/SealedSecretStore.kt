package one.rarebit.cruciform.platform

import android.content.Context
import android.security.keystore.KeyGenParameterSpec
import android.security.keystore.KeyPermanentlyInvalidatedException
import android.security.keystore.KeyProperties
import android.security.keystore.StrongBoxUnavailableException
import java.io.File
import java.security.GeneralSecurityException
import java.security.KeyStore
import javax.crypto.Cipher
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.GCMParameterSpec

/**
 * Seals app-owned secrets at rest with a non-extractable AES-256-GCM key held in
 * the AndroidKeyStore (StrongBox where the device has one, TEE otherwise) — the
 * same mechanism the library's [one.rarebit.voidwhichbinds.DeviceKeyStore] uses for the
 * Ed25519 seed (ADR-0001), applied here to the device **X25519 encryption private
 * key**, which no secure element can hold as an agreement key.
 *
 * [seal] is deliberately **not** user-authentication-gated: this is at-rest
 * protection, and the key is unsealed inside a pairing flow that is already gated
 * on the SAS + a biometric signature. An attacker with the flash but not the secure
 * element cannot recover the sealed secret.
 *
 * [sealStrong] is for the one secret that IS the identity's root authority — the
 * recovery secret, which acts as genesis and so bypasses the co-signed remove
 * quorum (void-which-binds-go ADR-0008). Its wrapping key is usable only for a few seconds
 * after a **strong biometric** (a screen-lock PIN does not unlock it), and enrolling
 * a new fingerprint destroys it. The caller prompts for the strong biometric first;
 * [unseal] then works inside that window.
 */
class SealedSecretStore internal constructor(
    /** The directory the sealed blobs live in; resolved (and created) on each access. */
    private val dir: () -> File,
    /** Where the per-secret wrapping keys live — the AndroidKeyStore in production. */
    private val wrapKeys: WrapKeys,
) : SecretSealer {

    constructor(context: Context) : this({ File(context.filesDir, "voidbind") }, AndroidKeyStoreWrapKeys)

    override fun exists(name: String): Boolean = file(name).exists()

    override fun seal(name: String, secret: ByteArray) {
        val key = wrapKeys.load(wrapAlias(name)) ?: wrapKeys.create(wrapAlias(name), strong = false)
        writeSealed(name, key, secret)
    }

    override fun sealStrong(name: String, secret: ByteArray) {
        val existing = wrapKeys.load(strongAlias(name))
        val key = existing ?: wrapKeys.create(strongAlias(name), strong = true)
        try {
            writeSealed(name, key, secret)
        } catch (e: GeneralSecurityException) {
            // Outside the biometric window the keystore refuses the key. Drop a strong
            // key minted just now, or [unseal] would try it against the old plain blob.
            if (existing == null) wrapKeys.delete(strongAlias(name))
            throw e
        }
        // A secret sealed before the strong key existed was wrapped under the plain
        // alias; once it is re-sealed under the strong one, the plain key must go so
        // nothing unlocks this secret without a biometric.
        wrapKeys.delete(wrapAlias(name))
    }

    override fun isStrong(name: String): Boolean = wrapKeys.load(strongAlias(name)) != null

    override fun unseal(name: String): ByteArray? {
        val f = file(name)
        if (!f.exists()) return null
        val (iv, ct) = readFramed(f) ?: return null
        val key = wrapKeys.load(strongAlias(name)) ?: wrapKeys.load(wrapAlias(name)) ?: return null
        val cipher = Cipher.getInstance(TRANSFORMATION)
        try {
            cipher.init(Cipher.DECRYPT_MODE, key, GCMParameterSpec(GCM_TAG_BITS, iv))
        } catch (_: KeyPermanentlyInvalidatedException) {
            // A new biometric was enrolled since this was sealed: the keystore has
            // destroyed the strong key by design. The secret is unrecoverable here, so
            // forget it rather than report a copy that can never open.
            delete(name)
            return null
        }
        return cipher.doFinal(ct)
    }

    override fun delete(name: String) {
        file(name).delete()
        wrapKeys.delete(wrapAlias(name))
        wrapKeys.delete(strongAlias(name))
    }

    private fun writeSealed(name: String, key: SecretKey, secret: ByteArray) {
        val cipher = Cipher.getInstance(TRANSFORMATION).apply { init(Cipher.ENCRYPT_MODE, key) }
        val ct = cipher.doFinal(secret)
        writeFramed(file(name), cipher.iv, ct)
    }

    private fun file(name: String): File {
        val root = dir().apply { mkdirs() }
        return File(root, "secret.$name")
    }

    private fun writeFramed(f: File, iv: ByteArray, ct: ByteArray) {
        val out = ArrayList<Byte>()
        fun put(b: ByteArray) {
            val n = b.size
            out.add((n ushr 24).toByte())
            out.add((n ushr 16).toByte())
            out.add((n ushr 8).toByte())
            out.add(n.toByte())
            b.forEach { out.add(it) }
        }
        put(iv)
        put(ct)
        f.writeBytes(out.toByteArray())
    }

    private fun readFramed(f: File): Pair<ByteArray, ByteArray>? = try {
        val bytes = f.readBytes()
        var i = 0
        fun take(): ByteArray {
            val n = ((bytes[i].toInt() and 0xFF) shl 24) or ((bytes[i + 1].toInt() and 0xFF) shl 16) or
                ((bytes[i + 2].toInt() and 0xFF) shl 8) or (bytes[i + 3].toInt() and 0xFF)
            i += 4
            val slice = bytes.copyOfRange(i, i + n)
            i += n
            return slice
        }
        take() to take()
    } catch (_: Exception) {
        null
    }

    private companion object {
        const val TRANSFORMATION = "AES/GCM/NoPadding"
        const val GCM_TAG_BITS = 128
        fun wrapAlias(name: String) = "voidbind.secret.wrap.$name"
        fun strongAlias(name: String) = "voidbind.secret.wrap-strong.$name"
    }
}

/**
 * Named secrets sealed at rest. [SealedSecretStore] is the hardware-backed
 * implementation; the seam lets [IdentityStore] be unit-tested without a keystore.
 */
interface SecretSealer {
    fun exists(name: String): Boolean

    fun seal(name: String, secret: ByteArray)

    /**
     * Seal [secret] under a wrapping key that only a recent **strong biometric**
     * unlocks, replacing any plain-sealed copy. The caller must have just passed a
     * strong-biometric prompt; the keystore refuses the key otherwise.
     */
    fun sealStrong(name: String, secret: ByteArray)

    /** True when [name] is sealed under the strong-biometric key (see [sealStrong]). */
    fun isStrong(name: String): Boolean

    /**
     * The secret, or null when it was never sealed or its wrapping key is gone
     * (including a strong key the keystore destroyed when a new biometric was enrolled).
     */
    fun unseal(name: String): ByteArray?

    /** Forget [name]: the sealed blob and every wrapping key it used. */
    fun delete(name: String)
}

/** Holds the non-extractable AES wrapping key for each sealed secret, by alias. */
internal interface WrapKeys {
    fun load(alias: String): SecretKey?

    /**
     * Create the key for [alias]. A [strong] key is usable only for
     * [STRONG_WINDOW_SECONDS] after a strong biometric, and is invalidated when a
     * new biometric is enrolled.
     */
    fun create(alias: String, strong: Boolean): SecretKey

    fun delete(alias: String)
}

/**
 * How long after a strong biometric a [SecretSealer.sealStrong] key stays usable:
 * long enough to unseal right after the prompt, short enough that the key is locked
 * again before the phone is put down.
 */
internal const val STRONG_WINDOW_SECONDS = 10

/** The AndroidKeyStore: StrongBox where the device has one, TEE otherwise. */
internal object AndroidKeyStoreWrapKeys : WrapKeys {
    private const val KEYSTORE = "AndroidKeyStore"
    private const val WRAP_KEY_BITS = 256

    override fun load(alias: String): SecretKey? {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        return ks.getKey(alias, null) as? SecretKey
    }

    override fun delete(alias: String) {
        val ks = KeyStore.getInstance(KEYSTORE).apply { load(null) }
        if (ks.containsAlias(alias)) ks.deleteEntry(alias)
    }

    override fun create(alias: String, strong: Boolean): SecretKey {
        fun spec(strongBox: Boolean) = KeyGenParameterSpec.Builder(
            alias,
            KeyProperties.PURPOSE_ENCRYPT or KeyProperties.PURPOSE_DECRYPT,
        )
            .setBlockModes(KeyProperties.BLOCK_MODE_GCM)
            .setEncryptionPaddings(KeyProperties.ENCRYPTION_PADDING_NONE)
            .setKeySize(WRAP_KEY_BITS)
            .setIsStrongBoxBacked(strongBox)
            .apply {
                if (strong) {
                    // Strong biometric only: a device-credential (PIN) unlock does not
                    // authorise this key, so knowing the screen lock is not enough.
                    setUserAuthenticationRequired(true)
                    setUserAuthenticationParameters(STRONG_WINDOW_SECONDS, KeyProperties.AUTH_BIOMETRIC_STRONG)
                    setInvalidatedByBiometricEnrollment(true)
                }
            }
            .build()

        val gen = KeyGenerator.getInstance(KeyProperties.KEY_ALGORITHM_AES, KEYSTORE)
        return try {
            gen.init(spec(strongBox = true))
            gen.generateKey()
        } catch (_: StrongBoxUnavailableException) {
            gen.init(spec(strongBox = false))
            gen.generateKey()
        }
    }
}
