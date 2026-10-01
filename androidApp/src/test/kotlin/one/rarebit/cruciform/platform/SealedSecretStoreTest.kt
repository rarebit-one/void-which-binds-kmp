package one.rarebit.cruciform.platform

import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.io.File
import java.security.InvalidKeyException
import javax.crypto.AEADBadTagException
import javax.crypto.KeyGenerator
import javax.crypto.SecretKey
import javax.crypto.spec.SecretKeySpec
import kotlin.test.assertFailsWith

/**
 * The seal/unseal framing and key handling of [SealedSecretStore], with the
 * AndroidKeyStore swapped for plain JCA AES keys (the cipher, AES-256-GCM, is the
 * same). StrongBox/TEE non-extractability itself is device-tested (docs/DEVICE-TESTING.md).
 */
class SealedSecretStoreTest {

    @get:Rule
    val tmp = TemporaryFolder()

    /** Software wrap keys keyed by alias; [created] records every alias provisioned. */
    private class SoftwareWrapKeys : WrapKeys {
        val keys = HashMap<String, SecretKey>()
        val created = mutableListOf<String>()

        /** When set, a strong key is minted but refuses use — the keystore outside its biometric window. */
        var refuseStrong = false

        override fun load(alias: String): SecretKey? = keys[alias]

        override fun create(alias: String, strong: Boolean): SecretKey {
            created += alias
            val key = if (strong && refuseStrong) {
                SecretKeySpec(ByteArray(32), "HmacSHA256") // AES/GCM rejects it at init
            } else {
                KeyGenerator.getInstance("AES").apply { init(256) }.generateKey()
            }
            return key.also { keys[alias] = it }
        }

        override fun delete(alias: String) {
            keys.remove(alias)
        }
    }

    private val keys = SoftwareWrapKeys()
    private val dir: File by lazy { File(tmp.root, "void-which-binds") }
    private val store by lazy { SealedSecretStore({ dir }, keys) }

    private val secret = ByteArray(32) { it.toByte() }

    @Test
    fun `seal then unseal round-trips the secret`() {
        store.seal("device-enc", secret)

        assertTrue(store.exists("device-enc"))
        assertArrayEquals(secret, store.unseal("device-enc"))
    }

    @Test
    fun `the blob at rest is not the plaintext`() {
        store.seal("recovery", secret)

        val onDisk = File(dir, "secret.recovery").readBytes()
        // 4-byte length + 12-byte IV + 4-byte length + ciphertext (32) + GCM tag (16).
        assertEquals(4 + 12 + 4 + 32 + 16, onDisk.size)
        assertFalse(onDisk.toList().windowed(secret.size).any { it == secret.toList() })
    }

    @Test
    fun `each secret gets its own wrapping key alias`() {
        store.seal("device-enc", secret)
        store.seal("recovery", secret)

        assertEquals(
            listOf("void-which-binds.secret.wrap.device-enc", "void-which-binds.secret.wrap.recovery"),
            keys.created,
        )
    }

    @Test
    fun `re-sealing reuses the existing wrapping key and replaces the value`() {
        store.seal("device-enc", secret)
        val replacement = ByteArray(32) { 7 }
        store.seal("device-enc", replacement)

        assertEquals(1, keys.created.size)
        assertArrayEquals(replacement, store.unseal("device-enc"))
    }

    @Test
    fun `sealStrong uses its own key and retires the plain one`() {
        store.seal("recovery", secret) // an install from before strong sealing
        assertFalse(store.isStrong("recovery"))

        store.sealStrong("recovery", secret)

        assertTrue(store.isStrong("recovery"))
        assertNull(keys.load("void-which-binds.secret.wrap.recovery"))
        assertArrayEquals(secret, store.unseal("recovery"))
    }

    @Test
    fun `a strong seal the keystore refuses leaves the plain copy readable`() {
        store.seal("recovery", secret)
        keys.refuseStrong = true

        assertFailsWith<InvalidKeyException> { store.sealStrong("recovery", secret) }

        assertFalse(store.isStrong("recovery"))
        assertArrayEquals(secret, store.unseal("recovery"))
    }

    @Test
    fun `delete forgets the blob and every wrapping key`() {
        store.seal("recovery", secret)
        store.sealStrong("recovery", secret)

        store.delete("recovery")

        assertFalse(store.exists("recovery"))
        assertNull(store.unseal("recovery"))
        assertTrue(keys.keys.isEmpty())
    }

    @Test
    fun `an unknown name is absent and unseals to null`() {
        assertFalse(store.exists("nope"))
        assertNull(store.unseal("nope"))
    }

    @Test
    fun `a blob whose wrapping key is gone unseals to null`() {
        store.seal("device-enc", secret)
        keys.keys.clear() // e.g. the keystore entry was wiped (lock-screen removal on some OEMs)

        assertTrue(store.exists("device-enc"))
        assertNull(store.unseal("device-enc"))
    }

    @Test
    fun `a truncated blob unseals to null instead of throwing`() {
        store.seal("device-enc", secret)
        val f = File(dir, "secret.device-enc")
        f.writeBytes(f.readBytes().copyOf(10))

        assertNull(store.unseal("device-enc"))
    }

    @Test
    fun `a tampered ciphertext fails authentication`() {
        store.seal("device-enc", secret)
        val f = File(dir, "secret.device-enc")
        val bytes = f.readBytes()
        bytes[bytes.size - 1] = (bytes[bytes.size - 1].toInt() xor 0x01).toByte()
        f.writeBytes(bytes)

        // GCM refuses the forged tag rather than returning garbage.
        assertFailsWith<AEADBadTagException> { store.unseal("device-enc") }
    }

    @Test
    fun `the directory is created on first use`() {
        assertFalse(dir.exists())
        store.seal("device-enc", secret)
        assertTrue(dir.isDirectory)
    }
}
