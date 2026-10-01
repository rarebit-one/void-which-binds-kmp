package one.rarebit.cruciform.platform

import one.rarebit.cruciform.domain.SiteAccent
import one.rarebit.cruciform.domain.TrustedSite
import one.rarebit.cruciform.testing.InMemoryPrefs
import one.rarebit.cruciform.testing.InMemorySealer
import one.rarebit.cruciform.testing.SoftwareDeviceKeys
import one.rarebit.voidwhichbinds.DeviceIdentity
import one.rarebit.voidwhichbinds.Enrolment
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.UserIdentity
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [IdentityStore] over in-memory prefs + an in-memory sealer: what is public vs.
 * sealed, the owner vs. joined shapes, the pre-0.5.0 replica migration, and the
 * membership replica merge (ADR-0005).
 */
class IdentityStoreTest {

    private val prefs = InMemoryPrefs()
    private val sealer = InMemorySealer()
    private val store = IdentityStore(prefs, sealer)

    private val user = UserIdentity.create()
    private val enc = DeviceIdentity.generateEncryptionKey()

    /** A real, verifiable genesis add (self-enrolment cert) for a fresh software device. */
    private fun cert(issuedAt: Long = NOW): String {
        val key = SoftwareDeviceKeys().getOrCreate()
        val device = DeviceIdentity(key.publicKey, enc.publicKey, enc.privateKey) { key.sign(it) }
        return Enrolment.selfEnrol(user, device, issuedAt)
    }

    private fun saveOwner(token: String = cert()) {
        store.saveOwner(
            enrolmentCert = token,
            userPublicKey = user.userPublicKey,
            encPublicKey = enc.publicKey,
            encPrivateKey = enc.privateKey,
            deviceName = "Pixel 9",
        )
        store.keepRecoverySecret(user.recovery.bytes)
    }

    @Test
    fun `an empty store is unprovisioned and loads nothing`() {
        assertFalse(store.isProvisioned())
        assertNull(store.load())
        assertEquals(emptyList<String>(), store.knownOps())
        assertFalse(store.hasUserKey())
        assertNull(store.encPrivateKey())
        assertNull(store.recoverySecret())
    }

    @Test
    fun `saveOwner persists public material in prefs and seals the secrets`() {
        val c = cert()
        saveOwner(c)

        assertTrue(store.isProvisioned())
        val loaded = store.load()!!
        assertEquals(c, loaded.enrolmentCert)
        assertArrayEquals(user.userPublicKey, loaded.userPublicKey)
        assertArrayEquals(enc.publicKey, loaded.encPublicKey)
        assertEquals("Pixel 9", loaded.deviceName)
        assertTrue(loaded.biometricApproval)
        assertEquals(listOf(c), loaded.ops)

        // The owner holds the recovery secret (sealed) and the enc private key (sealed)…
        assertTrue(store.hasUserKey())
        assertArrayEquals(user.recovery.bytes, store.recoverySecret())
        assertArrayEquals(enc.privateKey, store.encPrivateKey())
        // …and neither secret ever lands in plain prefs.
        val plain = prefs.values.values.joinToString("|")
        assertFalse(plain.contains(one.rarebit.voidwhichbinds.crypto.Hex.encode(enc.privateKey)))
        assertFalse(plain.contains(one.rarebit.voidwhichbinds.crypto.Hex.encode(user.recovery.bytes)))
        assertEquals(setOf("device-enc", "recovery"), sealer.secrets.keys)
        // Only the recovery secret — the genesis authority — is behind the strong key.
        assertEquals(setOf("recovery"), sealer.strong)
    }

    @Test
    fun `an older install's plain-sealed recovery secret moves under the strong key on first read`() {
        saveOwner()
        sealer.strong.clear() // as sealed by a build before strong sealing

        assertArrayEquals(user.recovery.bytes, store.recoverySecret())

        assertEquals(setOf("recovery"), sealer.strong)
    }

    @Test
    fun `forgetRecoverySecret leaves the identity but no recovery secret`() {
        saveOwner()

        store.forgetRecoverySecret()

        assertTrue(store.isProvisioned())
        assertFalse(store.hasUserKey())
        assertNull(store.recoverySecret())
        assertArrayEquals(enc.privateKey, store.encPrivateKey())
    }

    @Test
    fun `saveJoined holds no recovery secret and merges its admitting op into the replica`() {
        val genesis = cert()
        val op = cert(NOW + 1)
        store.saveJoined(
            op = op,
            ops = listOf(genesis),
            userPublicKey = user.userPublicKey,
            encPublicKey = enc.publicKey,
            encPrivateKey = enc.privateKey,
            deviceName = "Tablet",
        )

        assertFalse(store.hasUserKey())
        assertNull(store.recoverySecret())
        assertArrayEquals(enc.privateKey, store.encPrivateKey())
        val loaded = store.load()!!
        assertEquals(op, loaded.enrolmentCert)
        assertEquals(Membership.merge(listOf(genesis, op)), loaded.ops)
    }

    @Test
    fun `a pre-0_5_0 install with a cert but no replica is migrated on load`() {
        saveOwner()
        val c = prefs.getString("cert", null)!!
        prefs.edit().remove("ops").apply() // what a 0.4.x install looks like

        val loaded = store.load()!!

        assertEquals(listOf(c), loaded.ops)
        assertEquals(c, prefs.getString("ops", null)) // written back, so later reads need no merge
    }

    @Test
    fun `load is null when the public keys are missing`() {
        saveOwner()
        prefs.edit().remove("encPub").apply()

        assertNull(store.load())
    }

    @Test
    fun `recordOps merges without duplicates and always keeps the admitting op`() {
        val c = cert()
        saveOwner(c)
        val other = cert(NOW + 5)

        store.recordOps(listOf(other))
        store.recordOps(listOf(other, c)) // re-delivery is idempotent

        assertEquals(Membership.merge(listOf(c, other)), store.knownOps())
        assertEquals(2, store.knownOps().size)
    }

    @Test
    fun `device name and biometric approval are settable`() {
        assertEquals("This device", store.deviceName())
        saveOwner()

        store.setDeviceName("Work phone")
        store.setBiometricApproval(false)

        assertEquals("Work phone", store.deviceName())
        assertFalse(store.biometricApproval())
        assertEquals("Work phone", store.load()!!.deviceName)
        assertFalse(store.load()!!.biometricApproval)
    }

    @Test
    fun `trusted sites upsert by id and can be removed`() {
        val a = TrustedSite("a.example", "a.example", "", "just now", SiteAccent.MINT)
        val b = TrustedSite("b.example", "b.example", "", "just now", SiteAccent.BLUE)

        store.upsertTrustedSite(a)
        store.upsertTrustedSite(b)
        store.upsertTrustedSite(a.copy(lastUsed = "later"))

        assertEquals(listOf("b.example", "a.example"), store.trustedSites().map { it.id })
        assertEquals("later", store.trustedSites().single { it.id == "a.example" }.lastUsed)

        store.removeTrustedSite("b.example")
        assertEquals(listOf("a.example"), store.trustedSites().map { it.id })
    }

    @Test
    fun `clear forgets the public identity`() {
        saveOwner()
        store.clear()

        assertFalse(store.isProvisioned())
        assertNull(store.load())
    }

    private companion object {
        const val NOW = 1_800_000_000L
    }
}
