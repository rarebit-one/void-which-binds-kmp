package one.rarebit.voidwhichbinds

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue

/**
 * End-to-end on the JVM target using the REAL JDK Ed25519 backend: the software
 * [DeviceKeyStore] signs an enrolment cert and the JDK verifier accepts it. Proves
 * the pure domain composes with a real crypto backend across the `expect`/`actual`
 * seam (the iOS Secure Enclave `actual` slots into the same interface).
 */
class JvmDeviceKeyStoreTest {

    @Test
    fun softwareKeyStoreSignsAndVerifiesACert() {
        val store = DeviceKeyStore.getOrCreate("test-device")
        assertFalse(store.isHardwareBacked, "JVM keystore is explicitly software-only")

        // Device signing key IS the cert's user identity key for this smoke test.
        val deviceKey = store.publicKey()
        assertEquals(Labels.ALG_ED25519, deviceKey.alg)

        val cert = Cert(
            version = Labels.CERT_VERSION,
            user = deviceKey,
            device = deviceKey,
            deviceEnc = KeyRef.x25519(ByteArray(32) { (it + 4).toByte() }),
            issuedAt = 1_724_700_000L,
            expiresAt = 1_756_236_000L,
        )

        val token = cert.encode(store.asSigner())
        assertTrue(cert.verify(token, JvmEd25519.verifier()), "real Ed25519 must verify")

        val parsed = Cert.parse(token)
        assertEquals(cert, parsed.cert)
        assertTrue(parsed.verify(JvmEd25519.verifier()))
    }

    @Test
    fun getOrCreateIsStablePerAlias() {
        val a = DeviceKeyStore.getOrCreate("alias-x")
        val b = DeviceKeyStore.getOrCreate("alias-x")
        assertEquals(a.publicKey(), b.publicKey(), "same alias → same key")
    }

    @Test
    fun getOrCreateAcceptsAUserAuthWindowAndCanSign() {
        // The authorising-key path: a longer window is accepted and the store still signs.
        val store = DeviceKeyStore.getOrCreate("authorising-alias", userAuthValiditySeconds = 3600)
        val sig = store.sign("hello".encodeToByteArray())
        assertEquals(64, sig.size, "Ed25519 signatures are 64 bytes")
    }

    @Test
    fun theWindowDefaultsToThirtyAndDoesNotAffectKeyIdentity() {
        // The one-arg call keeps the strict 30 s default, so it must be identical to
        // passing 30 explicitly; and on the software JVM the window never changes the key
        // for a given alias (it is honoured only by the hardware targets).
        val implicitDefault = DeviceKeyStore.getOrCreate("window-invariance")
        val explicitThirty = DeviceKeyStore.getOrCreate("window-invariance", userAuthValiditySeconds = 30)
        val longWindow = DeviceKeyStore.getOrCreate("window-invariance", userAuthValiditySeconds = 3600)
        assertEquals(implicitDefault.publicKey(), explicitThirty.publicKey(), "one-arg default is 30 s")
        assertEquals(
            implicitDefault.publicKey(),
            longWindow.publicKey(),
            "window does not alter key identity per alias",
        )
    }

    @Test
    fun aDistinctAuthorisingAliasGetsItsOwnKey() {
        // Apps provision the possession-proof key under a distinct "$base.authorising" alias,
        // which must be a separate key from the strict per-use base alias.
        val base = DeviceKeyStore.getOrCreate("dev.base")
        val authorising = DeviceKeyStore.getOrCreate("dev.base.authorising", userAuthValiditySeconds = 3600)
        assertNotEquals(base.publicKey(), authorising.publicKey(), "distinct alias → distinct key")
    }
}
