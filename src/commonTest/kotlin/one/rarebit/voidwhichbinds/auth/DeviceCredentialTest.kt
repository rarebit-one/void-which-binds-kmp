package one.rarebit.voidwhichbinds.auth

import one.rarebit.voidwhichbinds.Cert
import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.assertMatchesGoToken
import one.rarebit.voidwhichbinds.crypto.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotEquals
import kotlin.test.assertSame
import kotlin.test.assertTrue

/**
 * [DeviceCredential]: the `Device <cert>~<proof>` wire join against the Go vector,
 * and the reuse window / forced refresh a transport leans on.
 */
class DeviceCredentialTest {

    // Vector B (see PossessionProofTest / device-scheme-vector.json): the gen2,
    // typed cert and proof (ADR-0022). The library's minters emit this form.

    @Suppress("MaxLineLength")
    private val cert =
        "eyJ2IjoyLCJ0eXAiOiJ2b2lkLXdoaWNoLWJpbmRzLmNlcnQiLCJ1c3IiOiJlZDI1NTE5OjAzYTEwN2JmZjNjZTEwYmUxZDcwZGQxOGU3NGJjMDk5NjdlNGQ2MzA5YmE1MGQ1ZjFkZGM4NjY0MTI1NTMxYjgiLCJkZXYiOiJlZDI1NTE5OmNkMTRiMzdmOTU2ZTk1MzE5NGZmN2ZiNzNiM2Q4MWRjYzU2MWQ2MWE3NTM4MDk0YjdjM2UxYTY0M2VlNWYzYWEiLCJkZW5jIjoieDI1NTE5OjAwMTEyMjMzNDQ1NTY2Nzc4ODk5YWFiYmNjZGRlZWZmMDAxMTIyMzM0NDU1NjY3Nzg4OTlhYWJiY2NkZGVlZmYiLCJpYXQiOjE3ODgzMDcyMDAsImV4cCI6MTc5NjA4MzIwMH0.j8lN2bHcHRnUh-01C9wzZ5MeH6VlquX98QmzHGw210af4sU6_onRYVTwAgHR21XZZCg1wNhzgpnOXni1-c3cCA"

    @Suppress("MaxLineLength")
    private val proof =
        "eyJ2IjoyLCJ0eXAiOiJ2b2lkLXdoaWNoLWJpbmRzLnBvc3Nlc3Npb24iLCJjcnQiOiJJTVdqZ1BEeFlZcHpEeVQ4RGJQcFBwVENKakJEY2lDc3QzNEdSQWpFUHowIiwiaWF0IjoxNzg4MzUwNDAwLCJleHAiOjE3ODgzNTA1MjB9.m79EwR8_djhsdo4PF2LFgXGptgQP-KWcZ1z9bt7ZHNy0gA9IRWUEZOzKIw5H3nPdlHYSKEqocjLSb90ktoGyAA"

    private val seed = Hex.decode("808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9f")
    private val now = 1_788_350_400L
    private val devicePub = Cert.parse(cert).cert.device.bytes

    private var signCount = 0
    private val signer = Ed25519Signer {
        signCount++
        Ed25519Engine.sign(seed, it)
    }

    @Test
    fun headerValueMatchesTheGoVector() {
        val p = DeviceCredential.mint(cert, signer, now)
        assertMatchesGoToken(proof, p.proof, devicePub)
        assertEquals("Device $cert~${p.proof}", p.headerValue)
        assertEquals("$cert~${p.proof}", p.value)
        assertEquals(now, p.issuedAt)
        assertEquals(now + 120, p.expiresAt)
        assertEquals(DeviceCredential.headerValue(cert, p.proof), p.headerValue)
    }

    @Test
    fun formatAndParseRoundTrip() {
        val value = DeviceCredential.format(cert, proof)
        assertEquals(cert to proof, DeviceCredential.parse(value))
        assertEquals(cert to proof, DeviceCredential.parse("Device $value"))
        assertTrue(DeviceCredential.isDeviceHeader("Device $value"))
        assertTrue(!DeviceCredential.isDeviceHeader("Bearer tok"))
        assertTrue(!DeviceCredential.isDeviceHeader(null))
        assertFailsWith<IllegalArgumentException> { DeviceCredential.parse("no-separator") }
        assertFailsWith<IllegalArgumentException> { DeviceCredential.format("a~b", proof) }
        assertFailsWith<IllegalArgumentException> { DeviceCredential.format("", proof) }
    }

    @Test
    fun reusesThePresentationInsideTheWindowAndReMintsAfter() {
        var clock = now
        val cred = DeviceCredential(cert, signer, { clock })
        assertEquals(120L, cred.ttlSeconds)
        assertEquals(90L, cred.reuseForSeconds, "default reuse = ttl - skew")

        val first = cred.current()
        assertEquals(1, signCount)
        assertMatchesGoToken(proof, first.proof, devicePub)
        assertEquals("Device $cert~${first.proof}", first.headerValue)

        clock = now + 89
        assertSame(first, cred.current(), "still inside the reuse window")
        assertEquals(1, signCount, "no new signature while reusing")

        clock = now + 90
        val second = cred.current()
        assertEquals(2, signCount, "re-minted once the window lapses")
        assertNotEquals(first.proof, second.proof)
        assertEquals(now + 90, second.issuedAt)
        assertEquals(now + 210, second.expiresAt)

        // The re-minted proof verifies at the new clock, for the same cert, by the device key.
        PossessionProof.verify(second.proof, devicePub, cert, now + 91, Ed25519Engine.verifier())
    }

    @Test
    fun refreshForcesAFreshProofEvenInsideTheWindow() {
        val cred = DeviceCredential(cert, signer, { now })
        val first = cred.current()
        val forced = cred.refresh()
        assertEquals(2, signCount)
        assertTrue(first !== forced)
        assertSame(forced, cred.current(), "the forced presentation is now the live one")
        assertEquals(forced.headerValue, cred.headerValue())
    }

    @Test
    fun customTtlAndReuseWindow() {
        var clock = now
        val cred = DeviceCredential(cert, signer, { clock }, ttlSeconds = 60, reuseForSeconds = 10)
        val p = cred.current()
        assertEquals(now + 60, p.expiresAt)
        clock = now + 10
        assertTrue(p !== cred.current(), "re-minted at the custom window")
        assertFailsWith<IllegalArgumentException> {
            DeviceCredential(cert, signer, { now }, ttlSeconds = 60, reuseForSeconds = 61)
        }
        assertFailsWith<IllegalArgumentException> {
            DeviceCredential(cert, signer, { now }, ttlSeconds = 60, reuseForSeconds = 0)
        }
        assertFailsWith<IllegalArgumentException> { DeviceCredential("", signer, { now }) }
    }
}
