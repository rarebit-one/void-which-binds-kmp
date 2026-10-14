package one.rarebit.cruciform.platform

import one.rarebit.cruciform.BuildConfig
import one.rarebit.cruciform.platform.RelayConfig.Validation
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Pure-JVM rules for the "Pairing relay" setting: the default and what the field accepts. */
class RelayConfigTest {

    @Test
    fun `default is the build-time value, and is itself valid when the build sets one`() {
        // Never a committed constant: it comes from CRUCIFORM_DEFAULT_RELAY / the
        // cruciformDefaultRelay property, and is "" (not configured) when unset.
        assertEquals(BuildConfig.DEFAULT_RELAY_URL.trim(), RelayConfig.DEFAULT_RELAY)
        assertEquals(RelayConfig.DEFAULT_RELAY.isNotEmpty(), RelayConfig.hasDefault)
        if (RelayConfig.hasDefault) {
            assertEquals(Validation.Valid(RelayConfig.DEFAULT_RELAY), RelayConfig.validate(RelayConfig.DEFAULT_RELAY))
        }
    }

    @Test
    fun `validation messages use a placeholder example, not a real endpoint`() {
        val invalid = assertIs<Validation.Invalid>(RelayConfig.validate("http:///pair"))
        assertTrue(invalid.reason.contains(RelayConfig.EXAMPLE_RELAY), invalid.reason)
    }

    @Test
    fun `accepts http and https bases with a host, and a path mount`() {
        assertEquals(
            Validation.Valid("https://relay.example.org"),
            RelayConfig.validate("https://relay.example.org"),
        )
        assertEquals(
            Validation.Valid("http://192.168.16.224:8080/pair"),
            RelayConfig.validate("http://192.168.16.224:8080/pair"),
        )
        assertEquals(Validation.Valid("HTTPS://relay.example"), RelayConfig.validate("HTTPS://relay.example"))
    }

    @Test
    fun `normalises whitespace and trailing slashes so the client's slash-v1 join cannot double up`() {
        assertEquals(
            Validation.Valid("http://192.168.16.224:7777/pair"),
            RelayConfig.validate("  http://192.168.16.224:7777/pair/  "),
        )
        assertEquals(
            Validation.Valid("https://relay.example.org"),
            RelayConfig.validate("https://relay.example.org///"),
        )
        assertEquals("https://relay.example.org", RelayConfig.normalizeOrNull("https://relay.example.org/"))
    }

    @Test
    fun `rejects blank input - the default is a reset, not an empty string`() {
        assertIs<Validation.Invalid>(RelayConfig.validate(""))
        assertIs<Validation.Invalid>(RelayConfig.validate("   "))
        assertNull(RelayConfig.normalizeOrNull(""))
    }

    @Test
    fun `rejects non-http schemes and bare hosts`() {
        assertIs<Validation.Invalid>(RelayConfig.validate("wss://relay.example.org"))
        assertIs<Validation.Invalid>(RelayConfig.validate("ftp://relay.example.org"))
        assertIs<Validation.Invalid>(RelayConfig.validate("relay.example.org"))
        assertIs<Validation.Invalid>(RelayConfig.validate("192.168.16.224:7777/pair"))
        assertIs<Validation.Invalid>(RelayConfig.validate("/pair"))
    }

    @Test
    fun `rejects a scheme with no host`() {
        assertIs<Validation.Invalid>(RelayConfig.validate("http://"))
        assertIs<Validation.Invalid>(RelayConfig.validate("http:///pair"))
    }

    @Test
    fun `rejects query, fragment and userinfo - the base is a mount point, not a request`() {
        assertIs<Validation.Invalid>(RelayConfig.validate("http://192.168.16.224:7777/pair?x=1"))
        assertIs<Validation.Invalid>(RelayConfig.validate("http://192.168.16.224:7777/pair#frag"))
        assertIs<Validation.Invalid>(RelayConfig.validate("http://user:pw@192.168.16.224:7777/pair"))
    }

    @Test
    fun `rejects unparseable input`() {
        assertIs<Validation.Invalid>(RelayConfig.validate("http://exa mple.com/pair"))
        assertIs<Validation.Invalid>(RelayConfig.validate("http://[::1"))
    }

    @Test
    fun `invalid input carries a human-readable reason`() {
        val invalid = assertIs<Validation.Invalid>(RelayConfig.validate("wss://relay"))
        assert(invalid.reason.contains("http://")) { invalid.reason }
    }
}
