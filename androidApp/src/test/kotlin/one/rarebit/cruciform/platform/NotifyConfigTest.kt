package one.rarebit.cruciform.platform

import one.rarebit.cruciform.BuildConfig
import one.rarebit.cruciform.platform.RelayConfig.Validation
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

/** Pure-JVM rules for the "Push plane" setting: the default and what the field accepts. */
class NotifyConfigTest {

    @Test
    fun `default is the build-time value, and is itself valid when the build sets one`() {
        // Never a committed constant: it comes from CRUCIFORM_DEFAULT_NOTIFY / the
        // cruciformDefaultNotify property, and is "" (push registration skipped) when unset.
        assertEquals(BuildConfig.DEFAULT_NOTIFY_URL.trim(), NotifyConfig.DEFAULT_NOTIFY)
        assertEquals(NotifyConfig.DEFAULT_NOTIFY.isNotEmpty(), NotifyConfig.hasDefault)
        if (NotifyConfig.hasDefault) {
            assertEquals(
                Validation.Valid(NotifyConfig.DEFAULT_NOTIFY),
                NotifyConfig.validate(NotifyConfig.DEFAULT_NOTIFY),
            )
        }
    }

    @Test
    fun `validation messages use a placeholder example, not a real endpoint`() {
        val invalid = assertIs<Validation.Invalid>(NotifyConfig.validate("http:///v1"))
        assertTrue(invalid.reason.contains(NotifyConfig.EXAMPLE_NOTIFY), invalid.reason)
    }

    @Test
    fun `accepts http and https bases with a host`() {
        assertEquals(
            Validation.Valid("https://notify.example.org"),
            NotifyConfig.validate("https://notify.example.org"),
        )
        assertEquals(Validation.Valid("http://192.168.24.1:2587"), NotifyConfig.validate("http://192.168.24.1:2587"))
    }

    @Test
    fun `normalises whitespace and trailing slashes so the client's slash-v1 join cannot double up`() {
        assertEquals(
            Validation.Valid("http://192.168.16.224:2587"),
            NotifyConfig.validate("  http://192.168.16.224:2587/  "),
        )
        assertEquals("https://notify.example.org", NotifyConfig.normalizeOrNull("https://notify.example.org///"))
    }

    @Test
    fun `rejects blank, non-http schemes, credentials and query fragments`() {
        assertIs<Validation.Invalid>(NotifyConfig.validate(""))
        assertIs<Validation.Invalid>(NotifyConfig.validate("ftp://notify.example"))
        assertIs<Validation.Invalid>(NotifyConfig.validate("http://user:pw@notify.example"))
        assertIs<Validation.Invalid>(NotifyConfig.validate("http://notify.example?a=1"))
        assertNull(NotifyConfig.normalizeOrNull("notify.example"))
    }

    @Test
    fun `its messages name the push plane, not the relay`() {
        val reason = (NotifyConfig.validate("") as Validation.Invalid).reason
        assertTrue(reason.contains("push plane"), "message should name this field: $reason")
    }
}
