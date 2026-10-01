package one.rarebit.voidwhichbinds

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The push/wake ping is OPAQUE — a wake signal, not a crypto path. These tests pin
 * that invariant on the device parser: a ping is the same public `(rp, id)` tuple a
 * QR carries and NOTHING else, so [PushPing] does no more than decode that tuple and
 * hands the phone exactly what a scan would. It never expects — and there is nothing
 * in the ping to read — a challenge, nonce, cert, key, or (for a number-matching
 * login) a match number. This mirrors void-which-binds-go/notify's `TestPingIsOpaque`.
 */
class PushPingTest {

    @Test
    fun aPingIsJustTheOpaqueLoginTuple() {
        val tuple = LoginQr.encode("https://allthing.local", "L123")
        val decoded = PushPing.parse(tuple)
        assertTrue(decoded is VoidbindQr.Login)
        val login = decoded.request
        assertEquals("https://allthing.local", login.rp)
        assertEquals("L123", login.id)
    }

    @Test
    fun surroundingWhitespaceFromTheWakeChannelIsTolerated() {
        val tuple = LoginQr.encode("https://rp.example", "abc")
        // ntfy delivers the published body; be forgiving of a trailing newline.
        val decoded = PushPing.parse("  $tuple\n")
        assertTrue(decoded is VoidbindQr.Login)
    }

    @Test
    fun theParserReadsNoSecretFields_theTupleCarriesOnlyRpAndId() {
        // A ping that (impossibly) tried to smuggle a nonce/cert/match number as extra
        // query params is still parsed as ONLY rp+id — the parser reads nothing else,
        // so no secret channel exists even if a sender tried to open one.
        val sneaky = "voidbind:login?rp=https%3A%2F%2Frp&id=L1&nonce=deadbeef&cert=forged&match_number=42"
        val login = (PushPing.parse(sneaky) as VoidbindQr.Login).request
        assertEquals("L1", login.id)
        assertEquals("https://rp", login.rp)
        // The parsed shape exposes rp and id only — there is no accessor for a secret,
        // by construction (LoginQr.Parsed has exactly these two fields).
    }

    @Test
    fun aNonVoidbindOrMalformedPushIsRejected_notActedOn() {
        assertFailsWith<Exception> { PushPing.parse("https://evil.example/notaping") }
        assertFailsWith<Exception> { PushPing.parse("""{"challenge":"...","nonce":"..."}""") }
        assertFailsWith<Exception> { PushPing.parse("") }
    }

    @Test
    fun parseOrNullSilentlyDropsAStrayPush() {
        assertNull(PushPing.parseOrNull("garbage"))
        assertNull(PushPing.parseOrNull(""))
        assertTrue(PushPing.parseOrNull(LoginQr.encode("https://rp", "x")) is VoidbindQr.Login)
    }
}
