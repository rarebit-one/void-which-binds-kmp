package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Pins the app-to-app handoff URI ([VoidbindDeepLink]): the QR tuple stays the
 * byte-identical void-which-binds-go wire, `callback` is the only addition, and a callback
 * is kept only when it is a private app-scheme URI.
 */
class DeepLinkTest {

    private val rp = "http://192.168.16.224:7777"
    private val id = "d0865b8fd4dd6174b0c35e514a0a5e37"
    private val brokerQr = "void-which-binds:login?id=$id&rp=http%3A%2F%2F192.168.16.224%3A7777"

    @Test
    fun loginUriWithoutCallbackIsTheQrTuple() {
        assertEquals(LoginQr.encode(rp, id), VoidbindDeepLink.loginUri(rp, id))
        assertEquals(brokerQr, VoidbindDeepLink.loginUri(rp, id))
    }

    @Test
    fun loginUriAppendsAnEscapedCallback() {
        val uri = VoidbindDeepLink.loginUri(rp, id, "heyarr://login/done?x=1&y=2")
        assertEquals("$brokerQr&callback=heyarr%3A%2F%2Flogin%2Fdone%3Fx%3D1%26y%3D2", uri)
        val parsed = VoidbindDeepLink.parse(uri) as VoidbindDeepLink.Parsed.Login
        assertEquals(rp, parsed.rp)
        assertEquals(id, parsed.id)
        assertEquals("heyarr://login/done?x=1&y=2", parsed.callback)
        // The bare tuple the authenticator hands its engine is the broker's QR, exactly.
        assertEquals(brokerQr, parsed.tuple)
    }

    @Test
    fun loginUriFromTheBrokerTupleRoundTrips() {
        assertEquals(brokerQr, VoidbindDeepLink.loginUriFromTuple(brokerQr))
        assertEquals(
            "$brokerQr&callback=allthing%3A%2F%2Fsignin",
            VoidbindDeepLink.loginUriFromTuple(brokerQr, "allthing://signin"),
        )
        assertFailsWith<IllegalArgumentException> {
            VoidbindDeepLink.loginUriFromTuple("void-which-binds:pair?v=4", "allthing://x")
        }
    }

    @Test
    fun builderRefusesAMalformedCallback() {
        assertFailsWith<IllegalArgumentException> { VoidbindDeepLink.loginUri(rp, id, "https://evil.example") }
        assertFailsWith<IllegalArgumentException> { VoidbindDeepLink.loginUri(rp, id, "not a uri") }
        assertFailsWith<IllegalArgumentException> { VoidbindDeepLink.loginUri(rp, id, "") }
    }

    @Test
    fun parseToleratesKeyOrderAndDropsAMalformedCallback() {
        // rp first, callback in the middle — a deep link built by hand.
        val hand = "void-which-binds:login?rp=http%3A%2F%2Fh&callback=myapp%3A%2F%2Fback&id=XYZ"
        val p = VoidbindDeepLink.parse(hand) as VoidbindDeepLink.Parsed.Login
        assertEquals("http://h", p.rp)
        assertEquals("XYZ", p.id)
        assertEquals("myapp://back", p.callback)

        // A web / javascript / intent / void-which-binds callback is dropped, the login kept.
        for (bad in listOf(
            "https://evil.example/x",
            "javascript:alert(1)",
            "intent://x#Intent;end",
            "void-which-binds:login?rp=a&id=b",
            "file:///etc/passwd",
            "content://media/1",
        )) {
            val u = "$brokerQr&callback=${one.rarebit.voidwhichbinds.crypto.UrlQuery.escape(bad)}"
            val q = VoidbindDeepLink.parse(u) as VoidbindDeepLink.Parsed.Login
            assertNull(q.callback, "callback '$bad' must be dropped")
            assertEquals(id, q.id)
        }
        // Absent → null.
        assertNull((VoidbindDeepLink.parse(brokerQr) as VoidbindDeepLink.Parsed.Login).callback)
    }

    @Test
    fun parseIsAsStrictAsAScan() {
        assertFailsWith<IllegalArgumentException> { VoidbindDeepLink.parse("https://example.com/login") }
        assertFailsWith<IllegalArgumentException> {
            VoidbindDeepLink.parse("void-which-binds:login?rp=x&callback=myapp%3A%2F%2Fx")
        } // no id
        assertFailsWith<IllegalArgumentException> { VoidbindDeepLink.parse("void-which-binds:other?rp=x&id=y") }
        assertNull(VoidbindDeepLink.parseOrNull("nope"))
    }

    @Test
    fun pairHandoffCarriesTheInviteAndCallback() {
        val saltHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        val invite = Invite.encode(
            "http://relay",
            "sess1",
            Hex.decode(saltHex),
            "ed25519:f947b10c8089aa8fed2d435fae069d0ca1513b33691955ae963dfe8bc5b398c4",
        )
        val uri = VoidbindDeepLink.pairUri(invite, "myapp://paired")
        assertEquals("$invite&callback=myapp%3A%2F%2Fpaired", uri)
        val p = VoidbindDeepLink.parse(uri) as VoidbindDeepLink.Parsed.Pair
        assertEquals("sess1", p.invite.session)
        assertEquals("http://relay", p.invite.relay)
        assertEquals("myapp://paired", p.callback)
        assertEquals(invite, p.tuple)
        assertEquals(invite, VoidbindDeepLink.pairUri(invite))
    }

    @Test
    fun callbackWellFormedness() {
        assertTrue(VoidbindDeepLink.isWellFormedCallback("heyarr://login/done"))
        assertTrue(VoidbindDeepLink.isWellFormedCallback("one.rarebit.allthing:signin"))
        assertTrue(VoidbindDeepLink.isWellFormedCallback("my-app+x:///"))
        assertFalse(VoidbindDeepLink.isWellFormedCallback(""))
        assertFalse(VoidbindDeepLink.isWellFormedCallback("://x"))
        assertFalse(VoidbindDeepLink.isWellFormedCallback("1app://x"))
        assertFalse(VoidbindDeepLink.isWellFormedCallback("my app://x"))
        assertFalse(VoidbindDeepLink.isWellFormedCallback("myapp://x\ny"))
        assertFalse(VoidbindDeepLink.isWellFormedCallback("HTTPS://x"))
        assertFalse(VoidbindDeepLink.isWellFormedCallback("Void-Which-Binds:login?rp=a&id=b"))
        assertFalse(VoidbindDeepLink.isWellFormedCallback("noscheme"))
        assertFalse(VoidbindDeepLink.isWellFormedCallback("myapp:" + "a".repeat(VoidbindDeepLink.MAX_CALLBACK_LENGTH)))
    }
}
