package one.rarebit.voidwhichbinds

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Pins the web-login QR wire ([LoginQr]) to void-which-binds-go's `weblogin.EncodeLogin`
 * and the scan dispatcher ([VoidbindQr]). The encoded strings are captured from
 * Go, so a kmp-rendered QR is indistinguishable from a Go-rendered one (keys
 * SORTED → `id` before `rp`, values query-escaped).
 */
class LoginQrTest {

    @Test
    fun encodeMatchesVoidbindGoByteForByte() {
        assertEquals(
            "void-which-binds:login?id=L1a2b3&rp=https%3A%2F%2Fhomelab.example%3A8443%2Fapp",
            LoginQr.encode("https://homelab.example:8443/app", "L1a2b3"),
        )
        assertEquals(
            "void-which-binds:login?id=abc+DEF%2B%2F%3D%3F%26&rp=http%3A%2F%2F127.0.0.1%3A9000",
            LoginQr.encode("http://127.0.0.1:9000", "abc DEF+/=?&"),
        )
    }

    @Test
    fun decodeRoundTrips() {
        val rp = "https://homelab.example:8443/app"
        val id = "L1a2b3"
        val parsed = LoginQr.decode(LoginQr.encode(rp, id))
        assertEquals(rp, parsed.rp)
        assertEquals(id, parsed.id)
    }

    @Test
    fun decodeToleratesKeyOrder() {
        // rp before id — a decoder must not depend on the sorted order encode emits.
        val parsed = LoginQr.decode("void-which-binds:login?rp=http%3A%2F%2Fh&id=XYZ")
        assertEquals("http://h", parsed.rp)
        assertEquals("XYZ", parsed.id)
    }

    @Test
    fun refusesEmptyFieldsAndWrongScheme() {
        assertFailsWith<IllegalArgumentException> { LoginQr.encode("", "id") }
        assertFailsWith<IllegalArgumentException> { LoginQr.encode("rp", "") }
        assertFailsWith<IllegalArgumentException> { LoginQr.decode("void-which-binds:login?rp=x") } // no id
        assertFailsWith<IllegalArgumentException> { LoginQr.decode("void-which-binds:pair?v=4") } // not a login QR
    }

    @Test
    fun aGen1LoginQrIsRefused() {
        // ADR-0022 (void-which-binds-go TestDecodeLoginRefusesGen1): `voidbind:login` is not dual-parsed.
        val gen1 = "voidbind:login?id=L1a2b3&rp=https%3A%2F%2Fhomelab.example%3A8443%2Fapp"
        assertFailsWith<IllegalArgumentException> { LoginQr.decode(gen1) }
        assertFailsWith<IllegalArgumentException> { VoidbindQr.parse(gen1) }
        assertFailsWith<IllegalArgumentException> { PushPing.parse(gen1) }
    }

    @Test
    fun dispatcherClassifiesLoginAndPair() {
        val login = VoidbindQr.parse("void-which-binds:login?id=L1&rp=http%3A%2F%2Fh")
        assertTrue(login is VoidbindQr.Login)
        assertEquals("L1", (login as VoidbindQr.Login).request.id)

        val saltHex = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
        val invite = Invite.encode(
            relay = "http://relay",
            session = "sess1",
            salt = one.rarebit.voidwhichbinds.crypto.Hex.decode(saltHex),
            usr = "ed25519:f947b10c8089aa8fed2d435fae069d0ca1513b33691955ae963dfe8bc5b398c4",
        )
        val pair = VoidbindQr.parse(invite)
        assertTrue(pair is VoidbindQr.Pair)
        assertEquals("sess1", (pair as VoidbindQr.Pair).invite.session)
    }

    @Test
    fun dispatcherRejectsForeignQr() {
        assertFailsWith<IllegalArgumentException> { VoidbindQr.parse("https://example.com/login") }
        assertFailsWith<IllegalArgumentException> { VoidbindQr.parse("void-which-binds:unknown?x=1") }
    }
}
