package one.rarebit.voidwhichbinds

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Golden vector CAPTURED FROM void-which-binds-go's `pairflow.EncodeInvite` (gen2,
 * void-which-binds-go v0.19.0) with fixed inputs (relay = "http://relay.local:8090",
 * session = "sess123", salt = 0x33×32, usr = a fixed genesis key) — invite v4: v3's
 * fields, `usr` included, under the `void-which-binds:` scheme (ADR-0022).
 * It proves the KMP invite encoder is byte-identical to the Go side — the wire a
 * device scans must render the same on both, or an invite produced by one is not
 * decodable-as-expected by the other.
 */
class InviteTest {

    private val relay = "http://relay.local:8090"
    private val session = "sess123"
    private val salt = ByteArray(32) { 0x33 }
    private val usr = "ed25519:f947b10c8089aa8fed2d435fae069d0ca1513b33691955ae963dfe8bc5b398c4"

    private val golden =
        "void-which-binds:pair?relay=http%3A%2F%2Frelay.local%3A8090" +
            "&salt=3333333333333333333333333333333333333333333333333333333333333333" +
            "&session=sess123&usr=ed25519%3Af947b10c8089aa8fed2d435fae069d0ca1513b33691955ae963dfe8bc5b398c4&v=4"

    @Test
    fun encodeMatchesVoidbindGo() {
        assertEquals(golden, Invite.encode(relay, session, salt, usr))
    }

    @Test
    fun decodeParsesTheGoldenInvite() {
        val p = Invite.decode(golden)
        assertEquals(relay, p.relay)
        assertEquals(session, p.session)
        assertContentEquals(salt, p.salt)
        assertEquals(usr, p.user)
    }

    @Test
    fun roundTrips() {
        val p = Invite.decode(Invite.encode(relay, session, salt, usr))
        assertEquals(relay, p.relay)
        assertEquals(session, p.session)
        assertContentEquals(salt, p.salt)
        assertEquals(usr, p.user)
    }

    @Test
    fun decodeIsKeyOrderIndependent() {
        // Same fields, keys in a different order than Encode emits.
        val reordered =
            "void-which-binds:pair?v=4&usr=ed25519%3Af947b10c8089aa8fed2d435fae069d0ca1513b33691955ae963dfe8bc5b398c4" +
                "&session=sess123&relay=http%3A%2F%2Frelay.local%3A8090" +
                "&salt=3333333333333333333333333333333333333333333333333333333333333333"
        val p = Invite.decode(reordered)
        assertEquals(relay, p.relay)
        assertEquals(session, p.session)
        assertContentEquals(salt, p.salt)
    }

    @Test
    fun rejectsWrongSchemeVersionAndShortSalt() {
        assertFailsWith<IllegalArgumentException> {
            Invite.decode(golden.replaceFirst("void-which-binds:", "https:"))
        }
        assertFailsWith<IllegalArgumentException> {
            Invite.decode(golden.replaceFirst("v=4", "v=9"))
        }
        assertFailsWith<IllegalArgumentException> {
            // A v2 invite (no usr) is refused: the responder needs the identity to evaluate.
            Invite.decode(
                golden.replaceFirst(
                    "v=4",
                    "v=2",
                ).replaceFirst("&usr=ed25519%3Af947b10c8089aa8fed2d435fae069d0ca1513b33691955ae963dfe8bc5b398c4", ""),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            Invite.decode(
                golden.replaceFirst(
                    "&usr=ed25519%3Af947b10c8089aa8fed2d435fae069d0ca1513b33691955ae963dfe8bc5b398c4",
                    "",
                ),
            )
        }
        assertFailsWith<IllegalArgumentException> {
            Invite.decode("void-which-binds:pair?v=4&relay=http://r&session=s&salt=33&usr=$usr")
        }
        assertFailsWith<IllegalArgumentException> {
            Invite.decode("https://example.com/not-an-invite")
        }
    }

    @Test
    fun aGen1InviteIsRefusedNotDualParsed() {
        // ADR-0022: the gen1 `voidbind:` scheme and invite v3 are refused, whichever changed.
        val gen1 = golden.replaceFirst("void-which-binds:", "voidbind:").replaceFirst("v=4", "v=3")
        val gen1Variants = listOf(
            gen1,
            golden.replaceFirst("v=4", "v=3"),
            golden.replaceFirst("void-which-binds:", "voidbind:"),
        )
        for (uri in gen1Variants) {
            assertFailsWith<IllegalArgumentException>(uri) { Invite.decode(uri) }
            assertFailsWith<IllegalArgumentException>(uri) { VoidbindQr.parse(uri) }
        }
    }

    @Test
    fun encodeRejectsEmptyAndShortSalt() {
        assertFailsWith<IllegalArgumentException> { Invite.encode("", session, salt, usr) }
        assertFailsWith<IllegalArgumentException> { Invite.encode(relay, "", salt, usr) }
        assertFailsWith<IllegalArgumentException> { Invite.encode(relay, session, ByteArray(8), usr) }
        assertFailsWith<IllegalArgumentException> { Invite.encode(relay, session, salt, "") }
        assertFailsWith<IllegalArgumentException> { Invite.encode(relay, session, salt, "x25519:00") }
    }

    @Test
    fun encodesTheMinimumSaltLength() {
        // A salt at exactly the floor is accepted and round-trips.
        val minSalt = ByteArray(Pairing.MIN_SALT_LEN) { 0x44 }
        val p = Invite.decode(Invite.encode(relay, session, minSalt, usr))
        assertTrue(p.salt.size == Pairing.MIN_SALT_LEN)
        assertContentEquals(minSalt, p.salt)
    }
}
