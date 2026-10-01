package one.rarebit.cruciform.handoff

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Routing of an incoming intent (action + data string) into a [Handoff]. Pure JVM —
 * no Android runtime — because the router deliberately takes strings, not an Intent.
 */
class HandoffRouterTest {

    private val tuple =
        "void-which-binds:login?id=d0865b8fd4dd6174b0c35e514a0a5e37&rp=http%3A%2F%2F192.168.16.224%3A7777"

    @Test
    fun viewOfALoginUriRoutesToLoginAndReturnsToCaller() {
        val h = HandoffRouter.fromDeepLink(HandoffRouter.ACTION_VIEW, tuple, seq = 1)
        assertNotNull(h)
        assertEquals(Handoff.Kind.LOGIN, h!!.kind)
        assertEquals(Handoff.Origin.DEEP_LINK, h.origin)
        assertEquals(tuple, h.tuple)
        assertNull(h.callback)
        assertTrue(h.returnsToCaller)
    }

    @Test
    fun callbackIsCarriedButStrippedFromTheTuple() {
        val uri = "void-which-binds:login?rp=http%3A%2F%2F192.168.16.224%3A7777" +
            "&id=d0865b8fd4dd6174b0c35e514a0a5e37&callback=heyarr%3A%2F%2Fdone"
        val h = HandoffRouter.fromDeepLink(HandoffRouter.ACTION_VIEW, uri, seq = 1)!!
        assertEquals("heyarr://done", h.callback)
        // The engine sees the canonical broker tuple, never the callback.
        assertEquals(tuple, h.tuple)
    }

    @Test
    fun aWebCallbackIsDroppedNotHonoured() {
        val uri = "$tuple&callback=https%3A%2F%2Fevil.example"
        val h = HandoffRouter.fromDeepLink(HandoffRouter.ACTION_VIEW, uri, seq = 1)!!
        assertNull(h.callback)
        assertEquals(Handoff.Kind.LOGIN, h.kind)
    }

    @Test
    fun pairInviteRoutesToPair() {
        val invite = "void-which-binds:pair?relay=http%3A%2F%2Frelay&salt=00112233445566778899aabbccddeeff" +
            "00112233445566778899aabbccddeeff&session=sess1" +
            "&usr=ed25519%3Af947b10c8089aa8fed2d435fae069d0ca1513b33691955ae963dfe8bc5b398c4&v=4"
        val h = HandoffRouter.fromDeepLink(
            HandoffRouter.ACTION_VIEW,
            "$invite&callback=myapp%3A%2F%2Fpaired",
            seq = 3,
        )!!
        assertEquals(Handoff.Kind.PAIR, h.kind)
        assertEquals(invite, h.tuple)
        assertEquals("myapp://paired", h.callback)
        assertEquals(3, h.seq)
    }

    @Test
    fun nonViewNonVoidWhichBindsOrMalformedYieldsNothing() {
        assertNull(HandoffRouter.fromDeepLink("android.intent.action.MAIN", tuple, 1))
        assertNull(HandoffRouter.fromDeepLink(HandoffRouter.ACTION_VIEW, null, 1))
        assertNull(HandoffRouter.fromDeepLink(HandoffRouter.ACTION_VIEW, "https://example.com/void-which-binds:x", 1))
        assertNull(HandoffRouter.fromDeepLink(HandoffRouter.ACTION_VIEW, "void-which-binds:login?rp=x", 1)) // no id
        assertNull(HandoffRouter.fromDeepLink(HandoffRouter.ACTION_VIEW, "void-which-binds:other?rp=x&id=y", 1))
        assertNull(HandoffRouter.fromDeepLink(HandoffRouter.ACTION_VIEW, "VOID-WHICH-BINDS:login?rp=x&id=y", 1))
    }

    @Test
    fun aGen1VoidbindLinkIsNotHandled() {
        // Gen2 has no gen1 reader (void-which-binds-go ADR-0022): the retired `voidbind:`
        // scheme is refused even when the rest of the tuple is well-formed.
        val gen1Login = tuple.replaceFirst("void-which-binds:", "voidbind:")
        assertNull(HandoffRouter.fromDeepLink(HandoffRouter.ACTION_VIEW, gen1Login, 1))
        assertNull(HandoffRouter.fromDeepLink(HandoffRouter.ACTION_VIEW, "$gen1Login&callback=heyarr%3A%2F%2Fdone", 1))
        val gen1Invite = "voidbind:pair?relay=http%3A%2F%2Frelay&salt=00112233445566778899aabbccddeeff" +
            "00112233445566778899aabbccddeeff&session=sess1" +
            "&usr=ed25519%3Af947b10c8089aa8fed2d435fae069d0ca1513b33691955ae963dfe8bc5b398c4&v=3"
        assertNull(HandoffRouter.fromDeepLink(HandoffRouter.ACTION_VIEW, gen1Invite, 1))
    }

    @Test
    fun pushWakeStaysInTheApp() {
        val h = HandoffRouter.fromPush(tuple, seq = 7)!!
        assertEquals(Handoff.Origin.PUSH, h.origin)
        assertFalse(h.returnsToCaller)
        assertNull(h.callback)
        assertNull(HandoffRouter.fromPush(null, 1))
        assertNull(HandoffRouter.fromPush("  ", 1))
    }

    @Test
    fun twoIdenticalWakesAreDistinctBySeq() {
        val a = HandoffRouter.fromDeepLink(HandoffRouter.ACTION_VIEW, tuple, 1)
        val b = HandoffRouter.fromDeepLink(HandoffRouter.ACTION_VIEW, tuple, 2)
        assertTrue(a != b)
    }
}
