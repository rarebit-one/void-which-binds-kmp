package one.rarebit.cruciform.handoff

import one.rarebit.cruciform.handoff.SamePhonePairCallback.Decision
import one.rarebit.cruciform.handoff.SamePhonePairCallback.Joined
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The compare-and-decide half of the same-phone one-tap path (ADR-0008). This is the
 * whole of the security judgement: a relying-party app on this phone reports the device
 * key and SAS it derived, and these rules say whether that agrees with what the RELAY
 * revealed. Everything else — the sheet, the icon, the biometric — sits behind a
 * [Decision.Match] produced here.
 */
class SamePhonePairCallbackTest {

    private val dev = "ed25519:9f1c0aa2b3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e"
    private val sas = "1234567"

    // --- routing ------------------------------------------------------------

    @Test
    fun routesAWellFormedCallback() {
        val r = SamePhonePairCallback.route(
            SamePhonePairCallback.ACTION_VIEW,
            "cruciform://pair-joined?session=abc123&dev=$dev&sas=$sas",
        )
        assertEquals(Joined("abc123", dev, sas), r)
    }

    @Test
    fun percentDecodesValuesAndToleratesOrder() {
        val r = SamePhonePairCallback.route(
            SamePhonePairCallback.ACTION_VIEW,
            "cruciform://pair-joined?sas=123%204567&dev=$dev&session=abc%2D123",
        ) as Joined
        assertEquals("abc-123", r.session)
        assertEquals("123 4567", r.sas)
    }

    @Test
    fun acceptsTheExactWireHeyarrMobileProduces() {
        // Pinned against heyarr-mobile's CruciformPairCallback.joinedUri: the `:` of
        // `ed25519:` is reserved and travels as `%3A`, so a decode-then-compare is the
        // only thing that lines the two renderings up.
        val r = SamePhonePairCallback.route(
            SamePhonePairCallback.ACTION_VIEW,
            "cruciform://pair-joined?session=sessA&dev=ed25519%3A" + "cd".repeat(32) + "&sas=1234567",
        ) as Joined
        assertEquals("ed25519:" + "cd".repeat(32), r.dev)
        assertEquals(Decision.Match, SamePhonePairCallback.decide(r, "sessA", "ed25519:" + "cd".repeat(32), "123 4567"))
    }

    @Test
    fun ignoresAnythingThatIsNotOurs() {
        // Not a VIEW; another app's scheme; our own login scheme; a near-miss host.
        assertNull(
            SamePhonePairCallback.route(
                "android.intent.action.SEND",
                "cruciform://pair-joined?session=a&dev=$dev&sas=$sas",
            ),
        )
        assertNull(SamePhonePairCallback.route(SamePhonePairCallback.ACTION_VIEW, "heyarr-mobile://pair?invite=x"))
        assertNull(SamePhonePairCallback.route(SamePhonePairCallback.ACTION_VIEW, "void-which-binds:login?rp=a&id=b"))
        assertNull(
            SamePhonePairCallback.route(SamePhonePairCallback.ACTION_VIEW, "cruciform://pair-joined-x?session=a"),
        )
        assertNull(SamePhonePairCallback.route(SamePhonePairCallback.ACTION_VIEW, null))
    }

    @Test
    fun ourSchemeWithMissingOrEmptyValuesIsMalformedNotIgnored() {
        // Malformed, not null: it IS addressed to us, and a silent drop would hide a bug
        // in an RP's callback behind "nothing happened".
        assertTrue(
            SamePhonePairCallback.route(SamePhonePairCallback.ACTION_VIEW, "cruciform://pair-joined?session=a&dev=$dev")
                is SamePhonePairCallback.Malformed,
        )
        assertTrue(
            SamePhonePairCallback.route(
                SamePhonePairCallback.ACTION_VIEW,
                "cruciform://pair-joined?session=&dev=$dev&sas=$sas",
            )
                is SamePhonePairCallback.Malformed,
        )
        assertTrue(
            SamePhonePairCallback.route(SamePhonePairCallback.ACTION_VIEW, "cruciform://pair-joined")
                is SamePhonePairCallback.Malformed,
        )
    }

    // --- deciding -----------------------------------------------------------

    @Test
    fun matchesWhenTheReportAgreesWithTheRelay() {
        assertEquals(Decision.Match, SamePhonePairCallback.decide(Joined("s1", dev, sas), "s1", dev, sas))
    }

    @Test
    fun theSasIsComparedOnItsDigitsNotItsGrouping() {
        // Cruciform groups the SAS `NNN NNNN` for the eye; an RP shows it however it likes.
        assertEquals(Decision.Match, SamePhonePairCallback.decide(Joined("s1", dev, "1234567"), "s1", dev, "123 4567"))
        assertEquals(Decision.Match, SamePhonePairCallback.decide(Joined("s1", dev, "123-4567"), "s1", dev, "123 4567"))
    }

    @Test
    fun theDeviceKeyIsComparedCaseInsensitivelyAndTrimmed() {
        assertEquals(
            Decision.Match,
            SamePhonePairCallback.decide(Joined("s1", " ${dev.uppercase()} ", sas), "s1", dev, sas),
        )
    }

    @Test
    fun aDifferentDeviceKeyIsRefused() {
        val other = dev.dropLast(1) + "f"
        val d = SamePhonePairCallback.decide(Joined("s1", other, sas), "s1", dev, sas)
        assertTrue("expected a mismatch, got $d", d is Decision.Mismatch)
        assertTrue((d as Decision.Mismatch).reason.contains("device key"))
    }

    @Test
    fun aDifferentSasIsRefused() {
        val d = SamePhonePairCallback.decide(Joined("s1", dev, "7654321"), "s1", dev, sas)
        assertTrue("expected a mismatch, got $d", d is Decision.Mismatch)
        assertTrue((d as Decision.Mismatch).reason.contains("security code"))
    }

    @Test
    fun anEmptySasNeverMatchesEvenAgainstAnEmptyOne() {
        // A degenerate "both sides have nothing" must not read as agreement.
        assertTrue(
            SamePhonePairCallback.decide(Joined("s1", dev, "no digits"), "s1", dev, "also none") is Decision.Mismatch,
        )
    }

    @Test
    fun aReportForAnotherSessionIsIgnoredNotRefused() {
        // Ignored, NOT a mismatch: a stale callback from an abandoned invite must never
        // tear down the invite that is actually live.
        val d = SamePhonePairCallback.decide(Joined("other", dev, sas), "s1", dev, sas)
        assertTrue(d is Decision.OtherSession)
    }

    @Test
    fun aReportWithNoLiveInviteIsIgnored() {
        assertTrue(SamePhonePairCallback.decide(Joined("s1", dev, sas), null, null, null) is Decision.OtherSession)
        assertTrue(SamePhonePairCallback.decide(Joined("s1", dev, sas), "", null, null) is Decision.OtherSession)
    }

    @Test
    fun aReportThatBeatsTheRelayRevealIsHeldNotJudged() {
        // The RP posted its commit and called us back before our own poll came round:
        // there is nothing to compare against yet, and neither approving nor refusing
        // would be honest.
        assertEquals(Decision.TooEarly, SamePhonePairCallback.decide(Joined("s1", dev, sas), "s1", null, null))
        assertEquals(Decision.TooEarly, SamePhonePairCallback.decide(Joined("s1", dev, sas), "s1", dev, null))
    }

    // --- the return trip ----------------------------------------------------

    @Test
    fun buildsTheRpsDoneUri() {
        assertEquals(
            "heyarr-mobile://pair-done?session=abc123",
            SamePhonePairCallback.doneUri("heyarr-mobile", "abc123"),
        )
    }

    @Test
    fun theDoneUrisSessionIsPercentEncoded() {
        assertEquals("allthing://pair-done?session=a%26b%3Dc", SamePhonePairCallback.doneUri("allthing", "a&b=c"))
        assertEquals(
            "heyarr-mobile://pair-done?session=abc123&outcome=refused&reason=the%20SAS%20differed%3A%20%3D",
            SamePhonePairCallback.refusedUri("heyarr-mobile", "abc123", "the SAS differed: ="),
        )
    }
}
