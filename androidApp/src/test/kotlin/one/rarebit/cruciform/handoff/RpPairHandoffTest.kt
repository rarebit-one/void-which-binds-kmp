package one.rarebit.cruciform.handoff

import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertThrows
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * The reverse handoff URI (ADR-0006) and the discovery mapping (ADR-0009 / #39): an
 * RP's own pair-callback scheme carrying the byte-identical invite as one
 * percent-encoded query value, and the pure advert → target/identity logic that
 * replaced the hard-coded registry. Pure JVM.
 */
class RpPairHandoffTest {

    private val invite = "void-which-binds:pair?relay=http%3A%2F%2F192.168.16.224%3A8788&salt=" +
        "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff&session=sess1" +
        "&usr=ed25519%3Af947b10c8089aa8fed2d435fae069d0ca1513b33691955ae963dfe8bc5b398c4&v=4"
    private val heyarr = RpPairTarget(appName = "heyarr", callbackBase = "heyarr-mobile://pair")

    @Test
    fun uriIsTheRpSchemePlusOneEncodedInviteValue() {
        val uri = RpPairHandoff.uriFor(heyarr, invite)
        assertTrue(uri, uri.startsWith("heyarr-mobile://pair?invite="))
        val value = uri.substringAfter("invite=")
        // The tuple's own delimiters are all encoded, so the RP sees a single value.
        assertTrue(value, '?' !in value && '&' !in value && '=' !in value && ':' !in value)
        assertEquals(invite, percentDecode(value))
    }

    @Test
    fun encodingIsRfc3986UppercaseAndKeepsTheUnreservedSet() {
        assertEquals("a-b_c.d~e", RpPairHandoff.percentEncode("a-b_c.d~e"))
        assertEquals("%3A%2F%3F%26%3D%25%20%2B", RpPairHandoff.percentEncode(":/?&=% +"))
        assertEquals("%C3%A9", RpPairHandoff.percentEncode("é"))
    }

    @Test
    fun aLoginTupleIsRefused() {
        assertThrows(IllegalArgumentException::class.java) {
            RpPairHandoff.uriFor(heyarr, "void-which-binds:login?id=x&rp=http%3A%2F%2Fh")
        }
    }

    // --- discovery mapping (ADR-0009) ------------------------------------------------

    @Test
    fun anAdvertWithASchemeBecomesASchemePairTarget() {
        val t = RpPairHandoff.targetFrom(
            RpHandoffAdvert(packageName = "one.rarebit.heyarr", label = "heyarr", pairScheme = "heyarr-mobile"),
        )
        assertEquals(RpPairTarget("heyarr", "heyarr-mobile://pair"), t)
        assertEquals("heyarr-mobile", t!!.scheme)
    }

    @Test
    fun schemeIsLowercasedAndLabelDefaultsWhenBlank() {
        val t = RpPairHandoff.targetFrom(
            RpHandoffAdvert(packageName = "p", label = "  ", pairScheme = "AllThing"),
        )
        assertEquals("allthing://pair", t!!.callbackBase)
        assertEquals("this app", t.appName)
    }

    @Test
    fun aGen1InviteIsRefused() {
        assertThrows(IllegalArgumentException::class.java) {
            RpPairHandoff.uriFor(heyarr, invite.replaceFirst("void-which-binds:", "voidbind:"))
        }
    }

    @Test
    fun advertsWithoutASchemeOrWithOursAreRefused() {
        assertNull(RpPairHandoff.targetFrom(RpHandoffAdvert("p", "X", pairScheme = null)))
        assertNull(RpPairHandoff.targetFrom(RpHandoffAdvert("p", "X", pairScheme = "  ")))
        // `void-which-binds` is ours — firing it would loop back into Cruciform.
        assertNull(RpPairHandoff.targetFrom(RpHandoffAdvert("p", "X", pairScheme = "void-which-binds")))
        assertNull(RpPairHandoff.targetFrom(RpHandoffAdvert("p", "X", pairScheme = "Void-Which-Binds")))
        // The retired gen1 `voidbind` would hand a gen2 invite to a gen1 authenticator.
        assertNull(RpPairHandoff.targetFrom(RpHandoffAdvert("p", "X", pairScheme = "voidbind")))
        assertNull(RpPairHandoff.targetFrom(RpHandoffAdvert("p", "X", pairScheme = "VoidBind")))
    }

    @Test
    fun targetsAreDedupedBySchemeAndOrderedByLabel() {
        val targets = RpPairHandoff.targetsFrom(
            listOf(
                RpHandoffAdvert("p.heyarr", "heyarr", "heyarr-mobile"),
                RpHandoffAdvert("p.allthing", "All Thing", "allthing"),
                RpHandoffAdvert("p.dup", "heyarr (clone)", "heyarr-mobile"), // same scheme, dropped
                RpHandoffAdvert("p.bad", "Bad", null), // no scheme, dropped
            ),
        )
        assertEquals(listOf("allthing://pair", "heyarr-mobile://pair"), targets.map { it.callbackBase })
        assertEquals(listOf("All Thing", "heyarr"), targets.map { it.appName })
    }

    @Test
    fun advertForPackageMapsTheReturnLegBackToItsScheme() {
        val adverts = listOf(
            RpHandoffAdvert("one.rarebit.heyarr", "heyarr", "heyarr-mobile"),
            RpHandoffAdvert("one.rarebit.allthing", "All Thing", "allthing"),
        )
        val hit = RpPairHandoff.advertForPackage(adverts, "one.rarebit.allthing")
        assertEquals("allthing", RpPairHandoff.targetFrom(hit!!)!!.scheme)
        assertNull(RpPairHandoff.advertForPackage(adverts, "com.someone.else"))
        assertNull(RpPairHandoff.advertForPackage(adverts, null))
        assertNull(RpPairHandoff.advertForPackage(adverts, " "))
    }

    private fun percentDecode(s: String): String {
        val out = ArrayList<Byte>()
        var i = 0
        while (i < s.length) {
            if (s[i] == '%') {
                out.add(s.substring(i + 1, i + 3).toInt(16).toByte())
                i += 3
            } else {
                out.add(s[i].code.toByte())
                i++
            }
        }
        return out.toByteArray().decodeToString()
    }
}
