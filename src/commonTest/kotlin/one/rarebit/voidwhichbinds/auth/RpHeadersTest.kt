package one.rarebit.voidwhichbinds.auth

import one.rarebit.voidwhichbinds.MembershipOp
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * [RpHeaders] and [OrgRequest]: ports of void-which-binds-go's `TestParseOrgHeader`,
 * `TestParseRosterHeader` and `TestMembershipHeader` (rp), plus the Go-semantics edges a
 * Kotlin port can get wrong (TrimSpace's whitespace set, `len` in UTF-8 bytes).
 */
class RpHeadersTest {

    private val org = "ed25519:30d6fc5c2729046ad577bba0893c1034f9f1aae45858b285e00d9281dc5b9bb9"
    private val other = "ed25519:a8a81e17ee54352555bd45f8110b7664c7bbaa8fc3e57111ff60b1913a50d9dd"

    private fun failure(block: () -> Unit): RpHeaderException.Failure =
        assertFailsWith<RpHeaderException> { block() }.failure

    @Test
    fun theWireSpellingsAndCapsAreGos() {
        assertEquals("Void-Which-Binds-Org", RpHeaders.ORG_HEADER)
        assertEquals("Void-Which-Binds-Roster", RpHeaders.ROSTER_HEADER)
        assertEquals("Void-Which-Binds-Membership", RpHeaders.MEMBERSHIP_HEADER)
        assertEquals(16, RpHeaders.MAX_PRESENTED_ROSTER_OPS)
        assertEquals(4096, RpHeaders.MAX_PRESENTED_ROSTER_OP_BYTES)
        assertEquals(64 * 1024 + 32 * 1024, RpHeaders.MAX_PRESENTED_OPS_BODY_BYTES)
        assertEquals(
            RpHeaders.MAX_PRESENTED_OPS * RpHeaders.MAX_PRESENTED_OP_BYTES,
            RpHeaders.MAX_PRESENTED_ROSTER_OPS * RpHeaders.MAX_PRESENTED_ROSTER_OP_BYTES,
            "the roster header's budget is the membership header's 64 KiB",
        )
        assertEquals(64 * 1024 + 96 * 1024, RpHeaders.MAX_PRESENTED_ROSTER_BODY_BYTES)
    }

    @Test
    fun parseOrgHeader() {
        assertEquals(org, RpHeaders.parseOrgHeader("  $org "))
        assertEquals(org, RpHeaders.parseOrgHeader("\u0085\t$org　"))
        for (bad in listOf(
            "", "  ", "$org,$other", org.uppercase(), "ed25519:00", "mp:0123456789abcdef0123456789abcdef",
            "x25519:" + org.removePrefix("ed25519:"),
            org.removePrefix("ed25519:"),
            "ed25519:" + org.removePrefix("ed25519:").uppercase(),
            // Kotlin's trim() would strip U+001F; Go's TrimSpace does not.
            "\u001F$org",
        )) {
            assertEquals(RpHeaderException.Failure.MALFORMED, failure { RpHeaders.parseOrgHeader(bad) }, "'$bad'")
        }
        assertEquals("malformed", RpHeaderException.Failure.MALFORMED.reason)
    }

    @Test
    fun formatOrgHeaderOnlyRendersTheCanonicalId() {
        assertEquals(org, RpHeaders.formatOrgHeader(org))
        for (bad in listOf(" $org", "$org,$other", org.uppercase(), "")) {
            assertEquals(RpHeaderException.Failure.MALFORMED, failure { RpHeaders.formatOrgHeader(bad) }, "'$bad'")
        }
    }

    @Test
    fun parseRosterHeader() {
        val tok = "a".repeat(RpHeaders.MAX_PRESENTED_ROSTER_OP_BYTES)
        val full = List(RpHeaders.MAX_PRESENTED_ROSTER_OPS) { tok }
        assertEquals(full, RpHeaders.parseRosterHeader(RpHeaders.formatRosterHeader(full)), "at both caps")
        assertEquals(listOf("x", "y"), RpHeaders.parseRosterHeader(" , x ,, y "))
        assertEquals(emptyList(), RpHeaders.parseRosterHeader(""))
        assertEquals(emptyList(), RpHeaders.parseRosterHeader(" , , "))
        val tooMany = RpHeaderException.Failure.TOO_MANY_OPS
        assertEquals(tooMany, failure { RpHeaders.parseRosterHeader(RpHeaders.formatRosterHeader(full + "x")) })
        assertEquals(tooMany, failure { RpHeaders.parseRosterHeader(tok + "a") })
        assertEquals("too_many_ops", tooMany.reason)
    }

    @Test
    fun theRosterOpCapCountsUtf8BytesAsGosLenDoes() {
        // 2048 × "é" is 2048 UTF-16 units but 4096 UTF-8 bytes: at the cap. One more is over.
        assertEquals(1, RpHeaders.parseRosterHeader("é".repeat(2048)).size)
        assertEquals(
            RpHeaderException.Failure.TOO_MANY_OPS,
            failure { RpHeaders.parseRosterHeader("é".repeat(2048) + "a") },
        )
        // A surrogate pair is one 4-byte code point.
        assertEquals(1, RpHeaders.parseRosterHeader("😀".repeat(1024)).size)
        assertEquals(
            RpHeaderException.Failure.TOO_MANY_OPS,
            failure { RpHeaders.parseRosterHeader("😀".repeat(1024) + "a") },
        )
        // Trimming happens before the size check, as in Go.
        assertEquals(1, RpHeaders.parseRosterHeader("  " + "a".repeat(4096) + "\t").size)
    }

    @Test
    fun membershipHeader() {
        val ops = RpHeaders.parseMembershipHeader(" a.b , c.d,,")
        assertEquals(listOf("a.b", "c.d"), ops)
        assertEquals("a.b,c.d", RpHeaders.formatMembershipHeader(ops))
        assertEquals(
            RpHeaderException.Failure.TOO_MANY_OPS,
            failure { RpHeaders.parseMembershipHeader("x,".repeat(RpHeaders.MAX_PRESENTED_OPS + 1)) },
        )
        assertEquals(RpHeaders.MAX_PRESENTED_OPS, RpHeaders.parseMembershipHeader("x,".repeat(64)).size)
        // Go caps only the count of the membership header, never a token's size.
        assertEquals(1, RpHeaders.parseMembershipHeader("a".repeat(10_000)).size)
    }

    @Test
    fun orgRequestAssemblesTheOrgPathHeaders() {
        val r = OrgRequest(org, rosterOps = listOf("r2", " r1 ", "r2", ""), membershipOps = listOf("p.b", "p.a"))
        val byHash = { xs: List<String> -> xs.sortedBy { MembershipOp.hash(it) } }
        assertEquals(byHash(listOf("r1", "r2")), r.rosterOps)
        assertEquals(byHash(listOf("p.a", "p.b")), r.membershipOps)
        val auth = "Device cred~proof"
        val h = r.headers(auth)
        assertEquals(
            listOf("Authorization", RpHeaders.ORG_HEADER, RpHeaders.ROSTER_HEADER, RpHeaders.MEMBERSHIP_HEADER),
            h.keys.toList(),
        )
        assertEquals(auth, h["Authorization"])
        assertEquals(org, h[RpHeaders.ORG_HEADER])
        assertEquals(r.rosterOps, RpHeaders.parseRosterHeader(h.getValue(RpHeaders.ROSTER_HEADER)))
        assertEquals(r.membershipOps, RpHeaders.parseMembershipHeader(h.getValue(RpHeaders.MEMBERSHIP_HEADER)))
        assertEquals(h - "Authorization", r.presentedHeaders())
        assertFailsWith<IllegalArgumentException> { r.headers("Bearer x") }
    }

    @Test
    fun orgRequestSendsNoEmptyHeaders() {
        val h = OrgRequest(org).presentedHeaders()
        assertEquals(mapOf(RpHeaders.ORG_HEADER to org), h)
        assertFalse(RpHeaders.ROSTER_HEADER in h)
    }

    @Test
    fun orgRequestRefusesWhatEveryRpWouldRefuse() {
        val tooMany = RpHeaderException.Failure.TOO_MANY_OPS
        val atCap = List(RpHeaders.MAX_PRESENTED_ROSTER_OPS) { "r$it" }
        assertEquals(16, OrgRequest(org, atCap).rosterOps.size)
        assertEquals(tooMany, failure { OrgRequest(org, atCap + "r16") })
        assertEquals(tooMany, failure { OrgRequest(org, listOf("a".repeat(4097))) })
        assertEquals(tooMany, failure { OrgRequest(org, membershipOps = List(65) { "p$it" }) })
        assertEquals(RpHeaderException.Failure.MALFORMED, failure { OrgRequest(" $org") })
        assertEquals(RpHeaderException.Failure.MALFORMED, failure { OrgRequest("$org,$other") })
        // Duplicates collapse before the cap is applied.
        assertTrue(OrgRequest(org, atCap + atCap).rosterOps.size == 16)
    }
}
