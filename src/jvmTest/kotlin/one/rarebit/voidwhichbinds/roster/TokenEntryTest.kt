package one.rarebit.voidwhichbinds.roster

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.GoJson
import one.rarebit.voidwhichbinds.crypto.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * Every token entry point reads a token as Go does (#102): it trims with Go's
 * `strings.TrimSpace` set (U+0085 is space, U+001C..U+001F are not), and a body nested
 * past Go's decoder limit is malformed, never a stack overflow. The verdicts are the ones
 * void-which-binds-go v0.21.0 returns for the same shapes (checked with a throwaway Go
 * program against `roster.Merge`/`Evaluate` and `enrolment.Merge`/`Evaluate`). The nested
 * cases run on a small (mobile-sized) thread stack.
 */
class TokenEntryTest {

    private fun onSmallStack(block: () -> Unit) {
        var failure: Throwable? = null
        val t = Thread(null, {
            try {
                block()
            } catch (e: Throwable) {
                failure = e
            }
        }, "small-stack", SMALL_STACK)
        t.start()
        t.join()
        failure?.let { throw AssertionError("failed on a ${SMALL_STACK / 1024} KiB stack: $it", it) }
    }

    private class Actor(label: String) {
        val seed: ByteArray = Hex.decode(MembershipOp.hash("token-entry:$label").substring(7))
        val pub: ByteArray = Ed25519Group.publicKeyFromSeed(seed)
        val id: String = KeyRef.ed25519(pub).render()
        val signer = Ed25519Signer { Ed25519Engine.sign(seed, it) }
    }

    private val org = Actor("org")
    private val p = Actor("P")
    private val v = Actor("V")
    private val founding = Roster.signWith(
        org.signer,
        org.pub,
        RosterDraft(org = org.id, op = OpKind.SET, mem = p.id, role = Role.OWNER, by = org.id, iat = T0),
        emptyList(),
    )
    private val op2 = Roster.signWith(
        org.signer,
        org.pub,
        RosterDraft(
            org = org.id,
            op = OpKind.SET,
            mem = v.id,
            role = Role.MEMBER,
            by = org.id,
            prev = listOf(Roster.opHash(founding)),
            iat = T0 + 1,
        ),
        emptyList(),
    )
    private val g = Actor("genesis")
    private val a = Actor("A")
    private val op1 = MembershipOp.sign(g.signer, g.pub, g.id, MembershipOp.Kind.ADD, a.id, "", emptyList(), T0)

    private fun nest(n: Int) = "[".repeat(n) + "]".repeat(n)

    /** An unsigned token whose body is `{<prefix>"x":<n nested arrays>}` (n + 1 levels deep). */
    private fun deep(prefix: String, n: Int) = Base64Url.encode("{$prefix\"x\":${nest(n)}}".encodeToByteArray()) + ".AA"

    private fun rosterRejected(founding: String, ops: List<String>): Pair<Int, List<String>> {
        val view = Roster.evaluate(org.id, founding, ops, null, T0 + HOUR)
        return view.accepted.size to view.rejected.values.toList()
    }

    private fun membershipRejected(toks: List<String>): Pair<Int, List<String>> {
        val view = Membership.evaluate(g.id, toks, T0 + HOUR)
        return view.accepted.size to view.rejected.values.toList()
    }

    @Test
    fun rosterTrimsWithGoWhitespace() {
        // Go: Merge keeps both, the U+0085-padded one trimmed to op2, the U+001F one as is.
        val merged = Roster.merge(listOf("\u0085$op2\u0085", "\u001f$op2"))
        assertEquals(setOf(op2, "\u001f$op2"), merged.toSet())
        // Go: accepted 2 (V is a member); U+001F and U+001C padding are malformed.
        val padded = Roster.evaluate(org.id, founding, listOf("\u0085$op2\u0085"), null, T0 + HOUR)
        assertEquals(2, padded.accepted.size)
        assertEquals(Role.MEMBER, padded.persons.getValue(v.id).role)
        assertEquals(1 to listOf(RosterReason.MALFORMED), rosterRejected(founding, listOf("\u001f$op2")))
        assertEquals(1 to listOf(RosterReason.MALFORMED), rosterRejected(founding, listOf("$op2\u001c")))
        // The pinned founding token: U+0085 trims, U+001F is ErrFounding.
        assertEquals(2 to emptyList(), rosterRejected("\u0085$founding\u0085", listOf(op2)))
        val e = assertFailsWith<RosterException> { Roster.evaluate(org.id, "\u001f$founding", listOf(op2), null, T0) }
        assertEquals(RosterException.Failure.FOUNDING, e.failure)
        // A roster op parsed on its own trims the same way.
        assertEquals(op2, Roster.verify("\u0085$op2\u0085").token)
        assertFailsWith<RosterException> { Roster.verify("\u001f$op2") }
    }

    @Test
    fun membershipTrimsWithGoWhitespace() {
        // Go's enrolment.Merge does not trim: three distinct tokens.
        assertEquals(3, Membership.merge(listOf("\u0085$op1", "\u001f$op1", op1)).size)
        // Go: VerifyOp trims U+0085, so the op is accepted (as the trimmed token) and A is a member.
        val view = Membership.evaluate(g.id, listOf("\u0085$op1\u0085"), T0 + HOUR)
        assertTrue(view.isMember(a.id))
        assertEquals(listOf(op1), view.tokens())
        assertEquals(0 to listOf(Membership.Reason.MALFORMED), membershipRejected(listOf("\u001f$op1")))
        assertEquals(0 to listOf(Membership.Reason.MALFORMED), membershipRejected(listOf("$op1\u001c")))
        assertEquals(op1, MembershipOp.verify("\u0085$op1\u0085").token)
        assertFailsWith<MembershipOp.OpException> { MembershipOp.verify("\u001f$op1") }
    }

    @Test
    fun rosterRefusesDeepBodiesAsGoDoes() = onSmallStack {
        val max = GoJson.MAX_DEPTH - 1 // arrays inside the top-level object: Go's limit exactly
        val malformed = 1 to listOf(RosterReason.MALFORMED)
        assertEquals(malformed, rosterRejected(founding, listOf(deep("", DEEP))))
        // At the limit the body parses: a roster typ is then non-canonical, another typ is wrong_type.
        assertEquals(malformed, rosterRejected(founding, listOf(deep("\"typ\":\"void-which-binds.roster\",", max))))
        assertEquals(
            1 to listOf(RosterReason.WRONG_TYPE),
            rosterRejected(founding, listOf(deep("\"typ\":\"void-which-binds.op\",", max))),
        )
        // One level past it Go's scanner refuses the body before the typ is read.
        assertEquals(malformed, rosterRejected(founding, listOf(deep("\"typ\":\"void-which-binds.op\",", max + 1))))
    }

    @Test
    fun membershipRefusesDeepBodiesAsGoDoes() = onSmallStack {
        val max = GoJson.MAX_DEPTH - 1
        val malformed = 0 to listOf(Membership.Reason.MALFORMED)
        assertEquals(malformed, membershipRejected(listOf(deep("", DEEP))))
        assertEquals(malformed, membershipRejected(listOf(deep("\"typ\":\"void-which-binds.op\",", max))))
        // VerifyOp ignores unknown members, so a signed op carrying one nested to the limit
        // is accepted by Go; one level deeper is malformed.
        val body = Base64Url.decode(op1.substringBefore('.')).decodeToString()
        fun withX(n: Int): String {
            val b = (body.dropLast(1) + ",\"x\":" + nest(n) + "}").encodeToByteArray()
            return Base64Url.encode(b) + "." + Base64Url.encode(Ed25519Engine.sign(g.seed, b))
        }
        val view = Membership.evaluate(g.id, listOf(withX(max)), T0 + HOUR)
        assertTrue(view.isMember(a.id) && view.rejected.isEmpty())
        assertEquals(malformed, membershipRejected(listOf(withX(max + 1))))
    }

    private companion object {
        const val SMALL_STACK = 256L * 1024
        const val T0 = 1_790_856_000L
        const val HOUR = 3_600L
        const val DEEP = 60_000
    }
}
