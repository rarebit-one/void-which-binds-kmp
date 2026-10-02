package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith

/**
 * [Membership.memberAt] — the port of void-which-binds-go `enrolment.MemberAt` (Phase 3
 * G1) the org roster judges person signatures with. These are Go's `TestMemberAt` and
 * `TestMemberAtRefusals` (enrolment/memberat_test.go), case for case.
 */
@Suppress("LongParameterList")
class MemberAtTest {

    private class Actor(val seed: ByteArray) {
        val pub: ByteArray = Ed25519Group.publicKeyFromSeed(seed)
        val id: String = KeyRef.ed25519(pub).render()
        val signer = Ed25519Signer { Ed25519Engine.sign(seed, it) }
    }

    private val actors = HashMap<String, Actor>()
    private fun actor(label: String): Actor =
        actors.getOrPut(label) { Actor(ByteArray(32) { (label.hashCode() + it * 7).toByte() }) }

    private val genesis get() = actor("genesis")
    private val tokens = ArrayList<String>()
    private val byLabel = HashMap<String, String>()

    private fun at(minutes: Int): Long = T0 + minutes * 60L

    private fun op(
        label: String,
        by: String,
        kind: MembershipOp.Kind,
        dev: String,
        prev: List<String>,
        minute: Int,
        lifetimeSeconds: Long,
    ) {
        val a = actor(by)
        val tok = MembershipOp.sign(
            a.signer, a.pub, genesis.id, kind, actor(dev).id, "", prev.map(::hash), at(minute), lifetimeSeconds,
        )
        tokens.add(tok)
        byLabel[label] = tok
    }

    private fun hash(label: String): String = MembershipOp.hash(byLabel.getValue(label))

    private fun memberAt(dev: String, heads: List<String>, whenS: Long, ops: List<String> = tokens): Boolean =
        Membership.memberAt(genesis.id, actor(dev).id, ops, heads.map(::hash), whenS)

    private fun build() {
        op("add-A", "genesis", MembershipOp.Kind.ADD, "A", emptyList(), 0, 0)
        op("add-B", "A", MembershipOp.Kind.ADD, "B", listOf("add-A"), 5, 0)
        // Genesis removes: three devices make the high-water 3, so a lone member's remove
        // would be under_threshold (rule 5).
        op("rm-B", "genesis", MembershipOp.Kind.REMOVE, "B", listOf("add-B"), 10, 0)
        op("add-C", "A", MembershipOp.Kind.ADD, "C", listOf("add-A"), 6, 30 * 60) // expires at 36
        op("rm-C-alone", "A", MembershipOp.Kind.REMOVE, "C", listOf("rm-B", "add-C"), 12, 0)
        tokens.add("not-a-token")
        byLabel["junk"] = "not-a-token"
    }

    private data class Case(
        val name: String,
        val dev: String,
        val heads: List<String>,
        val whenS: Long,
        val want: Boolean,
    )

    @Test
    fun memberAtAnswersRuleTwosQuestion() {
        build()
        val cases = listOf(
            Case("admitted in the frame", "B", listOf("add-B"), at(6), true),
            Case("a later remove does not reach back", "B", listOf("add-B"), at(60), true),
            Case("removed in the frame", "B", listOf("rm-B"), at(11), false),
            Case("others unaffected by the remove", "A", listOf("rm-B"), at(11), true),
            Case("add outside the frame", "C", listOf("rm-B"), at(11), false),
            Case("concurrent heads merge their pasts", "C", listOf("rm-B", "add-C"), at(11), true),
            Case("add expired at the instant", "C", listOf("add-C"), at(36), false),
            Case("add live just before expiry", "C", listOf("add-C"), at(35), true),
            Case("head issued at the instant counts", "B", listOf("add-B"), at(5), true),
            Case("no heads is the empty frame", "A", emptyList(), at(60), false),
            Case("genesis is never a fleet member", "genesis", listOf("rm-B"), at(60), false),
            Case("under-threshold remove leaves the member", "C", listOf("rm-C-alone"), at(12), true),
            Case("a stranger", "Z", listOf("rm-B", "add-C"), at(11), false),
        )
        for (c in cases) assertEquals(c.want, memberAt(c.dev, c.heads, c.whenS), c.name)
        // Order independence: any permutation of the ops gives the same answers.
        val rng = Random(7)
        repeat(10) { i ->
            val perm = tokens.shuffled(rng)
            for (c in cases) assertEquals(c.want, memberAt(c.dev, c.heads, c.whenS, perm), "permutation $i, ${c.name}")
        }
    }

    @Test
    fun memberAtRefusals() {
        op("add-A", "genesis", MembershipOp.Kind.ADD, "A", emptyList(), 0, 0)
        op("add-B", "A", MembershipOp.Kind.ADD, "B", listOf("add-A"), 5, 0)
        tokens.add("not-a-token")
        byLabel["junk"] = "not-a-token"
        val b = actor("B").id
        assertFailsWith<Membership.MissingContextException>("head issued after the instant") {
            memberAt("B", listOf("add-B"), at(4))
        }
        assertFailsWith<Membership.MissingContextException>("unknown head") {
            Membership.memberAt(genesis.id, b, tokens, listOf(MembershipOp.hash("unseen")), at(60))
        }
        assertFailsWith<Membership.MissingContextException>("invalid head") {
            memberAt("B", listOf("junk"), at(60))
        }
        // A head the set lacks the past of is not valid either.
        assertFailsWith<Membership.MissingContextException>("head with a missing prev") {
            memberAt("B", listOf("add-B"), at(60), ops = listOf(byLabel.getValue("add-B")))
        }
        assertFailsWith<IllegalArgumentException>("bad usr") {
            Membership.memberAt("not-a-key", b, tokens, emptyList(), at(60))
        }
        assertFailsWith<IllegalArgumentException>("zero instant") {
            Membership.memberAt(genesis.id, b, tokens, emptyList(), 0)
        }
    }

    private companion object {
        const val T0 = 1_790_850_000L
    }
}
