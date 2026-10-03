package one.rarebit.voidwhichbinds.roster

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.OpDag
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/**
 * Long signed histories must not overflow a small (mobile-sized) thread stack: every
 * walk over the op DAG, and every memo that recurses through closures (the roster's
 * frames, the membership evaluator's authority frames), is settled iteratively or in
 * causal order. Each case runs on a thread with a [SMALL_STACK] stack, on which the
 * recursive walks they replace overflowed.
 */
@Suppress("LongMethod")
class DeepChainTest {

    private fun onSmallStack(stack: Long = SMALL_STACK, block: () -> Unit) {
        var failure: Throwable? = null
        val t = Thread(null, {
            try {
                block()
            } catch (e: Throwable) {
                failure = e
            }
        }, "small-stack", stack)
        t.start()
        t.join()
        failure?.let { throw AssertionError("failed on a ${stack / 1024} KiB stack: $it", it) }
    }

    private class Node(val hash: String, val prev: List<String>)

    @Test
    fun opDagResolvesALongChainIteratively() = onSmallStack {
        val n = 20_000
        val dag = OpDag<Node>({ it.prev }, null)
        // Added newest first, so resolving the head walks the whole chain.
        for (i in n - 1 downTo 0) dag.add("n$i", Node("n$i", if (i == 0) emptyList() else listOf("n${i - 1}")))
        dag.add("orphan", Node("orphan", listOf("missing")))
        dag.add("on-orphan", Node("on-orphan", listOf("n${n - 1}", "orphan")))
        assertEquals(listOf("on-orphan", "orphan"), dag.resolveAll())
        assertEquals(n - 1, dag.depth("n${n - 1}"))
        assertEquals(n, dag.valid().size)
        // A cycle hanging off the chain rejects the cycle and what cites it, not the chain.
        val cyc = OpDag<Node>({ it.prev }, null)
        for (i in 0 until n) cyc.add("c$i", Node("c$i", listOf("c${(i + 1) % n}")))
        cyc.add("root", Node("root", emptyList()))
        assertEquals(n, cyc.resolveAll().size)
        assertTrue(cyc.resolve("root"))
    }

    @Test
    fun opDagAncestorsOfALongChain() = onSmallStack {
        val n = 3_000 // ancestor bitsets are quadratic in a chain (n²/16 bytes), so a shorter chain
        val dag = OpDag<Node>({ it.prev }, null)
        for (i in 0 until n) dag.add("n$i", Node("n$i", if (i == 0) emptyList() else listOf("n${i - 1}")))
        dag.resolveAll()
        assertEquals(n - 1, dag.ancestors("n${n - 1}").size)
        assertTrue(dag.precedes("n0", "n${n - 1}"))
        assertFalse(dag.precedes("n${n - 1}", "n0"))
    }

    private class Actor(label: String) {
        val seed: ByteArray = Hex.decode(MembershipOp.hash("deep-chain:$label").substring(7))
        val pub: ByteArray = Ed25519Group.publicKeyFromSeed(seed)
        val id: String = KeyRef.ed25519(pub).render()
        val signer = Ed25519Signer { Ed25519Engine.sign(seed, it) }
    }

    @Test
    fun rosterEvaluatesALongChain() {
        val n = 2_000
        val org = Actor("org")
        val p = Actor("P")
        val v = Actor("V")
        fun sign(d: RosterDraft) = Roster.signWith(org.signer, org.pub, d, emptyList())
        val founding =
            sign(RosterDraft(org = org.id, op = OpKind.SET, mem = p.id, role = Role.OWNER, by = org.id, iat = T0))
        val toks = ArrayList<String>()
        var head = Roster.opHash(founding)
        // The authority moves V up and down, each op citing the last: every grant/reduction
        // test reads the previous op's closure frame, all the way down.
        for (i in 1..n) {
            val role = if (i % 2 == 0) Role.MEMBER else Role.VIEWER
            val tok = sign(
                RosterDraft(
                    org = org.id,
                    op = OpKind.SET,
                    mem = v.id,
                    role = role,
                    by = org.id,
                    prev = listOf(head),
                    iat =
                    T0 + i,
                ),
            )
            toks.add(tok)
            head = Roster.opHash(tok)
        }
        onSmallStack {
            val view = Roster.evaluate(org.id, founding, toks.reversed(), null, T0 + n + 60)
            assertEquals(n + 1, view.accepted.size)
            assertTrue(view.ineffective.isEmpty() && view.rejected.isEmpty())
            assertEquals(listOf(head), view.heads)
            assertEquals(Role.MEMBER, view.persons.getValue(v.id).role)
        }
    }

    @Test
    fun rerootJudgesALongChainOfAppointments() {
        val n = 400
        val org = Actor("org")
        val plog = HashMap<String, List<String>>()
        val heads = HashMap<String, String>()
        fun person(label: String): Actor {
            val g = Actor(label)
            if (g.id !in plog) {
                val tok = MembershipOp.sign(
                    g.signer,
                    g.pub,
                    g.id,
                    MembershipOp.Kind.ADD,
                    Actor("$label.D").id,
                    "",
                    emptyList(),
                    T0,
                )
                plog[g.id] = listOf(tok)
                heads[g.id] = MembershipOp.hash(tok)
            }
            return g
        }
        val p = person("P")
        val pe = Actor("P.E")
        plog[p.id] = plog.getValue(p.id) + MembershipOp.sign(
            p.signer,
            p.pub,
            p.id,
            MembershipOp.Kind.ADD,
            pe.id,
            "",
            listOf(heads.getValue(p.id)),
            T0,
        )
        heads[p.id] = MembershipOp.hash(plog.getValue(p.id).last())
        val founding = Roster.signWith(
            org.signer,
            org.pub,
            RosterDraft(org = org.id, op = OpKind.SET, mem = p.id, role = Role.OWNER, by = org.id, iat = T0),
            emptyList(),
        )
        val toks = ArrayList<String>()
        var head = Roster.opHash(founding)
        // A_i is appointed admin by A_(i-1) and P together, each grant citing the last:
        // whether A_n is independent of the authority asks the same of every A_i below.
        var prevAppointer: Pair<Actor, Actor> = p to Actor("P.D")
        var prevCosigner: Pair<Actor, Actor> = p to pe
        for (i in 1..n) {
            val a = person("A$i")
            val (pp, pd) = prevAppointer
            val (cp, cd) = prevCosigner
            val d = RosterDraft(
                org = org.id, op = OpKind.SET, mem = a.id, role = Role.ADMIN, by = pd.id, usr = pp.id,
                bprev = listOf(heads.getValue(pp.id)), prev = listOf(head), iat = T0 + i,
            )
            val cs = Roster.cosignWith(cd.signer, cd.pub, d, cp.id, listOf(heads.getValue(cp.id)))
            val tok = Roster.signWith(pd.signer, pd.pub, d, listOf(cs))
            toks.add(tok)
            head = Roster.opHash(tok)
            prevAppointer = a to Actor("A$i.D")
            prevCosigner = p to Actor("P.D")
        }
        val k1 = Actor("K1")
        val (lp, ld) = prevAppointer
        val rd0 = RosterDraft(
            org = org.id,
            op = OpKind.REROOT,
            succ = k1.id,
            by = org.id,
            prev = listOf(head),
            iat = T0 + n + 1,
        )
        val rd = rd0.copy(succSig = Roster.succSigWith(k1.signer, k1.pub, rd0))
        val pd = Actor("P.D")
        val reroot = Roster.signWith(
            org.signer,
            org.pub,
            rd,
            listOf(
                Roster.cosignWith(ld.signer, ld.pub, rd, lp.id, listOf(heads.getValue(lp.id))),
                Roster.cosignWith(pd.signer, pd.pub, rd, p.id, listOf(heads.getValue(p.id))),
            ),
        )
        toks.add(reroot)
        onSmallStack(TINY_STACK) {
            val view = Roster.evaluate(org.id, founding, toks.reversed(), { plog[it].orEmpty() }, T0 + n + 60)
            assertTrue(view.ineffective.isEmpty() && view.rejected.isEmpty(), "${view.ineffective} ${view.rejected}")
            assertEquals(k1.id, view.authority)
            assertEquals(n + 1, view.adminHighWater)
        }
    }

    @Test
    fun membershipEvaluatesALongMemberSignedChain() {
        val n = 1_500
        val g = Actor("genesis")
        val a = Actor("A")
        val toks = ArrayList<String>()
        val first = MembershipOp.sign(g.signer, g.pub, g.id, MembershipOp.Kind.ADD, a.id, "", emptyList(), T0)
        toks.add(first)
        var head = MembershipOp.hash(first)
        // Member A admits device after device, each citing the last: each op's authority
        // frame is its whole past.
        for (i in 1..n) {
            val tok = MembershipOp.sign(
                a.signer,
                a.pub,
                g.id,
                MembershipOp.Kind.ADD,
                Actor("D$i").id,
                "",
                listOf(head),
                T0 + i,
            )
            toks.add(tok)
            head = MembershipOp.hash(tok)
        }
        onSmallStack {
            val view = Membership.evaluate(g.id, toks.reversed(), T0 + n + 60)
            assertEquals(n + 1, view.members.size)
            assertTrue(view.ineffective.isEmpty())
            assertTrue(Membership.memberAt(g.id, Actor("D$n").id, toks, listOf(head), T0 + n))
        }
    }

    private companion object {
        const val SMALL_STACK = 256L * 1024

        /** Signed appointment chains are costly to build, so that case uses a shorter one on a smaller stack. */
        const val TINY_STACK = 128L * 1024
        const val T0 = 1_790_856_000L
    }
}
