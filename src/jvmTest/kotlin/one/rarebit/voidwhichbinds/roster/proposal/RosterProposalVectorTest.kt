package one.rarebit.voidwhichbinds.roster.proposal

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.roster.Roster
import java.io.File
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.fail

/**
 * The cross-implementation PARITY suite for the roster cosign transport (ADR-0014,
 * "Proposal transport"): void-which-binds-go's golden vectors,
 * `testvectors/vectors/roster-proposal/` (pinned by `VOID_WHICH_BINDS_GO_REF`), copied
 * verbatim into `src/jvmTest/resources/vectors/roster-proposal/` and replayed as Go's
 * `replay` (roster/proposal/vectors_test.go) does: every key's seed renders as its id;
 * `check(proposal ‖ pad×" ")` with no replica reaches the file's verdict; every cosig's
 * `verifyCosig` does too, and each `ok` cosig is re-minted by [Checked.cosign] byte for
 * byte; and a round trip's [Checked.assemble] mints the file's op, hash, closure, person
 * context and verdict exactly (JDK Ed25519 is deterministic).
 */
@Suppress("UNCHECKED_CAST")
class RosterProposalVectorTest {
    private val cases: List<String> = run {
        val dir = javaClass.getResource("/vectors/roster-proposal") ?: error("vectors/roster-proposal missing")
        File(dir.toURI()).listFiles { f -> f.isFile && f.name.endsWith(".json") }.orEmpty()
            .map { it.name.removeSuffix(".json") }.sorted()
            .also { check(it.size >= MIN_VECTORS) { "expected >= $MIN_VECTORS vectors, found ${it.size}" } }
    }

    private fun load(name: String): Map<String, Any> {
        val raw = javaClass.getResourceAsStream("/vectors/roster-proposal/$name.json")!!.readBytes().decodeToString()
        return MiniJson.parseObject(raw).also { assertEquals(name, it["name"], "file stem must equal its name") }
    }

    private class Key(val signer: Ed25519Signer, val pub: ByteArray)

    private fun keys(v: Map<String, Any>): Map<String, Key> =
        (v["keys"] as Map<String, Map<String, Any>>).mapValues { (label, k) ->
            val seed = Hex.decode(k["sign_seed"] as String)
            val pub = Ed25519Group.publicKeyFromSeed(seed)
            assertEquals(k["id"], KeyRef.ed25519(pub).render(), "key $label: id does not match its seed")
            Key(Ed25519Signer { Ed25519Engine.sign(seed, it) }, pub)
        }

    private fun reasonOrOk(block: () -> Unit): String = try {
        block()
        OK
    } catch (e: ProposalException) {
        e.reason.wire
    }

    @Test
    @Suppress("LoopWithTooManyJumpStatements")
    fun everyGoldenVectorReplays() {
        var cosigs = 0
        var assembled = 0
        for (name in cases) {
            val v = load(name)
            val ks = keys(v)
            val expect = Expect(org = v["org"] as String, founding = v["founding"] as String)
            val pad = (v["pad"] as? Long ?: 0L).toInt()
            val raw = (v["proposal"] as String).encodeToByteArray() + ByteArray(pad) { ' '.code.toByte() }
            var checked: Checked? = null
            val got = reasonOrOk { checked = RosterProposal.check(raw, expect) }
            assertEquals(v["expect"], got, "$name: proposal")
            val c = checked ?: continue

            // An accepted proposal re-encodes to its own bytes, and New rebuilds them.
            assertContentEquals(raw, c.proposal.encode(), "$name: re-encode")
            assertContentEquals(
                raw,
                RosterProposal.create(c.draft, c.proposal.roster, c.proposal.persons).encode(),
                "$name: create",
            )

            val good = ArrayList<Cosig>()
            for (vc in (v["cosigs"] as? List<Map<String, Any>>).orEmpty()) {
                val signer = vc["signer"] as String
                val cosigRaw = (vc["cosig"] as String).encodeToByteArray()
                var cs: Cosig? = null
                assertEquals(vc["expect"], reasonOrOk { cs = c.verifyCosig(cosigRaw) }, "$name: cosig by $signer")
                val ok = cs ?: continue
                val k = ks.getValue(signer)
                val again = c.cosign(k.signer, k.pub, ok.entry.usr, ok.entry.bprev, ok.persons[ok.entry.usr].orEmpty())
                assertContentEquals(cosigRaw, again.encode(), "$name: cosig by $signer re-minted")
                good += ok
                cosigs++
            }

            val va = v["assembled"] as? Map<String, Any> ?: continue
            val signer = ks.getValue(va["signer"] as String)
            val succ = (va["succ"] as? String)?.let(ks::getValue)
            val a = c.assemble(signer.signer, signer.pub, good, succ?.signer, succ?.pub)
            assertEquals(va["op"], a.op, "$name: assembled op")
            assertEquals(va["hash"], a.hash, "$name: assembled hash")
            assertEquals(va["hash"], Roster.opHash(a.op), "$name: hash of the op")
            assertEquals(va["roster"], a.roster.map(Roster::opHash), "$name: assembled roster")
            assertEquals(
                (va["persons"] as Map<String, List<String>>).toSortedMap(),
                a.persons.mapValues { (_, l) -> l.map(Roster::opHash) }.toSortedMap(),
                "$name: assembled persons",
            )
            assertEquals(va["verdict"], a.verdict.ifEmpty { "effective" }, "$name: verdict")
            assembled++
        }
        println("roster-proposal vector parity: ${cases.size} vectors, $cosigs cosigs re-minted, $assembled assembled")
        check(cosigs >= 3 && assembled >= 2) { "the round trips did not run" }
    }

    /** [RosterProposal.context] over the round trip's own world reproduces the attachments its proposal carries. */
    @Test
    fun contextReproducesTheCarriedAttachments() {
        val v = load("set-round-trip")
        val p = RosterProposal.decode((v["proposal"] as String).encodeToByteArray())
        val qPersons = RosterProposal.decodeCosig(
            ((v["cosigs"] as List<Map<String, Any>>)[0]["cosig"] as String).encodeToByteArray(),
        ).persons
        val replica = p.persons + qPersons
        val ctx = RosterProposal.context(p.draft, v["founding"] as String, p.roster, persons = {
            replica[it].orEmpty()
        })
        assertEquals(p.roster, ctx.roster)
        assertEquals(p.persons, ctx.persons)
        // The founding op alone does not resolve prev; no person log does not resolve P's bprev.
        assertEquals(
            ProposalReason.MISSING_ROSTER_CONTEXT,
            reasonOf { RosterProposal.context(p.draft, v["founding"] as String, emptyList(), null) },
        )
        assertEquals(
            ProposalReason.MISSING_PERSON_CONTEXT,
            reasonOf { RosterProposal.context(p.draft, v["founding"] as String, p.roster, null) },
        )
    }

    /** Go `TestCheckMergesReplica`: a cosigner holding the closure needs none of it attached. */
    @Test
    fun checkMergesTheReceiversReplica() {
        val v = load("set-round-trip")
        val p = RosterProposal.decode((v["proposal"] as String).encodeToByteArray())
        val bare = RosterProposal.create(p.draft, emptyList(), emptyMap()).encode()
        val base = Expect(org = v["org"] as String, founding = v["founding"] as String)
        assertEquals(ProposalReason.MISSING_ROSTER_CONTEXT, reasonOf { RosterProposal.check(bare, base) })
        val full = base.copy(roster = p.roster, persons = { p.persons[it].orEmpty() })
        assertNull(reasonOf { RosterProposal.check(bare, full) })
        val half = RosterProposal.create(p.draft, p.roster, emptyMap()).encode()
        assertEquals(ProposalReason.MISSING_PERSON_CONTEXT, reasonOf { RosterProposal.check(half, base) })
        assertNull(reasonOf { RosterProposal.check(half, base.copy(persons = { p.persons[it].orEmpty() })) })
    }

    private fun reasonOf(block: () -> Unit): ProposalReason? = try {
        block()
        null
    } catch (e: ProposalException) {
        assertNotNull(ProposalException.reasonOf(e))
    } catch (e: IllegalArgumentException) {
        fail("not a refusal: $e")
    }

    private companion object {
        const val OK = "ok"
        const val MIN_VECTORS = 19
    }
}
