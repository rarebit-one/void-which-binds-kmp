package one.rarebit.voidwhichbinds.roster.proposal

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.GoJson
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.net.RelayClient
import one.rarebit.voidwhichbinds.roster.OpKind
import one.rarebit.voidwhichbinds.roster.Role
import one.rarebit.voidwhichbinds.roster.Roster
import one.rarebit.voidwhichbinds.roster.RosterException
import one.rarebit.voidwhichbinds.roster.RosterException.Failure
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Ports of void-which-binds-go's `roster/proposal` unit tests (TestDecodeRefusesNonCanonical,
 * TestDecodeCosigRefuses, TestCosignAndAssembleRefusals, TestCosignOverRelay's slot check)
 * and `roster/core_test.go` (ParseCore, VerifyDraftCosig, CheckDraftClosure,
 * AuthorityOnly), over the golden vectors' own world, plus the cases where the refusal
 * ORDER depends on reading non-canonical JSON exactly as Go's `encoding/json` does, and
 * the no-stack-exhaustion guarantees for hostile nesting.
 */
@Suppress("UNCHECKED_CAST")
class RosterProposalTest {
    private fun vector(name: String): Map<String, Any> = MiniJson.parseObject(
        javaClass.getResourceAsStream("/vectors/roster-proposal/$name.json")!!.readBytes().decodeToString(),
    )

    private val v = vector("set-round-trip")
    private val good = v["proposal"] as String
    private val goodCosig = ((v["cosigs"] as List<Map<String, Any>>)[0]["cosig"] as String)
    private val expect = Expect(org = v["org"] as String, founding = v["founding"] as String)
    private val p = RosterProposal.decode(good.encodeToByteArray())
    private val checked = RosterProposal.check(good.encodeToByteArray(), expect)

    private fun key(label: String): Pair<Ed25519Signer, ByteArray> {
        val seed = Hex.decode((v["keys"] as Map<String, Map<String, Any>>).getValue(label)["sign_seed"] as String)
        return Ed25519Signer { Ed25519Engine.sign(seed, it) } to Ed25519Group.publicKeyFromSeed(seed)
    }

    private fun reasonOf(block: () -> Unit): ProposalReason? = try {
        block()
        null
    } catch (e: ProposalException) {
        e.reason
    } catch (e: IllegalArgumentException) {
        fail("not a refusal: $e")
    }

    private fun first(s: String, old: String, new: String): String {
        assertTrue(s.contains(old), "fixture lacks $old")
        return s.replaceFirst(old, new)
    }

    /** Re-encode [good] with an edit, as Go's `rewire` does (still Go's canonical encoding). */
    private fun rewire(edit: (SlotCodec.ProposalWire) -> Unit): String {
        val w = SlotCodec.proposalWire(GoJson.parse(good)!!)
        edit(w)
        return SlotCodec.marshal(w).decodeToString()
    }

    @Test
    @Suppress("LongMethod")
    fun decodeRefusesNonCanonical() {
        val someKey = "ed25519:" + "ab".repeat(32)
        val cases = mapOf(
            "not json" to ("{" to ProposalReason.MALFORMED),
            "not an object" to ("[]" to ProposalReason.MALFORMED),
            "other slot" to (first(good, "\"slot\":\"proposal\"", "\"slot\":\"cosig\"") to ProposalReason.MALFORMED),
            "no version" to (first(good, "\"v\":1,", "") to ProposalReason.BAD_VERSION),
            "string version" to (first(good, "\"v\":1", "\"v\":\"1\"") to ProposalReason.MALFORMED),
            "whitespace" to (first(good, "\"v\":1,", "\"v\": 1,") to ProposalReason.MALFORMED),
            "trailing newline" to (good + "\n" to ProposalReason.MALFORMED),
            "extra member" to (first(good, "\"v\":1,", "\"v\":1,\"x\":0,") to ProposalReason.MALFORMED),
            "case-variant key" to (first(good, "\"core\":", "\"Core\":") to ProposalReason.MALFORMED),
            "null persons" to (rewire { it.persons = null } to ProposalReason.MALFORMED),
            "roster absent" to (rewire { it.roster = null } to ProposalReason.MALFORMED),
            "roster reversed" to (rewire { it.roster = it.roster!!.reversed() } to ProposalReason.MALFORMED),
            "roster duplicate" to
                (rewire { it.roster = listOf(it.roster!![0], it.roster!![0]) } to ProposalReason.MALFORMED),
            "empty person list" to (rewire { it.persons!![someKey] = emptyList() } to ProposalReason.MALFORMED),
            "managed person key" to
                (rewire { it.persons!!["mp:" + "ab".repeat(16)] = listOf("x") } to ProposalReason.MALFORMED),
            "padded core" to (rewire { it.core += "=" } to ProposalReason.BAD_CORE),
            "garbage core" to (rewire { it.core = "e30" } to ProposalReason.BAD_CORE),
            "usr dropped" to (rewire { it.usr = "" } to ProposalReason.RESTATEMENT_MISMATCH),
            // Go's encoding/json, not a strict reader: these decide WHICH refusal applies.
            "null document" to ("null" to ProposalReason.BAD_VERSION),
            "case-variant v=2" to (first(good, "\"v\":1,", "\"V\":2,") to ProposalReason.BAD_VERSION),
            "case-variant v=1" to (first(good, "\"v\":1,", "\"V\":1,") to ProposalReason.MALFORMED),
            "long-s slot" to (first(good, "\"slot\":", "\"ſlot\":") to ProposalReason.MALFORMED),
            "null version" to (first(good, "\"v\":1,", "\"v\":null,") to ProposalReason.BAD_VERSION),
            "fractional version" to (first(good, "\"v\":1,", "\"v\":1.0,") to ProposalReason.MALFORMED),
            "later duplicate v wins (bad)" to
                (first(good, "\"v\":1,", "\"v\":1,\"v\":2,") to ProposalReason.BAD_VERSION),
            "later duplicate v wins (good)" to (
                first(
                    good,
                    "\"v\":1,",
                    "\"v\":2,\"v\":1,",
                ) to ProposalReason.MALFORMED
                ),
            "count caps before canonical form" to (
                first(good, "\"roster\":[", "\"roster\" : [" + "\"x\",".repeat(RosterProposal.MAX_ROSTER_OPS + 1)) to
                    ProposalReason.TOO_LARGE
                ),
            "too deep to scan" to (
                first(
                    good,
                    "\"v\":1,",
                    "\"v\":2,\"x\":" + "[".repeat(GoJson.MAX_DEPTH) + "]".repeat(GoJson.MAX_DEPTH) + ",",
                ) to
                    ProposalReason.MALFORMED
                ),
            "deep but scannable" to (
                first(
                    good,
                    "\"v\":1,",
                    "\"v\":2,\"x\":" + "[".repeat(GoJson.MAX_DEPTH - 1) + "]".repeat(GoJson.MAX_DEPTH - 1) + ",",
                ) to
                    ProposalReason.BAD_VERSION
                ),
            "escaped core restates nothing" to
                (first(good, "\"core\":\"e", "\"core\":\"\\u0065") to ProposalReason.MALFORMED),
        )
        for ((name, c) in cases) {
            assertEquals(c.second, reasonOf { RosterProposal.decode(c.first.encodeToByteArray()) }, name)
        }
        // The happy path decodes, and New/Encode reproduce the bytes.
        assertContentEquals(good.encodeToByteArray(), p.encode())
    }

    @Test
    fun decodeCosigRefuses() {
        val cases = mapOf(
            "too large" to (goodCosig + " ".repeat(RosterProposal.MAX_COSIG_BYTES) to ProposalReason.TOO_LARGE),
            "bad version" to (first(goodCosig, "\"v\":1", "\"v\":9") to ProposalReason.BAD_VERSION),
            "proposal slot" to
                (first(goodCosig, "\"slot\":\"cosig\"", "\"slot\":\"proposal\"") to ProposalReason.MALFORMED),
            "null persons" to
                (goodCosig.substringBefore("\"persons\"") + "\"persons\":null}" to ProposalReason.MALFORMED),
            "no usr" to (
                goodCosig.replaceFirst(
                    goodCosig.substring(goodCosig.indexOf("\"usr\""), goodCosig.indexOf("\"bprev\"")),
                    "",
                ) to ProposalReason.MALFORMED
                ),
            "entry not an object" to (
                goodCosig.substringBefore("\"entry\"") + "\"entry\":[],\"persons\":{}}" to ProposalReason.MALFORMED
                ),
        )
        for ((name, c) in cases) {
            assertEquals(c.second, reasonOf { checked.verifyCosig(c.first.encodeToByteArray()) }, name)
        }
        val cs = checked.verifyCosig(goodCosig.encodeToByteArray())
        assertContentEquals(goodCosig.encodeToByteArray(), cs.encode())
    }

    @Test
    fun cosignAndAssembleRefusals() {
        val (pd, pdPub) = key("P.D")
        val usrP = v.keyId("P")
        // The proposer's own key never counts toward its quorum.
        val pLog = p.persons.getValue(usrP)
        val pHead = p.draft.bprev
        assertEquals(
            ProposalReason.COSIGNER_NOT_COUNTED,
            reasonOf { checked.cosign(pd, pdPub, usrP, pHead, pLog) },
        )
        // A cosigner whose own log does not resolve its bprev writes nothing back.
        val (qd, qdPub) = key("Q.D")
        val cs = checked.verifyCosig(goodCosig.encodeToByteArray())
        assertEquals(
            ProposalReason.MISSING_PERSON_CONTEXT,
            reasonOf { checked.cosign(qd, qdPub, cs.entry.usr, cs.entry.bprev, emptyList()) },
        )
        // Duplicate cosigs are dropped: the op is the one a single cosig mints.
        val once = checked.assemble(pd, pdPub, listOf(cs))
        val twice = checked.assemble(pd, pdPub, listOf(cs, cs))
        assertEquals(once, twice)
        assertEquals("", once.verdict)
        // A cosig that does not count is refused at assembly as at verification.
        val bad = Cosig(cs.entry.copy(sig = Base64Url.encode(ByteArray(64))), cs.persons)
        assertEquals(ProposalReason.BAD_COSIG, reasonOf { checked.assemble(pd, pdPub, listOf(bad)) })
        // A re-root needs its successor's signer.
        val rv = vector("reroot-round-trip")
        val rc = RosterProposal.check(
            (rv["proposal"] as String).encodeToByteArray(),
            Expect(rv["org"] as String, rv["founding"] as String),
        )
        val (org, orgPub) = key("org")
        assertFailsWith<IllegalArgumentException> { rc.assemble(org, orgPub, emptyList()) }
    }

    @Test
    fun replicaTokensTrimWithGoWhitespace() {
        // U+0085 is space to Go's strings.TrimSpace but not to Kotlin's trim(): a replica
        // padded with it must still supply the roster context, as in Go.
        val bare = RosterProposal.create(p.draft, emptyList(), p.persons).encode()
        val padded = expect.copy(roster = p.roster.map { "\u0085$it\u0085" })
        RosterProposal.check(bare, padded)
        assertEquals(ProposalReason.MISSING_ROSTER_CONTEXT, reasonOf { RosterProposal.check(bare, expect) })
        // U+001F is the reverse case: Kotlin's trim() strips it and Go's does not, so an
        // attachment padded with it is bad_context in both.
        val usrP = v.keyId("P")
        val sep = RosterProposal.create(
            p.draft,
            p.roster,
            mapOf(usrP to p.persons.getValue(usrP).map { "\u001f$it" }),
        ).encode()
        assertEquals(ProposalReason.BAD_CONTEXT, reasonOf { RosterProposal.check(sep, expect) })
        // The pinned founding token gets the same guard: Go refuses it, so does this.
        val e = assertFailsWith<RosterException> {
            RosterProposal.check(good.encodeToByteArray(), expect.copy(founding = "\u001f" + expect.founding))
        }
        assertEquals(RosterException.Failure.FOUNDING, e.failure)
    }

    @Test
    fun hostileNestingIsRefusedNotFatal() {
        // A roster attachment, a person attachment and a cosig person op whose bodies nest
        // far deeper than the recursive body parser could follow.
        val deep = Base64Url.encode(("{\"x\":" + "[".repeat(DEEP) + "]".repeat(DEEP) + "}").encodeToByteArray()) + ".AA"
        val withRoster = RosterProposal.create(p.draft, p.roster + deep, p.persons).encode()
        assertEquals(ProposalReason.BAD_CONTEXT, reasonOf { RosterProposal.check(withRoster, expect) })
        val usrP = v.keyId("P")
        val withPerson = RosterProposal.create(
            p.draft,
            p.roster,
            mapOf(usrP to p.persons.getValue(usrP) + deep),
        ).encode()
        assertEquals(ProposalReason.BAD_CONTEXT, reasonOf { RosterProposal.check(withPerson, expect) })
        val cs = checked.verifyCosig(goodCosig.encodeToByteArray())
        // (A cosig is capped at 128 KiB, so its deep op is shallower, still far past the stack.)
        val deeper =
            Base64Url.encode(("{\"x\":" + "[".repeat(DEEP_COSIG) + "]".repeat(DEEP_COSIG) + "}").encodeToByteArray()) +
                ".AA"
        val deepCosig =
            Cosig(cs.entry, mapOf(cs.entry.usr to RosterProposal.byHash(cs.persons.getValue(cs.entry.usr) + deeper)))
        assertEquals(ProposalReason.BAD_CONTEXT, reasonOf { checked.verifyCosig(deepCosig.encode()) })
        // A slot document nested past Go's scanner limit is malformed, not a crash.
        val doc = "[".repeat(RosterProposal.MAX_PROPOSAL_BYTES / 2) + "]".repeat(RosterProposal.MAX_PROPOSAL_BYTES / 2)
        assertEquals(ProposalReason.MALFORMED, reasonOf { RosterProposal.decode(doc.encodeToByteArray()) })
    }

    @Test
    fun createRefusesOverCaps() {
        val many = (0..RosterProposal.MAX_ROSTER_OPS).map { "op%03d".format(it) }
        assertEquals(ProposalReason.TOO_LARGE, reasonOf { RosterProposal.create(p.draft, many, emptyMap()) })
        assertEquals(
            ProposalReason.BAD_CORE,
            reasonOf { RosterProposal.create(p.draft.copy(iat = 0), emptyList(), emptyMap()) },
        )
    }

    @Test
    fun goJsonEncodesStringsAsGoDoes() {
        val sb = StringBuilder()
        GoJson.appendString(sb, "a\"\\/<>&\b\u000C\n\r\t\u0001\u007F  é😀\uD800")
        assertEquals(
            "\"a\\\"\\\\/\\u003c\\u003e\\u0026\\b\\f\\n\\r\\t\\u0001\u007F\\u2028\\u2029é😀\\ufffd\"",
            sb.toString(),
        )
        assertTrue(GoJson.foldsTo("V", "v") && GoJson.foldsTo("ſlot", "slot") && GoJson.foldsTo("Key", "key"))
        assertFalse(GoJson.foldsTo("vv", "v") || GoJson.foldsTo("é", "e"))
        assertNull(GoJson.parse("{\"a\":01}"))
        assertNull(GoJson.parse("{\"a\":\"\u0001\"}"))
        assertNull(GoJson.parse(" "))
        val s = GoJson.parse("\"\\ud800\\u0041\\ud83d\\ude00\"") as GoJson.Str
        assertEquals("�A😀", s.value)
    }

    @Test
    fun relaySlotTypes() {
        assertEquals(listOf(RosterProposal.SLOT_PROPOSAL, RosterProposal.SLOT_COSIG), RelayClient.COSIGN_TYPES)
        assertEquals(RosterProposal.MAX_PROPOSAL_BYTES, RelayClient.COSIGN_MAX_MESSAGE_BYTES)
        assertTrue(RosterProposal.MAX_COSIG_BYTES <= RelayClient.COSIGN_MAX_MESSAGE_BYTES)
    }

    // --- roster/core_test.go -----------------------------------------------------------

    @Test
    fun parseCoreRoundTripsAndRefuses() {
        val core = p.core
        assertEquals(p.draft, Roster.parseCore(core))
        assertContentEquals(core, Roster.parseCore(core).core())
        val s = core.decodeToString()
        val cases = mapOf(
            "not json" to ("{" to Failure.MALFORMED),
            "null" to ("null" to Failure.WRONG_TYPE),
            "reordered" to
                (
                    first(
                        s,
                        "{\"v\":1,\"typ\":\"void-which-binds.roster\"",
                        "{\"typ\":\"void-which-binds.roster\",\"v\":1",
                    ) to
                        Failure.MALFORMED
                    ),
            "cosig present" to (first(s, ",\"iat\":", ",\"cosig\":[],\"iat\":") to Failure.MALFORMED),
            "succsig" to (first(s, ",\"iat\":", ",\"succsig\":\"x\",\"iat\":") to Failure.MALFORMED),
            "other typ" to
                (
                    first(s, "\"typ\":\"void-which-binds.roster\"", "\"typ\":\"void-which-binds.op\"") to
                        Failure.WRONG_TYPE
                    ),
            "no typ" to (first(s, "\"typ\":\"void-which-binds.roster\",", "") to Failure.WRONG_TYPE),
            "case-variant typ" to (first(s, "\"v\":1,", "\"v\":1,\"Typ\":\"x\",") to Failure.MALFORMED),
            "version 2" to (first(s, "\"v\":1", "\"v\":2") to Failure.MALFORMED),
            "no iat" to (first(s, "\"iat\":", "\"iat\":0,\"x\":") to Failure.MALFORMED),
            "whitespace" to (first(s, "\"v\":1,", "\"v\":1 ,") to Failure.MALFORMED),
            "bad role" to (first(s, "\"viewer\"", "\"Viewer\"") to Failure.MALFORMED),
            "trailing space" to ("$s " to Failure.MALFORMED),
            "deep" to
                (
                    first(
                        s,
                        "\"v\":1,",
                        "\"v\":1,\"x\":" + "[".repeat(DEEP) + "]".repeat(DEEP) + ",",
                    ) to Failure.MALFORMED
                    ),
        )
        for ((name, c) in cases) {
            val e = assertFailsWith<RosterException>(name) { Roster.parseCore(c.first.encodeToByteArray()) }
            assertEquals(c.second, e.failure, name)
        }
    }

    @Test
    fun verifyDraftCosig() {
        val d = p.draft
        val sig = checked.verifyCosig(goodCosig.encodeToByteArray()).entry
        Roster.verifyDraftCosig(d, sig)
        fun failure(block: () -> Unit) = assertFailsWith<RosterException> { block() }.failure
        assertEquals(Failure.COSIG_SIGNATURE, failure { Roster.verifyDraftCosig(d.copy(role = Role.MEMBER), sig) })
        assertEquals(Failure.COSIG_SIGNATURE, failure { Roster.verifyDraftCosig(d, sig.copy(bprev = emptyList())) })
        assertEquals(Failure.MALFORMED, failure { Roster.verifyDraftCosig(d, sig.copy(usr = "", bprev = emptyList())) })
        assertEquals(Failure.MALFORMED, failure { Roster.verifyDraftCosig(d, sig.copy(sig = "AAAA")) })
        assertEquals(Failure.MALFORMED, failure { Roster.verifyDraftCosig(d, sig.copy(by = d.org)) })
        // A succsig on the draft does not change the core a cosig covers.
        Roster.verifyDraftCosig(d.copy(succSig = "anything"), sig)
    }

    @Test
    fun checkDraftClosure() {
        val persons: (String) -> List<String> = { p.persons[it].orEmpty() }
        fun check(d: one.rarebit.voidwhichbinds.roster.RosterDraft) =
            Roster.checkDraftClosure(expect.org, expect.founding, d, p.roster, persons)
        check(p.draft.copy(exp = p.draft.iat + 60))
        val q = p.draft.copy(mem = v.keyId("Q"), exp = p.draft.iat + 60) // Q is an admin: a reduction with exp
        val reroot = p.draft.copy(
            op = OpKind.REROOT,
            mem = "",
            role = "",
            succ = v.keyId("Q"),
            by = expect.org,
            usr = "",
            bprev = emptyList(),
        )
        val early = p.draft.copy(iat = 1)
        for ((name, d) in mapOf(
            "exp on a reduction" to q,
            "succ is a roster mem" to reroot,
            "prev after the op" to early,
        )) {
            assertEquals(Failure.MALFORMED, assertFailsWith<RosterException>(name) { check(d) }.failure, name)
        }
        assertTrue(
            Roster.authorityOnly(OpKind.RESET) && Roster.authorityOnly(OpKind.REROOT) &&
                Roster.authorityOnly(OpKind.RESOLVE),
        )
        assertFalse(Roster.authorityOnly(OpKind.SET))
    }

    private fun Map<String, Any>.keyId(label: String): String =
        (this["keys"] as Map<String, Map<String, Any>>).getValue(label)["id"] as String

    private companion object {
        const val DEEP = 60_000
        const val DEEP_COSIG = 40_000
    }
}
