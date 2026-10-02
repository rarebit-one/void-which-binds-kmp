package one.rarebit.voidwhichbinds.roster

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.crypto.Base64Url
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * The roster op wire and [Roster.evaluate]'s refusals: ports of void-which-binds-go
 * roster/op_test.go (`TestSignWithRoundTrip`, `TestVerifyRefusesNonCanonical`,
 * `TestSignWithRefusals`, `TestRerootAndResolveWire`, `TestEvaluateRefusals`,
 * `TestNewManagedID`, `TestMerge`). The golden vectors (`RosterVectorTest`, jvmTest)
 * pin the bytes and the verdicts; these pin the API's refusals.
 */
@Suppress("LongParameterList")
class RosterOpTest {

    /** A labelled test key, deterministic from its label (Go `keyActor`). */
    private class Actor(label: String) {
        val seed: ByteArray = Hex.decode(MembershipOp.hash("void-which-binds-roster-vector:$label").substring(7))
        val pub: ByteArray = Ed25519Group.publicKeyFromSeed(seed)
        val id: String = KeyRef.ed25519(pub).render()
        val signer = Ed25519Signer { Ed25519Engine.sign(seed, it) }
    }

    private val actors = HashMap<String, Actor>()
    private fun actor(label: String) = actors.getOrPut(label) { Actor(label) }
    private fun id(label: String) = actor(label).id
    private val org get() = actor("org")

    private val ops = LinkedHashMap<String, String>() // label -> roster token
    private val plog = HashMap<String, MutableList<String>>() // person id -> person-op tokens
    private val pHead = HashMap<String, String>() // person label -> head hash

    private fun at(minutes: Int): Long = T0 + minutes * 60L
    private fun hash(label: String) = Roster.opHash(ops.getValue(label))

    /** Person [p]'s genesis adds each device, chained, at minute 0. */
    private fun devices(p: String, vararg devs: String) {
        val g = actor(p)
        for (d in devs) {
            val tok = MembershipOp.sign(
                g.signer,
                g.pub,
                g.id,
                MembershipOp.Kind.ADD,
                id("$p.$d"),
                "",
                listOfNotNull(pHead[p]),
                at(0),
            )
            plog.getOrPut(g.id) { ArrayList() }.add(tok)
            pHead[p] = MembershipOp.hash(tok)
        }
    }

    /** (key, usr, bprev) of a signer spec: "org", "!K" (authority shape), "P" (genesis) or "P.D" (device). */
    private fun signer(spec: String): Triple<Actor, String, List<String>> = when {
        spec == "org" -> Triple(org, "", emptyList())

        spec.startsWith("!") -> Triple(actor(spec.substring(1)), "", emptyList())

        '.' in spec -> {
            val p = spec.substringBefore('.')
            Triple(actor(spec), id(p), listOfNotNull(pHead[p]))
        }

        else -> Triple(actor(spec), id(spec), emptyList())
    }

    private fun draft(
        kind: OpKind,
        prev: List<String>,
        minute: Int,
        primary: String,
        mem: String = "",
        role: String = "",
        exp: Int = 0,
        succ: String = "",
        pick: String = "",
    ): RosterDraft {
        val (k, usr, bprev) = signer(primary)
        return RosterDraft(
            org = org.id, op = kind, mem = if (mem.isEmpty()) "" else id(mem), role = role,
            exp = if (exp == 0) 0 else at(exp), succ = if (succ.isEmpty()) "" else id(succ),
            pick = if (pick.isEmpty()) "" else hash(pick), by = k.id, usr = usr, bprev = bprev,
            prev = prev.map(::hash), iat = at(minute),
        )
    }

    /** Mint and record an op: the first signer is primary, the rest cosign; a re-root gets its succsig. */
    private fun op(label: String, d0: RosterDraft, vararg signers: String, succ: String = ""): String {
        var d = d0
        if (d.op == OpKind.REROOT) {
            val s = actor(succ)
            d = d.copy(succSig = Roster.succSigWith(s.signer, s.pub, d))
        }
        val cosigs = signers.drop(1).map {
            val (k, usr, bprev) = signer(it)
            Roster.cosignWith(k.signer, k.pub, d, usr, bprev)
        }
        val (k, _, _) = signer(signers[0])
        val tok = Roster.signWith(k.signer, k.pub, d, cosigs)
        ops[label] = tok
        return tok
    }

    private fun orgP() {
        devices("P", "D", "E")
        op("founding", draft(OpKind.SET, emptyList(), 1, "org", mem = "P", role = Role.OWNER), "org")
    }

    private fun orgPQ() {
        orgP()
        devices("Q", "D", "E")
        op("set-Q", draft(OpKind.SET, listOf("founding"), 2, "P.D", mem = "Q", role = Role.ADMIN), "P.D", "P.E")
    }

    private fun eval(toks: List<String> = ops.values.toList()): RosterView =
        Roster.evaluate(org.id, ops.getValue("founding"), toks, { plog[it].orEmpty() }, at(60))

    private fun signRaw(body: ByteArray, by: Actor = org): String =
        Base64Url.encode(body) + "." + Base64Url.encode(Ed25519Engine.sign(by.seed, body))

    private fun failure(block: () -> Unit): RosterException.Failure = assertFailsWith<RosterException> {
        block()
    }.failure

    @Test
    fun signWithRoundTrip() {
        orgP()
        val d = draft(OpKind.SET, listOf("founding"), 2, "P.D", mem = "V", role = Role.VIEWER, exp = 90)
        val (e, usr, bprev) = signer("P.E")
        val cs = Roster.cosignWith(e.signer, e.pub, d, usr, bprev)
        val p = actor("P.D")
        val tok = Roster.signWith(p.signer, p.pub, d, listOf(cs))
        val o = Roster.verify(tok)
        assertEquals(OpKind.SET, o.kind)
        assertEquals(id("V"), o.mem)
        assertEquals(Role.VIEWER, o.role)
        assertEquals(at(90), o.exp)
        assertEquals(id("P"), o.usr)
        assertEquals(listOf(cs), o.cosig)
        assertTrue(Roster.verifyCosig(o, o.cosig[0]), "cosig must verify")
        assertTrue(d.core().contentEquals(o.draft().core()), "the parsed op's draft must rebuild the core")
        val core = d.core().decodeToString()
        assertFalse("\"cosig\"" in core || "\"succsig\"" in core, "the core carries cosig or succsig")
        assertFalse(Roster.verifyCosig(o, cs.copy(usr = id("Q"))), "a cosig verified under another usr")
        // The minting order is ADR-0014's.
        val body = Base64Url.decode(tok.substringBefore('.')).decodeToString()
        assertEquals(
            "v,typ,org,op,mem,role,exp,by,usr,bprev,prev,cosig,iat",
            MiniJson.parseObject(body).keys.joinToString(","),
        )
    }

    @Test
    fun verifyRefusesNonCanonical() {
        orgP()
        val d = draft(OpKind.SET, listOf("founding"), 2, "org", mem = "V", role = Role.VIEWER)
        val body = RosterWire.encode(d.payload()).decodeToString()
        Roster.verify(signRaw(body.encodeToByteArray()))
        val f = hash("founding")
        val variants = mapOf(
            "extra member" to body.replaceFirst("{\"v\":1,", "{\"v\":1,\"x\":1,"),
            "reordered" to body.replaceFirst(
                "\"v\":1,\"typ\":\"void-which-binds.roster\"",
                "\"typ\":\"void-which-binds.roster\",\"v\":1",
            ),
            "prev null" to body.replaceFirst("\"prev\":[\"$f\"]", "\"prev\":null"),
            "empty bprev" to body.replaceFirst("\"prev\":", "\"bprev\":[],\"prev\":"),
            "case variant" to body.replaceFirst("\"org\":", "\"Org\":"),
            "whitespace" to " $body",
            "duplicate prev" to body.replaceFirst("\"prev\":[\"$f\"]", "\"prev\":[\"$f\",\"$f\"]"),
        )
        for ((name, b) in variants) {
            assertTrue(b != body, "$name: the variant must differ")
            assertEquals(
                RosterException.Failure.MALFORMED,
                failure {
                    Roster.verify(signRaw(b.encodeToByteArray()))
                },
                name,
            )
        }
        // A tampered signature is bad_signature, a foreign typ wrong_type.
        val sig = Ed25519Engine.sign(org.seed, body.encodeToByteArray())
        sig[10] = (sig[10].toInt() xor 1).toByte()
        val tampered = Base64Url.encode(body.encodeToByteArray()) + "." + Base64Url.encode(sig)
        assertEquals(RosterException.Failure.BAD_SIGNATURE, failure { Roster.verify(tampered) })
        val personTyp = RosterWire.encode(d.payload().copy(typ = "void-which-binds.op"))
        assertEquals(RosterException.Failure.WRONG_TYPE, failure { Roster.verify(signRaw(personTyp)) })
    }

    @Test
    fun signWithRefusals() {
        orgP()
        val managed = "mp:" + "ab".repeat(16)
        val base = draft(OpKind.SET, listOf("founding"), 2, "P.D", mem = "V", role = Role.VIEWER)
        val cases: Map<String, (RosterDraft) -> RosterDraft> = mapOf(
            "exp on remove" to { d -> d.copy(op = OpKind.REMOVE, role = "", exp = at(9)) },
            "exp not after iat" to { d -> d.copy(exp = d.iat) },
            "unknown role" to { d -> d.copy(role = "superuser") },
            "mem is org" to { d -> d.copy(mem = org.id) },
            "no prev" to { d -> d.copy(prev = emptyList()) },
            "enrol sovereign mem" to { d -> d.copy(op = OpKind.ENROL, role = "", key = id("P.D")) },
            "enrol bad key" to { d -> d.copy(op = OpKind.ENROL, role = "", mem = managed, key = "ed25519:zz") },
            "set with key" to { d -> d.copy(key = id("P.D")) },
            "reset with mem" to { d -> d.copy(op = OpKind.RESET, role = "") },
            "reroot without succ" to { d -> d.copy(op = OpKind.REROOT, role = "", mem = "") },
            "pick on set" to { d -> d.copy(pick = hash("founding")) },
            "managed usr bprev" to { d -> d.copy(usr = managed) },
            "genesis bprev" to { d -> d.copy(usr = d.by) },
            "bad managed mem" to { d -> d.copy(mem = "mp:XYZ") },
            "bprev without usr" to { d -> d.copy(usr = "") },
            "org as a person" to { d -> d.copy(usr = org.id, bprev = emptyList()) },
            "resolve with bad pick" to { d -> d.copy(op = OpKind.RESOLVE, role = "", mem = "", pick = "sha256:00") },
            "padded mem" to { d -> d.copy(mem = " " + d.mem) },
        )
        val p = actor("P.D")
        for ((name, mutate) in cases) {
            assertEquals(
                RosterException.Failure.MALFORMED,
                failure { Roster.signWith(p.signer, p.pub, mutate(base), emptyList()) },
                name,
            )
        }
        val e = actor("P.E")
        assertEquals(RosterException.Failure.MALFORMED, failure { Roster.signWith(e.signer, e.pub, base, emptyList()) })
        val nine = List(Roster.MAX_COSIGS + 1) { Roster.cosignWith(e.signer, e.pub, base, id("P"), emptyList()) }
        assertEquals(RosterException.Failure.MALFORMED, failure { Roster.signWith(p.signer, p.pub, base, nine) })
        assertEquals(
            RosterException.Failure.MALFORMED,
            failure { Roster.cosignWith(e.signer, e.pub, base, "", emptyList()) },
            "cosig with no usr",
        )
        assertEquals(
            RosterException.Failure.MALFORMED,
            failure { Roster.cosignWith(e.signer, e.pub, base, " " + id("P") + " ", emptyList()) },
            "cosig with a padded usr",
        )
    }

    @Test
    fun rerootAndResolveWire() {
        orgPQ()
        op(
            "reroot",
            draft(OpKind.REROOT, listOf("set-Q"), 3, "org", succ = "K1"),
            "org",
            "P.D",
            "Q.D",
            succ = "K1",
        )
        op("resolve", draft(OpKind.RESOLVE, listOf("reroot"), 4, "org", pick = "reroot"), "org")
        op("k1-sets-V", draft(OpKind.SET, listOf("resolve"), 5, "!K1", mem = "V", role = Role.VIEWER), "!K1")
        val v = eval()
        assertEquals(id("K1"), v.authority)
        assertFalse(v.frozen)
        assertNull(v.conflict)
        assertNull(v.ineffective[hash("reroot")])
        assertEquals(RosterReason.RETIRED_AUTHORITY, v.ineffective[hash("resolve")])
        assertNull(v.ineffective[hash("k1-sets-V")])
        assertEquals(Role.VIEWER, v.persons[id("V")]?.role)

        val rd = draft(OpKind.REROOT, listOf("set-Q"), 3, "org", succ = "K4")
        assertEquals(
            RosterException.Failure.MALFORMED,
            failure { Roster.signWith(org.signer, org.pub, rd, emptyList()) },
            "reroot without succsig",
        )
        val k4 = actor("K4")
        val signed = rd.copy(succSig = Roster.succSigWith(k4.signer, k4.pub, rd))
        Roster.verify(Roster.signWith(org.signer, org.pub, signed, emptyList()))
        assertEquals(
            RosterException.Failure.MALFORMED,
            failure { Roster.signWith(org.signer, org.pub, signed.copy(succ = id("K5")), emptyList()) },
            "reroot with another key's succsig",
        )
        assertEquals(
            RosterException.Failure.MALFORMED,
            failure { Roster.signWith(org.signer, org.pub, signed.copy(succSig = "not base64!"), emptyList()) },
            "reroot with a garbage succsig",
        )
        val k9 = actor("K9")
        assertEquals(
            RosterException.Failure.MALFORMED,
            failure {
                Roster.succSigWith(k9.signer, k9.pub, draft(OpKind.REROOT, listOf("set-Q"), 3, "org", succ = "K1"))
            },
            "succsig by a key that is not succ",
        )
        // A re-root to the org itself is malformed on its own.
        val toOrg = draft(OpKind.REROOT, listOf("set-Q"), 3, "org").copy(succ = org.id)
        val forged = RosterWire.encode(toOrg.payload())
        assertEquals(RosterException.Failure.MALFORMED, failure { Roster.verify(signRaw(forged)) })
    }

    @Test
    fun evaluateRefusals() {
        orgPQ()
        val toks = ops.values.toList()
        val founding = ops.getValue("founding")
        assertEquals(
            RosterException.Failure.NO_ORG,
            failure { Roster.evaluate("ed25519:nope", founding, toks, null, at(60)) },
        )
        assertEquals(
            RosterException.Failure.NO_ORG,
            failure { Roster.evaluate(" " + org.id, founding, toks, null, at(60)) },
        )
        assertFailsWith<IllegalArgumentException> { Roster.evaluate(org.id, founding, toks, null, 0) }
        for ((name, f) in mapOf("not a founding op" to ops.getValue("set-Q"), "junk" to "x.y")) {
            assertEquals(
                RosterException.Failure.FOUNDING,
                failure { Roster.evaluate(org.id, f, toks, null, at(60)) },
                name,
            )
        }
        // No person logs: an op whose bprev is not given is rejected.
        val v = Roster.evaluate(org.id, founding, toks, null, at(60))
        assertEquals(RosterReason.MISSING_PERSON_CONTEXT, v.rejected[hash("set-Q")])
        // With them, Q is an admin and the high-water is 2.
        val full = eval()
        assertEquals(Role.ADMIN, full.persons[id("Q")]?.role)
        assertEquals(2, full.adminHighWater)
        assertEquals(full.accepted.keys.sorted(), full.tokens().map(Roster::opHash))
    }

    @Test
    fun newManagedIdAndMerge() {
        val mp = Roster.newManagedId(
            object : Random() {
                override fun nextBits(bitCount: Int): Int = 0xab
                override fun nextBytes(array: ByteArray): ByteArray = array.also { it.fill(0xab.toByte()) }
            },
        )
        assertEquals("mp:abababababababababababababababab", mp)
        assertTrue(RosterWire.validManagedId(Roster.newManagedId()))
        val got = Roster.merge(listOf("b", " a ", ""), listOf("a", "c"))
        assertEquals(3, got.size)
        assertEquals(got.map(Roster::opHash).sorted(), got.map(Roster::opHash))
    }

    private companion object {
        /** Go's t0: 2026-10-01T12:00:00Z. */
        const val T0 = 1_790_856_000L
    }
}
