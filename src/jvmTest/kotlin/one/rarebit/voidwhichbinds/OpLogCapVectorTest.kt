package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import one.rarebit.voidwhichbinds.roster.OpKind
import one.rarebit.voidwhichbinds.roster.Role
import one.rarebit.voidwhichbinds.roster.Roster
import one.rarebit.voidwhichbinds.roster.RosterDraft
import one.rarebit.voidwhichbinds.roster.RosterException
import one.rarebit.voidwhichbinds.roster.RosterView
import java.io.File
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/**
 * The op-log history cap (void-which-binds-go #122: ADR-0007 rule 6 and ADR-0014, amended
 * 2026-10-03). [everyCapVectorReplays] is Go's `TestCapVectors` (enrolment and roster
 * `capvectors_test.go`): each file of `testvectors/vectors/op-log-cap/` is evaluated
 * under its own small `max_ops` through the internal seams
 * ([Membership.evaluateWithCap], [Roster.evaluateWithCap]), in file order and seven
 * shuffled orders (of the roster ops and of each person's ops), and must reach the
 * file's `expect` or its `log_too_large` refusal. The other tests are Go's
 * `TestMaxLogOpsIsTenThousand` and `TestCapAtTheRealLimit`, for both logs, plus the
 * refusal through [Membership.memberAt] and [Membership.newLog].
 */
@Suppress("UNCHECKED_CAST")
class OpLogCapVectorTest {

    private val cases: List<String> = run {
        val dir = javaClass.getResource("/vectors/op-log-cap")
            ?: error("vectors/op-log-cap missing from test resources")
        val names = File(dir.toURI()).listFiles { f -> f.isFile && f.name.endsWith(".json") }
            .orEmpty()
            .map { it.name.removeSuffix(".json") }
            .sorted()
        check(names.size >= MIN_VECTORS) { "expected >= $MIN_VECTORS op-log-cap vectors, found ${names.size}: $names" }
        names
    }

    private fun load(name: String): Map<String, Any?> {
        val raw = javaClass.getResourceAsStream("/vectors/op-log-cap/$name.json")?.readBytes()?.decodeToString()
            ?: error("vector $name.json missing")
        val o = MiniJson.parseObject(raw)
        assertEquals(name, o["name"], "vector file stem must equal its name")
        return o
    }

    private fun tokensOf(list: Any?, hash: (String) -> String, name: String): List<String> =
        (list as List<Map<String, Any>>).map {
            val tok = it["token"] as String
            assertEquals(it["hash"], hash(tok), "$name: op ${it["label"]} hash")
            tok
        }

    // --- the membership projection (Go enrolment `summarise`) -----------------------

    private fun summariseMembership(v: Membership.View): Map<String, Any> {
        val members = LinkedHashMap<String, Any>()
        for ((dev, m) in v.members.toSortedMap()) {
            val fields = LinkedHashMap<String, Any>()
            fields["admitted_by"] = m.admittedBy
            if (m.deviceEnc.isNotEmpty()) fields["denc"] = m.deviceEnc
            fields["admitted_at"] = m.admittedAt
            fields["expires"] = m.expiresAt
            members[dev] = fields
        }
        return mapOf(
            "members" to members,
            "removed" to v.removed.sorted(),
            "heads" to v.heads,
            "rejected" to v.rejected.toSortedMap().toMap(),
            "ineffective" to v.ineffective.toSortedMap().toMap(),
        )
    }

    private fun normaliseMembership(expect: Map<String, Any>): Map<String, Any> {
        val members = (expect["members"] as Map<String, Map<String, Any>>).toSortedMap().mapValues { (_, m) ->
            val fields = LinkedHashMap<String, Any>()
            fields["admitted_by"] = m["admitted_by"] as String
            (m["denc"] as? String)?.let { fields["denc"] = it }
            fields["admitted_at"] = m["admitted_at"] as Long
            fields["expires"] = m["expires"] as Long
            fields as Any
        }.toMap()
        return mapOf(
            "members" to members,
            "removed" to (expect["removed"] as List<Any>).map { it as String },
            "heads" to (expect["heads"] as List<Any>).map { it as String },
            "rejected" to (expect["rejected"] as Map<String, Any>).toSortedMap().toMap(),
            "ineffective" to (expect["ineffective"] as Map<String, Any>).toSortedMap().toMap(),
        )
    }

    // --- the roster projection (Go roster `summarise`) ------------------------------

    private fun summariseRoster(v: RosterView): Map<String, Any?> = mapOf(
        "persons" to v.persons.toSortedMap().mapValues { (_, p) ->
            mapOf(
                "role" to p.role,
                "kind" to p.kind.wire,
                "keys" to p.keys?.takeIf { it.isNotEmpty() }?.toSortedMap(),
                "assigned_by" to p.assignedBy,
                "expires" to p.expires,
            )
        },
        "removed" to v.removed.sorted(),
        "heads" to v.heads,
        "authority" to v.authority,
        "admin_high_water" to v.adminHighWater,
        "frozen" to v.frozen,
        "conflict" to v.conflict?.takeIf { it.isNotEmpty() },
        "rejected" to v.rejected.toSortedMap(),
        "ineffective" to v.ineffective.toSortedMap(),
    )

    private fun normaliseRoster(e: Map<String, Any>): Map<String, Any?> {
        val persons = (e["persons"] as Map<String, Map<String, Any>>).toSortedMap().mapValues { (_, p) ->
            mapOf(
                "role" to p["role"],
                "kind" to p["kind"],
                "keys" to (p["keys"] as? Map<String, Any>)?.toSortedMap(),
                "assigned_by" to p["assigned_by"],
                "expires" to (p["expires"] as? Long ?: 0L),
            )
        }
        return mapOf(
            "persons" to persons,
            "removed" to e["removed"],
            "heads" to e["heads"],
            "authority" to e["authority"],
            "admin_high_water" to (e["admin_high_water"] as Long).toInt(),
            "frozen" to e["frozen"],
            "conflict" to e["conflict"],
            "rejected" to (e["rejected"] as Map<String, Any>).toSortedMap(),
            "ineffective" to (e["ineffective"] as Map<String, Any>).toSortedMap(),
        )
    }

    @Test
    fun everyCapVectorReplays() {
        var membership = 0
        var roster = 0
        for ((n, name) in cases.withIndex()) {
            val o = load(name)
            val error = o["error"] as String?
            assertTrue((error == null) != (o["expect"] == null), "$name: exactly one of expect and error")
            if (error != null) assertEquals(LOG_TOO_LARGE, error, "$name: the only refusal is log_too_large")
            val rng = Random(n.toLong() + 1)
            when (o["log"]) {
                "membership" -> membership += replayMembership(name, o, rng)
                "roster" -> roster += replayRoster(name, o, rng)
                else -> error("$name: unknown log ${o["log"]}")
            }
        }
        assertTrue(membership >= 4 && roster >= 4, "op-log-cap coverage: $membership membership, $roster roster")
        println("op-log-cap vector parity: $membership membership + $roster roster cases, $ORDERS orders each")
    }

    /** One membership case, in file order and shuffled orders, under its max_ops. */
    private fun replayMembership(name: String, o: Map<String, Any?>, rng: Random): Int {
        val maxOps = (o["max_ops"] as Long).toInt()
        val usr = o["usr"] as String
        val now = o["now"] as Long
        val toks = tokensOf(o["ops"], MembershipOp::hash, name)
        val want = (o["expect"] as Map<String, Any>?)?.let(::normaliseMembership)
        for (p in 0 until ORDERS) {
            val order = if (p == 0) toks else toks.shuffled(rng)
            val eval = { Membership.evaluateWithCap(usr, order, now, Ed25519Engine.verifier(), maxOps) }
            if (want == null) {
                assertFailsWith<Membership.LogTooLargeException>("$name: order $p") { eval() }
            } else {
                assertEquals(want, summariseMembership(eval()), "$name: order $p diverged")
            }
        }
        return 1
    }

    /** One roster case, in file order and shuffled orders (of roster and person ops), under its max_ops. */
    private fun replayRoster(name: String, o: Map<String, Any?>, rng: Random): Int {
        val maxOps = (o["max_ops"] as Long).toInt()
        val org = o["org"] as String
        val founding = o["founding"] as String
        val now = o["now"] as Long
        val toks = tokensOf(o["ops"], Roster::opHash, name)
        val persons = (o["persons"] as Map<String, Any>).mapValues { (_, l) -> tokensOf(l, MembershipOp::hash, name) }
        val want = (o["expect"] as Map<String, Any>?)?.let(::normaliseRoster)
        for (p in 0 until ORDERS) {
            val ps = persons.mapValues { it.value.toMutableList() }
            val order = if (p == 0) {
                toks
            } else {
                for (l in ps.values) l.shuffle(rng)
                toks.shuffled(rng)
            }
            val eval = {
                val verifier = Ed25519Engine.verifier()
                Roster.evaluateWithCap(org, founding, order, { ps[it].orEmpty() }, now, verifier, maxOps)
            }
            if (want == null) {
                val e = assertFailsWith<RosterException>("$name: order $p") { eval() }
                assertEquals(RosterException.Failure.LOG_TOO_LARGE, e.failure, "$name: order $p")
            } else {
                assertEquals(want, summariseRoster(eval()), "$name: order $p diverged")
            }
        }
        return 1
    }

    /** Go `TestMaxLogOpsIsTenThousand` (enrolment and roster). */
    @Test
    fun maxLogOpsIsTenThousand() {
        assertEquals(10_000, Membership.MAX_LOG_OPS, "ADR-0007 says 10,000")
        assertEquals(10_000, Roster.MAX_LOG_OPS, "ADR-0014 says 10,000")
    }

    /** The cap vector refusals also come out of [Membership.newLog] and [Membership.memberAt]. */
    @Test
    fun logConstructionRefusesOverTheCap() {
        val o = load("membership-over-cap")
        val usr = o["usr"] as String
        val toks = tokensOf(o["ops"], MembershipOp::hash, "membership-over-cap")
        val maxOps = (o["max_ops"] as Long).toInt()
        assertFailsWith<Membership.LogTooLargeException> {
            Membership.newLogWithCap(usr, toks, Ed25519Engine.verifier(), maxOps)
        }
        // At the protocol cap the same set is a log like any other.
        Membership.newLog(usr, toks)
        // Over the cap, junk is unanchored: a stranger's op is no head (missing context).
        val junk = load("membership-junk-unanchored")
        val jt = tokensOf(junk["ops"], MembershipOp::hash, "membership-junk-unanchored")
        val unanchored = (junk["expect"] as Map<String, Any>)["rejected"] as Map<String, Any>
        val log = Membership.newLogWithCap(
            junk["usr"] as String,
            jt,
            Ed25519Engine.verifier(),
            (junk["max_ops"] as Long).toInt(),
        )
        assertFailsWith<Membership.MissingContextException> {
            log.memberAt(usr, listOf(unanchored.keys.first()), junk["now"] as Long)
        }
    }

    private class Actor(label: String) {
        val seed: ByteArray = Hex.decode(MembershipOp.hash("op-log-cap:$label").substring(HASH_PREFIX_LEN))
        val pub: ByteArray = Ed25519Group.publicKeyFromSeed(seed)
        val id: String = KeyRef.ed25519(pub).render()
        val signer = Ed25519Signer { Ed25519Engine.sign(seed, it) }
    }

    /** A canonical Ed25519 key rendering that nobody signs with: a device that is only ever added. */
    private fun keyOf(label: String): String =
        KeyRef.ed25519(Hex.decode(MembershipOp.hash(label).substring(HASH_PREFIX_LEN))).render()

    /**
     * Go enrolment `TestCapAtTheRealLimit`: genesis admits A, A admits device after device
     * citing add-A (the wide log): 10,000 anchored ops evaluate, 10,001 are refused, and
     * so is [Membership.memberAt] over them.
     */
    @Test
    fun membershipCapAtTheRealLimit() {
        val g = Actor("genesis")
        val a = Actor("A")
        val started = System.nanoTime()
        val addA = MembershipOp.sign(g.signer, g.pub, g.id, MembershipOp.Kind.ADD, a.id, "", emptyList(), T0)
        val toks = arrayListOf(addA)
        val prev = listOf(MembershipOp.hash(addA))
        for (i in 1..Membership.MAX_LOG_OPS) {
            toks.add(MembershipOp.sign(a.signer, a.pub, g.id, MembershipOp.Kind.ADD, keyOf("W$i"), "", prev, T0 + 60))
        }
        val minted = System.nanoTime()
        val now = T0 + 3600
        val v = Membership.evaluate(g.id, toks.subList(0, Membership.MAX_LOG_OPS), now)
        assertEquals(Membership.MAX_LOG_OPS, v.members.size)
        assertTrue(v.rejected.isEmpty() && v.ineffective.isEmpty())
        val evaluated = System.nanoTime()
        assertFailsWith<Membership.LogTooLargeException> { Membership.evaluate(g.id, toks, now) }
        assertFailsWith<Membership.LogTooLargeException> {
            Membership.memberAt(g.id, a.id, toks, prev, T0 + 60)
        }
        val refused = System.nanoTime()
        println(
            "membership cap at ${Membership.MAX_LOG_OPS}: mint ${ms(started, minted)} ms, " +
                "evaluate ${ms(minted, evaluated)} ms, refuse ${ms(evaluated, refused)} ms",
        )
    }

    /**
     * Go roster `TestCapAtTheRealLimit`: the founding op and the authority setting viewer
     * after viewer, each citing the founding op: 10,000 roster ops evaluate, 10,001 are
     * refused.
     */
    @Test
    fun rosterCapAtTheRealLimit() {
        val org = Actor("org")
        val p = Actor("P")
        val started = System.nanoTime()
        fun sign(d: RosterDraft) = Roster.signWith(org.signer, org.pub, d, emptyList())
        val founding =
            sign(RosterDraft(org = org.id, op = OpKind.SET, mem = p.id, role = Role.OWNER, by = org.id, iat = T0))
        val toks = arrayListOf(founding)
        val prev = listOf(Roster.opHash(founding))
        for (i in 1..Roster.MAX_LOG_OPS) {
            toks.add(
                sign(
                    RosterDraft(
                        org = org.id,
                        op = OpKind.SET,
                        mem = keyOf("V$i"),
                        role = Role.VIEWER,
                        by = org.id,
                        prev = prev,
                        iat = T0 + 60,
                    ),
                ),
            )
        }
        val minted = System.nanoTime()
        val v = Roster.evaluate(org.id, founding, toks.subList(0, Roster.MAX_LOG_OPS), null, T0 + 3600)
        assertEquals(Roster.MAX_LOG_OPS, v.accepted.size)
        assertTrue(v.ineffective.isEmpty() && v.rejected.isEmpty())
        val evaluated = System.nanoTime()
        val e = assertFailsWith<RosterException> { Roster.evaluate(org.id, founding, toks, null, T0 + 3600) }
        assertEquals(RosterException.Failure.LOG_TOO_LARGE, e.failure)
        val refused = System.nanoTime()
        println(
            "roster cap at ${Roster.MAX_LOG_OPS}: mint ${ms(started, minted)} ms, " +
                "evaluate ${ms(minted, evaluated)} ms, refuse ${ms(evaluated, refused)} ms",
        )
    }

    private fun ms(from: Long, to: Long): Long = (to - from) / 1_000_000

    private companion object {
        /** The eight cases void-which-binds-go v0.22.0 ships; only ever grows. */
        const val MIN_VECTORS = 8

        /** File order and seven shuffles, as Go's replay. */
        const val ORDERS = 8
        const val LOG_TOO_LARGE = "log_too_large"
        const val T0 = 1_790_856_000L

        /** `sha256:` */
        const val HASH_PREFIX_LEN = 7
    }
}
