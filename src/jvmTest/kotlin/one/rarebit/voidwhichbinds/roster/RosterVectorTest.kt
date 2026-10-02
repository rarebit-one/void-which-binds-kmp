package one.rarebit.voidwhichbinds.roster

import one.rarebit.voidwhichbinds.Ed25519Engine
import one.rarebit.voidwhichbinds.Ed25519Signer
import one.rarebit.voidwhichbinds.KeyRef
import one.rarebit.voidwhichbinds.Membership
import one.rarebit.voidwhichbinds.MembershipOp
import one.rarebit.voidwhichbinds.crypto.Ed25519Group
import one.rarebit.voidwhichbinds.crypto.Hex
import one.rarebit.voidwhichbinds.crypto.MiniJson
import java.io.File
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The cross-implementation PARITY suite for the org roster (ADR-0014, ADR-0015):
 * void-which-binds-go's golden vectors, `testvectors/vectors/roster/` (one JSON file per
 * case, pinned by `VOID_WHICH_BINDS_GO_REF`), copied verbatim into
 * `src/jvmTest/resources/vectors/roster/` and replayed here.
 *
 * [everyGoldenVectorReplays] is Go's `replay` (roster/vectors_test.go): each file's
 * tokens are evaluated under several permutations of both the roster ops and each
 * person's ops — file order, hash order, then seeded shuffles; 16 permutations, or 4
 * when a file has more than 20 ops — and every field Go's `summarise` projects must
 * equal the file's `expect`. The `enrolment` cross-check (roster tokens fed to the
 * membership evaluator) is asserted too. The other tests port Go's property tests over
 * the same files, and re-mint every op from the files' seeds byte-for-byte.
 */
@Suppress(
    "LongParameterList",
    "CyclomaticComplexMethod",
    "NestedBlockDepth",
    "LoopWithTooManyJumpStatements",
)
class RosterVectorTest {

    private val cases: List<String> = run {
        val dir = javaClass.getResource("/vectors/roster") ?: error("vectors/roster missing from test resources")
        val names = File(dir.toURI()).listFiles { f -> f.isFile && f.name.endsWith(".json") }
            .orEmpty()
            .map { it.name.removeSuffix(".json") }
            .sorted()
        check(names.size >= MIN_VECTORS) { "expected >= $MIN_VECTORS roster vectors, found ${names.size}" }
        names
    }

    private class VOp(val label: String, val token: String, val hash: String)

    private class Vector(
        val name: String,
        val org: String,
        val founding: String,
        val now: Long,
        val keys: Map<String, Map<String, Any>>,
        val persons: Map<String, List<VOp>>,
        val ops: List<VOp>,
        val expect: Map<String, Any?>,
        val enrolmentUsr: String?,
        val enrolmentRejected: Map<String, Any>?,
    )

    @Suppress("UNCHECKED_CAST")
    private fun load(name: String): Vector {
        val raw = javaClass.getResourceAsStream("/vectors/roster/$name.json")?.readBytes()?.decodeToString()
            ?: error("vector $name.json missing")
        val o = MiniJson.parseObject(raw)
        assertEquals(name, o["name"], "vector file stem must equal its name")
        fun vops(x: Any?): List<VOp> = (x as List<Map<String, Any>>).map {
            VOp(it["label"] as String, it["token"] as String, it["hash"] as String)
        }
        val enrol = o["enrolment"] as? Map<String, Any>
        return Vector(
            name = name,
            org = o["org"] as String,
            founding = o["founding"] as String,
            now = o["now"] as Long,
            keys = o["keys"] as Map<String, Map<String, Any>>,
            persons = (o["persons"] as Map<String, Any>).mapValues { vops(it.value) },
            ops = vops(o["ops"]),
            expect = normalise(o["expect"] as Map<String, Any>),
            enrolmentUsr = enrol?.get("usr") as? String,
            enrolmentRejected = enrol?.get("rejected") as? Map<String, Any>,
        )
    }

    /** The file's `expect`, in the same shape [summarise] builds. */
    @Suppress("UNCHECKED_CAST")
    private fun normalise(e: Map<String, Any>): Map<String, Any?> {
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

    /** Go's `summarise`. */
    private fun summarise(v: RosterView): Map<String, Any?> = mapOf(
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

    private fun eval(vec: Vector, ops: List<String>, persons: Map<String, List<String>>): RosterView =
        Roster.evaluate(vec.org, vec.founding, ops, { persons[it].orEmpty() }, vec.now)

    private fun personTokens(vec: Vector): Map<String, List<String>> =
        vec.persons.mapValues { (_, l) -> l.map { it.token } }

    @Test
    fun everyGoldenVectorReplays() {
        val started = System.nanoTime()
        var evaluations = 0
        for ((i, name) in cases.withIndex()) {
            val vec = load(name)
            for (o in vec.ops) assertEquals(o.hash, Roster.opHash(o.token), "$name: op ${o.label} hash")
            for (l in vec.persons.values) {
                for (o in l) assertEquals(o.hash, MembershipOp.hash(o.token), "$name: person op ${o.label} hash")
            }
            val toks = vec.ops.map { it.token }
            val persons = personTokens(vec)
            val perms = if (vec.ops.size > 20) 4 else 16
            val rng = Random(i.toLong() + 1)
            for (p in 0 until perms) {
                val ps = persons.mapValues { it.value.toMutableList() }
                val order = when (p) {
                    0 -> toks

                    1 -> toks.sorted()

                    else -> {
                        for (l in ps.values) l.shuffle(rng)
                        toks.shuffled(rng)
                    }
                }
                val got = summarise(eval(vec, order, ps))
                evaluations++
                if (got != vec.expect) {
                    throw AssertionError("$name: permutation $p diverged\n got: $got\nwant: ${vec.expect}")
                }
            }
            if (vec.enrolmentUsr != null) {
                val v = Membership.evaluate(vec.enrolmentUsr, toks, vec.now)
                val want = vec.enrolmentRejected!!.mapValues { it.value as String }.toSortedMap()
                assertEquals<Map<String, String>>(want, v.rejected.toSortedMap(), "$name: enrolment")
                assertTrue(v.accepted.isEmpty(), "$name: enrolment accepted a roster token")
            }
        }
        val ms = (System.nanoTime() - started) / 1_000_000
        println("roster vector parity: ${cases.size}/${cases.size} vectors, $evaluations evaluations in ${ms}ms")
    }

    /**
     * Go `TestRosterMergeIsACRDTJoin`, over the golden files: across random partitions
     * of each case's state (roster ops and person ops) into replicas, [Roster.merge] is
     * commutative, associative and idempotent, and evaluating the join of every replica
     * equals evaluating the whole.
     */
    @Test
    fun mergeIsACrdtJoin() {
        val rng = Random(11)
        for (name in cases) {
            val vec = load(name)
            if (vec.ops.size > 20) continue
            val toks = vec.ops.map { it.token }
            val ptoks = personTokens(vec)
            repeat(6) {
                class Replica(val ops: List<String>, val persons: Map<String, List<String>>)
                fun split() = Replica(
                    toks.filter { rng.nextInt(2) == 0 },
                    ptoks.mapValues { (_, l) -> l.filter { rng.nextInt(2) == 0 } },
                )
                val a = split()
                val b = split()
                val c = split()
                assertEquals(Roster.merge(a.ops, b.ops), Roster.merge(b.ops, a.ops), "$name: merge must commute")
                assertEquals(
                    Roster.merge(Roster.merge(a.ops, b.ops), c.ops),
                    Roster.merge(a.ops, Roster.merge(b.ops, c.ops)),
                    "$name: merge must associate",
                )
                assertEquals(Roster.merge(a.ops, a.ops), Roster.merge(a.ops), "$name: merge must be idempotent")
                fun evalJoin(vararg rs: Replica): Map<String, Any?> {
                    val ops = Roster.merge(*rs.map { it.ops }.toTypedArray())
                    val persons = HashMap<String, List<String>>()
                    for (usr in rs.flatMap { it.persons.keys }.toSet()) {
                        persons[usr] = Membership.merge(*rs.mapNotNull { it.persons[usr] }.toTypedArray())
                    }
                    return summarise(eval(vec, ops, persons))
                }
                assertEquals(evalJoin(a, b), evalJoin(b, a), "$name: Evaluate(a ∪ b) != Evaluate(b ∪ a)")
                val full = Replica(toks, ptoks)
                assertEquals(vec.expect, evalJoin(a, b, c, full), "$name: joining every replica must reach the whole")
            }
        }
    }

    /**
     * The high-water half of Go `TestRosterRandomReroots` (and `…StalePersonHeads`),
     * over the golden files: replaying each file's ops in build order (the reverse of
     * file order, so every prefix is downward closed), adding an op never changes H(X)
     * of any op X in its closure, and never lowers any op's H(X).
     */
    @Test
    fun highWaterIsNotRetroactiveAndNeverFalls() {
        var checked = 0
        for (name in cases) {
            val vec = load(name)
            val persons = personTokens(vec)
            val toks = vec.ops.map { it.token }.reversed()
            var prev = eval(vec, toks.take(1), persons)
            for (i in 1 until toks.size) {
                val next = eval(vec, toks.take(i + 1), persons)
                val y = Roster.opHash(toks[i].trim())
                val closure = if (next.accepted.containsKey(y)) ancestorsIn(next, y) else emptySet()
                for (j in 0 until i) {
                    val h = Roster.opHash(toks[j].trim())
                    val pv = prev.highWater[h] ?: continue
                    val nv = next.highWater[h] ?: continue
                    if (h in closure) assertEquals(pv, nv, "$name: adding op $i changed H of op $j, in its closure")
                    assertTrue(nv >= pv, "$name: adding op $i lowered H of op $j from $pv to $nv")
                    checked++
                }
                prev = next
            }
        }
        assertTrue(checked > 0)
    }

    private fun ancestorsIn(v: RosterView, h: String): Set<String> {
        val out = HashSet<String>()
        val stack = ArrayDeque(v.accepted.getValue(h).prev)
        while (stack.isNotEmpty()) {
            val p = stack.removeLast()
            if (!out.add(p)) continue
            v.accepted[p]?.let { stack.addAll(it.prev) }
        }
        return out
    }

    /**
     * Re-mints every op the files hold that verifies, from the files' own test-only
     * seeds, through [Roster.cosignWith], [Roster.succSigWith] and [Roster.signWith]:
     * each verifying cosig, each re-root's succsig and the token itself must come back
     * byte-for-byte (JDK Ed25519 is deterministic).
     */
    @Test
    fun everyGoldenOpReMintsByteForByte() {
        var reminted = 0
        var cosigs = 0
        var succsigs = 0
        for (name in cases) {
            val vec = load(name)
            val seedById = vec.keys.values.mapNotNull { k ->
                val seed = (k["sign_seed"] as? String)?.takeIf { it.isNotEmpty() }?.let(Hex::decode)
                    ?: return@mapNotNull null
                KeyRef.ed25519(Ed25519Group.publicKeyFromSeed(seed)).render() to seed
            }.toMap()
            fun signer(id: String): Pair<Ed25519Signer, ByteArray>? {
                val seed = seedById[id] ?: return null
                return Ed25519Signer { Ed25519Engine.sign(seed, it) } to Ed25519Group.publicKeyFromSeed(seed)
            }
            for (vo in vec.ops) {
                val op = try {
                    Roster.verify(vo.token)
                } catch (_: RosterException) {
                    continue
                }
                val d = op.draft()
                for (c in op.cosig) {
                    if (!Roster.verifyCosig(op, c)) continue
                    val (s, pub) = signer(c.by) ?: continue
                    assertEquals(c, Roster.cosignWith(s, pub, d, c.usr, c.bprev), "$name/${vo.label}: cosig")
                    cosigs++
                }
                if (op.kind == OpKind.REROOT) {
                    signer(op.succ)?.let { (s, pub) ->
                        assertEquals(op.succSig, Roster.succSigWith(s, pub, d), "$name/${vo.label}: succsig")
                        succsigs++
                    }
                }
                val (s, pub) = signer(op.by) ?: continue
                assertEquals(vo.token, Roster.signWith(s, pub, d, op.cosig), "$name/${vo.label}: token")
                reminted++
            }
        }
        assertTrue(reminted >= MIN_VECTORS && cosigs > 0 && succsigs > 0, "re-mint coverage")
        println("roster re-mint parity: $reminted ops, $cosigs cosigs, $succsigs succsigs")
    }

    private companion object {
        /** The 101 roster vectors void-which-binds-go d6fb806 ships; only ever grows. */
        const val MIN_VECTORS = 101
    }
}
