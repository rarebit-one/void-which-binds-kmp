package one.rarebit.voidwhichbinds

import one.rarebit.voidwhichbinds.crypto.MiniJson
import java.io.File
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/**
 * The cross-implementation PARITY suite for the membership op-set (ADR-0007):
 * void-which-binds-go's golden vectors, `testvectors/vectors/membership/` (one JSON file per case,
 * pinned by `VOID_WHICH_BINDS_GO_REF`),
 * copied verbatim into `src/jvmTest/resources/vectors/membership/` and replayed
 * here byte-for-byte — exactly as `CertTest` pins the cert wire. Each file holds
 * the op TOKENS (in reverse build order, so a naive in-order replay is still
 * out-of-order delivery) and the `expect` summary Go's `Evaluate` produced. A
 * vector that passes there and fails here is a divergence in the port.
 *
 * Beyond the straight replay, the CRDT properties Go's `TestEvaluateIsOrderIndependent`
 * and `TestMergeIsACRDTJoin` assert are re-asserted over the same vectors: every
 * permutation of a vector's tokens, and every random partition merged back, must
 * evaluate to the same summary.
 */
class MembershipVectorTest {

    /**
     * Every `*.json` under `vectors/membership/`, enumerated from the test resources
     * rather than hand-listed, so a vector newly re-copied from void-which-binds-go is replayed
     * automatically instead of silently skipped. The floor guards against the
     * enumeration itself breaking (e.g. a resource-path change) and passing vacuously.
     */
    private val cases: List<String> = run {
        val dir = javaClass.getResource("/vectors/membership")
            ?: error("vectors/membership missing from test resources")
        val names = File(dir.toURI()).listFiles { f -> f.isFile && f.name.endsWith(".json") }
            .orEmpty()
            .map { it.name.removeSuffix(".json") }
            .sorted()
        check(names.size >= MIN_VECTORS) { "expected >= $MIN_VECTORS membership vectors, found ${names.size}: $names" }
        names
    }

    private class Vector(
        val name: String,
        val usr: String,
        val now: Long,
        val tokens: List<String>,
        val hashes: List<String>,
        val expect: Map<String, Any>,
    )

    @Suppress("UNCHECKED_CAST")
    private fun load(name: String): Vector {
        val raw = javaClass.getResourceAsStream("/vectors/membership/$name.json")
            ?.readBytes()?.decodeToString()
            ?: error("vector $name.json missing from test resources")
        val o = MiniJson.parseObject(raw)
        assertEquals(name, o["name"], "vector file stem must equal its name")
        val ops = o["ops"] as List<Map<String, Any>>
        return Vector(
            name = name,
            usr = o["usr"] as String,
            now = o["now"] as Long,
            tokens = ops.map { it["token"] as String },
            hashes = ops.map { it["hash"] as String },
            expect = o["expect"] as Map<String, Any>,
        )
    }

    /** The same projection Go's `summarise` makes, as plain maps/lists for equality. */
    @Suppress("UNCHECKED_CAST")
    private fun summarise(v: Membership.View): Map<String, Any> {
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

    /** Normalise the file's `expect` (nested maps parse as LinkedHashMap, lists as ArrayList). */
    @Suppress("UNCHECKED_CAST")
    private fun normalise(expect: Map<String, Any>): Map<String, Any> {
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

    @Test
    fun everyGoldenVectorReplaysByteForByte() {
        var passed = 0
        for (name in cases) {
            val vec = load(name)
            for ((i, tok) in vec.tokens.withIndex()) {
                assertEquals(vec.hashes[i], MembershipOp.hash(tok), "$name: op hash must match the file's")
            }
            val view = Membership.evaluate(vec.usr, vec.tokens, vec.now)
            assertEquals(normalise(vec.expect), summarise(view), "vector $name diverged")
            passed++
        }
        assertEquals(cases.size, passed)
        println("membership vector parity: $passed/${cases.size}")
    }

    @Test
    fun evaluateIsOrderIndependent() {
        val rng = Random(7)
        for (name in cases) {
            val vec = load(name)
            val want = normalise(vec.expect)
            repeat(40) { i ->
                val perm = vec.tokens.shuffled(rng)
                val got = summarise(Membership.evaluate(vec.usr, perm, vec.now))
                assertEquals(want, got, "$name: permutation $i diverged")
            }
        }
    }

    @Test
    fun mergeIsACrdtJoin() {
        val rng = Random(11)
        for (name in cases) {
            val vec = load(name)
            val whole = normalise(vec.expect)
            repeat(30) {
                val a = ArrayList<String>()
                val b = ArrayList<String>()
                val c = ArrayList<String>()
                for (tok in vec.tokens) {
                    // Each op lands in one to three replicas; some in none of a pair.
                    if (rng.nextInt(2) == 0) a.add(tok)
                    if (rng.nextInt(2) == 0) b.add(tok)
                    if (rng.nextInt(2) == 0 || (tok !in a && tok !in b)) c.add(tok)
                }
                // Commutative, associative, idempotent.
                assertEquals(Membership.merge(a, b), Membership.merge(b, a), "$name: merge must commute")
                assertEquals(
                    Membership.merge(Membership.merge(a, b), c),
                    Membership.merge(a, Membership.merge(b, c)),
                    "$name: merge must associate",
                )
                assertEquals(Membership.merge(a, a), Membership.merge(a), "$name: merge must be idempotent")
                // Evaluate ∘ Merge equals evaluating the whole.
                val joined = Membership.merge(a, b, c)
                assertEquals(vec.tokens.toSet(), joined.toSet(), "$name: every op must land somewhere")
                assertEquals(whole, summarise(Membership.evaluate(vec.usr, joined, vec.now)), "$name: join diverged")
            }
        }
    }

    @Test
    fun viewTokensAreTheAcceptedStateInHashOrder() {
        val vec = load("junk")
        val view = Membership.evaluate(vec.usr, vec.tokens, vec.now)
        assertTrue(view.rejected.isNotEmpty(), "junk must be rejected")
        val toks = view.tokens()
        assertEquals(view.accepted.size, toks.size)
        assertEquals(toks.map { MembershipOp.hash(it) }, toks.map { MembershipOp.hash(it) }.sorted())
        assertTrue(
            view.rejected.keys.none { h ->
                toks.any { MembershipOp.hash(it) == h }
            },
            "rejected tokens are not state",
        )
    }

    private companion object {
        /** The 21 vectors void-which-binds-go v0.9.0 + ADR-0008 ship; only ever grows. */
        const val MIN_VECTORS = 21
    }
}
