package one.rarebit.voidwhichbinds

/**
 * The content-addressed op DAG — a port of void-which-binds-go `internal/opdag`
 * (Phase 3 G1, compact since #122), which the membership evaluator (ADR-0007) and the
 * org roster evaluator (ADR-0014) are built on. It knows nothing about signatures,
 * users or authority: it holds nodes keyed by hash, each citing earlier nodes by hash
 * (its prevs), and settles which nodes are structurally valid, their causal depth and
 * their ancestors.
 *
 * A node is VALID iff every prev it cites is itself a valid node and [admit] accepts
 * each (child, prev) edge. A node that cites a hash the DAG has never been given,
 * cites an invalid node, sits on a cycle, or fails [admit] on any edge is REJECTED,
 * and so is everything that cites it, transitively. Every result is a function of the
 * set of nodes added, never of the order they were added or resolved in.
 *
 * **Compact reachability (#122).** Reachability is held as one bitset per valid node
 * over a topological index: the valid nodes are numbered in (depth, hash) order, so
 * every ancestor of node i has a smaller number, and node i's ancestor set is a bitset
 * of at most i bits, trimmed to its highest ancestor. A linear
 * history of n nodes costs about n²/16 bytes (≈ 6 MiB at the 10,000-op cap of
 * ADR-0007/ADR-0014), a wide one about n words; [precedes] is one bit test, and
 * [ancestors] and [closure] hand out an [OpSet] that shares the stored bits instead of
 * copying a set. The index and every bitset are built in one pass, in index order,
 * when first needed.
 *
 * Single-threaded working state: its memos are filled lazily and it does no locking.
 * Maps and sets it returns are its own memos and must not be modified. Every traversal
 * is iterative (an explicit stack, never one native frame per op), so a long signed
 * prev chain cannot overflow a small mobile thread stack.
 */
@Suppress("TooManyFunctions")
internal class OpDag<T : Any>(
    private val prev: (T) -> List<String>,
    private val admit: ((child: T, parent: T) -> Boolean)?,
) {
    private val pending = HashMap<String, T>()
    private var status = HashMap<String, Int>()
    private var nodes = HashMap<String, T>()
    private var depth = HashMap<String, Int>()
    private var ix: Index? = null // null until first needed; dropped by add

    /** The topological numbering of the valid nodes and their ancestor bitsets. */
    private class Index(
        val pos: HashMap<String, Int>, // valid node -> its number
        val hash: Array<String>, // number -> node
        val anc: Array<LongArray>, // number -> ancestor bitset, trimmed (all bits < number)
        val all: LongArray, // every valid node
    )

    /**
     * Offer [node] under [hash]. The first node added under a hash wins: a later add
     * of the same hash is a duplicate, is ignored, and reports false. Adding a new node
     * drops every resolution made so far.
     */
    fun add(hash: String, node: T): Boolean {
        if (pending.containsKey(hash)) return false
        pending[hash] = node
        if (status.isNotEmpty()) {
            status = HashMap()
            nodes = HashMap()
            depth = HashMap()
        }
        ix = null
        return true
    }

    /** Whether a node was added under [hash], valid or not. */
    fun has(hash: String): Boolean = pending.containsKey(hash)

    /** Every node added, valid or not, by hash. The DAG's own map: do not modify. */
    fun pending(): Map<String, T> = pending

    /** Resolve every added node; the hashes of those rejected, sorted. */
    fun resolveAll(): List<String> {
        val out = ArrayList<String>()
        for (h in pending.keys.toList()) {
            if (!resolve(h)) out.add(h)
        }
        out.sort()
        return out
    }

    /** One node being resolved: its next prev to examine and its depth so far. */
    private class Pending<T>(val hash: String, val node: T, val prevs: List<String>) {
        var next = 0
        var depth = 0
    }

    /**
     * Whether the node at [h] is valid, settling its prevs first. An unknown hash is not
     * valid. A depth-first walk with an explicit stack, deciding exactly as the recursive
     * definition does: prevs in order; a prev that is missing, rejected or on the walk
     * (a cycle) rejects the node, and the rejection propagates to every node waiting on it.
     */
    @Suppress("ReturnCount", "CyclomaticComplexMethod", "NestedBlockDepth", "LoopWithTooManyJumpStatements")
    fun resolve(h: String): Boolean {
        when (status[h] ?: UNKNOWN) {
            VALID -> return true
            REJECTED -> return false
            IN_PROGRESS -> return false // a cycle is impossible for honest content hashes; it rejects the cycle
        }
        val root = pending[h] ?: return false
        val stack = ArrayDeque<Pending<T>>()
        status[h] = IN_PROGRESS
        stack.addLast(Pending(h, root, prev(root)))
        // The verdict of the node just finished, owed to the node now on top of the stack.
        var owed: Boolean? = null
        while (stack.isNotEmpty()) {
            val f = stack.last()
            var ok = true
            if (owed != null) {
                // f.prevs[f.next] was just resolved.
                ok = owed && edge(f, f.prevs[f.next])
                owed = null
                if (ok) f.next++
            }
            var pushed = false
            while (ok && f.next < f.prevs.size) {
                val p = f.prevs[f.next]
                when (status[p] ?: UNKNOWN) {
                    VALID -> if (edge(f, p)) f.next++ else ok = false

                    REJECTED, IN_PROGRESS -> ok = false

                    else -> {
                        val n = pending[p]
                        if (n == null) {
                            ok = false
                        } else {
                            status[p] = IN_PROGRESS
                            stack.addLast(Pending(p, n, prev(n)))
                            pushed = true
                            break
                        }
                    }
                }
            }
            if (pushed) continue
            stack.removeLast()
            if (ok) {
                status[f.hash] = VALID
                nodes[f.hash] = f.node
                depth[f.hash] = f.depth
            } else {
                status[f.hash] = REJECTED
            }
            owed = ok
        }
        return status[h] == VALID
    }

    /** The edge from [f] to its valid prev [p]: [admit] must accept it; it raises f's depth. */
    private fun edge(f: Pending<T>, p: String): Boolean {
        if (admit != null && !admit.invoke(f.node, nodes.getValue(p))) return false
        val dp = depth.getValue(p) + 1
        if (dp > f.depth) f.depth = dp
        return true
    }

    /** The resolved valid nodes by hash (call after [resolveAll]). */
    fun valid(): Map<String, T> = nodes

    /** The valid node at [h], or null. */
    fun node(h: String): T? = nodes[h]

    /** The causal depth of a valid node: 0 with no prevs, else one more than its deepest prev; 0 if not valid. */
    fun depth(h: String): Int = depth[h] ?: 0

    /** Build (once) the topological numbering and every ancestor bitset, resolving every node first. */
    private fun index(): Index {
        ix?.let { return it }
        resolveAll()
        val hs = nodes.keys.toTypedArray()
        hs.sortWith { a, b ->
            val da = depth.getValue(a)
            val db = depth.getValue(b)
            if (da != db) da.compareTo(db) else a.compareTo(b)
        }
        val pos = HashMap<String, Int>(hs.size * 2)
        for ((i, h) in hs.withIndex()) pos[h] = i
        // Node i's set ends at its highest prev, and a prev's own set ends below it, so
        // the length is known before the copy. (Go keeps them in one arena; Kotlin has
        // no slices, so each is its own array of the same length.)
        val anc = arrayOfNulls<LongArray>(hs.size)
        for ((i, h) in hs.withIndex()) {
            val ps = prev(nodes.getValue(h))
            var top = -1
            for (p in ps) top = maxOf(top, pos.getValue(p))
            val set = if (top < 0) EMPTY else LongArray(top / WORD + 1)
            for (p in ps) {
                val j = pos.getValue(p)
                set[j / WORD] = set[j / WORD] or (1L shl (j % WORD))
                val a = anc[j]!!
                for (w in a.indices) set[w] = set[w] or a[w]
            }
            anc[i] = set
        }
        val all = LongArray((hs.size + WORD - 1) / WORD)
        for (i in hs.indices) all[i / WORD] = all[i / WORD] or (1L shl (i % WORD))
        @Suppress("UNCHECKED_CAST")
        val built = Index(pos, hs, anc as Array<LongArray>, all)
        ix = built
        return built
    }

    /**
     * The number of 64-bit words the ancestor bitsets hold: the reachability memory, at
     * most about n²/128 words (n²/16 bytes) for n valid nodes.
     */
    fun footprint(): Int = index().anc.sumOf { it.size }

    /**
     * A set of valid nodes of one DAG, held as a bitset over the DAG's topological index.
     * Read-only, it shares storage with the DAG, and is meaningful until the DAG's next
     * [add].
     */
    class OpSet internal constructor(
        private val pos: Map<String, Int>?,
        private val hashes: Array<String>?,
        internal val bits: LongArray,
    ) {
        /** Whether [h] is in the set. */
        operator fun contains(h: String): Boolean {
            val i = pos?.get(h) ?: return false
            return hasIndex(i)
        }

        /** The number of nodes in the set. */
        val size: Int get() = bits.sumOf { it.countOneBits() }

        /** Whether the node numbered [i] is in the set. */
        fun hasIndex(i: Int): Boolean = i >= 0 && i / WORD < bits.size && (bits[i / WORD] ushr (i % WORD)) and 1L != 0L

        /** One more than the highest topological index the set can hold. */
        val bound: Int get() = bits.size * WORD

        /** Each member's topological index, ascending. */
        inline fun forEachIndex(action: (Int) -> Unit) {
            val b = bits
            for (w in b.indices) {
                var x = b[w]
                while (x != 0L) {
                    val t = x.countTrailingZeroBits()
                    x = x and (x - 1)
                    action(w * WORD + t)
                }
            }
        }

        /** The set's nodes in topological-index order: (depth, hash). */
        fun all(): List<String> {
            val out = ArrayList<String>()
            forEachIndex { out.add(hashes!![it]) }
            return out
        }

        /** The set's nodes in hash order. */
        fun sorted(): List<String> = all().sorted()
    }

    /** The transitive prev closure of a valid node, excluding the node itself; empty if not valid. */
    fun ancestors(h: String): OpSet {
        val x = index()
        val i = x.pos[h] ?: return OpSet(x.pos, x.hash, EMPTY)
        return OpSet(x.pos, x.hash, x.anc[i])
    }

    /** The set of the given valid nodes; a hash that is not valid is left out. */
    fun setOf(hs: Collection<String>): OpSet {
        val x = index()
        val b = LongArray((x.hash.size + WORD - 1) / WORD)
        for (h in hs) {
            val i = x.pos[h] ?: continue
            b[i / WORD] = b[i / WORD] or (1L shl (i % WORD))
        }
        return OpSet(x.pos, x.hash, b)
    }

    /** The set of every valid node. */
    fun all(): OpSet {
        val x = index()
        return OpSet(x.pos, x.hash, x.all)
    }

    /**
     * The causal past a new node citing [heads] would have: the heads themselves plus
     * all their ancestors. Null if a head is not valid. No heads is the empty closure.
     */
    fun closure(heads: List<String>): OpSet? {
        val x = index()
        var n = 0
        for (h in heads) {
            val i = x.pos[h] ?: return null
            n = maxOf(n, i / WORD + 1)
        }
        val b = LongArray(n)
        for (h in heads) {
            val i = x.pos.getValue(h)
            b[i / WORD] = b[i / WORD] or (1L shl (i % WORD))
            val a = x.anc[i]
            for (w in a.indices) b[w] = b[w] or a[w]
        }
        return OpSet(x.pos, x.hash, b)
    }

    /** The number of valid nodes: the topological index runs 0 until size(). */
    fun size(): Int = index().hash.size

    /** The topological index of valid node [h], in (depth, hash) order; -1 if not valid. */
    fun index(h: String): Int = index().pos[h] ?: -1

    /** The valid node numbered [i]. */
    fun hash(i: Int): String = index().hash[i]

    /** [precedes] by topological index. */
    fun precedesIndex(i: Int, j: Int): Boolean {
        val s = index().anc[j]
        return i / WORD < s.size && (s[i / WORD] ushr (i % WORD)) and 1L != 0L
    }

    /**
     * The causal frontier of the candidates kept: candidate k (0 ≤ k < [n]) is the valid
     * node numbered at(k), ascending in k, and the result is every kept candidate that
     * precedes no other kept candidate, newest first. It walks the candidates newest
     * first, keeping the union of the ancestors of the frontier found so far: a candidate
     * in that union is covered, and [keep] is never asked about it.
     */
    @Suppress("LoopWithTooManyJumpStatements")
    fun frontier(n: Int, at: (Int) -> Int, keep: (Int) -> Boolean): List<Int> {
        val x = index()
        val out = ArrayList<Int>()
        var seen = EMPTY
        for (k in n - 1 downTo 0) {
            val i = at(k)
            if (i / WORD < seen.size && (seen[i / WORD] ushr (i % WORD)) and 1L != 0L) continue
            if (!keep(k)) continue
            out.add(k)
            val a = x.anc[i]
            if (a.size > seen.size) seen = seen.copyOf(a.size)
            for (w in a.indices) seen[w] = seen[w] or a[w]
        }
        return out
    }

    /** Whether valid node [a] is a strict ancestor of valid node [b]. */
    @Suppress("ReturnCount")
    fun precedes(a: String, b: String): Boolean {
        val x = index()
        val j = x.pos[b] ?: return false
        val i = x.pos[a] ?: return false
        val s = x.anc[j]
        return i / WORD < s.size && (s[i / WORD] ushr (i % WORD)) and 1L != 0L
    }

    /** The frontier of the valid DAG, the valid nodes no valid node cites, sorted. */
    fun heads(): List<String> {
        val cited = HashSet<String>()
        for (n in nodes.values) cited.addAll(prev(n))
        return nodes.keys.filter { it !in cited }.sorted()
    }

    internal companion object {
        const val WORD = 64
        private val EMPTY = LongArray(0)
        const val UNKNOWN = 0
        const val VALID = 1
        const val REJECTED = 2
        const val IN_PROGRESS = 3
    }
}
