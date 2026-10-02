package one.rarebit.voidwhichbinds

/**
 * The content-addressed op DAG — a port of void-which-binds-go `internal/opdag`
 * (Phase 3 G1), which the org roster evaluator (ADR-0014) is built on. It knows
 * nothing about signatures, users or authority: it holds nodes keyed by hash, each
 * citing earlier nodes by hash (its prevs), and settles which nodes are structurally
 * valid, their causal depth and their ancestors.
 *
 * A node is VALID iff every prev it cites is itself a valid node and [admit] accepts
 * each (child, prev) edge. A node that cites a hash the DAG has never been given,
 * cites an invalid node, sits on a cycle, or fails [admit] on any edge is REJECTED,
 * and so is everything that cites it, transitively. Every result is a function of the
 * set of nodes added, never of the order they were added or resolved in.
 *
 * Single-threaded working state: its memos are filled lazily and it does no locking.
 * Sets it returns are its own memos and must not be modified. Every traversal is
 * iterative (an explicit stack, never one native frame per op), so a long signed prev
 * chain cannot overflow a small mobile thread stack.
 */
internal class OpDag<T : Any>(
    private val prev: (T) -> List<String>,
    private val admit: ((child: T, parent: T) -> Boolean)?,
) {
    private val pending = HashMap<String, T>()
    private var status = HashMap<String, Int>()
    private var nodes = HashMap<String, T>()
    private var depth = HashMap<String, Int>()
    private var anc = HashMap<String, Set<String>>()

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
            anc = HashMap()
        }
        return true
    }

    /** Whether a node was added under [hash], valid or not. */
    fun has(hash: String): Boolean = pending.containsKey(hash)

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

    /** The causal depth of a valid node: 0 with no prevs, else one more than its deepest prev; 0 if not valid. */
    fun depth(h: String): Int = depth[h] ?: 0

    /**
     * The transitive prev closure of a valid node, excluding the node itself, memoised;
     * empty if not valid. Filled bottom-up with an explicit stack: a node's set is built
     * once every prev's set is.
     */
    @Suppress("ReturnCount", "LoopWithTooManyJumpStatements")
    fun ancestors(h: String): Set<String> {
        anc[h]?.let { return it }
        if (!nodes.containsKey(h)) return emptySet()
        val stack = ArrayDeque<String>()
        stack.addLast(h)
        while (stack.isNotEmpty()) {
            val x = stack.last()
            if (anc.containsKey(x)) {
                stack.removeLast()
                continue
            }
            val ps = prev(nodes.getValue(x))
            var waiting = false
            for (p in ps) {
                if (!anc.containsKey(p)) {
                    stack.addLast(p)
                    waiting = true
                }
            }
            if (waiting) continue
            val a = HashSet<String>()
            for (p in ps) {
                a.add(p)
                a.addAll(anc.getValue(p))
            }
            anc[x] = a
            stack.removeLast()
        }
        return anc.getValue(h)
    }

    /** Whether valid node [a] is a strict ancestor of valid node [b]. */
    fun precedes(a: String, b: String): Boolean = a in ancestors(b)

    private companion object {
        const val UNKNOWN = 0
        const val VALID = 1
        const val REJECTED = 2
        const val IN_PROGRESS = 3
    }
}
