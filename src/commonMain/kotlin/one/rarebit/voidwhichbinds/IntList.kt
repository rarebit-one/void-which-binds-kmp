package one.rarebit.voidwhichbinds

/**
 * A growable list of unboxed ints: the evaluators' per-op scratch (#122), where a
 * `List<Int>` would box every topological index it holds.
 */
internal class IntList(capacity: Int = MIN_CAPACITY) {
    private var a = IntArray(capacity)

    var size: Int = 0
        private set

    operator fun get(i: Int): Int = a[i]

    fun add(x: Int) {
        if (size == a.size) a = a.copyOf(maxOf(MIN_CAPACITY, size * 2))
        a[size++] = x
    }

    fun clear() {
        size = 0
    }

    fun isEmpty(): Boolean = size == 0

    fun isNotEmpty(): Boolean = size != 0

    inline fun forEach(action: (Int) -> Unit) {
        for (i in 0 until size) action(get(i))
    }

    private companion object {
        const val MIN_CAPACITY = 4
    }
}
