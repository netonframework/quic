package neton.quic.proto

// Primitive collections for the stream and connection-ID state.
//
// ⚖️ quinn keys its stream maps and sets by `StreamId` / `u64` in `FxHashMap` / `FxHashSet` and keeps plain
// `Vec<u64>` lists. Kotlin's `HashMap<StreamId, _>` would box the (value-class) key on every lookup and insert,
// so these small open-addressing tables over `LongArray` are used instead: lookups and updates allocate nothing.
// Keys are non-negative (stream IDs and sequence numbers are below 2^62), so -1 marks an empty slot. Collisions use
// linear probing with backward-shift deletion (no tombstones). The hash is a Fibonacci multiply, a cheap mix in the
// spirit of FxHash; quinn uses FxHash for these same keys. Iteration order is unspecified, as with hashbrown, and
// differs from it; quinn does not rely on that order. `CollectionsTest` checks both tables against `HashMap` /
// `HashSet` on random operation sequences.

private const val EMPTY_KEY = -1L
private const val FIB = -7046029254386353131L // 2^64 / golden ratio

private fun tableSizeFor(expected: Int): Int {
    var cap = 8
    while (cap < expected * 2) cap = cap shl 1
    return cap
}

/** Map from non-negative `Long` keys to values; a present key may map to `null` (quinn's `Option<_>` values). */
internal class LongMap<V : Any>(expected: Int = 4) {
    private var keys = LongArray(tableSizeFor(expected)).also { it.fill(EMPTY_KEY) }
    private var values = arrayOfNulls<Any>(keys.size)
    private var shift = 64 - keys.size.countTrailingZeroBits()

    var size: Int = 0
        private set

    private fun ideal(key: Long): Int = ((key * FIB) ushr shift).toInt()

    /** The slot holding [key], or -1 when absent. */
    fun find(key: Long): Int {
        val mask = keys.size - 1
        var i = ideal(key)
        while (true) {
            val k = keys[i]
            if (k == key) return i
            if (k == EMPTY_KEY) return -1
            i = (i + 1) and mask
        }
    }

    fun containsKey(key: Long): Boolean = find(key) >= 0

    @Suppress("UNCHECKED_CAST")
    fun valueAt(slot: Int): V? = values[slot] as V?

    fun setValueAt(slot: Int, value: V?) { values[slot] = value }

    /** The value for [key]; `null` when absent or mapped to `null` (use [find] to tell them apart). */
    fun get(key: Long): V? {
        val s = find(key)
        return if (s < 0) null else valueAt(s)
    }

    /** Insert or replace; returns whether [key] was absent. */
    fun put(key: Long, value: V?): Boolean {
        require(key >= 0)
        val s = find(key)
        if (s >= 0) {
            values[s] = value
            return false
        }
        if ((size + 1) * 2 > keys.size) grow()
        val mask = keys.size - 1
        var i = ideal(key)
        while (keys[i] != EMPTY_KEY) i = (i + 1) and mask
        keys[i] = key
        values[i] = value
        size++
        return true
    }

    /** Remove [key]; returns whether it was present. */
    fun remove(key: Long): Boolean {
        val s = find(key)
        if (s < 0) return false
        removeAt(s)
        return true
    }

    /** Remove the entry in [slot] (from [find]). Slots found earlier are invalid afterwards. */
    fun removeAt(slot: Int) {
        val mask = keys.size - 1
        var hole = slot
        var j = slot
        while (true) {
            j = (j + 1) and mask
            val k = keys[j]
            if (k == EMPTY_KEY) break
            // The entry at j may move into the hole iff the hole lies on its probe path.
            if (((j - ideal(k)) and mask) >= ((j - hole) and mask)) {
                keys[hole] = k
                values[hole] = values[j]
                hole = j
            }
        }
        keys[hole] = EMPTY_KEY
        values[hole] = null
        size--
    }

    fun clear() {
        keys.fill(EMPTY_KEY)
        values.fill(null)
        size = 0
    }

    /** Remove every entry, adding its non-null value to [out] (quinn's `HashMap::drain`, used by the driver). */
    @Suppress("UNCHECKED_CAST")
    fun drainValuesTo(out: MutableList<V>) {
        if (size == 0) return
        for (i in keys.indices) {
            if (keys[i] == EMPTY_KEY) continue
            (values[i] as V?)?.let { out.add(it) }
        }
        clear()
    }

    private fun grow() {
        val oldKeys = keys
        val oldValues = values
        keys = LongArray(oldKeys.size * 2).also { it.fill(EMPTY_KEY) }
        values = arrayOfNulls(keys.size)
        shift = 64 - keys.size.countTrailingZeroBits()
        val mask = keys.size - 1
        for (i in oldKeys.indices) {
            val k = oldKeys[i]
            if (k == EMPTY_KEY) continue
            var j = ideal(k)
            while (keys[j] != EMPTY_KEY) j = (j + 1) and mask
            keys[j] = k
            values[j] = oldValues[i]
        }
    }
}

/** Set of non-negative `Long` values (quinn's `FxHashSet<StreamId>` / `FxHashSet<u64>`). */
internal class LongHashSet(expected: Int = 4) {
    @PublishedApi internal var keys = LongArray(tableSizeFor(expected)).also { it.fill(EMPTY_KEY) }
    private var shift = 64 - keys.size.countTrailingZeroBits()

    var size: Int = 0
        private set

    fun isEmpty(): Boolean = size == 0

    private fun ideal(key: Long): Int = ((key * FIB) ushr shift).toInt()

    private fun find(key: Long): Int {
        val mask = keys.size - 1
        var i = ideal(key)
        while (true) {
            val k = keys[i]
            if (k == key) return i
            if (k == EMPTY_KEY) return -1
            i = (i + 1) and mask
        }
    }

    operator fun contains(key: Long): Boolean = find(key) >= 0

    /** Returns whether [key] was absent. */
    fun add(key: Long): Boolean {
        require(key >= 0)
        if (find(key) >= 0) return false
        if ((size + 1) * 2 > keys.size) grow()
        val mask = keys.size - 1
        var i = ideal(key)
        while (keys[i] != EMPTY_KEY) i = (i + 1) and mask
        keys[i] = key
        size++
        return true
    }

    /** Returns whether [key] was present. */
    fun remove(key: Long): Boolean {
        val slot = find(key)
        if (slot < 0) return false
        val mask = keys.size - 1
        var hole = slot
        var j = slot
        while (true) {
            j = (j + 1) and mask
            val k = keys[j]
            if (k == EMPTY_KEY) break
            if (((j - ideal(k)) and mask) >= ((j - hole) and mask)) {
                keys[hole] = k
                hole = j
            }
        }
        keys[hole] = EMPTY_KEY
        size--
        return true
    }

    /** Some element (quinn's `iter().next()`), or -1 when empty. */
    fun first(): Long {
        if (size == 0) return EMPTY_KEY
        for (k in keys) if (k != EMPTY_KEY) return k
        return EMPTY_KEY
    }

    inline fun forEach(action: (Long) -> Unit) {
        val ks = keys
        for (i in ks.indices) {
            val k = ks[i]
            if (k != -1L) action(k)
        }
    }

    /** Whether [predicate] holds for every element. */
    inline fun all(predicate: (Long) -> Boolean): Boolean {
        val ks = keys
        for (i in ks.indices) {
            val k = ks[i]
            if (k != -1L && !predicate(k)) return false
        }
        return true
    }

    fun addAll(other: LongHashSet) = other.forEach { add(it) }

    fun clear() {
        keys.fill(EMPTY_KEY)
        size = 0
    }

    fun copy(): LongHashSet = LongHashSet(size).also { it.addAll(this) }

    fun toSet(): Set<Long> = buildSet { this@LongHashSet.forEach { add(it) } }

    override fun toString(): String = toSet().toString()

    private fun grow() {
        val old = keys
        keys = LongArray(old.size * 2).also { it.fill(EMPTY_KEY) }
        shift = 64 - keys.size.countTrailingZeroBits()
        val mask = keys.size - 1
        for (k in old) {
            if (k == EMPTY_KEY) continue
            var j = ideal(k)
            while (keys[j] != EMPTY_KEY) j = (j + 1) and mask
            keys[j] = k
        }
    }
}

/** Growable list of `Long` (quinn's `Vec<u64>` / `Vec<StreamId>`). */
internal class LongList(capacity: Int = 4) {
    private var a = LongArray(capacity)

    var size: Int = 0
        private set

    fun isEmpty(): Boolean = size == 0

    operator fun get(i: Int): Long {
        if (i !in 0 until size) throw IndexOutOfBoundsException("index $i, size $size")
        return a[i]
    }

    fun add(x: Long) {
        if (size == a.size) a = a.copyOf(maxOf(4, size * 2))
        a[size++] = x
    }

    /** Remove and return the last element (quinn `Vec::pop`); the list must not be empty. */
    fun removeLast(): Long {
        if (size == 0) throw NoSuchElementException()
        return a[--size]
    }

    fun addAll(other: LongList) {
        for (i in 0 until other.size) add(other.a[i])
    }

    fun clear() { size = 0 }

    fun copy(): LongList = LongList(maxOf(size, 1)).also { it.addAll(this) }

    fun toList(): List<Long> = List(size) { a[it] }

    override fun toString(): String = toList().toString()
}
