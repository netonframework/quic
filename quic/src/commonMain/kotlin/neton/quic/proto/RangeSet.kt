package neton.quic.proto

// Sets of non-negative Long values stored as sorted, disjoint, non-adjacent half-open ranges
// (quinn-proto `range_set/`). Ranges are `[start, end)` as in Rust's `Range<u64>`; the `LongRange` overloads and
// views convert (`a..<b` in, `start..end - 1` out).
//
// Deviation: quinn's `RangeSet` is a `BTreeMap<u64, u64>`; Kotlin common has no sorted map, so it is a pair of
// sorted `LongArray`s with binary search: O(log n) lookups, O(n) memmove on inserts/removes that change the
// range count. For the range counts QUIC produces (ACK ranges, retransmit and assembler bookkeeping) this is
// typically faster than a tree and allocates nothing per operation.

/** Growable storage of `(start, end)` pairs. */
internal class RangeVec(initialRanges: Int) {
    var starts = LongArray(initialRanges)
    var ends = LongArray(initialRanges)
    var n = 0

    fun insertAt(i: Int, s: Long, e: Long) {
        if (n == starts.size) {
            val cap = maxOf(4, n * 2)
            starts = starts.copyOf(cap)
            ends = ends.copyOf(cap)
        }
        if (i < n) {
            starts.copyInto(starts, i + 1, i, n)
            ends.copyInto(ends, i + 1, i, n)
        }
        starts[i] = s; ends[i] = e
        n++
    }

    fun removeAt(i: Int) = removeRange(i, i + 1)

    /** Remove entries `[from, to)`. */
    fun removeRange(from: Int, to: Int) {
        if (from >= to) return
        if (to < n) {
            starts.copyInto(starts, from, to, n)
            ends.copyInto(ends, from, to, n)
        }
        n -= to - from
    }

    fun copy(): RangeVec {
        val c = RangeVec(0)
        c.starts = starts.copyOf(maxOf(n, 2)); c.ends = ends.copyOf(maxOf(n, 2)); c.n = n
        return c
    }

    fun elts(): List<Long> {
        val out = ArrayList<Long>()
        for (i in 0 until n) for (x in starts[i] until ends[i]) out.add(x)
        return out
    }

    fun ranges(): List<LongRange> = List(n) { starts[it] until ends[it] }

    fun contentEquals(o: RangeVec): Boolean {
        if (n != o.n) return false
        for (i in 0 until n) if (starts[i] != o.starts[i] || ends[i] != o.ends[i]) return false
        return true
    }

    override fun toString(): String = (0 until n).joinToString(", ", "[", "]") { "${starts[it]}..${ends[it]}" }
}

/**
 * A set of values optimized for long runs and random insert/delete/contains, kept in one small array
 * (quinn `ArrayRangeSet`, range_set/array_range_set.rs). Especially useful for ACK ranges, whose count is
 * usually very low. The algorithms are linear scans, ported as-is.
 */
class ArrayRangeSet private constructor(private val v: RangeVec) {

    constructor() : this(RangeVec(ARRAY_RANGE_SET_INLINE_CAPACITY))

    /** Number of disjoint ranges. */
    val len: Int get() = v.n
    fun isEmpty(): Boolean = v.n == 0

    /** Start of the [i]-th range (ascending order). */
    fun startAt(i: Int): Long { checkIndex(i); return v.starts[i] }

    /** Exclusive end of the [i]-th range. */
    fun endAt(i: Int): Long { checkIndex(i); return v.ends[i] }

    private fun checkIndex(i: Int) { if (i !in 0 until v.n) throw IndexOutOfBoundsException("range $i of ${v.n}") }

    /** The ranges in ascending order, as closed [LongRange]s. */
    fun ranges(): List<LongRange> = v.ranges()

    /** Every element, ascending. */
    fun elts(): List<Long> = v.elts()

    /** Visit `[start, end)` of every range in ascending order without allocating. */
    inline fun forEachRange(action: (start: Long, end: Long) -> Unit) {
        for (i in 0 until len) action(startAt(i), endAt(i))
    }

    fun contains(x: Long): Boolean {
        for (i in 0 until v.n) {
            if (v.starts[i] > x) return false
            if (x < v.ends[i]) return true
        }
        return false
    }

    fun subtract(other: ArrayRangeSet) {
        for (i in 0 until other.v.n) remove(other.v.starts[i], other.v.ends[i])
    }

    fun insertOne(x: Long): Boolean = insert(x, x + 1)

    fun insert(range: LongRange): Boolean = insert(range.first, range.last + 1)

    /** Insert `[start, end)`; returns whether the set changed (array_range_set.rs:85). */
    fun insert(start: Long, end: Long): Boolean {
        var result = false
        if (end <= start) return false
        val v = v
        var idx = 0
        while (idx != v.n) {
            if (v.starts[idx] > end) {
                // Fully before this range and not extensible: add a new range to the left.
                v.insertAt(idx, start, end)
                return true
            } else if (v.starts[idx] > start) {
                // Starts before this range but overlaps: extend the current range to the left.
                result = true
                v.starts[idx] = start
            }
            if (end <= v.ends[idx]) {
                return result // fully contained
            } else if (start <= v.ends[idx]) {
                // Extend the current range to the end of the new range, then merge the overlapping followers.
                v.ends[idx] = end
                while (idx != v.n - 1) {
                    val currEnd = v.ends[idx]
                    val nextStart = v.starts[idx + 1]
                    val nextEnd = v.ends[idx + 1]
                    if (currEnd >= nextStart) {
                        v.ends[idx] = maxOf(nextEnd, currEnd)
                        v.removeAt(idx + 1)
                    } else {
                        break
                    }
                }
                return true
            }
            idx += 1
        }
        v.insertAt(v.n, start, end)
        return true
    }

    fun remove(range: LongRange): Boolean = remove(range.first, range.last + 1)

    /** Remove `[start, end)`; returns whether the set changed (array_range_set.rs:151). */
    fun remove(start: Long, end: Long): Boolean {
        var result = false
        if (end <= start) return false
        val v = v
        var idx = 0
        while (idx != v.n) {
            val rs = v.starts[idx]
            val re = v.ends[idx]
            if (end <= rs) return result          // fully before this range
            if (start >= re) { idx += 1; continue } // fully after this range
            result = true
            val leftEmpty = start <= rs
            val rightEmpty = re <= end
            if (leftEmpty && rightEmpty) {
                v.removeAt(idx)
            } else if (leftEmpty) {
                v.starts[idx] = end
                idx += 1
            } else if (rightEmpty) {
                v.ends[idx] = start
                idx += 1
            } else {
                v.starts[idx] = end
                v.insertAt(idx, rs, start)
                idx += 2
            }
        }
        return result
    }

    /** Remove and return the lowest range as `[start, end - 1]`, or `null` when empty. */
    fun popMin(): LongRange? {
        if (v.n == 0) return null
        val r = v.starts[0] until v.ends[0]
        v.removeAt(0)
        return r
    }

    fun min(): Long? = if (v.n == 0) null else v.starts[0]
    fun max(): Long? = if (v.n == 0) null else v.ends[v.n - 1] - 1

    /** An independent copy. */
    fun copy(): ArrayRangeSet = ArrayRangeSet(v.copy())

    override fun equals(other: Any?): Boolean = other is ArrayRangeSet && v.contentEquals(other.v)
    override fun hashCode(): Int {
        var h = v.n
        for (i in 0 until v.n) h = (h * 31 + v.starts[i].hashCode()) * 31 + v.ends[i].hashCode()
        return h
    }

    override fun toString(): String = "ArrayRangeSet$v"

    private companion object {
        /** quinn keeps 2 ranges inline to keep `SentFrame` small (array_range_set.rs:34). */
        const val ARRAY_RANGE_SET_INLINE_CAPACITY = 2
    }
}

/**
 * A set of values optimized for long runs and random insert/delete/contains (quinn `RangeSet`,
 * range_set/btree_range_set.rs), with binary search over sorted range arrays (see the file comment).
 */
class RangeSet private constructor(private val v: RangeVec) {

    constructor() : this(RangeVec(4))

    val len: Int get() = v.n
    fun isEmpty(): Boolean = v.n == 0

    fun startAt(i: Int): Long { checkIndex(i); return v.starts[i] }
    fun endAt(i: Int): Long { checkIndex(i); return v.ends[i] }
    private fun checkIndex(i: Int) { if (i !in 0 until v.n) throw IndexOutOfBoundsException("range $i of ${v.n}") }

    fun ranges(): List<LongRange> = v.ranges()
    fun elts(): List<Long> = v.elts()

    inline fun forEachRange(action: (start: Long, end: Long) -> Unit) {
        for (i in 0 until len) action(startAt(i), endAt(i))
    }

    /** Index of the last range starting at or before [x], or -1 (quinn `pred`). */
    private fun pred(x: Long): Int {
        var lo = 0
        var hi = v.n
        while (lo < hi) {
            val mid = (lo + hi) ushr 1
            if (v.starts[mid] <= x) lo = mid + 1 else hi = mid
        }
        return lo - 1
    }

    fun contains(x: Long): Boolean {
        val i = pred(x)
        return i >= 0 && v.ends[i] > x
    }

    fun insertOne(x: Long): Boolean = insert(x, x + 1)

    fun insert(range: LongRange): Boolean = insert(range.first, range.last + 1)

    /** Insert `[start, end)`; returns whether the set changed (btree_range_set.rs:57). */
    fun insert(start: Long, end: Long): Boolean {
        if (end <= start) return false
        val v = v
        val i = pred(start)
        var s = start
        var e = end
        val lo: Int
        if (i >= 0 && v.ends[i] >= start) {
            if (v.ends[i] >= end) return false // wholly contained
            s = v.starts[i]                     // extend the overlapping predecessor
            lo = i
        } else {
            lo = i + 1
        }
        var k = i + 1
        while (k < v.n && v.starts[k] <= e) { // merge overlapping / adjacent successors
            e = maxOf(e, v.ends[k])
            k++
        }
        if (k - lo >= 1) {
            v.starts[lo] = s; v.ends[lo] = e
            v.removeRange(lo + 1, k)
        } else {
            v.insertAt(lo, s, e)
        }
        return true
    }

    fun remove(range: LongRange): Boolean = remove(range.first, range.last + 1)

    /** Remove `[start, end)`; returns whether the set changed (btree_range_set.rs:103). */
    fun remove(start: Long, end: Long): Boolean {
        if (end <= start) return false
        val v = v
        val i = pred(start)
        val a = if (i >= 0 && v.ends[i] > start) i else i + 1
        var b = i + 1
        while (b < v.n && v.starts[b] < end) b++
        if (b <= a) return false
        val leftStart = v.starts[a]
        val rightEnd = v.ends[b - 1]
        val hasLeft = leftStart < start
        val hasRight = rightEnd > end
        v.removeRange(a, b)
        var at = a
        if (hasLeft) v.insertAt(at++, leftStart, start)
        if (hasRight) v.insertAt(at, end, rightEnd)
        return true
    }

    /**
     * Add `[start, end)` to the set, returning the intersection of the previous ranges with it
     * (quinn `RangeSet::replace` and its `Replace` iterator, btree_range_set.rs:136; the iterator is drained
     * eagerly, which is what its `Drop` does anyway).
     */
    fun replace(range: LongRange): List<LongRange> = replace(range.first, range.last + 1)

    fun replace(start: Long, end: Long): List<LongRange> {
        val out = ArrayList<LongRange>(2)
        val v = v
        var rs = start
        var re = end
        val i = pred(start)
        if (i >= 0 && v.ends[i] >= start) {
            val prevStart = v.starts[i]
            val prevEnd = v.ends[i]
            v.removeAt(i)
            val replacedEnd = minOf(re, prevEnd)
            rs = minOf(rs, prevStart)
            re = maxOf(re, prevEnd)
            if (start != replacedEnd) out.add(start until replacedEnd)
        }
        if (re <= rs) return out // empty range: nothing inserted (quinn's Drop returns early)
        while (true) {
            val j = pred(rs) + 1
            if (j >= v.n) break
            val nextStart = v.starts[j]
            val nextEnd = v.ends[j]
            if (nextStart > re) break
            v.removeAt(j)
            val replacedEnd = minOf(re, nextEnd)
            re = maxOf(re, nextEnd)
            if (nextStart == replacedEnd) break
            out.add(nextStart until replacedEnd)
        }
        // Drain any remaining overlaps (quinn's `Drop` loops until the iterator ends), then insert the union.
        while (true) {
            val j = pred(rs) + 1
            if (j >= v.n) break
            val nextStart = v.starts[j]
            if (nextStart > re) break
            re = maxOf(re, v.ends[j])
            v.removeAt(j)
        }
        v.insertAt(pred(rs) + 1, rs, re)
        return out
    }

    fun add(other: RangeSet) {
        for (i in 0 until other.v.n) insert(other.v.starts[i], other.v.ends[i])
    }

    fun subtract(other: RangeSet) {
        for (i in 0 until other.v.n) remove(other.v.starts[i], other.v.ends[i])
    }

    fun min(): Long? = if (v.n == 0) null else v.starts[0]
    fun max(): Long? = if (v.n == 0) null else v.ends[v.n - 1] - 1

    fun peekMin(): LongRange? = if (v.n == 0) null else v.starts[0] until v.ends[0]

    fun popMin(): LongRange? {
        val r = peekMin() ?: return null
        v.removeAt(0)
        return r
    }

    fun copy(): RangeSet = RangeSet(v.copy())

    override fun equals(other: Any?): Boolean = other is RangeSet && v.contentEquals(other.v)
    override fun hashCode(): Int {
        var h = v.n
        for (i in 0 until v.n) h = (h * 31 + v.starts[i].hashCode()) * 31 + v.ends[i].hashCode()
        return h
    }

    override fun toString(): String = "RangeSet$v"
}
