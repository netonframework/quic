package neton.quic.proto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

/** The operations common to both range sets, so range_set/tests.rs runs against each. */
private interface SetUnderTest {
    fun insert(r: LongRange): Boolean
    fun remove(r: LongRange): Boolean
    fun contains(x: Long): Boolean
    fun len(): Int
    fun isEmpty(): Boolean
    fun elts(): List<Long>
    fun min(): Long?
    fun max(): Long?
}

private class ArraySet : SetUnderTest {
    val s = ArrayRangeSet()
    override fun insert(r: LongRange) = s.insert(r)
    override fun remove(r: LongRange) = s.remove(r)
    override fun contains(x: Long) = s.contains(x)
    override fun len() = s.len
    override fun isEmpty() = s.isEmpty()
    override fun elts() = s.elts()
    override fun min() = s.min()
    override fun max() = s.max()
}

private class TreeSet : SetUnderTest {
    val s = RangeSet()
    override fun insert(r: LongRange) = s.insert(r)
    override fun remove(r: LongRange) = s.remove(r)
    override fun contains(x: Long) = s.contains(x)
    override fun len() = s.len
    override fun isEmpty() = s.isEmpty()
    override fun elts() = s.elts()
    override fun min() = s.min()
    override fun max() = s.max()
}

/** A very simple reference implementation of a range set (range_set/tests.rs `RefRangeSet`). */
private class RefRangeSet(capacity: Int) {
    val data = BooleanArray(capacity)

    fun len(): Int {
        var last = false
        var count = 0
        for (v in data) {
            if (!last && v) count++
            last = v
        }
        return count
    }

    fun isEmpty() = len() == 0

    fun insert(x: LongRange): Boolean {
        var result = false
        require(x.last + 1 <= data.size)
        for (i in x) if (!data[i.toInt()]) { result = true; data[i.toInt()] = true }
        return result
    }

    fun remove(x: LongRange): Boolean {
        var result = false
        require(x.last + 1 <= data.size)
        for (i in x) if (data[i.toInt()]) { result = true; data[i.toInt()] = false }
        return result
    }

    fun elts(): List<Long> = data.indices.filter { data[it] }.map { it.toLong() }
}

/** range_set/tests.rs `common_set_tests!`, instantiated for both implementations below. */
abstract class CommonSetTests {
    private fun newSet(): SetUnderTest = if (this is RangeSetCommonTest) TreeSet() else ArraySet()

    @Test
    fun mergeAndSplit() {
        val set = newSet()
        assertTrue(set.insert(0L..<2))
        assertTrue(set.insert(2L..<4))
        assertFalse(set.insert(1L..<3))
        assertEquals(1, set.len())
        assertEquals(listOf(0L, 1, 2, 3), set.elts())
        assertFalse(set.contains(4))
        assertTrue(set.remove(2L..<3))
        assertEquals(2, set.len())
        assertFalse(set.contains(2))
        assertEquals(listOf(0L, 1, 3), set.elts())
    }

    @Test
    fun doubleMergeExact() {
        val set = newSet()
        assertTrue(set.insert(0L..<2))
        assertTrue(set.insert(4L..<6))
        assertEquals(2, set.len())
        assertTrue(set.insert(2L..<4))
        assertEquals(1, set.len())
        assertEquals(listOf(0L, 1, 2, 3, 4, 5), set.elts())
    }

    @Test
    fun singleMergeLow() {
        val set = newSet()
        assertTrue(set.insert(0L..<2))
        assertTrue(set.insert(4L..<6))
        assertEquals(2, set.len())
        assertTrue(set.insert(2L..<3))
        assertEquals(2, set.len())
        assertEquals(listOf(0L, 1, 2, 4, 5), set.elts())
    }

    @Test
    fun singleMergeHigh() {
        val set = newSet()
        assertTrue(set.insert(0L..<2))
        assertTrue(set.insert(4L..<6))
        assertEquals(2, set.len())
        assertTrue(set.insert(3L..<4))
        assertEquals(2, set.len())
        assertEquals(listOf(0L, 1, 3, 4, 5), set.elts())
    }

    @Test
    fun doubleMergeWide() {
        val set = newSet()
        assertTrue(set.insert(0L..<2))
        assertTrue(set.insert(4L..<6))
        assertEquals(2, set.len())
        assertTrue(set.insert(1L..<5))
        assertEquals(1, set.len())
        assertEquals(listOf(0L, 1, 2, 3, 4, 5), set.elts())
    }

    @Test
    fun doubleRemove() {
        val set = newSet()
        assertTrue(set.insert(0L..<2))
        assertTrue(set.insert(4L..<6))
        assertTrue(set.remove(1L..<5))
        assertEquals(2, set.len())
        assertEquals(listOf(0L, 5), set.elts())
    }

    @Test
    fun insertMultiple() {
        val set = newSet()
        assertTrue(set.insert(0L..<1))
        assertTrue(set.insert(2L..<3))
        assertTrue(set.insert(4L..<5))
        assertTrue(set.insert(0L..<5))
        assertEquals(1, set.len())
    }

    @Test
    fun removeMultiple() {
        val set = newSet()
        assertTrue(set.insert(0L..<1))
        assertTrue(set.insert(2L..<3))
        assertTrue(set.insert(4L..<5))
        assertTrue(set.remove(0L..<5))
        assertTrue(set.isEmpty())
    }

    @Test
    fun doubleInsert() {
        val set = newSet()
        assertTrue(set.insert(0L..<2))
        assertFalse(set.insert(0L..<2))
        assertTrue(set.insert(2L..<4))
        assertFalse(set.insert(2L..<4))
        assertFalse(set.insert(0L..<4))
        assertFalse(set.insert(1L..<2))
        assertFalse(set.insert(1L..<3))
        assertFalse(set.insert(1L..<4))
        assertEquals(1, set.len())
    }

    @Test
    fun skipEmptyRanges() {
        val set = newSet()
        assertFalse(set.insert(2L..<2))
        assertEquals(0, set.len())
        assertFalse(set.insert(4L..<4))
        assertEquals(0, set.len())
        assertFalse(set.insert(0L..<0))
        assertEquals(0, set.len())
    }

    @Test
    fun compareInsertToReference() {
        val maxRange = 50L
        for (start in 0L..maxRange) for (end in 0L..maxRange) {
            val (set, reference) = createInitialSets(maxRange)
            assertEquals(reference.insert(start..<end), set.insert(start..<end), "insert($start..$end)")
            assertSetsEqual(set, reference)
        }
    }

    @Test
    fun compareRemoveToReference() {
        val maxRange = 50L
        for (start in 0L..maxRange) for (end in 0L..maxRange) {
            val (set, reference) = createInitialSets(maxRange)
            assertEquals(reference.remove(start..<end), set.remove(start..<end), "remove($start..$end)")
            assertSetsEqual(set, reference)
        }
    }

    @Test
    fun minMax() {
        val set = newSet()
        set.insert(1L..<3)
        set.insert(4L..<5)
        set.insert(6L..<10)
        assertEquals(1L, set.min())
        assertEquals(9L, set.max())
    }

    private fun createInitialSets(maxRange: Long): Pair<SetUnderTest, RefRangeSet> {
        val set = newSet()
        val reference = RefRangeSet(maxRange.toInt())
        assertSetsEqual(set, reference)
        for (r in listOf(2L..<6, 10L..<14, 14L..<14, 18L..<19, 20L..<21, 22L..<24, 26L..<30, 34L..<38, 42L..<44)) {
            assertEquals(reference.insert(r), set.insert(r))
        }
        assertSetsEqual(set, reference)
        return set to reference
    }

    private fun assertSetsEqual(set: SetUnderTest, reference: RefRangeSet) {
        assertEquals(reference.len(), set.len())
        assertEquals(reference.isEmpty(), set.isEmpty())
        assertEquals(reference.elts(), set.elts())
    }
}

/** `common_set_tests!(range_set, RangeSet)`. */
class RangeSetCommonTest : CommonSetTests()

/** `common_set_tests!(array_range_set, ArrayRangeSet)`. */
class ArrayRangeSetCommonTest : CommonSetTests()

/** range_set/btree_range_set.rs tests (only for [RangeSet]). */
class RangeSetReplaceTest {
    @Test
    fun replaceContained() {
        val set = RangeSet()
        set.insert(2L..<4)
        assertEquals(listOf(2L..<4), set.replace(1L..<5))
        assertEquals(1, set.len)
        assertEquals(1L..<5, set.peekMin())
    }

    @Test
    fun replaceContains() {
        val set = RangeSet()
        set.insert(1L..<5)
        assertEquals(listOf(2L..<4), set.replace(2L..<4))
        assertEquals(1, set.len)
        assertEquals(1L..<5, set.peekMin())
    }

    @Test
    fun replacePred() {
        val set = RangeSet()
        set.insert(2L..<4)
        assertEquals(listOf(3L..<4), set.replace(3L..<5))
        assertEquals(1, set.len)
        assertEquals(2L..<5, set.peekMin())
    }

    @Test
    fun replaceSucc() {
        val set = RangeSet()
        set.insert(2L..<4)
        assertEquals(listOf(2L..<3), set.replace(1L..<3))
        assertEquals(1, set.len)
        assertEquals(1L..<4, set.peekMin())
    }

    @Test
    fun replaceExactPred() {
        val set = RangeSet()
        set.insert(2L..<4)
        assertEquals(emptyList(), set.replace(4L..<6))
        assertEquals(1, set.len)
        assertEquals(2L..<6, set.peekMin())
    }

    @Test
    fun replaceExactSucc() {
        val set = RangeSet()
        set.insert(2L..<4)
        assertEquals(emptyList(), set.replace(0L..<2))
        assertEquals(1, set.len)
        assertEquals(0L..<4, set.peekMin())
    }

    @Test
    fun replaceEmpty() {
        val set = RangeSet()
        set.replace(3L..<3)
        set.replace(6L..<10)
        set.replace(5L..<5)
        set.replace(2L..<7)
        assertEquals(listOf(2L..<10), set.ranges())
    }
}

/** Behaviour beyond the reference tests that the connection layer relies on. */
class RangeSetExtraTest {
    @Test
    fun replaceAcrossSeveralRanges() {
        val set = RangeSet()
        set.insert(0L..<2); set.insert(4L..<6); set.insert(8L..<10); set.insert(20L..<30)
        assertEquals(listOf(1L..<2, 4L..<6, 8L..<9), set.replace(1L..<9))
        assertEquals(listOf(0L..<10, 20L..<30), set.ranges())
    }

    @Test
    fun popMinSubtractAdd() {
        for (mk in listOf({ ArrayRangeSet() })) {
            val a = mk()
            a.insert(0L..<5); a.insert(10L..<15)
            val b = ArrayRangeSet(); b.insert(3L..<12)
            a.subtract(b)
            assertEquals(listOf(0L..<3, 12L..<15), a.ranges())
            assertEquals(0L..<3, a.popMin())
            assertEquals(listOf(12L..<15), a.ranges())
            assertEquals(a, a.copy())
        }
        val t = RangeSet(); t.insert(0L..<5)
        val u = RangeSet(); u.insert(5L..<7); u.insert(9L..<10)
        t.add(u)
        assertEquals(listOf(0L..<7, 9L..<10), t.ranges())
        t.subtract(u)
        assertEquals(listOf(0L..<5), t.ranges())
        assertEquals(0L..<5, t.popMin())
        assertTrue(t.isEmpty())
        assertEquals(null, t.popMin())
    }

    @Test
    fun insertOneAndContains() {
        val a = ArrayRangeSet()
        val t = RangeSet()
        for (x in longArrayOf(5, 3, 4, 10, 6, 9)) {
            assertTrue(a.insertOne(x)); assertTrue(t.insertOne(x))
        }
        assertFalse(a.insertOne(4)); assertFalse(t.insertOne(4))
        assertEquals(listOf(3L..<7, 9L..<11), a.ranges())
        assertEquals(a.ranges(), t.ranges())
        for (x in 0L..12) assertEquals(x in 3..6 || x in 9..10, t.contains(x))
    }
}
