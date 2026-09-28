package neton.quic.proto

import neton.io.bytes.Bytes
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue

private fun b(s: String): Bytes = Bytes.wrap(s.encodeToByteArray())

private fun Assembler.ins(offset: Long, s: String, allocationSize: Int) =
    assertTrue(insert(offset, b(s), allocationSize), "insert($offset, $s) rejected")

// assembler.rs tests
class AssemblerTest {

    private fun next(x: Assembler, size: Int): String? = x.read(size, true)?.bytes?.decodeToString()

    private fun nextUnordered(x: Assembler): Chunk = x.read(Int.MAX_VALUE, false)!!

    @Test
    fun assembleOrdered() {
        val x = Assembler()
        assertNull(next(x, 32))
        x.ins(0, "123", 3)
        assertEquals("1", next(x, 1))
        assertEquals("23", next(x, 3))
        x.ins(3, "456", 3)
        assertEquals("456", next(x, 32))
        x.ins(6, "789", 3)
        x.ins(9, "10", 2)
        assertEquals("789", next(x, 32))
        assertEquals("10", next(x, 32))
        assertNull(next(x, 32))
    }

    @Test
    fun assembleUnordered() {
        val x = Assembler()
        assertTrue(x.ensureOrdering(false))
        x.ins(3, "456", 3)
        assertNull(next(x, 32))
        x.ins(0, "123", 3)
        assertEquals("123", next(x, 32))
        assertEquals("456", next(x, 32))
        assertNull(next(x, 32))
    }

    @Test
    fun assembleDuplicate() {
        val x = Assembler()
        x.ins(0, "123", 3)
        x.ins(0, "123", 3)
        assertEquals("123", next(x, 32))
        assertNull(next(x, 32))
    }

    @Test
    fun assembleDuplicateCompact() {
        val x = Assembler()
        x.ins(0, "123", 3)
        x.ins(0, "123", 3)
        x.defragment()
        assertEquals("123", next(x, 32))
        assertNull(next(x, 32))
    }

    @Test
    fun assembleContained() {
        val x = Assembler()
        x.ins(0, "12345", 5)
        x.ins(1, "234", 3)
        assertEquals("12345", next(x, 32))
        assertNull(next(x, 32))
    }

    @Test
    fun assembleContainedCompact() {
        val x = Assembler()
        x.ins(0, "12345", 5)
        x.ins(1, "234", 3)
        x.defragment()
        assertEquals("12345", next(x, 32))
        assertNull(next(x, 32))
    }

    @Test
    fun assembleContains() {
        val x = Assembler()
        x.ins(1, "234", 3)
        x.ins(0, "12345", 5)
        assertEquals("12345", next(x, 32))
        assertNull(next(x, 32))
    }

    @Test
    fun assembleContainsCompact() {
        val x = Assembler()
        x.ins(1, "234", 3)
        x.ins(0, "12345", 5)
        x.defragment()
        assertEquals("12345", next(x, 32))
        assertNull(next(x, 32))
    }

    @Test
    fun assembleOverlapping() {
        val x = Assembler()
        x.ins(0, "123", 3)
        x.ins(1, "234", 3)
        assertEquals("123", next(x, 32))
        assertEquals("4", next(x, 32))
        assertNull(next(x, 32))
    }

    @Test
    fun assembleOverlappingCompact() {
        val x = Assembler()
        x.ins(0, "123", 4)
        x.ins(1, "234", 4)
        x.defragment()
        assertEquals("1234", next(x, 32))
        assertNull(next(x, 32))
    }

    @Test
    fun assembleComplex() {
        val x = Assembler()
        x.ins(0, "1", 1)
        x.ins(2, "3", 1)
        x.ins(4, "5", 1)
        x.ins(0, "123456", 6)
        assertEquals("123456", next(x, 32))
        assertNull(next(x, 32))
    }

    @Test
    fun assembleComplexCompact() {
        val x = Assembler()
        x.ins(0, "1", 1)
        x.ins(2, "3", 1)
        x.ins(4, "5", 1)
        x.ins(0, "123456", 6)
        x.defragment()
        assertEquals("123456", next(x, 32))
        assertNull(next(x, 32))
    }

    @Test
    fun assembleOld() {
        val x = Assembler()
        x.ins(0, "1234", 4)
        assertEquals("1234", next(x, 32))
        x.ins(0, "1234", 4)
        assertNull(next(x, 32))
    }

    @Test
    fun compact() {
        val x = Assembler()
        x.ins(0, "abc", 4)
        x.ins(3, "def", 4)
        x.ins(9, "jkl", 4)
        x.ins(12, "mno", 4)
        x.defragment()
        assertEquals(Chunk(0, b("abcdef")), nextUnordered(x))
        assertEquals(Chunk(9, b("jklmno")), nextUnordered(x))
    }

    @Test
    fun defragWithMissingPrefix() {
        val x = Assembler()
        x.ins(3, "def", 3)
        x.defragment()
        assertEquals(Chunk(3, b("def")), nextUnordered(x))
    }

    @Test
    fun defragReadChunk() {
        val x = Assembler()
        x.ins(3, "def", 4)
        x.ins(0, "abc", 4)
        x.ins(7, "hij", 4)
        x.ins(11, "lmn", 4)
        x.defragment()
        assertEquals("abcdef", x.read(Int.MAX_VALUE, true)?.bytes?.decodeToString())
        x.ins(5, "fghijklmn", 9)
        assertEquals("ghijklmn", x.read(Int.MAX_VALUE, true)?.bytes?.decodeToString())
        x.ins(13, "nopq", 4)
        assertEquals("opq", x.read(Int.MAX_VALUE, true)?.bytes?.decodeToString())
        x.ins(15, "pqrs", 4)
        assertEquals("rs", x.read(Int.MAX_VALUE, true)?.bytes?.decodeToString())
        assertNull(x.read(Int.MAX_VALUE, true))
    }

    @Test
    fun unorderedHappyPath() {
        val x = Assembler()
        assertTrue(x.ensureOrdering(false))
        x.ins(0, "abc", 3)
        assertEquals(Chunk(0, b("abc")), nextUnordered(x))
        assertNull(x.read(Int.MAX_VALUE, false))
        x.ins(3, "def", 3)
        assertEquals(Chunk(3, b("def")), nextUnordered(x))
        assertNull(x.read(Int.MAX_VALUE, false))
    }

    @Test
    fun unorderedDedup() {
        val x = Assembler()
        assertTrue(x.ensureOrdering(false))
        x.ins(3, "def", 3)
        assertEquals(Chunk(3, b("def")), nextUnordered(x))
        assertNull(x.read(Int.MAX_VALUE, false))
        x.ins(0, "a", 1)
        x.ins(0, "abcdefghi", 9)
        x.ins(0, "abcd", 4)
        assertEquals(Chunk(0, b("a")), nextUnordered(x))
        assertEquals(Chunk(1, b("bc")), nextUnordered(x))
        assertEquals(Chunk(6, b("ghi")), nextUnordered(x))
        assertNull(x.read(Int.MAX_VALUE, false))
        x.ins(8, "ijkl", 4)
        assertEquals(Chunk(9, b("jkl")), nextUnordered(x))
        assertNull(x.read(Int.MAX_VALUE, false))
        x.ins(12, "mno", 3)
        assertEquals(Chunk(12, b("mno")), nextUnordered(x))
        assertNull(x.read(Int.MAX_VALUE, false))
        x.ins(2, "cde", 3)
        assertNull(x.read(Int.MAX_VALUE, false))
    }

    @Test
    fun chunksDedup() {
        val x = Assembler()
        x.ins(3, "def", 3)
        assertNull(x.read(Int.MAX_VALUE, true))
        x.ins(0, "a", 1)
        x.ins(1, "bcdefghi", 9)
        x.ins(0, "abcd", 4)
        assertEquals(Chunk(0, b("abcd")), x.read(Int.MAX_VALUE, true))
        assertEquals(Chunk(4, b("efghi")), x.read(Int.MAX_VALUE, true))
        assertNull(x.read(Int.MAX_VALUE, true))
        x.ins(8, "ijkl", 4)
        assertEquals(Chunk(9, b("jkl")), x.read(Int.MAX_VALUE, true))
        assertNull(x.read(Int.MAX_VALUE, true))
        x.ins(12, "mno", 3)
        assertEquals(Chunk(12, b("mno")), x.read(Int.MAX_VALUE, true))
        assertNull(x.read(Int.MAX_VALUE, true))
        x.ins(2, "cde", 3)
        assertNull(x.read(Int.MAX_VALUE, true))
    }

    @Test
    fun orderedEagerDiscard() {
        val x = Assembler()
        x.ins(0, "abc", 3)
        assertEquals(1, x.data.size)
        assertEquals(Chunk(0, b("abc")), x.read(Int.MAX_VALUE, true))
        x.ins(0, "ab", 2)
        assertEquals(0, x.data.size)
        x.ins(2, "cd", 2)
        // quinn compares `Buffer`s by (offset, len): Buffer::new(3, b"d", 2)
        assertEquals(3L, x.data.offset(0))
        assertEquals(1, x.data.len(0))
        assertEquals("d", x.data.bytes(0).decodeToString())
    }

    @Test
    fun orderedInsertUnorderedRead() {
        val x = Assembler()
        x.ins(0, "abc", 3)
        x.ins(0, "abc", 3)
        assertTrue(x.ensureOrdering(false))
        assertEquals(Chunk(0, b("abc")), x.read(3, false))
        assertNull(x.read(3, false))
    }

    @Test
    fun orderedLosslessStreamIsNotRejected() {
        val frameLen = 32
        val x = Assembler()
        val data = Bytes.wrap(ByteArray(frameLen))
        var offset = 0L
        while (offset < 2L * Assembler.COMPACT_THRESHOLD * frameLen) {
            assertTrue(x.insert(offset, data, frameLen), "contiguous lossless data must not be rejected")
            offset += frameLen
        }
    }

    @Test
    fun defragRespectsMaxChunksAtRoundingBoundary() {
        val x = Assembler()
        val data = Bytes.wrap(ByteArray(Assembler.MIN_RETAINED_CHUNK_SIZE))
        var offset = 0L
        // Fill with minimum sized chunks.
        repeat(Assembler.MAX_CHUNKS) {
            assertTrue(x.insert(offset, data, data.size))
            offset += data.size
        }
        // Add 1 extra chunk, defragment must coalesce the previous chunks to stay within MAX_CHUNKS
        x.ins(offset, "x", 1)
        x.defragment()
        assertTrue(x.data.size <= Assembler.MAX_CHUNKS)
    }

    @Test
    fun boundedChunksUnderLowOverAllocation() {
        // Gapped frames whose `allocation_size` equals their length hold `over_allocation` at zero, so that trigger
        // never fires.
        val x = Assembler()
        // Withhold offset 0 so an ordered reader can never drain anything.
        var offset = 1L
        var result = true
        for (i in 0 until Assembler.MAX_CHUNKS * 8) {
            result = x.insert(offset, b("gap"), 3)
            if (!result) break
            offset += 3 + 1 // 3 data bytes, 1 byte gap
        }
        assertFalse(result, "expected TooManyChunks")
        assertTrue(x.data.size <= Assembler.COMPACT_THRESHOLD + 1, "chunk count ${x.data.size} exceeded the bound")
    }

    @Test
    fun boundedChunksUnorderedOverlapFlood() {
        // Overlapping frames whose tail is already received: the dedup loop pushes the fresh head byte and leaves
        // `bytes` empty, and `end` never rises, so the flood costs the peer no flow control.
        val x = Assembler()
        assertTrue(x.ensureOrdering(false))
        val top = 1_000_000L
        x.ins(top, "ab", 2)
        for (k in 0 until 4L * Assembler.MAX_CHUNKS) {
            x.ins(top - k - 1, "ab", 2)
            assertTrue(x.data.size <= Assembler.COMPACT_THRESHOLD + 1, "chunk count ${x.data.size} exceeded the bound at k=$k")
        }
    }

    @Test
    fun boundedChunksDuplicateFlood() {
        // Duplicates against a stream already at the cap. Ordered mode does not dedup, so each one pushes a chunk;
        // they must not be rejected, or compact every frame.
        val x = Assembler()
        // Withhold offset 0 so nothing can be drained.
        for (i in 0 until Assembler.MAX_CHUNKS.toLong()) x.ins(1 + i * 4, "abc", 3)
        var maxLen = x.data.size
        repeat(3 * Assembler.MAX_CHUNKS) {
            assertTrue(x.insert(1, b("abc"), 3), "duplicate flood must not be rejected")
            maxLen = maxOf(maxLen, x.data.size)
            assertTrue(x.data.size <= Assembler.COMPACT_THRESHOLD + 1, "chunk count ${x.data.size} exceeded the bound")
        }
        // Compacting on every frame would pin the count at `MAX_CHUNKS`.
        assertTrue(maxLen > Assembler.MAX_CHUNKS, "buffer compacted on every frame (max observed len $maxLen)")
    }

    // --- Beyond the reference: the heap against a reference model, and end-to-end reassembly properties ---

    /**
     * [ChunkHeap] against a sorted-list model: with distinct (offset, length) keys the order is fully determined, so
     * pops, root updates and the in-place sort must agree with plain sorting by quinn's `Ord for Buffer`.
     */
    @Test
    fun chunkHeapMatchesReferenceModel() {
        val rnd = Random(7)
        // quinn's `Ord for Buffer`, greatest first: the lowest offset, then the longest
        val order = compareBy<Triple<Long, Int, Int>> { it.first }.thenByDescending { it.second }
        repeat(200) { round ->
            val heap = ChunkHeap(1)
            val model = ArrayList<Triple<Long, Int, Int>>() // (offset, len, tag)
            var tag = 0
            val base = Bytes.wrap(ByteArray(4096))
            repeat(300) {
                when (rnd.nextInt(10)) {
                    in 0..4 -> {
                        val off = rnd.nextLong(0, 64)
                        val len = rnd.nextInt(1, 64)
                        if (model.none { it.first == off && it.second == len }) {
                            heap.push(off, base, 0, len, tag, false)
                            model.add(Triple(off, len, tag++))
                        }
                    }
                    in 5..7 -> if (model.isNotEmpty()) {
                        val top = model.sortedWith(order).first()
                        assertEquals(top, Triple(heap.offset(0), heap.len(0), heap.allocationSize(0)), "round $round")
                        heap.pop()
                        model.remove(top)
                    }
                    else -> if (model.isNotEmpty()) {
                        val top = model.sortedWith(order).first()
                        assertEquals(top, Triple(heap.offset(0), heap.len(0), heap.allocationSize(0)))
                        if (top.second > 1) {
                            val k = rnd.nextInt(1, top.second)
                            val moved = Triple(top.first + k, top.second - k, top.third)
                            if (model.none { it.first == moved.first && it.second == moved.second }) {
                                heap.advance(0, k)
                                heap.siftDownRoot()
                                model[model.indexOf(top)] = moved
                            }
                        }
                    }
                }
                assertEquals(model.size, heap.size)
            }
            heap.sortAscending()
            val sorted = List(heap.size) { Triple(heap.offset(it), heap.len(it), heap.allocationSize(it)) }
            assertEquals(model.sortedWith(order).reversed(), sorted)
        }
    }

    /**
     * Ordered reassembly of a random stream from random overlapping, duplicated, reordered frames with random
     * allocation sizes (driving the defragmentation paths): the reads must reproduce the stream exactly.
     */
    @Test
    fun orderedReassemblyMatchesStream() {
        val rnd = Random(11)
        repeat(100) { round ->
            val content = rnd.nextBytes(rnd.nextInt(1, 5000))
            val x = Assembler()
            val out = ArrayList<Byte>()
            val frames = ArrayList<Pair<Int, Int>>()
            var pos = 0
            while (pos < content.size) {
                val len = minOf(rnd.nextInt(1, 300), content.size - pos)
                frames.add(pos to len)
                // sometimes an overlapping or duplicate frame
                if (rnd.nextInt(4) == 0) {
                    val s = maxOf(0, pos - rnd.nextInt(0, 100))
                    frames.add(s to minOf(content.size - s, len + rnd.nextInt(0, 200)))
                }
                pos += len
            }
            frames.shuffle(rnd)
            for ((s, len) in frames) {
                val packet = content.copyOfRange(0, content.size) // each frame is a slice of its own "packet"
                val data = Bytes.wrap(packet).slice(s, s + len)
                assertTrue(x.insert(s.toLong(), data, len + rnd.nextInt(0, 1500)))
                if (rnd.nextBoolean()) {
                    while (true) {
                        val c = x.read(rnd.nextInt(1, 500), true) ?: break
                        assertEquals(out.size.toLong(), c.offset)
                        for (i in 0 until c.bytes.size) out.add(c.bytes[i])
                    }
                }
            }
            while (true) {
                val c = x.read(Int.MAX_VALUE, true) ?: break
                assertEquals(out.size.toLong(), c.offset)
                for (i in 0 until c.bytes.size) out.add(c.bytes[i])
            }
            assertEquals(content.toList(), out, "round $round")
            assertEquals(content.size.toLong(), x.bytesRead)
        }
    }

    /**
     * Unordered reads of the same kind of input: every chunk matches the stream at its offset, no byte is delivered
     * twice once reads are unordered, and together the chunks cover the stream. (Bytes already returned by an ordered
     * read before the switch can come again, see [unorderedAfterPartialOrderedReadMayRedeliver].)
     */
    @Test
    fun unorderedReassemblyDeliversEachByteOnce() {
        val rnd = Random(13)
        repeat(100) { round ->
            val content = rnd.nextBytes(rnd.nextInt(1, 3000))
            val x = Assembler()
            val seenOrdered = BooleanArray(content.size)
            val seen = BooleanArray(content.size)
            val frames = ArrayList<Pair<Int, Int>>()
            repeat(rnd.nextInt(1, 60)) {
                val s = rnd.nextInt(0, content.size)
                frames.add(s to rnd.nextInt(1, minOf(400, content.size - s) + 1))
            }
            frames.add(0 to content.size) // eventually everything arrives
            frames.shuffle(rnd)
            var unordered = false
            fun drain(maxLength: () -> Int) {
                while (true) {
                    val c = x.read(maxLength(), false) ?: break
                    for (i in 0 until c.bytes.size) {
                        val at = (c.offset + i).toInt()
                        assertFalse(seen[at], "round $round: byte $at delivered twice")
                        seen[at] = true
                        assertEquals(content[at], c.bytes[i])
                    }
                }
            }
            for ((s, len) in frames) {
                assertTrue(x.insert(s.toLong(), Bytes.wrap(content).slice(s, s + len), len + rnd.nextInt(0, 1500)))
                if (!unordered && rnd.nextInt(3) == 0) {
                    // an ordered read first, then switch
                    x.read(rnd.nextInt(1, 100), true)?.let { c ->
                        for (i in 0 until c.bytes.size) seenOrdered[(c.offset + i).toInt()] = true
                    }
                    assertTrue(x.ensureOrdering(false))
                    unordered = true
                }
                if (unordered) drain { rnd.nextInt(1, 500) }
            }
            if (!unordered) assertTrue(x.ensureOrdering(false))
            drain { Int.MAX_VALUE }
            for (i in content.indices) assertTrue(seen[i] || seenOrdered[i], "round $round: byte $i not delivered")
        }
    }

    /**
     * quinn behaviour kept as is: switching to unordered reads defragments from offset 0 rather than from the read
     * offset, so a duplicate buffered below the ordered read position is delivered again.
     */
    @Test
    fun unorderedAfterPartialOrderedReadMayRedeliver() {
        val x = Assembler()
        x.ins(0, "0123456789", 10)
        x.ins(2, "234567", 6)
        assertEquals(Chunk(0, b("01234")), x.read(5, true))
        assertTrue(x.ensureOrdering(false))
        assertEquals(Chunk(2, b("23456789")), x.read(Int.MAX_VALUE, false))
        assertNull(x.read(Int.MAX_VALUE, false))
    }
}
