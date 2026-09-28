package neton.quic.proto

import neton.io.bytes.Bytes

// Reassembly of stream / CRYPTO data (quinn-proto `connection/assembler.rs`).

/**
 * Helper to assemble unordered stream frames into an ordered stream (assembler.rs:13).
 *
 * Received data is kept as zero-copy slices of the packets it arrived in, like quinn's `Bytes`, until
 * [defragment] decides that too little of those packet buffers is still useful and copies the live bytes into one
 * compact array.
 */
internal class Assembler {
    /** `State::Ordered` when `null`, else `State::Unordered { recvd }`: offsets received, including unread ones. */
    private var recvd: RangeSet? = null

    internal var data = ChunkHeap(4)
        private set

    /** Total number of buffered bytes, including duplicates in ordered mode. */
    private var buffered = 0L

    /** Estimated number of allocated bytes, will never be less than [buffered]. */
    private var allocated = 0L

    /**
     * Number of bytes read by the application. When only ordered reads have been used, this is the length of the
     * contiguous prefix of the stream which has been consumed by the application, aka the stream offset.
     */
    var bytesRead = 0L
        private set

    private var end = 0L

    /** Reset to the initial state (assembler.rs:34). */
    fun reinit() {
        recvd = null
        data.clear()
        buffered = 0
        allocated = 0
        bytesRead = 0
        end = 0
    }

    /** Returns `false` for quinn's `Err(IllegalOrderedRead)` (assembler.rs:41). ⚖️ `Boolean` for the unit error type. */
    fun ensureOrdering(ordered: Boolean): Boolean {
        val isOrdered = recvd == null
        if (ordered && !isOrdered) {
            return false
        } else if (!ordered && isOrdered) {
            // Enter unordered mode
            if (!data.isEmpty()) {
                // Get rid of possible duplicates
                defragment()
            }
            val r = RangeSet()
            r.insert(0, bytesRead)
            for (i in 0 until data.size) r.insert(data.offset(i), data.offset(i) + data.len(i))
            recvd = r
        }
        return true
    }

    /** Get the next chunk (assembler.rs:61); [maxLength] `Int.MAX_VALUE` stands for quinn's `usize::MAX`. */
    fun read(maxLength: Int, ordered: Boolean): Chunk? {
        while (true) {
            if (data.isEmpty()) return null

            if (ordered) {
                val offset = data.offset(0)
                val len = data.len(0)
                if (offset > bytesRead) {
                    // Next chunk is after current read index
                    return null
                } else if (offset + len <= bytesRead) {
                    // Next chunk is useless as the read index is beyond its end
                    buffered -= len
                    allocated -= data.allocationSize(0)
                    data.pop()
                    continue
                }

                // Determine `start` and `len` of the slice of useful data in chunk
                val start = (bytesRead - offset).toInt()
                if (start > 0) {
                    data.advance(0, start)
                    buffered -= start
                }
            }

            val len = data.len(0)
            return if (maxLength < len) {
                bytesRead += maxLength
                val offset = data.offset(0)
                val bytes = data.splitTo(0, maxLength)
                buffered -= maxLength
                data.siftDownRoot() // quinn's `PeekMut` drop after the root was modified
                Chunk(offset, bytes)
            } else {
                bytesRead += len
                buffered -= len
                allocated -= data.allocationSize(0)
                val offset = data.offset(0)
                val bytes = data.bytes(0)
                data.pop()
                Chunk(offset, bytes)
            }
        }
    }

    /**
     * Copy fragmented chunk data to new chunks backed by a single buffer (assembler.rs:105).
     *
     * This makes sure we're not unnecessarily holding on to many larger allocations. We merge contiguous chunks in
     * the process of doing so.
     */
    internal fun defragment() {
        // Chunks smaller than minChunkSize are merged regardless of fragmentation
        val minChunkSize = maxOf((buffered + MAX_CHUNKS - 1) / MAX_CHUNKS, MIN_RETAINED_CHUNK_SIZE.toLong())
        val old = data
        old.sortAscending() // `into_sorted_vec`; iterated in reverse below
        val n = old.size
        buffered = 0
        var fragmentedBuffered = 0L
        var offset = 0L
        for (i in n - 1 downTo 0) {
            old.tryMarkDefragment(i, offset)
            val size = old.len(i)
            offset = old.offset(i) + size
            buffered += size
            if (!old.defragmented(i) || size < minChunkSize) fragmentedBuffered += size
        }
        allocated = buffered
        val fresh = ChunkHeap(n)
        val array = ByteArray(fragmentedBuffered.toInt())
        val whole = Bytes.wrap(array) // only regions that are complete are ever sliced
        var bufStart = 0 // start of the not yet split part of `array` (quinn's `buffer`)
        var bufLen = 0
        offset = 0
        for (i in n - 1 downTo 0) {
            val len = old.len(i)
            // bytes might be empty after tryMarkDefragment
            if (len == 0) continue
            if (old.defragmented(i) && len >= minChunkSize) {
                fresh.pushFrom(old, i)
                continue
            }
            // Overlap is resolved by tryMarkDefragment
            if (old.offset(i) != offset + bufLen) {
                if (bufLen != 0) {
                    fresh.push(offset, whole, bufStart, bufLen, bufLen, true)
                    bufStart += bufLen
                    bufLen = 0
                }
                offset = old.offset(i)
            }
            old.copyBytesInto(i, array, bufStart + bufLen)
            bufLen += len
        }
        if (bufLen != 0) fresh.push(offset, whole, bufStart, bufLen, bufLen, true)
        data = fresh
    }

    /**
     * Add [bytes] at stream [offset] (assembler.rs:161). [allocationSize] is the size of the packet buffer [bytes]
     * is a slice of. Returns `false` for quinn's `Err(TooManyChunks)` (⚖️ `Boolean` for the unit error type).
     *
     * Note: If a packet contains many frames from the same stream, the estimated over-allocation will be much higher
     * because we are counting the same allocation multiple times.
     */
    fun insert(offset: Long, bytes: Bytes, allocationSize: Int): Boolean {
        // quinn: debug_assert!(bytes.len() <= allocation_size)
        var offset = offset
        var start = 0 // quinn advances `bytes`; here the view is `bytes[start, bytes.size)`
        end = maxOf(end, offset + bytes.size)
        val recvd = recvd
        if (recvd != null) {
            // Discard duplicate data
            recvd.replaceEach(offset, offset + bytes.size) { dupStart, dupEnd ->
                if (dupStart > offset) {
                    val n = (dupStart - offset).toInt()
                    data.push(offset, bytes, start, n, allocationSize, false)
                    buffered += n
                    allocated += allocationSize
                    start += n
                    offset = dupStart
                }
                start += (dupEnd - offset).toInt()
                offset = dupEnd
            }
        } else if (offset < bytesRead) {
            if (offset + bytes.size <= bytesRead) {
                return true
            } else {
                val diff = bytesRead - offset
                offset += diff
                start += diff.toInt()
            }
        }

        // No early return when empty: the dedup loop above may already have pushed chunks.
        if (start < bytes.size) {
            data.push(offset, bytes, start, bytes.size - start, allocationSize, false)
            buffered += bytes.size - start
            allocated += allocationSize
        }
        // `buffered` also counts duplicate bytes, therefore we use `end - bytesRead` as an upper bound of buffered
        // unique bytes. This will cause a defragmentation if the amount of duplicate bytes exceeds a proportion of the
        // receive window size.
        val bufferedUnique = minOf(buffered, end - bytesRead)
        val overAllocation = allocated - bufferedUnique
        // Rationale: on the one hand, we want to defragment rarely, ideally never in non-pathological scenarios.
        // However, a pathological or malicious peer could send us one-byte frames, and since we use
        // reference-counted buffers in order to prevent copying, this could result in keeping a lot of memory
        // allocated. This limits over-allocation in proportion to the buffered data. The constants are chosen
        // somewhat arbitrarily and try to balance between defragmentation overhead and over-allocation.
        val threshold = maxOf(32768L, bufferedUnique * 3 / 2)
        // Small gapped frames hold over-allocation below the threshold, so bound the count too.
        if (overAllocation > threshold || data.size > COMPACT_THRESHOLD) {
            defragment()
            // ngtcp2 uses a threshold of 4000 -- try to be a little more conservative?
            if (data.size > MAX_CHUNKS) return false
        }
        return true
    }

    /** Discard all buffered data (assembler.rs:250). */
    fun clear() {
        data.clear()
        buffered = 0
        allocated = 0
    }

    internal companion object {
        /**
         * Bound on the number of distinct spans kept for a stream. Independent of how much memory those spans
         * over-allocate. A frame is rejected only if compaction cannot get the count back down to this.
         */
        const val MAX_CHUNKS = 1024

        /**
         * Minimum size of a defragmented chunk that is retained without coalescing. Chunks below this size will be
         * copied on every compaction. 128 bytes balances being cheap to copy while reducing the overhead of many
         * small buffer nodes.
         */
        const val MIN_RETAINED_CHUNK_SIZE = 128

        /** Chunk count past which `insert` compacts before deciding whether to reject. */
        const val COMPACT_THRESHOLD = 2 * MAX_CHUNKS
    }
}

/**
 * A chunk of data from the receive stream (assembler.rs:258).
 *
 * ⚖️ quinn returns it by value; here each chunk read is one small object plus its `Bytes` view (the data itself is
 * not copied).
 */
data class Chunk(
    /** The offset in the stream. */
    val offset: Long,
    /** The contents of the chunk. */
    val bytes: Bytes,
) : ReadResult

/**
 * quinn's `BinaryHeap<Buffer>` of received chunks (assembler.rs:15, 272), as a structure of arrays.
 *
 * ⚖️ quinn keeps one `Buffer { offset, bytes, allocation_size, defragmented }` per chunk inline in the heap's
 * vector; a Kotlin object per chunk would add an allocation per received frame, so the fields live in parallel
 * arrays, and `bytes` is a view `base[start, start + len)` that is narrowed in place instead of re-sliced
 * (quinn's `Bytes::advance` does not allocate either). The sift operations are those of Rust's `BinaryHeap`
 * (`sift_up`, `sift_down_range`, `sift_down_to_bottom`, `into_sorted_vec`) step for step, so chunks that compare
 * equal (same offset and length) come out in the same order as in quinn. `AssemblerTest.chunkHeapMatchesReferenceModel`
 * checks the ordering against a straightforward sorted-list model.
 *
 * Ordering (assembler.rs:318): the root is the chunk with the lowest offset; among equal offsets, the longest.
 */
internal class ChunkHeap(capacity: Int) {
    private var offsets = LongArray(maxOf(capacity, 1))
    private var bases = arrayOfNulls<Bytes>(offsets.size)
    private var starts = IntArray(offsets.size)
    private var lens = IntArray(offsets.size)
    private var allocs = IntArray(offsets.size)
    private var defrags = BooleanArray(offsets.size)

    var size: Int = 0
        private set

    fun isEmpty(): Boolean = size == 0

    fun offset(i: Int): Long = offsets[i]
    fun len(i: Int): Int = lens[i]
    fun allocationSize(i: Int): Int = allocs[i]
    fun defragmented(i: Int): Boolean = defrags[i]

    /** The bytes of chunk [i] (the whole base slice when the view covers it, so usually no allocation). */
    fun bytes(i: Int): Bytes = if (lens[i] == 0) Bytes.EMPTY else bases[i]!!.slice(starts[i], starts[i] + lens[i])

    /** Drop the first [n] bytes of chunk [i] (quinn `Bytes::advance`). */
    fun advance(i: Int, n: Int) {
        starts[i] += n
        lens[i] -= n
        offsets[i] += n
    }

    /** Split off and return the first [n] bytes of chunk [i] (quinn `Bytes::split_to` plus the offset update). */
    fun splitTo(i: Int, n: Int): Bytes {
        val out = bases[i]!!.slice(starts[i], starts[i] + n)
        advance(i, n)
        return out
    }

    fun copyBytesInto(i: Int, dst: ByteArray, dstOffset: Int) {
        bytes(i).copyInto(dst, dstOffset)
    }

    /** quinn `Buffer::try_mark_defragment` (assembler.rs:295) on chunk [i]. */
    fun tryMarkDefragment(i: Int, offset: Long) {
        val duplicate = maxOf(offset - offsets[i], 0L)
        offsets[i] = maxOf(offsets[i], offset)
        if (duplicate >= lens[i]) {
            // All bytes are duplicate
            bases[i] = null
            starts[i] = 0
            lens[i] = 0
            defrags[i] = true
            allocs[i] = 0
            return
        }
        starts[i] += duplicate.toInt()
        lens[i] -= duplicate.toInt()
        // Make sure that fragmented buffers with high utilization become defragmented and defragmented buffers
        // remain defragmented
        defrags[i] = defrags[i] || lens[i].toLong() * 6 / 5 >= allocs[i]
        if (defrags[i]) {
            // Make sure that defragmented buffers do not contribute to over-allocation
            allocs[i] = lens[i]
        }
    }

    fun clear() {
        bases.fill(null, 0, size)
        size = 0
    }

    /** quinn `BinaryHeap::push`: append and `sift_up(0, old_len)`. */
    fun push(offset: Long, base: Bytes, start: Int, len: Int, allocationSize: Int, defragmented: Boolean) {
        if (size == offsets.size) grow()
        val i = size++
        offsets[i] = offset; bases[i] = base; starts[i] = start; lens[i] = len
        allocs[i] = allocationSize; defrags[i] = defragmented
        siftUp(0, i)
    }

    /** Push a copy of chunk [i] of [other]. */
    fun pushFrom(other: ChunkHeap, i: Int) =
        push(other.offsets[i], other.bases[i]!!, other.starts[i], other.lens[i], other.allocs[i], other.defrags[i])

    /** quinn `BinaryHeap::pop`, discarding the root: move the last element to the root and `sift_down_to_bottom(0)`. */
    fun pop() {
        val last = --size
        if (last > 0) {
            move(last, 0)
            siftDownToBottom(0)
        }
        bases[last] = null
    }

    /** quinn's `PeekMut` drop after the root was changed: `sift_down(0)`. */
    fun siftDownRoot() = siftDownRange(0, size)

    /** quinn `BinaryHeap::into_sorted_vec`, in place: afterwards the chunks are in ascending order. */
    fun sortAscending() {
        var end = size
        while (end > 1) {
            end -= 1
            swap(0, end)
            siftDownRange(0, end)
        }
    }

    // --- Rust `BinaryHeap` internals (`Hole` moves are element moves; the hole's element sits in slot `size`) ---

    /** Compare slot [a] with slot [b] (quinn's `Ord for Buffer`). */
    private fun cmp(a: Int, b: Int): Int {
        val c = offsets[b].compareTo(offsets[a]) // reversed: lower offsets are greater
        return if (c != 0) c else lens[a].compareTo(lens[b])
    }

    private fun siftUp(start: Int, pos0: Int) {
        var pos = pos0
        val hole = holeFrom(pos)
        while (pos > start) {
            val parent = (pos - 1) / 2
            if (cmp(hole, parent) <= 0) break
            move(parent, pos)
            pos = parent
        }
        move(hole, pos)
    }

    private fun siftDownRange(pos0: Int, end: Int) {
        var pos = pos0
        val hole = holeFrom(pos)
        var child = 2 * pos + 1
        while (child <= end - 2) {
            if (cmp(child, child + 1) <= 0) child += 1
            if (cmp(hole, child) >= 0) {
                move(hole, pos)
                return
            }
            move(child, pos)
            pos = child
            child = 2 * pos + 1
        }
        if (child == end - 1 && cmp(hole, child) < 0) {
            move(child, pos)
            pos = child
        }
        move(hole, pos)
    }

    private fun siftDownToBottom(pos0: Int) {
        val end = size
        val start = pos0
        var pos = pos0
        val hole = holeFrom(pos)
        var child = 2 * pos + 1
        while (child <= end - 2) {
            if (cmp(child, child + 1) <= 0) child += 1
            move(child, pos)
            pos = child
            child = 2 * pos + 1
        }
        if (child == end - 1) {
            move(child, pos)
            pos = child
        }
        move(hole, pos)
        siftUp(start, pos)
    }

    /** Save slot [pos] into the scratch slot at index [size] (the `Hole`'s element) and return that index. */
    private fun holeFrom(pos: Int): Int {
        if (size == offsets.size) grow()
        move(pos, size)
        return size
    }

    private fun move(from: Int, to: Int) {
        if (from == to) return
        offsets[to] = offsets[from]; bases[to] = bases[from]; starts[to] = starts[from]; lens[to] = lens[from]
        allocs[to] = allocs[from]; defrags[to] = defrags[from]
        if (from == size) bases[from] = null // the scratch slot must not keep a reference
    }

    private fun swap(a: Int, b: Int) {
        val o = offsets[a]; offsets[a] = offsets[b]; offsets[b] = o
        val by = bases[a]; bases[a] = bases[b]; bases[b] = by
        val s = starts[a]; starts[a] = starts[b]; starts[b] = s
        val l = lens[a]; lens[a] = lens[b]; lens[b] = l
        val al = allocs[a]; allocs[a] = allocs[b]; allocs[b] = al
        val d = defrags[a]; defrags[a] = defrags[b]; defrags[b] = d
    }

    private fun grow() {
        val cap = offsets.size * 2
        offsets = offsets.copyOf(cap); bases = bases.copyOf(cap); starts = starts.copyOf(cap)
        lens = lens.copyOf(cap); allocs = allocs.copyOf(cap); defrags = defrags.copyOf(cap)
    }
}
