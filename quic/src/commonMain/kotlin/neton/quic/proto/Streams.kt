package neton.quic.proto

import neton.io.bytes.Bytes

// Application-facing stream handles and stream events (quinn-proto `connection/streams/mod.rs`).
//
// ⚖️ Error style (quinn returns `Result` everywhere): outcomes that are part of normal flow-controlled operation ([WriteError], [ReadError], both
// "would block" and the terminal ones reported alongside them) are returned as sealed results; misuse of a closed
// stream ([ClosedStream], [FinishError], [ReadableError]) and peer protocol violations ([TransportError]) are thrown.
//
// ⚖️ quinn's handles borrow the connection's `State` to ask `is_closed()`; here the connection passes that answer
// in ([connClosed]), which is equivalent because the connection state cannot change while a handle is in use.

/** Access to streams (mod.rs:30). */
class Streams internal constructor(
    internal val state: StreamsState,
    private val connClosed: Boolean,
) {
    /** Open a single stream if possible; `null` if the streams in the given direction are currently exhausted. */
    fun open(dir: Dir): StreamId? {
        if (connClosed) return null

        // TODO (quinn): Queue STREAM_ID_BLOCKED if this fails
        val d = dir.ordinal
        if (state.next[d] >= state.max[d]) return null

        state.next[d] += 1
        val id = StreamId.of(state.side, dir, state.next[d] - 1)
        state.insert(false, id)
        state.sendStreams += 1
        return id
    }

    /**
     * Accept a remotely initiated stream of a certain directionality, if possible; `null` if there are no new
     * incoming streams for this connection. Has no impact on the data flow-control or stream concurrency limits.
     */
    fun accept(dir: Dir): StreamId? {
        val d = dir.ordinal
        if (state.nextRemote[d] == state.nextReportedRemote[d]) return null

        val x = state.nextReportedRemote[d]
        state.nextReportedRemote[d] = x + 1
        if (dir == Dir.Bi) state.sendStreams += 1

        return StreamId.of(!state.side, dir, x)
    }

    /** The number of streams that may have unacknowledged data. */
    fun sendStreams(): Int = state.sendStreams

    /**
     * The number of remotely initiated open streams of a certain directionality, including those not yet accepted.
     * These streams count against the respective concurrency limit.
     */
    fun remoteOpenStreams(dir: Dir): Long {
        // total opened - total closed = total opened - ( total permitted - total permitted unclosed )
        val d = dir.ordinal
        return state.nextRemote[d] - (state.maxRemote[d] - state.allocatedRemoteCount[d])
    }
}

/** Access to the receive half of a stream (mod.rs:104). */
class RecvStream internal constructor(
    internal val id: StreamId,
    internal val state: StreamsState,
    internal val pending: Retransmits,
) {
    /**
     * Read from the given recv stream (mod.rs:127).
     *
     * `maxLength` of [Chunks.next] limits the size of each returned chunk; `Int.MAX_VALUE` yields the best
     * performance. [ordered] makes sure each returned chunk's offset is exactly the previous chunk's offset plus its
     * length. Unordered reads can improve performance when packet loss occurs; a stream can switch from ordered to
     * unordered reads, but not back ([ReadableError.IllegalOrderedRead]).
     *
     * Throws [ReadableError].
     */
    fun read(ordered: Boolean): Chunks = Chunks(id, ordered, state, pending)

    /**
     * Stop accepting data on the given receive stream (mod.rs:135). Discards unread data and notifies the peer to
     * stop transmitting. Once stopped, further attempts to operate on a stream will throw [ClosedStream].
     */
    fun stop(errorCode: VarInt) {
        val slot = state.recv.find(id.value)
        if (slot < 0) throw ClosedStream()
        val stream = state.getOrInsertRecv(slot)

        val readCredits = stream.stop()
        if (stream.isReceiving) pending.stopSending.add(Frame.StopSending(id, errorCode))

        // We need to keep stopped streams around until they're finished or reset so we can update connection-level
        // flow control to account for discarded data. Otherwise, we can discard state immediately.
        if (!stream.finalOffsetUnknown) {
            state.recv.removeAt(slot)
            state.streamRecvFreed(id, stream)
        }

        if (state.addReadCredits(readCredits).shouldTransmit) pending.maxData = true
    }

    /**
     * Check whether this stream has been reset by the peer, returning the reset error code if so (mod.rs:172).
     * After returning a code once, stream state will be discarded and all future calls will throw [ClosedStream].
     */
    fun receivedReset(): VarInt? {
        val slot = state.recv.find(id.value)
        if (slot < 0) throw ClosedStream()
        val s = state.recv.valueAt(slot)
        if (s == null || !s.open) return null
        if (s.stopped) throw ClosedStream()
        val code = s.resetCode ?: return null

        // Clean up state after application observes the reset, since there's no reason for the application to attempt
        // to read or stop the stream once it knows it's reset
        state.recv.removeAt(slot)
        state.streamRecvFreed(id, s)
        state.queueMaxStreamId(pending)

        return code
    }
}

/** Access to the send half of a stream (mod.rs:199). */
class SendStream internal constructor(
    internal val id: StreamId,
    internal val state: StreamsState,
    internal val pending: Retransmits,
    private val connClosed: Boolean,
) {
    /**
     * Send data on the given stream (mod.rs:224): copies what fits under flow control and the send window.
     *
     * ⚖️ quinn returns the number of bytes written; here the full [Written] (its `chunks` is 1 when all of [data]
     * was taken), so success and the errors share one result type.
     */
    fun write(data: ByteArray, from: Int = 0, to: Int = data.size): WriteResult = writeSource(ByteSlice(data, from, to))

    /**
     * Send data on the given stream without copying (mod.rs:233). A chunk may be written partially; it is then not
     * counted in [Written.chunks], and its entry in [data] is replaced by the unwritten rest.
     */
    fun writeChunks(data: Array<Bytes>): WriteResult = writeSource(BytesArray(data))

    private fun writeSource(source: BytesSource): WriteResult {
        if (connClosed) return WriteError.Blocked // write blocked; connection draining

        val limit = state.writeLimit()

        val maxSendData = state.maxSendData(id)

        val slot = state.send.find(id.value)
        if (slot < 0) return WriteError.ClosedStream
        val stream = state.getOrInsertSend(slot, maxSendData)

        // ⚖️ quinn checks the connection-level limit first, so a write on a stream the peer stopped reports `Blocked`
        // while the connection window is full; the stream then waits on the connection-blocked list, which only reports
        // streams that still have stream-level credit — a stopped stream whose own window is used up never gets more,
        // so its writer never learns of the stop and waits forever. A stopped or closed stream fails first.
        if (!stream.isWritable) return WriteError.ClosedStream
        stream.stopReason?.let { return WriteError.Stopped(it) }

        if (limit == 0L) {
            // write blocked by connection-level flow control or send window
            if (!stream.connectionBlocked) {
                stream.connectionBlocked = true
                state.connectionBlocked.add(id.value)
            }
            // Only report blocking on the peer's limit, not on our own send window
            if (state.dataSent == state.maxData && state.dataBlockedLimit != state.maxData) {
                state.dataBlockedLimit = state.maxData
                pending.dataBlocked = true
            }
            return WriteError.Blocked
        }

        val wasPending = stream.isPending
        val written = when (val r = stream.write(source, limit)) {
            is Written -> r
            WriteError.Blocked -> {
                if (stream.dataBlockedLimit != stream.maxData) {
                    stream.dataBlockedLimit = stream.maxData
                    pending.streamDataBlocked.add(id.value)
                }
                return WriteError.Blocked
            }
            is WriteError -> return r
        }
        state.dataSent += written.bytes
        state.bufferedData += written.bytes
        if (!wasPending) state.pending.pushPending(id.value, stream.priority)
        return written
    }

    /** Check if this stream was stopped, get the reason if it was (mod.rs:302). Throws [ClosedStream]. */
    fun stopped(): VarInt? {
        val slot = state.send.find(id.value)
        if (slot < 0) throw ClosedStream()
        return state.send.valueAt(slot)?.stopReason
    }

    /**
     * Finish a send stream, signalling that no more data will be sent (mod.rs:315). If this fails, no
     * [StreamEvent.Finished] will be generated. Throws [FinishError].
     */
    fun finish() {
        val maxSendData = state.maxSendData(id)
        val slot = state.send.find(id.value)
        if (slot < 0) throw FinishError.ClosedStream
        val stream = state.getOrInsertSend(slot, maxSendData)

        val wasPending = stream.isPending
        stream.finish()
        if (!wasPending) state.pending.pushPending(id.value, stream.priority)
    }

    /** Abandon transmitting data on a stream (mod.rs:338). Throws [ClosedStream]. */
    fun reset(errorCode: VarInt) {
        val maxSendData = state.maxSendData(id)
        val slot = state.send.find(id.value)
        if (slot < 0) throw ClosedStream()
        val stream = state.getOrInsertSend(slot, maxSendData)

        // Redundant reset call
        if (stream.state == SendState.ResetSent) throw ClosedStream()

        // Restore the portion of the send window consumed by the data that we aren't about to send. We leave flow
        // control alone because the peer's responsible for issuing additional credit based on the final offset
        // communicated in the RESET_STREAM frame we send.
        state.bufferedData -= stream.pending.buffered
        stream.reset()
        pending.resetStream.add(StreamReset(id, errorCode))

        // Don't reopen an already-closed stream we haven't forgotten yet
    }

    /** Set the priority of a stream (mod.rs:368). Throws [ClosedStream]. */
    fun setPriority(priority: Int) {
        val maxSendData = state.maxSendData(id)
        val slot = state.send.find(id.value)
        if (slot < 0) throw ClosedStream()
        state.getOrInsertSend(slot, maxSendData).priority = priority
    }

    /** Get the priority of a stream (mod.rs:385). Throws [ClosedStream]. */
    fun priority(): Int {
        val slot = state.send.find(id.value)
        if (slot < 0) throw ClosedStream()
        return state.send.valueAt(slot)?.priority ?: 0
    }
}

/**
 * A queue of streams with pending outgoing data, sorted by priority (mod.rs:398).
 *
 * ⚖️ quinn's `BinaryHeap<PendingStream { priority, recency, id }>` is a binary max-heap over parallel arrays (no
 * object per entry). Every entry has a unique `recency`, so the pop order is fully determined by the keys and does
 * not depend on the heap's internal layout; `StreamsTest.pendingStreamsQueueMatchesReferenceModel` checks it against
 * a sorted-list model. `recency` is quinn's `u64` counting down from `u64::MAX`, stored as raw bits and compared
 * unsigned.
 */
internal class PendingStreamsQueue {
    private var priorities = IntArray(8)
    private var recencies = LongArray(8)
    private var ids = LongArray(8)
    private var n = 0

    /**
     * The next stream to write out. Set when `send_fairness` is off and writing a stream is interrupted while the
     * stream still has some pending data. See [reinsertPending].
     */
    private var hasNext = false
    private var nextPriority = 0
    private var nextId = 0L

    /**
     * A monotonically decreasing counter, used to implement round-robin scheduling for streams of the same
     * priority; starts at `u64::MAX` (-1 as raw bits) and is only decremented by 1 in [pushPending].
     */
    private var recency = -1L

    /** Reinsert a stream that was pending and still contains unsent data. */
    fun reinsertPending(id: Long, priority: Int) {
        check(!hasNext)
        hasNext = true
        nextPriority = priority
        nextId = id
    }

    /** Push a pending stream ID with the given priority, queued after any already-queued streams for the priority. */
    fun pushPending(id: Long, priority: Int) {
        // Note that in the case where fairness is disabled, if we have a reinserted stream we don't bump it even if
        // priority > next.priority. In order to minimize fragmentation we always try to complete a stream once part
        // of it has been written.

        // As the recency counter is monotonically decreasing, we know that using its value to sort this stream will
        // queue it after all other queued streams of the same priority.
        recency -= 1
        if (n == ids.size) {
            priorities = priorities.copyOf(n * 2)
            recencies = recencies.copyOf(n * 2)
            ids = ids.copyOf(n * 2)
        }
        var pos = n++
        while (pos > 0) {
            val parent = (pos - 1) / 2
            if (cmp(priority, recency, id, parent) <= 0) break
            set(pos, priorities[parent], recencies[parent], ids[parent])
            pos = parent
        }
        set(pos, priority, recency, id)
    }

    /** Pop the stream to write next; its ID, or -1 when empty. */
    fun pop(): Long {
        if (hasNext) {
            hasNext = false
            return nextId
        }
        if (n == 0) return -1
        val top = ids[0]
        n -= 1
        if (n > 0) {
            val p = priorities[n]
            val r = recencies[n]
            val id = ids[n]
            var pos = 0
            while (true) {
                var child = 2 * pos + 1
                if (child >= n) break
                if (child + 1 < n && cmpSlots(child + 1, child) > 0) child += 1
                if (cmp(p, r, id, child) >= 0) break
                set(pos, priorities[child], recencies[child], ids[child])
                pos = child
            }
            set(pos, p, r, id)
        }
        return top
    }

    fun clear() {
        hasNext = false
        n = 0
    }

    /** Whether [predicate] holds for any queued stream ID (quinn `iter().any(..)`). */
    inline fun any(predicate: (Long) -> Boolean): Boolean {
        if (hasNextStream() && predicate(nextStreamId())) return true
        for (i in 0 until size()) if (predicate(idAt(i))) return true
        return false
    }

    @PublishedApi internal fun hasNextStream(): Boolean = hasNext
    @PublishedApi internal fun nextStreamId(): Long = nextId
    @PublishedApi internal fun size(): Int = n
    @PublishedApi internal fun idAt(i: Int): Long = ids[i]

    /** Number of queued streams (quinn's test-only `len`). */
    val len: Int get() = n + (if (hasNext) 1 else 0)

    private fun set(i: Int, p: Int, r: Long, id: Long) {
        priorities[i] = p
        recencies[i] = r
        ids[i] = id
    }

    /** Compare the entry `(p, r, id)` with slot [j] (quinn's derived `Ord`: priority, then recency, then id). */
    private fun cmp(p: Int, r: Long, id: Long, j: Int): Int {
        if (p != priorities[j]) return p.compareTo(priorities[j])
        if (r != recencies[j]) return r.toULong().compareTo(recencies[j].toULong())
        return id.compareTo(ids[j])
    }

    private fun cmpSlots(i: Int, j: Int): Int = cmp(priorities[i], recencies[i], ids[i], j)
}

/**
 * Application events about streams (mod.rs:480).
 *
 * ⚖️ quinn queues these enum values inline; here each event is a small object. It is an [Event] itself rather than
 * wrapped in quinn's `Event::Stream`.
 */
sealed class StreamEvent : Event() {
    /** One or more new streams has been opened and might be readable. */
    data class Opened(val dir: Dir) : StreamEvent()

    /** A currently open stream likely has data or errors waiting to be read. */
    data class Readable(val id: StreamId) : StreamEvent()

    /** A formerly write-blocked stream might be ready for a write or have been stopped. Only for open streams. */
    data class Writable(val id: StreamId) : StreamEvent()

    /** A finished stream has been fully acknowledged or stopped. */
    data class Finished(val id: StreamId) : StreamEvent()

    /** The peer asked us to stop sending on an outgoing stream. */
    data class Stopped(val id: StreamId, val errorCode: VarInt) : StreamEvent()

    /** At least one new stream of a certain directionality may be opened. */
    data class Available(val dir: Dir) : StreamEvent()
}

/** Indicates whether a frame needs to be transmitted (mod.rs:525). */
value class ShouldTransmit(
    /** Whether a frame should be transmitted. */
    val shouldTransmit: Boolean,
)

/** Error indicating that a stream has not been opened or has already been finished or reset (mod.rs:537). */
class ClosedStream : Exception("closed stream") {
    override fun equals(other: Any?): Boolean = other is ClosedStream
    override fun hashCode(): Int = 0
}

/**
 * The STREAM frames written into one packet (quinn `frame::StreamMetaVec`, a `TinyVec<[StreamMeta; 1]>`): the
 * first entry is stored inline, further ones in parallel arrays, so a packet with one STREAM frame costs one object.
 */
class StreamMetaVec internal constructor() {
    var size: Int = 0
        private set

    private var id0 = 0L
    private var start0 = 0L
    private var end0 = 0L
    private var fin0 = false
    private var ids: LongArray? = null
    private var starts: LongArray? = null
    private var ends: LongArray? = null
    private var fins: BooleanArray? = null

    fun isEmpty(): Boolean = size == 0

    internal fun push(id: StreamId, start: Long, end: Long, fin: Boolean) {
        check(this !== EMPTY)
        if (size == 0) {
            id0 = id.value; start0 = start; end0 = end; fin0 = fin
        } else {
            val k = size - 1
            if (ids == null || k == ids!!.size) {
                val cap = maxOf(2, k * 2)
                ids = (ids ?: LongArray(0)).copyOf(cap)
                starts = (starts ?: LongArray(0)).copyOf(cap)
                ends = (ends ?: LongArray(0)).copyOf(cap)
                fins = (fins ?: BooleanArray(0)).copyOf(cap)
            }
            ids!![k] = id.value; starts!![k] = start; ends!![k] = end; fins!![k] = fin
        }
        size++
    }

    private fun checkIndex(i: Int) {
        if (i !in 0 until size) throw IndexOutOfBoundsException("index $i, size $size")
    }

    fun id(i: Int): StreamId { checkIndex(i); return StreamId(if (i == 0) id0 else ids!![i - 1]) }
    fun start(i: Int): Long { checkIndex(i); return if (i == 0) start0 else starts!![i - 1] }
    fun end(i: Int): Long { checkIndex(i); return if (i == 0) end0 else ends!![i - 1] }
    fun fin(i: Int): Boolean { checkIndex(i); return if (i == 0) fin0 else fins!![i - 1] }

    /** Entry [i] as a [StreamMeta] (allocates; the accessors above do not). */
    operator fun get(i: Int): StreamMeta = StreamMeta(id(i), start(i), end(i), fin(i))

    fun toList(): List<StreamMeta> = List(size) { get(it) }

    override fun toString(): String = toList().toString()

    companion object {
        /** The empty result shared by calls that write no STREAM frame; read-only. */
        val EMPTY = StreamMetaVec()
    }
}
