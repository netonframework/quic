package neton.quic.proto

import neton.io.net.SocketAddress

// Retransmittable frame queues (quinn-proto `connection/spaces.rs:306-465`).

/** A queued RESET_STREAM: the stream and the application error code (⚖️ quinn's `(StreamId, VarInt)` tuple). */
data class StreamReset(val id: StreamId, val errorCode: VarInt)

/** Retransmittable data queue (spaces.rs:309). */
class Retransmits {
    internal var maxData = false
    internal var dataBlocked = false
    internal val maxStreamId = BooleanArray(2)
    internal val resetStream = ArrayList<StreamReset>()
    internal val stopSending = ArrayList<Frame.StopSending>()

    /** Stream IDs (raw values) owed a MAX_STREAM_DATA frame. */
    internal val maxStreamData = LongHashSet()

    /** Stream IDs (raw values) owed a STREAM_DATA_BLOCKED frame. */
    internal val streamDataBlocked = LongHashSet()
    internal val crypto = ArrayDeque<Frame.Crypto>()
    internal val newCids = ArrayList<IssuedCid>()
    internal val retireCids = LongList()
    internal var ackFrequency = false
    internal var handshakeDone = false

    /**
     * For each enqueued NEW_TOKEN frame, a copy of the path's remote address (spaces.rs:323).
     *
     * If the path changes, NEW_TOKEN frames bound for the old path are not retransmitted on the new path, which is
     * why the address is kept; and a lost token is replaced by a fresh one rather than resent, which is why no token
     * is stored.
     */
    internal val newTokens = ArrayList<SocketAddress>()

    /** Queue RETIRE_CONNECTION_ID for sequence numbers `[start, end)` (spaces.rs:342). */
    internal fun retireCids(start: Long, end: Long) {
        // We don't bother counting in-flight frames because those are bounded by congestion control.
        val num = maxOf(end - start, 0L)
        if (retireCids.size.toLong() + num > MAX_PENDING_RETIRED_CIDS) {
            throw TransportError.CONNECTION_ID_LIMIT_ERROR("queued too many retired CIDs")
        }
        for (seq in start until end) retireCids.add(seq)
    }

    /** spaces.rs:355 */
    internal fun isEmpty(streams: StreamsState): Boolean =
        !maxData &&
            !(dataBlocked && streams.canSendDataBlocked()) &&
            !maxStreamId[0] && !maxStreamId[1] &&
            resetStream.isEmpty() &&
            stopSending.isEmpty() &&
            maxStreamData.all { !streams.canSendFlowControl(StreamId(it)) } &&
            streamDataBlocked.all { streams.streamDataBlockedLimit(StreamId(it)) < 0 } &&
            crypto.isEmpty() &&
            newCids.isEmpty() &&
            retireCids.isEmpty() &&
            !ackFrequency &&
            !handshakeDone &&
            newTokens.isEmpty()

    /** quinn's `Clone`. */
    fun copy(): Retransmits {
        val c = Retransmits()
        c.orAssign(this)
        return c
    }

    /** quinn's `BitOrAssign` (spaces.rs:383). */
    fun orAssign(rhs: Retransmits) {
        // We reduce in-stream head-of-line blocking by queueing retransmits before other data for STREAM and CRYPTO
        // frames.
        maxData = maxData || rhs.maxData
        dataBlocked = dataBlocked || rhs.dataBlocked
        for (dir in 0..1) maxStreamId[dir] = maxStreamId[dir] || rhs.maxStreamId[dir]
        resetStream.addAll(rhs.resetStream)
        stopSending.addAll(rhs.stopSending)
        maxStreamData.addAll(rhs.maxStreamData)
        streamDataBlocked.addAll(rhs.streamDataBlocked)
        for (i in rhs.crypto.indices.reversed()) crypto.addFirst(rhs.crypto[i])
        newCids.addAll(rhs.newCids)
        retireCids.addAll(rhs.retireCids)
        ackFrequency = ackFrequency || rhs.ackFrequency
        handshakeDone = handshakeDone || rhs.handshakeDone
        newTokens.addAll(rhs.newTokens)
    }

    /** quinn's `BitOrAssign<ThinRetransmits>`. */
    fun orAssign(rhs: ThinRetransmits) {
        rhs.get()?.let { orAssign(it) }
    }

    internal companion object {
        /** Ensure `pending_retired` cannot grow without bound; limit is somewhat arbitrary but very permissive. */
        const val MAX_PENDING_RETIRED_CIDS: Long = CidQueue.LEN.toLong() * 10

        /** quinn's `FromIterator<Retransmits>` (⚖️ a factory, Kotlin has no `collect` into a type). */
        fun of(items: Iterable<Retransmits>): Retransmits {
            val result = Retransmits()
            for (packet in items) result.orAssign(packet)
            return result
        }
    }
}

/** A variant of [Retransmits] which only allocates storage when required (spaces.rs:430). */
class ThinRetransmits {
    private var retransmits: Retransmits? = null

    /** Returns `true` if no retransmits are necessary. */
    internal fun isEmpty(streams: StreamsState): Boolean = retransmits?.isEmpty(streams) ?: true

    /** The retransmits stored in this box, if any. */
    fun get(): Retransmits? = retransmits

    /** The stored retransmits, allocating the backing storage if required. */
    fun getOrCreate(): Retransmits = retransmits ?: Retransmits().also { retransmits = it }

    /** quinn's `Clone`. */
    fun copy(): ThinRetransmits = ThinRetransmits().also { it.retransmits = retransmits?.copy() }

    /** Move the stored retransmits out, leaving this empty (quinn `mem::take`). */
    internal fun take(): Retransmits? = retransmits.also { retransmits = null }

    /** Replace the stored retransmits (used when a sent packet's record is copied out of its space). */
    internal fun set(value: Retransmits?) { retransmits = value }
}
