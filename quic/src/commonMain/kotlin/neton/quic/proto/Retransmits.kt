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
}

/** Number of frames transmitted or received of each frame type (quinn-proto `connection/stats.rs:33`). */
class FrameStats {
    var acks: Long = 0
    var ackFrequency: Long = 0
    var crypto: Long = 0
    var connectionClose: Long = 0
    var dataBlocked: Long = 0
    var datagram: Long = 0

    /** A `u8` in quinn, saturating at 255. */
    var handshakeDone: Int = 0
    var immediateAck: Long = 0
    var maxData: Long = 0
    var maxStreamData: Long = 0
    var maxStreamsBidi: Long = 0
    var maxStreamsUni: Long = 0
    var newConnectionId: Long = 0
    var newToken: Long = 0
    var pathChallenge: Long = 0
    var pathResponse: Long = 0
    var ping: Long = 0
    var resetStream: Long = 0
    var retireConnectionId: Long = 0
    var streamDataBlocked: Long = 0
    var streamsBlockedBidi: Long = 0
    var streamsBlockedUni: Long = 0
    var stopSending: Long = 0
    var stream: Long = 0

    /** stats.rs:61 */
    internal fun record(frame: Frame) {
        when (frame) {
            Frame.Padding -> {}
            Frame.Ping -> ping += 1
            is Frame.Ack -> acks += 1
            is Frame.ResetStream -> resetStream += 1
            is Frame.StopSending -> stopSending += 1
            is Frame.Crypto -> crypto += 1
            is Frame.Datagram -> datagram += 1
            is Frame.NewToken -> newToken += 1
            is Frame.MaxData -> maxData += 1
            is Frame.MaxStreamData -> maxStreamData += 1
            is Frame.MaxStreams -> if (frame.dir == Dir.Bi) maxStreamsBidi += 1 else maxStreamsUni += 1
            is Frame.DataBlocked -> dataBlocked += 1
            is Frame.Stream -> stream += 1
            is Frame.StreamDataBlocked -> streamDataBlocked += 1
            is Frame.StreamsBlocked -> if (frame.dir == Dir.Bi) streamsBlockedBidi += 1 else streamsBlockedUni += 1
            is Frame.NewConnectionId -> newConnectionId += 1
            is Frame.RetireConnectionId -> retireConnectionId += 1
            is Frame.PathChallenge -> pathChallenge += 1
            is Frame.PathResponse -> pathResponse += 1
            is Frame.Close -> connectionClose += 1
            is Frame.AckFrequency -> ackFrequency += 1
            Frame.ImmediateAck -> immediateAck += 1
            Frame.HandshakeDone -> handshakeDone = minOf(handshakeDone + 1, 255)
        }
    }

    /** quinn's `Clone` / `Copy`. */
    fun copy(): FrameStats = FrameStats().also {
        it.acks = acks; it.ackFrequency = ackFrequency; it.crypto = crypto; it.connectionClose = connectionClose
        it.dataBlocked = dataBlocked; it.datagram = datagram; it.handshakeDone = handshakeDone
        it.immediateAck = immediateAck; it.maxData = maxData; it.maxStreamData = maxStreamData
        it.maxStreamsBidi = maxStreamsBidi; it.maxStreamsUni = maxStreamsUni; it.newConnectionId = newConnectionId
        it.newToken = newToken; it.pathChallenge = pathChallenge; it.pathResponse = pathResponse; it.ping = ping
        it.resetStream = resetStream; it.retireConnectionId = retireConnectionId
        it.streamDataBlocked = streamDataBlocked; it.streamsBlockedBidi = streamsBlockedBidi
        it.streamsBlockedUni = streamsBlockedUni; it.stopSending = stopSending; it.stream = stream
    }

    /** quinn's `Debug`. */
    override fun toString(): String =
        "FrameStats { ACK: $acks, ACK_FREQUENCY: $ackFrequency, CONNECTION_CLOSE: $connectionClose, CRYPTO: $crypto, " +
            "DATA_BLOCKED: $dataBlocked, DATAGRAM: $datagram, HANDSHAKE_DONE: $handshakeDone, " +
            "IMMEDIATE_ACK: $immediateAck, MAX_DATA: $maxData, MAX_STREAM_DATA: $maxStreamData, " +
            "MAX_STREAMS_BIDI: $maxStreamsBidi, MAX_STREAMS_UNI: $maxStreamsUni, " +
            "NEW_CONNECTION_ID: $newConnectionId, NEW_TOKEN: $newToken, PATH_CHALLENGE: $pathChallenge, " +
            "PATH_RESPONSE: $pathResponse, PING: $ping, RESET_STREAM: $resetStream, " +
            "RETIRE_CONNECTION_ID: $retireConnectionId, STREAM_DATA_BLOCKED: $streamDataBlocked, " +
            "STREAMS_BLOCKED_BIDI: $streamsBlockedBidi, STREAMS_BLOCKED_UNI: $streamsBlockedUni, " +
            "STOP_SENDING: $stopSending, STREAM: $stream }"
}
