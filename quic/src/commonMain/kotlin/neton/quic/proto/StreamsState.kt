package neton.quic.proto

import neton.io.bytes.Buffer

// Connection-wide stream state and flow control (quinn-proto `connection/streams/state.rs`).

/**
 * All stream state of a connection (state.rs:69): the send and receive halves, stream limits in both directions,
 * connection-level flow control, the priority queue of streams with data to send and the stream events for the
 * application.
 *
 * ⚖️ quinn's `FxHashMap<StreamId, Option<Box<Send>>>` / `FxHashMap<StreamId, Option<StreamRecv>>` are [LongMap]s keyed
 * by the raw stream ID (no key boxing), where a present key with a `null` value is quinn's `Some(None)`: a stream the
 * peer may open that has no state yet. Per-direction arrays are indexed by `Dir.ordinal` (Bi = 0, Uni = 1, quinn's
 * `dir as usize`). quinn's `Option<u64>` limits (`data_blocked_limit`, `stream_data_blocked_limit`) use -1 for `None`,
 * which cannot collide with a real value (all are below 2^62).
 */
class StreamsState(
    internal val side: Side,
    maxRemoteUni: VarInt,
    maxRemoteBi: VarInt,
    sendWindow: Long,
    receiveWindow: VarInt,
    streamReceiveWindow: VarInt,
) {
    // Set of streams that are currently open, or could be immediately opened by the peer
    internal val send = LongMap<Send>(16)
    internal val recv = LongMap<Recv>(16)
    internal val freeRecv = ArrayList<Recv>()
    internal val next = LongArray(2)

    /** Maximum number of locally-initiated streams that may be opened over the lifetime of the connection so far. */
    internal val max = LongArray(2)

    /** Maximum number of remotely-initiated streams that may be opened over the lifetime of the connection so far. */
    internal val maxRemote = longArrayOf(maxRemoteBi.value, maxRemoteUni.value)

    /** Value of `max_remote` most recently transmitted to the peer in a `MAX_STREAMS` frame. */
    private val sentMaxRemote = longArrayOf(maxRemoteBi.value, maxRemoteUni.value)

    /** Number of streams that we've given the peer permission to open and which aren't fully closed. */
    internal val allocatedRemoteCount = longArrayOf(maxRemoteBi.value, maxRemoteUni.value)

    /**
     * Size of the desired stream flow control window. May be smaller than `allocated_remote_count` due to
     * `set_max_concurrent` calls.
     */
    private val maxConcurrentRemoteCount = longArrayOf(maxRemoteBi.value, maxRemoteUni.value)

    /** Whether `max_concurrent_remote_count` has ever changed. */
    private var flowControlAdjusted = false

    /** Lowest remotely-initiated stream index that haven't actually been opened by the peer. */
    internal val nextRemote = LongArray(2)

    /** Whether the remote endpoint has opened any streams the application doesn't know about yet. */
    private val opened = BooleanArray(2)

    /** Next to report to the application, once opened. */
    internal val nextReportedRemote = LongArray(2)

    /**
     * Number of outbound streams. This differs from `send.size` in that it does not include streams that the peer
     * is permitted to open but which have not yet been opened.
     */
    internal var sendStreams = 0

    /** Streams with outgoing data queued, sorted by priority. */
    internal val pending = PendingStreamsQueue()

    internal val events = ArrayDeque<StreamEvent>()

    /** Streams blocked on connection-level flow control or stream window space (added only when a write fails). */
    internal val connectionBlocked = LongList()

    /** Connection-level flow control budget dictated by the peer. */
    internal var maxData = 0L

    /** The initial receive window. */
    internal var receiveWindow = receiveWindow.value
        private set

    /** Limit on incoming data, which is transmitted through `MAX_DATA` frames. */
    internal var localMaxData = receiveWindow.value
        private set

    /** The last value of `MAX_DATA` which had been queued for transmission in an outgoing `MAX_DATA` frame. */
    private var sentMaxData = receiveWindow

    /** Sum of current offsets of all send streams. */
    internal var dataSent = 0L

    /** Sum of end offsets of all receive streams. Includes gaps, so it's an upper bound. */
    internal var dataRecvd = 0L
        private set

    /** Total quantity of outgoing data retained in send buffers, including acknowledged data. */
    internal var bufferedData = 0L

    /** Configured upper bound for `buffered_data`; may be less than it if the user has set a new value. */
    internal var sendWindow = sendWindow

    /** Configured upper bound for how much unacked data the peer can send us per stream. */
    internal var streamReceiveWindow = streamReceiveWindow.value

    // Pertinent state from the TransportParameters supplied by the peer
    private var initialMaxStreamDataUni = VarInt(0)
    private var initialMaxStreamDataBidiLocal = VarInt(0)
    private var initialMaxStreamDataBidiRemote = VarInt(0)

    /** The shrink to be applied to local_max_data when receive_window is shrunk. */
    internal var receiveWindowShrinkDebt = 0L
        private set

    /**
     * Value of `max_data` for which a `DATA_BLOCKED` frame was most recently queued, or -1 (quinn `None`). A new
     * frame is only queued once the peer has raised the limit.
     */
    internal var dataBlockedLimit = -1L

    init {
        for (dir in DIRS) {
            for (i in 0 until maxRemote[dir.ordinal]) insert(true, StreamId.of(!side, dir, i))
        }
    }

    /** state.rs:200 */
    internal fun setParams(params: TransportParameters) {
        initialMaxStreamDataUni = params.initialMaxStreamDataUni
        initialMaxStreamDataBidiLocal = params.initialMaxStreamDataBidiLocal
        initialMaxStreamDataBidiRemote = params.initialMaxStreamDataBidiRemote
        max[Dir.Bi.ordinal] = params.initialMaxStreamsBidi.value
        max[Dir.Uni.ordinal] = params.initialMaxStreamsUni.value
        receivedMaxData(params.initialMaxData)
        for (i in 0 until maxRemote[Dir.Bi.ordinal]) {
            val id = StreamId.of(!side, Dir.Bi, i)
            send.get(id.value)?.let { it.maxData = params.initialMaxStreamDataBidiLocal.value }
        }
    }

    /**
     * Ensure we have space for at least a full flow control window of remotely-initiated streams to be open, and
     * notify the peer if the window has moved (state.rs:217).
     */
    private fun ensureRemoteStreams(dir: Dir) {
        val d = dir.ordinal
        val newCount = maxOf(maxConcurrentRemoteCount[d] - allocatedRemoteCount[d], 0L)
        for (i in 0 until newCount) insert(true, StreamId.of(!side, dir, maxRemote[d] + i))
        allocatedRemoteCount[d] += newCount
        maxRemote[d] += newCount
    }

    /** state.rs:228 */
    internal fun zeroRttRejected() {
        // Revert to initial state for outgoing streams
        for (dir in DIRS) {
            val d = dir.ordinal
            for (i in 0 until next[d]) {
                // We don't bother calling `stream_freed` here because we explicitly reset affected counters below.
                val id = StreamId.of(side, dir, i)
                check(send.remove(id.value))
                if (dir == Dir.Bi) check(recv.remove(id.value))
            }
            next[d] = 0

            // If 0-RTT was rejected, any flow control frames we sent were lost.
            if (flowControlAdjusted) {
                // Conservative approximation of whatever we sent in transport parameters
                sentMaxRemote[d] = 0
            }
        }

        pending.clear()
        sendStreams = 0
        dataSent = 0
        bufferedData = 0
        connectionBlocked.clear()
        dataBlockedLimit = -1
    }

    /**
     * Process incoming stream frame (state.rs:260). [payloadLen] is the size of the packet payload the frame's data
     * is a slice of. Returns whether a `MAX_DATA` frame needs to be transmitted; throws [TransportError].
     */
    fun received(frame: Frame.Stream, payloadLen: Int): ShouldTransmit {
        val id = frame.id
        validateReceiveId(id)

        val slot = recv.find(id.value)
        if (slot < 0) return ShouldTransmit(false) // dropping frame for closed stream
        val rs = getOrInsertRecv(slot)

        if (!rs.isReceiving) return ShouldTransmit(false) // dropping frame for finished stream

        val newBytes = rs.ingest(frame, payloadLen, dataRecvd, localMaxData)
        val closed = frame.fin && rs.stopped
        dataRecvd = saturatingAdd(dataRecvd, newBytes)

        if (!rs.stopped) {
            onStreamFrame(true, id)
            return ShouldTransmit(false)
        }

        // Stopped streams become closed instantly on FIN, so check whether we need to clean up
        if (closed) {
            recv.remove(id.value)
            streamRecvFreed(id, rs)
        }

        // We don't buffer data on stopped streams, so issue flow control credit immediately
        return addReadCredits(newBytes)
    }

    /**
     * Process incoming RESET_STREAM frame (state.rs:310). Returns whether a `MAX_DATA` frame needs to be
     * transmitted; throws [TransportError].
     */
    fun receivedReset(frame: Frame.ResetStream): ShouldTransmit {
        val id = frame.id
        val finalOffset = frame.finalOffset.value
        validateReceiveId(id)

        val slot = recv.find(id.value)
        if (slot < 0) return ShouldTransmit(false) // received RESET_STREAM on closed stream
        val rs = getOrInsertRecv(slot)

        // State transition
        if (!rs.reset(frame.errorCode, frame.finalOffset, dataRecvd, localMaxData)) {
            // Redundant reset
            return ShouldTransmit(false)
        }
        val bytesRead = rs.assembler.bytesRead
        val stopped = rs.stopped
        val end = rs.end
        // Stopped streams have already returned read credits up to their highest offset.
        val credited = if (stopped) end else bytesRead
        if (stopped) {
            // Stopped streams should be disposed immediately on reset
            recv.remove(id.value)
            streamRecvFreed(id, rs)
        }
        onStreamFrame(!stopped, id)

        // Update connection-level flow control
        return if (credited != finalOffset) {
            // credited is always <= end, so this won't underflow.
            dataRecvd = saturatingAdd(dataRecvd, finalOffset - end)
            addReadCredits(finalOffset - credited)
        } else {
            ShouldTransmit(false)
        }
    }

    /** Process incoming `STOP_SENDING` frame (state.rs:371). */
    fun receivedStopSending(id: StreamId, errorCode: VarInt) {
        val maxSendData = maxSendData(id)
        val slot = send.find(id.value)
        if (slot < 0) return
        val stream = getOrInsertSend(slot, maxSendData)

        if (stream.tryStop(errorCode)) {
            events.addLast(StreamEvent.Stopped(id, errorCode))
            onStreamFrame(false, id)
        }
    }

    /** state.rs:389 */
    internal fun resetAcked(id: StreamId) {
        val slot = send.find(id.value)
        if (slot < 0) return
        if (send.valueAt(slot)?.state == SendState.ResetSent) {
            send.removeAt(slot)
            streamFreed(id, StreamHalf.Send)
        }
    }

    /** Whether any stream data is queued, regardless of control frames (state.rs:402). */
    internal fun canSendStreamData(): Boolean =
        // Reset streams may linger in the pending stream list, but will never produce stream frames
        pending.any { id -> send.get(id)?.let { !it.isReset } ?: false }

    /** Whether MAX_STREAM_DATA frames could be sent for stream [id] (state.rs:413). */
    internal fun canSendFlowControl(id: StreamId): Boolean {
        val rs = recv.get(id.value) ?: return false
        return rs.open && rs.canSendFlowControl
    }

    /** Whether a `DATA_BLOCKED` frame could be sent (state.rs:422). */
    internal fun canSendDataBlocked(): Boolean = dataBlockedLimit == maxData

    /**
     * Limit to send in a `STREAM_DATA_BLOCKED` frame for stream [id], or -1 (quinn `None`) if the stream is no
     * longer writable, was stopped by the peer, or the peer has raised the limit since the frame was queued
     * (state.rs:430).
     */
    internal fun streamDataBlockedLimit(id: StreamId): Long {
        val stream = send.get(id.value) ?: return -1
        val limit = stream.dataBlockedLimit
        if (limit < 0) return -1
        return if (stream.isWritable && stream.stopReason == null && limit == stream.maxData) limit else -1
    }

    /** state.rs:437 */
    internal fun writeControlFrames(
        buf: Buffer,
        pending: Retransmits,
        retransmits: ThinRetransmits,
        stats: FrameStats,
        maxSize: Int,
    ) {
        // RESET_STREAM
        while (buf.len + Frame.ResetStream.SIZE_BOUND < maxSize) {
            if (pending.resetStream.isEmpty()) break
            val reset = pending.resetStream.removeAt(pending.resetStream.size - 1)
            val id = reset.id
            val stream = send.get(id.value) ?: continue
            retransmits.getOrCreate().resetStream.add(reset)
            val finalOffset = VarInt.fromLongOrNull(stream.offset) ?: error("impossibly large offset")
            // Frame.ResetStream(id, errorCode, finalOffset).encode(buf), without allocating the frame
            FrameType.RESET_STREAM.encode(buf)
            buf.writeVar(id.value)
            buf.writeVar(reset.errorCode)
            buf.writeVar(finalOffset)
            stats.resetStream += 1
        }

        // STOP_SENDING
        while (buf.len + Frame.StopSending.SIZE_BOUND < maxSize) {
            if (pending.stopSending.isEmpty()) break
            val frame = pending.stopSending.removeAt(pending.stopSending.size - 1)
            // We may need to transmit STOP_SENDING even for streams whose state we have discarded, because we are
            // able to discard local state for stopped streams immediately upon receiving FIN, even if the peer still
            // has arbitrarily large amounts of data to (re)transmit due to loss or unconventional sending strategy.
            // We could fine-tune this a little by dropping the frame if we specifically know the stream's been reset
            // by the peer, but we discard that information as soon as the application consumes it, so it can't be
            // relied upon regardless.
            frame.encode(buf)
            retransmits.getOrCreate().stopSending.add(frame)
            stats.stopSending += 1
        }

        // MAX_DATA
        if (pending.maxData && buf.len + 9 < maxSize) {
            pending.maxData = false

            // `local_max_data` can grow bigger than `VarInt`. For transmission inside QUIC frames we need to clamp it
            // to the maximum allowed `VarInt` size.
            val max = VarInt.fromLongOrNull(localMaxData) ?: VarInt.MAX

            if (max > sentMaxData) {
                // Record that a `MAX_DATA` announcing a certain window was sent. This will suppress enqueuing further
                // `MAX_DATA` frames unless either the previous transmission was not acknowledged or the window
                // further increased.
                sentMaxData = max
            }

            retransmits.getOrCreate().maxData = true
            FrameType.MAX_DATA.encode(buf)
            buf.writeVar(max)
            stats.maxData += 1
        }

        // MAX_STREAM_DATA
        while (buf.len + 17 < maxSize) {
            val raw = pending.maxStreamData.first()
            if (raw < 0) break
            pending.maxStreamData.remove(raw)
            val rs = recv.get(raw) ?: continue
            if (!rs.open) continue
            if (!rs.canSendFlowControl) continue
            retransmits.getOrCreate().maxStreamData.add(raw)

            val max = rs.maxStreamData(streamReceiveWindow)
            rs.recordSentMaxStreamData(max)

            FrameType.MAX_STREAM_DATA.encode(buf)
            buf.writeVar(raw)
            buf.writeVar(max)
            stats.maxStreamData += 1
        }

        // MAX_STREAMS
        for (dir in DIRS) {
            val d = dir.ordinal
            if (!pending.maxStreamId[d] || buf.len + 9 >= maxSize) continue

            pending.maxStreamId[d] = false
            retransmits.getOrCreate().maxStreamId[d] = true
            sentMaxRemote[d] = maxRemote[d]
            (if (dir == Dir.Uni) FrameType.MAX_STREAMS_UNI else FrameType.MAX_STREAMS_BIDI).encode(buf)
            buf.writeVar(maxRemote[d])
            if (dir == Dir.Uni) stats.maxStreamsUni += 1 else stats.maxStreamsBidi += 1
        }

        // DATA_BLOCKED
        if (pending.dataBlocked && buf.len + 9 < maxSize) {
            pending.dataBlocked = false
            // The peer may have raised the limit since the frame was queued
            if (canSendDataBlocked()) {
                retransmits.getOrCreate().dataBlocked = true
                FrameType.DATA_BLOCKED.encode(buf)
                buf.writeVar(maxData)
                stats.dataBlocked += 1
            }
        }

        // STREAM_DATA_BLOCKED
        while (buf.len + 17 < maxSize) {
            val raw = pending.streamDataBlocked.first()
            if (raw < 0) break
            pending.streamDataBlocked.remove(raw)
            val limit = streamDataBlockedLimit(StreamId(raw))
            if (limit < 0) continue
            retransmits.getOrCreate().streamDataBlocked.add(raw)

            FrameType.STREAM_DATA_BLOCKED.encode(buf)
            buf.writeVar(raw)
            buf.writeVar(limit)
            stats.streamDataBlocked += 1
        }
    }

    /**
     * Write STREAM frames for the streams with pending data, in priority order, while at least
     * [Frame.Stream.SIZE_BOUND] bytes remain below [maxBufSize] (state.rs:598). Returns the frames written; the data
     * itself stays in the streams' send buffers for retransmission.
     */
    internal fun writeStreamFrames(buf: Buffer, maxBufSize: Int, fair: Boolean): StreamMetaVec {
        var streamFrames: StreamMetaVec? = null
        while (buf.len + Frame.Stream.SIZE_BOUND < maxBufSize) {
            // Pop the stream of the highest priority that currently has pending data. If the stream still has some
            // pending data left after writing, it will be reinserted, otherwise not.
            val raw = pending.pop()
            if (raw < 0) break
            val id = StreamId(raw)

            // Stream was reset with pending data and the reset was acknowledged
            val stream = send.get(raw) ?: continue

            // Reset streams aren't removed from the pending list and still exist while the peer hasn't acknowledged
            // the reset, but should not generate STREAM frames, so we need to check for them explicitly.
            if (stream.isReset) continue

            // Now that we know the `StreamId`, we can better account for how many bytes are required to encode it.
            val maxLen = maxBufSize - buf.len - 1 - varIntSize(raw)
            stream.pending.pollTransmit(maxLen)
            val start = stream.pending.polledStart
            val end = stream.pending.polledEnd
            val encodeLength = stream.pending.polledEncodeLength
            val fin = end == stream.pending.offset && stream.state == SendState.DataSent
            if (fin) stream.finPending = false

            if (stream.isPending) {
                // If the stream still has pending data, reinsert it, possibly with an updated priority value.
                // Fairness with other streams is achieved by implementing round-robin scheduling, so that the other
                // streams will have a chance to write data before we touch this stream again.
                if (fair) pending.pushPending(raw, stream.priority) else pending.reinsertPending(raw, stream.priority)
            }

            encodeStreamHeader(id, start, end, fin, encodeLength, buf)

            // The range might not be retrievable in a single `get` if it is stored in noncontiguous fashion.
            // Therefore this loop iterates until the range is fully copied into the frame.
            var offset = start
            while (offset != end) {
                val data = stream.pending.get(offset, end)
                offset += data.size
                buf.writeBytes(data)
            }
            (streamFrames ?: StreamMetaVec().also { streamFrames = it }).push(id, start, end, fin)
        }

        return streamFrames ?: StreamMetaVec.EMPTY
    }

    /** Notify the application that new streams were opened or a stream became readable (state.rs:676). */
    private fun onStreamFrame(notifyReadable: Boolean, stream: StreamId) {
        if (stream.initiator == side) {
            // Notifying about the opening of locally-initiated streams would be redundant.
            if (notifyReadable) events.addLast(StreamEvent.Readable(stream))
            return
        }
        val d = stream.dir.ordinal
        if (stream.index >= nextRemote[d]) {
            nextRemote[d] = stream.index + 1
            opened[d] = true
        } else if (notifyReadable) {
            events.addLast(StreamEvent.Readable(stream))
        }
    }

    /** Handle the acknowledgement of a STREAM frame (state.rs:693). */
    internal fun receivedAckOf(id: StreamId, start: Long, end: Long, fin: Boolean) {
        val slot = send.find(id.value)
        if (slot < 0) return
        // Because we only call this after sending data on this stream, a missing state should be unreachable. If we
        // did somehow screw that up, then we might hit an underflow below with unpredictable effects down the line.
        // Best to short-circuit.
        val stream = send.valueAt(slot) ?: return

        if (stream.isReset) {
            // We account for outstanding data on reset streams at time of reset
            return
        }
        val buffered = stream.pending.buffered
        val finished = stream.ack(start, end, fin)
        bufferedData -= buffered - stream.pending.buffered
        if (!finished) {
            // The stream is unfinished or may still need retransmits
            return
        }

        send.removeAt(slot)
        streamFreed(id, StreamHalf.Send)
        events.addLast(StreamEvent.Finished(id))
    }

    internal fun receivedAckOf(frame: StreamMeta) = receivedAckOf(frame.id, frame.start, frame.end, frame.fin)

    /** Handle the loss of a STREAM frame (state.rs:728). */
    internal fun retransmit(id: StreamId, start: Long, end: Long, fin: Boolean) {
        // Loss of data on a closed stream is a noop
        val stream = send.get(id.value) ?: return
        if (stream.isReset) return
        if (!stream.isPending) pending.pushPending(id.value, stream.priority)
        stream.finPending = stream.finPending || fin
        stream.pending.retransmit(start, end)
    }

    internal fun retransmit(frame: StreamMeta) = retransmit(frame.id, frame.start, frame.end, frame.fin)

    /** state.rs:744 */
    internal fun retransmitAllFor0rtt() {
        for (dir in DIRS) {
            for (index in 0 until next[dir.ordinal]) {
                val id = StreamId.of(Side.Client, dir, index)
                val stream = send.get(id.value) ?: continue
                if (stream.pending.isFullyAcked && !stream.finPending) {
                    // Stream data can't be acked in 0-RTT, so we must not have sent anything on this stream
                    continue
                }
                if (!stream.isPending) pending.pushPending(id.value, stream.priority)
                stream.pending.retransmitAllFor0rtt()
            }
        }
    }

    /** Handle a MAX_STREAMS frame (state.rs:765); throws [TransportError]. */
    internal fun receivedMaxStreams(dir: Dir, count: Long) {
        if (count > MAX_STREAM_COUNT) throw TransportError.FRAME_ENCODING_ERROR("unrepresentable stream limit")

        val d = dir.ordinal
        if (count > max[d]) {
            max[d] = count
            events.addLast(StreamEvent.Available(dir))
        }
    }

    /** Handle increase to connection-level flow control limit (state.rs:786). */
    internal fun receivedMaxData(n: VarInt) {
        maxData = maxOf(maxData, n.value)
    }

    /** Handle a MAX_STREAM_DATA frame (state.rs:790); throws [TransportError]. */
    internal fun receivedMaxStreamData(id: StreamId, offset: Long) {
        if (id.initiator != side && id.dir == Dir.Uni) {
            throw TransportError.STREAM_STATE_ERROR("MAX_STREAM_DATA on recv-only stream")
        }

        val writeLimit = writeLimit()
        val maxSendData = maxSendData(id)
        val slot = send.find(id.value)
        if (slot >= 0) {
            val ss = getOrInsertSend(slot, maxSendData)
            if (ss.increaseMaxData(offset)) {
                if (writeLimit > 0) {
                    events.addLast(StreamEvent.Writable(id))
                } else if (!ss.connectionBlocked) {
                    // The stream is still blocked on the connection flow control window. In order to get unblocked
                    // when the window relaxes it needs to be in the connection blocked list.
                    ss.connectionBlocked = true
                    connectionBlocked.add(id.value)
                }
            }
        } else if (id.initiator == side && isLocalUnopened(id)) {
            throw TransportError.STREAM_STATE_ERROR("MAX_STREAM_DATA on unopened stream")
        }

        onStreamFrame(false, id)
    }

    /** Returns the maximum amount of data this is allowed to be written on the connection (state.rs:832). */
    internal fun writeLimit(): Long =
        // `send_window` can be set after construction to something *less* than `buffered_data`
        minOf(maxData - dataSent, maxOf(sendWindow - bufferedData, 0L))

    /** Yield stream events (state.rs:839). */
    internal fun poll(): StreamEvent? {
        for (dir in DIRS) {
            if (opened[dir.ordinal]) {
                opened[dir.ordinal] = false
                return StreamEvent.Opened(dir)
            }
        }

        if (writeLimit() > 0) {
            while (!connectionBlocked.isEmpty()) {
                val raw = connectionBlocked.removeLast()
                val stream = send.get(raw) ?: continue

                // quinn: debug_assert!(stream.connection_blocked)
                stream.connectionBlocked = false

                // If it's no longer sensible to write to a stream (even to detect an error) then don't report it.
                if (stream.isWritable && stream.maxData > stream.offset) return StreamEvent.Writable(StreamId(raw))
            }
        }

        return events.removeFirstOrNull()
    }

    /** Queues MAX_STREAM_ID frames in [pending] if needed; returns whether any frames were queued (state.rs:869). */
    internal fun queueMaxStreamId(pending: Retransmits): Boolean {
        var queued = false
        for (d in 0..1) {
            val diff = maxRemote[d] - sentMaxRemote[d]
            // To reduce traffic, only announce updates if at least 1/8 of the flow control window has been consumed.
            if (diff > maxConcurrentRemoteCount[d] / 8) {
                pending.maxStreamId[d] = true
                queued = true
            }
        }
        return queued
    }

    /** Check for errors entailed by the peer's use of [id] as a send stream (state.rs:884). */
    private fun validateReceiveId(id: StreamId) {
        if (side == id.initiator) {
            when (id.dir) {
                Dir.Uni -> throw TransportError.STREAM_STATE_ERROR("illegal operation on send-only stream")
                Dir.Bi -> if (id.index >= next[Dir.Bi.ordinal]) {
                    throw TransportError.STREAM_STATE_ERROR("operation on unopened stream")
                }
            }
        } else {
            val limit = maxRemote[id.dir.ordinal]
            if (id.index >= limit) throw TransportError.STREAM_LIMIT_ERROR("")
        }
    }

    /** Whether a locally initiated stream has never been open (state.rs:909). */
    internal fun isLocalUnopened(id: StreamId): Boolean = id.index >= next[id.dir.ordinal]

    /** state.rs:913 */
    internal fun setMaxConcurrent(dir: Dir, count: VarInt) {
        flowControlAdjusted = true
        maxConcurrentRemoteCount[dir.ordinal] = count.value
        ensureRemoteStreams(dir)
    }

    internal fun maxConcurrent(dir: Dir): Long = allocatedRemoteCount[dir.ordinal]

    internal fun setSendWindow(sendWindow: Long) {
        this.sendWindow = sendWindow
    }

    /**
     * Set the receive window; returns whether it has been expanded (`true`) or shrunk (`false`) (state.rs:929).
     */
    internal fun setReceiveWindow(receiveWindow: VarInt): Boolean {
        val rw = receiveWindow.value
        var expanded = false
        if (rw > this.receiveWindow) {
            localMaxData = saturatingAdd(localMaxData, rw - this.receiveWindow)
            expanded = true
        } else {
            val diff = this.receiveWindow - rw
            receiveWindowShrinkDebt = saturatingAdd(receiveWindowShrinkDebt, diff)
        }
        this.receiveWindow = rw
        return expanded
    }

    /** state.rs:945 */
    internal fun insert(remote: Boolean, id: StreamId) {
        val bi = id.dir == Dir.Bi
        // bidirectional OR (unidirectional AND NOT remote)
        if (bi || !remote) check(send.put(id.value, null))
        // bidirectional OR (unidirectional AND remote)
        if (bi || remote) {
            val r = if (freeRecv.isEmpty()) null else freeRecv.removeAt(freeRecv.size - 1)
            check(recv.put(id.value, r))
        }
    }

    /**
     * Adds credits to the connection flow control window (state.rs:966). Returns whether a `MAX_DATA` frame should
     * be enqueued as soon as possible, which is only the case if the window update is significant enough.
     */
    internal fun addReadCredits(credits: Long): ShouldTransmit {
        if (credits > receiveWindowShrinkDebt) {
            val netCredits = credits - receiveWindowShrinkDebt
            localMaxData = saturatingAdd(localMaxData, netCredits)
            receiveWindowShrinkDebt = 0
        } else {
            receiveWindowShrinkDebt -= credits
        }

        if (localMaxData > VarInt.MAX.value) return ShouldTransmit(false)

        // Only announce a window update if it's significant enough to make it worthwhile sending a MAX_DATA frame.
        // We use a fraction of the configured connection receive window to make the decision, to accommodate for
        // connection using bigger windows requiring less updates.
        val diff = localMaxData - sentMaxData.value
        return ShouldTransmit(diff >= receiveWindow / 8)
    }

    /** Update counters for removal of a stream (state.rs:989). */
    internal fun streamFreed(id: StreamId, half: StreamHalf) {
        if (id.initiator != side) {
            val fullyFree = id.dir == Dir.Uni ||
                when (half) {
                    StreamHalf.Send -> !recv.containsKey(id.value)
                    StreamHalf.Recv -> !send.containsKey(id.value)
                }
            if (fullyFree) {
                allocatedRemoteCount[id.dir.ordinal] -= 1
                ensureRemoteStreams(id.dir)
            }
        }
        if (half == StreamHalf.Send) sendStreams -= 1
    }

    /** state.rs:1006: pool the `Recv` for reuse (quinn `StreamRecv::free`) and update the counters. */
    internal fun streamRecvFreed(id: StreamId, recv: Recv) {
        check(recv.open) { "Self::Free on reinit()" }
        recv.reinit(streamReceiveWindow)
        recv.open = false
        freeRecv.add(recv)
        streamFreed(id, StreamHalf.Recv)
    }

    /** state.rs:1011 */
    internal fun maxSendData(id: StreamId): VarInt {
        val remote = side != id.initiator
        return when {
            id.dir == Dir.Uni -> initialMaxStreamDataUni
            // Remote/local appear reversed here because the transport parameters are named from the perspective of
            // the peer.
            remote -> initialMaxStreamDataBidiLocal
            else -> initialMaxStreamDataBidiRemote
        }
    }

    /** quinn `get_or_insert_send` (state.rs:1024) on the entry in [slot] of [send]. */
    internal fun getOrInsertSend(slot: Int, maxData: VarInt): Send =
        send.valueAt(slot) ?: Send(maxData).also { send.setValueAt(slot, it) }

    /** quinn `get_or_insert_recv` (state.rs:1031) on the entry in [slot] of [recv]: opens a pooled or new `Recv`. */
    internal fun getOrInsertRecv(slot: Int): Recv {
        val r = recv.valueAt(slot)
        if (r != null) {
            r.open = true
            return r
        }
        return Recv(streamReceiveWindow).also { recv.setValueAt(slot, it) }
    }
}

/** quinn's `Dir::iter()` order; an array so that iterating it allocates nothing. */
private val DIRS = arrayOf(Dir.Bi, Dir.Uni)

/** quinn `StreamHalf` (mod.rs:541). */
internal enum class StreamHalf { Send, Recv }

/** `u64::saturating_add` for the non-negative values used here (saturates at `Long.MAX_VALUE`). */
internal fun saturatingAdd(a: Long, b: Long): Long {
    val r = a + b
    return if (r < a) Long.MAX_VALUE else r
}
