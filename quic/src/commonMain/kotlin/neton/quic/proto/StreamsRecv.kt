package neton.quic.proto

// Receive half of a stream (quinn-proto `connection/streams/recv.rs`).

/**
 * Receive-side stream state (recv.rs:14).
 *
 * ⚖️ quinn's `RecvState` enum (`Recv { size: Option<u64> }` / `ResetRecvd { size, error_code }`) is flattened into
 * [resetRecvd], [finalSize] (-1 for `None`) and [resetErrorCode]; and quinn's `StreamRecv::{Free, Open}` wrapper,
 * which lets a finished `Recv` be reused for a later stream, is the [open] flag on the same object, so reopening a
 * pooled `Recv` allocates nothing.
 */
internal class Recv(initialMaxData: Long) {
    // NB: when adding or removing fields, remember to update `reinit`.
    private var resetRecvd = false

    /** The final size, once known (FIN or RESET_STREAM); -1 otherwise. */
    private var finalSize = -1L
    private var resetErrorCode = VarInt(0)
    val assembler = Assembler()
    private var sentMaxStreamData = initialMaxData
    var end = 0L
    var stopped = false

    /** quinn `StreamRecv::Open` (true) or `StreamRecv::Free` (false). */
    var open = true

    /** Reset to the initial state (recv.rs:34). */
    fun reinit(initialMaxData: Long) {
        resetRecvd = false
        finalSize = -1
        resetErrorCode = VarInt(0)
        assembler.reinit()
        sentMaxStreamData = initialMaxData
        end = 0
        stopped = false
    }

    /**
     * Process a STREAM frame (recv.rs:45). Returns the number of new bytes ingested (credit consumed).
     *
     * ⚖️ quinn also returns whether the stream is now closed; that is `frame.fin && stopped`, which the caller
     * computes, saving a tuple per frame.
     */
    fun ingest(frame: Frame.Stream, payloadLen: Int, received: Long, maxData: Long): Long {
        val end = frame.offset + frame.data.size
        if (end >= 1L shl 62) throw TransportError.FLOW_CONTROL_ERROR("maximum stream offset too large")

        val finalOffset = finalSize
        if (finalOffset >= 0) {
            if (end > finalOffset || (frame.fin && end != finalOffset)) {
                throw TransportError.FINAL_SIZE_ERROR("")
            }
        }

        val newBytes = creditConsumedBy(end, received, maxData)

        // Stopped streams don't need to wait for the actual data, they just need to know how much there was.
        if (frame.fin && !stopped) {
            if (!resetRecvd) finalSize = end
        }

        this.end = maxOf(this.end, end)
        // Don't bother storing data or releasing stream-level flow control credit if the stream's already stopped
        if (!stopped) {
            if (!assembler.insert(frame.offset, frame.data, payloadLen)) {
                throw TransportError.INTERNAL_ERROR("too many gaps in stream buffer")
            }
        }

        return newBytes
    }

    /**
     * Stop the stream (recv.rs:87): returns the connection-level credit to issue for unread data, or throws
     * [ClosedStream] if already stopped.
     *
     * ⚖️ quinn also returns `ShouldTransmit(self.is_receiving())` (whether STOP_SENDING is worth sending); callers
     * read [isReceiving] afterwards.
     */
    fun stop(): Long {
        if (stopped) throw ClosedStream()

        stopped = true
        assembler.clear()
        // Issue flow control credit for unread data
        // This may send a spurious STOP_SENDING if we've already received all data, but it's a bit fiddly to
        // distinguish that from the case where we've received a FIN but are missing some data that the peer might
        // still be trying to retransmit, in which case a STOP_SENDING is still useful.
        return end - assembler.bytesRead
    }

    /**
     * The window that should be advertised in a `MAX_STREAM_DATA` frame (recv.rs:111, first tuple element).
     * ⚖️ quinn returns it together with [maxStreamDataShouldTransmit]; two calls avoid a tuple.
     */
    fun maxStreamData(streamReceiveWindow: Long): Long = assembler.bytesRead + streamReceiveWindow

    /**
     * Whether a transmission of [maxStreamData] is recommended (recv.rs:111, second tuple element). If `false` the
     * new window should only be transmitted if a previous transmission had failed.
     */
    fun maxStreamDataShouldTransmit(streamReceiveWindow: Long): Boolean {
        // Only announce a window update if it's significant enough to make it worthwhile sending a MAX_STREAM_DATA
        // frame. We use here a fraction of the configured stream receive window to make the decision, and
        // accommodate for streams using bigger windows requiring less updates. A fixed size would also work - but it
        // would need to be smaller than `stream_receive_window` in order to make sure the stream does not get stuck.
        val diff = maxStreamData(streamReceiveWindow) - sentMaxStreamData
        return canSendFlowControl && diff >= streamReceiveWindow / 8
    }

    /**
     * Records that a `MAX_STREAM_DATA` announcing a certain window was sent (recv.rs:132). This will suppress
     * enqueuing further `MAX_STREAM_DATA` frames unless either the previous transmission was not acknowledged or the
     * window further increased.
     */
    fun recordSentMaxStreamData(sentValue: Long) {
        if (sentValue > sentMaxStreamData) sentMaxStreamData = sentValue
    }

    /**
     * Whether the total amount of data that the peer will send on this stream is unknown (recv.rs:147). True until
     * we've received either a reset or the final frame.
     */
    val finalOffsetUnknown: Boolean get() = !resetRecvd && finalSize < 0

    /** Whether stream-level flow control updates should be sent for this stream (recv.rs:152). */
    val canSendFlowControl: Boolean
        // Stream-level flow control is redundant if the sender has already sent the whole stream, and moot if we no
        // longer want data on this stream.
        get() = finalOffsetUnknown && !stopped

    /** Whether data is still being accepted from the peer. */
    val isReceiving: Boolean get() = !resetRecvd

    /** Whether a RESET_STREAM was received (quinn `RecvState::ResetRecvd`). */
    val isResetRecvd: Boolean get() = resetRecvd

    /** The final size if known, else -1 (quinn `final_offset`). */
    val finalOffset: Long get() = finalSize

    /** Returns `false` iff the reset was redundant (recv.rs:176). */
    fun reset(errorCode: VarInt, finalOffset: VarInt, received: Long, maxData: Long): Boolean {
        // Validate final_offset
        val known = finalSize
        if (known >= 0) {
            if (known != finalOffset.value) throw TransportError.FINAL_SIZE_ERROR("inconsistent value")
        } else if (end > finalOffset.value) {
            throw TransportError.FINAL_SIZE_ERROR("lower than high water mark")
        }
        creditConsumedBy(finalOffset.value, received, maxData)

        if (resetRecvd) return false
        resetRecvd = true
        finalSize = finalOffset.value
        resetErrorCode = errorCode
        // Nuke buffers so that future reads fail immediately, which ensures future reads don't issue flow control
        // credit redundant to that already issued. We could instead special-case reset streams during read, but it's
        // unclear if there's any benefit to retaining data for reset streams.
        assembler.clear()
        return true
    }

    val resetCode: VarInt? get() = if (resetRecvd) resetErrorCode else null

    /**
     * Compute the amount of flow control credit consumed, or throw if more was consumed than issued (recv.rs:218).
     */
    private fun creditConsumedBy(offset: Long, received: Long, maxData: Long): Long {
        val prevEnd = end
        val newBytes = maxOf(offset - prevEnd, 0L)
        if (offset > sentMaxStreamData || received + newBytes > maxData) {
            throw TransportError.FLOW_CONTROL_ERROR("")
        }
        return newBytes
    }
}

/**
 * The outcome of [Chunks.next] (quinn's `Result<Option<Chunk>, ReadError>`): a [Chunk], [Finished] or a
 * [ReadError].
 *
 * ⚖️ quinn returns a `Result`; running out of buffered data is part of normal operation, so the error is returned
 * rather than thrown (a Kotlin/Native throw costs microseconds).
 */
sealed interface ReadResult {
    /** quinn's `Ok(None)`: the stream was finished and all its data read. */
    data object Finished : ReadResult
}

/**
 * Chunks returned from [RecvStream.read] (recv.rs:260).
 *
 * ### Note: Finalization Needed
 * Bytes read from the stream are not released from the congestion window until [finalize] (or [close]) is called.
 * It is recommended to call [finalize] because it returns a flag telling whether reading from the stream has
 * resulted in the need to transmit a packet. If this object is abandoned, the stream will remain blocked on the
 * remote peer until another read from the stream is done.
 *
 * ⚖️ quinn finalizes in `Drop`; Kotlin has no destructors, so this is [AutoCloseable] (`use { }`) and the caller
 * must finalize or close it.
 */
class Chunks internal constructor(
    private val id: StreamId,
    private val ordered: Boolean,
    private val streams: StreamsState,
    private val pending: Retransmits,
) : AutoCloseable {
    private var state = READABLE
    private var recv: Recv?
    private var resetCode = VarInt(0)
    private var read = 0L

    init {
        val slot = streams.recv.find(id.value)
        if (slot < 0) throw ReadableError.ClosedStream
        val rs = streams.getOrInsertRecv(slot)
        if (rs.stopped) throw ReadableError.ClosedStream
        streams.recv.removeAt(slot)
        // As in quinn, the stream state has already been taken out of the map when an illegal ordered read is
        // detected, so that stream state is dropped.
        if (!rs.assembler.ensureOrdering(ordered)) throw ReadableError.IllegalOrderedRead
        recv = rs
    }

    /** Next chunk of at most [maxLength] bytes (recv.rs:302). Call [finalize] when done calling this. */
    fun next(maxLength: Int): ReadResult {
        when (state) {
            RESET -> return ReadError.Reset(resetCode)
            FINISHED -> return ReadResult.Finished
            FINALIZED -> throw IllegalStateException("must not call next() after finalize()")
        }
        val rs = recv!!

        val chunk = rs.assembler.read(maxLength, ordered)
        if (chunk != null) {
            read += chunk.bytes.size
            return chunk
        }

        val code = rs.resetCode
        return if (code != null) {
            state = RESET
            resetCode = code
            recv = null
            streams.streamRecvFreed(id, rs)
            ReadError.Reset(code)
        } else if (rs.finalOffset == rs.end && rs.assembler.bytesRead == rs.end) {
            state = FINISHED
            recv = null
            streams.streamRecvFreed(id, rs)
            ReadResult.Finished
        } else {
            // We don't need a distinct state for a blocked stream because retrying a read harmlessly re-traces our
            // steps back to returning Blocked again. The buffers can't refill and the stream's own state can't
            // change so long as this `Chunks` exists.
            ReadError.Blocked
        }
    }

    /**
     * Mark the read data as consumed from the stream (recv.rs:359). The number of read bytes will be released from
     * the congestion window, allowing the remote peer to send more data if it was previously blocked.
     *
     * If the result's [ShouldTransmit.shouldTransmit] is `true`, a packet needs to be sent to the peer informing
     * them that the stream is unblocked.
     */
    fun finalize(): ShouldTransmit = finalizeInner()

    /** quinn's `Drop`: finalize, ignoring the result. */
    override fun close() {
        finalizeInner()
    }

    private fun finalizeInner(): ShouldTransmit {
        val prev = state
        if (prev == FINALIZED) return ShouldTransmit(false) // Noop on repeated calls
        state = FINALIZED

        // We issue additional stream ID credit after the application is notified that a previously open stream has
        // finished or been reset and we've therefore disposed of its state, as recorded by `stream_freed` calls in
        // `next`.
        var shouldTransmit = streams.queueMaxStreamId(pending)

        // If the stream hasn't finished, we may need to issue stream-level flow control credit
        if (prev == READABLE) {
            val rs = recv!!
            recv = null
            val maxStreamData = rs.maxStreamDataShouldTransmit(streams.streamReceiveWindow)
            shouldTransmit = shouldTransmit || maxStreamData
            if (maxStreamData) pending.maxStreamData.add(id.value)
            // Return the stream to storage for future use
            streams.recv.put(id.value, rs)
        }

        // Issue connection-level flow control credit for any data we read regardless of state
        val maxData = streams.addReadCredits(read).shouldTransmit
        pending.maxData = pending.maxData || maxData
        shouldTransmit = shouldTransmit || maxData
        return ShouldTransmit(shouldTransmit)
    }

    private companion object {
        const val READABLE = 0
        const val RESET = 1
        const val FINISHED = 2
        const val FINALIZED = 3
    }
}

/** Errors triggered when reading from a recv stream (recv.rs:411). */
sealed class ReadError : ReadResult {
    /**
     * No more data is currently available on this stream. If more data on this stream is received from the peer, a
     * [StreamEvent.Readable] will be generated for this stream, indicating that retrying the read might succeed.
     */
    data object Blocked : ReadError() {
        override fun toString(): String = "blocked"
    }

    /** The peer abandoned transmitting data on this stream. Carries an application-defined error code. */
    data class Reset(val errorCode: VarInt) : ReadError() {
        override fun toString(): String = "reset by peer: code $errorCode"
    }
}

/** Errors triggered when opening a recv stream for reading (recv.rs:427). */
sealed class ReadableError(message: String) : Exception(message) {
    /** The stream has not been opened or was already stopped, finished, or reset. */
    object ClosedStream : ReadableError("closed stream")

    /**
     * Attempted an ordered read following an unordered read. Performing an unordered read allows discontinuities to
     * arise in the receive buffer of a stream which cannot be recovered, making further ordered reads impossible.
     */
    object IllegalOrderedRead : ReadableError("ordered read after unordered read")
}
