package neton.quic.proto

import neton.io.bytes.Bytes

// Send half of a stream (quinn-proto `connection/streams/send.rs`).

/** quinn `SendState` (send.rs:376); `DataSent { finish_acked }` keeps its flag in [Send.finishAcked]. */
internal enum class SendState {
    /** Sending new data. */
    Ready,

    /** Stream was finished; now sending retransmits only. */
    DataSent,

    /** Sent RESET. */
    ResetSent,
}

/** Send-side stream state (send.rs:7). */
internal class Send(maxData: VarInt) {
    var maxData: Long = maxData.value
    var state = SendState.Ready

    /** quinn's `SendState::DataSent { finish_acked }`. */
    var finishAcked = false
    val pending = SendBuffer()
    var priority = 0

    /** Whether a frame containing a FIN bit must be transmitted, even if we don't have any new data. */
    var finPending = false

    /** Whether this stream is in the `connection_blocked` list of `Streams`. */
    var connectionBlocked = false

    /**
     * Value of `max_data` for which a `STREAM_DATA_BLOCKED` frame was most recently queued, or -1 (quinn `None`).
     * A new frame is only queued once the peer has raised the limit.
     */
    var dataBlockedLimit = -1L

    /** The reason the peer wants us to stop, if `STOP_SENDING` was received. */
    var stopReason: VarInt? = null

    /** Whether the stream has been reset. */
    val isReset: Boolean get() = state == SendState.ResetSent

    /** send.rs:47 */
    fun finish() {
        val code = stopReason
        if (code != null) {
            throw FinishError.Stopped(code)
        } else if (state == SendState.Ready) {
            state = SendState.DataSent
            finishAcked = false
            finPending = true
        } else {
            throw FinishError.ClosedStream
        }
    }

    /** send.rs:61 */
    fun write(source: BytesSource, limit: Long): WriteResult {
        if (!isWritable) return WriteError.ClosedStream
        stopReason?.let { return WriteError.Stopped(it) }
        val budget = maxData - pending.offset
        if (budget == 0L) return WriteError.Blocked
        var limit = minOf(limit, budget, Int.MAX_VALUE.toLong()).toInt()

        val chunksBefore = source.chunksConsumed
        var bytes = 0
        while (true) {
            val chunk = source.popChunk(limit)
            bytes += chunk.size
            if (chunk.isEmpty) break
            limit -= chunk.size
            pending.write(chunk)
        }
        return Written(bytes, source.chunksConsumed - chunksBefore)
    }

    /** Update stream state due to a reset sent by the local application (send.rs:101). */
    fun reset() {
        if (state == SendState.DataSent || state == SendState.Ready) {
            state = SendState.ResetSent
            pending.discard()
            finPending = false
        }
    }

    /**
     * Handle STOP_SENDING (send.rs:114). Returns true if the stream was stopped due to this frame, and false if it
     * had been stopped before.
     */
    fun tryStop(errorCode: VarInt): Boolean {
        if (stopReason == null) {
            stopReason = errorCode
            return true
        }
        return false
    }

    /**
     * Returns whether the stream has been finished and all data has been acknowledged by the peer (send.rs:124).
     */
    fun ack(start: Long, end: Long, fin: Boolean): Boolean {
        pending.ack(start, end)
        return when (state) {
            SendState.DataSent -> {
                finishAcked = finishAcked || fin
                finishAcked && pending.isFullyAcked
            }
            else -> false
        }
    }

    /** Handle increase to stream-level flow control limit; returns whether the stream was unblocked (send.rs:140). */
    fun increaseMaxData(offset: Long): Boolean {
        if (offset <= maxData || state != SendState.Ready) return false
        val wasBlocked = pending.offset == maxData
        maxData = offset
        return wasBlocked
    }

    val offset: Long get() = pending.offset

    val isPending: Boolean get() = pending.hasUnsentData || finPending

    val isWritable: Boolean get() = state == SendState.Ready
}

/**
 * A source of one or more buffers which can be converted into [Bytes] on demand (send.rs:251).
 *
 * The purpose of this type is to defer conversion as long as possible, so that no heap allocation is required in
 * case no data is writable.
 */
interface BytesSource {
    /**
     * Returns the next chunk from the source, consuming parts of it, up to [limit] bytes. The result is empty if the
     * limit is zero or no more data is available.
     *
     * ⚖️ quinn also returns how many complete chunks were consumed by this call; here that count accumulates in
     * [chunksConsumed], which saves a tuple per call.
     */
    fun popChunk(limit: Int): Bytes

    /** Complete chunks of the source consumed so far (skipped empty ones included, a partial one not). */
    val chunksConsumed: Int
}

/**
 * A [BytesSource] over an array of [Bytes] (send.rs:193): dequeues chunks up to a limit. Consumed entries are
 * replaced by empty ones and a partially consumed entry is replaced by its unwritten rest, as quinn does to the
 * caller's slice.
 */
class BytesArray(private val chunks: Array<Bytes>) : BytesSource {
    /** Index of the next entry. */
    private var consumed = 0

    override var chunksConsumed = 0
        private set

    override fun popChunk(limit: Int): Bytes {
        // The loop exists to skip empty chunks while still marking them as consumed
        while (consumed < chunks.size) {
            val chunk = chunks[consumed]
            if (chunk.size <= limit) {
                chunks[consumed] = Bytes.EMPTY
                consumed += 1
                chunksConsumed += 1
                if (chunk.isEmpty) continue
                return chunk
            } else if (limit > 0) {
                chunks[consumed] = chunk.slice(limit)
                return chunk.slice(0, limit)
            } else {
                break
            }
        }
        return Bytes.EMPTY
    }
}

/**
 * A [BytesSource] over a byte array (send.rs:231): yields a single chunk, copied lazily so that the copy happens
 * only once it is known how much data is writable.
 */
class ByteSlice(private val data: ByteArray, from: Int = 0, private val to: Int = data.size) : BytesSource {
    private var pos = from

    override var chunksConsumed = 0
        private set

    override fun popChunk(limit: Int): Bytes {
        val n = minOf(limit, to - pos)
        if (n == 0) return Bytes.EMPTY
        val chunk = Bytes.copyOf(data, pos, pos + n)
        pos += n
        if (pos == to) chunksConsumed += 1
        return chunk
    }
}

/**
 * The outcome of a write (quinn's `Result<Written, WriteError>`): [Written] or a [WriteError].
 *
 * ⚖️ quinn returns a `Result`; running out of flow-control credit is part of normal operation, so the error is
 * returned rather than thrown (a Kotlin/Native throw costs microseconds).
 */
sealed interface WriteResult

/** Indicates how many bytes and chunks had been transferred in a write operation (send.rs:268). */
data class Written(
    /** The amount of bytes which had been written. */
    val bytes: Int,
    /** The amount of full chunks which had been written; a partially written chunk is not counted. */
    val chunks: Int,
) : WriteResult

/** Errors triggered while writing to a send stream (send.rs:280). */
sealed class WriteError : WriteResult {
    /**
     * The peer is not able to accept additional data, or the connection is congested. If the peer issues additional
     * flow control credit, a [StreamEvent.Writable] event will be generated, indicating that retrying the write
     * might succeed.
     */
    data object Blocked : WriteError() {
        override fun toString(): String = "unable to accept further writes"
    }

    /**
     * The peer is no longer accepting data on this stream, and it has been implicitly reset. The stream cannot be
     * finished or further written to. Carries an application-defined error code.
     */
    data class Stopped(val errorCode: VarInt) : WriteError() {
        override fun toString(): String = "stopped by peer: code $errorCode"
    }

    /** The stream has not been opened or has already been finished or reset. */
    data object ClosedStream : WriteError() {
        override fun toString(): String = "closed stream"
    }
}

/** Reasons why attempting to finish a stream might fail (send.rs:387). */
sealed class FinishError(message: String) : Exception(message) {
    /**
     * The peer is no longer accepting data on this stream. No [StreamEvent.Finished] event will be emitted for this
     * stream. Carries an application-defined error code.
     */
    class Stopped(val errorCode: VarInt) : FinishError("stopped by peer: code $errorCode") {
        override fun equals(other: Any?): Boolean = other is Stopped && other.errorCode == errorCode
        override fun hashCode(): Int = errorCode.hashCode()
    }

    /** The stream has not been opened or was already finished or reset. */
    object ClosedStream : FinishError("closed stream")
}
