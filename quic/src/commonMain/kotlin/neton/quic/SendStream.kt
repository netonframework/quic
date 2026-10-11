package neton.quic

import neton.io.bytes.Bytes
import neton.quic.proto.ClosedStream
import neton.quic.proto.FinishError
import neton.quic.proto.StreamId
import neton.quic.proto.VarInt
import neton.quic.proto.WriteResult
import neton.quic.proto.Written
import neton.quic.proto.SendStream as ProtoSendStream
import neton.quic.proto.WriteError as ProtoWriteError

/**
 * A stream that can only be used to send data (send_stream.rs:20).
 *
 * If dropped, streams that haven't been explicitly [reset] will be implicitly [finished][finish], continuing to
 * (re)transmit previously written data until it has been fully acknowledged or the connection is closed.
 *
 * ⚖️ quinn finishes (or, when the peer stopped the stream, resets) a `SendStream` in `Drop`; here [close] does that,
 * so use it with `use { }` or call [close] when done. A write that is waiting for flow-control credit suspends.
 */
class SendStream internal constructor(
    private val conn: ConnectionState,
    /** The identity of this stream. */
    val id: StreamId,
    private val is0rtt: Boolean,
) : AutoCloseable {
    /** Whether a write is in progress (quinn's `&mut self` makes a second one impossible). */
    private var writing = false

    /**
     * Write bytes `data[from, to)` to the stream (send_stream.rs:55). Yields the number of bytes written on success;
     * congestion and flow control may cause this to be shorter than the input, and it suspends while nothing can be
     * written. Throws [WriteError].
     */
    suspend fun write(data: ByteArray, from: Int = 0, to: Int = data.size): Int = execute { it.write(data, from, to) }.bytes

    /** Convenience method to write an entire buffer to the stream (send_stream.rs:64). Throws [WriteError]. */
    suspend fun writeAll(data: ByteArray, from: Int = 0, to: Int = data.size) {
        var start = from
        while (start < to) start += write(data, start, to)
    }

    /**
     * Write chunks to the stream without copying (send_stream.rs:80). Yields the number of bytes and chunks written:
     * fully written chunks are replaced by empty ones in [data], a partially written chunk by its unwritten rest.
     * Throws [WriteError].
     */
    suspend fun writeChunks(data: Array<Bytes>): Written = execute { it.writeChunks(data) }

    /** Convenience method to write a single chunk in its entirety to the stream (send_stream.rs:87). */
    suspend fun writeChunk(data: Bytes) {
        writeAllChunks(arrayOf(data))
    }

    /**
     * Convenience method to write an entire list of chunks to the stream (send_stream.rs:95); [data] is left holding
     * empty chunks. Throws [WriteError].
     */
    suspend fun writeAllChunks(data: Array<Bytes>) {
        // Written chunks become empty in place and count as written again, so the whole array is passed each time
        while (data.isNotEmpty()) {
            if (writeChunks(data).chunks >= data.size) return
        }
    }

    /**
     * quinn `execute_poll`: run [writeFn], suspending while the stream is blocked. ⚖️ One write at a time: quinn's
     * writes borrow the stream mutably; here a second concurrent write throws [IllegalStateException] (it would
     * otherwise replace the first one's wake-up and leave it waiting forever).
     */
    private var writesSinceYield = 0

    private suspend inline fun execute(writeFn: (ProtoSendStream) -> WriteResult): Written {
        check(!writing) { "concurrent write on $this" }
        writing = true
        try {
            return executeLoop(writeFn)
        } finally {
            writing = false
        }
    }

    private suspend inline fun executeLoop(writeFn: (ProtoSendStream) -> WriteResult): Written {
        while (true) {
            if (is0rtt && !conn.check0rtt()) throw WriteError.ZeroRttRejected()
            conn.error?.let { throw WriteError.ConnectionLost(it) }
            when (val result = writeFn(conn.inner.sendStream(id))) {
                is Written -> {
                    conn.wake()
                    // Cooperative budget (tokio's coop budget in quinn): a writer that keeps finding credit never
                    // suspends, so the connection's driver it just woke would not run — nothing sent, no packet
                    // handled (a STOP_SENDING waited for a whole stream window). Yield after a bounded number of writes.
                    if (++writesSinceYield >= COOP_WRITES) {
                        writesSinceYield = 0
                        kotlinx.coroutines.yield()
                    }
                    return result
                }
                ProtoWriteError.Blocked -> { writesSinceYield = 0; conn.awaitWritable(id) }
                is ProtoWriteError.Stopped -> throw WriteError.Stopped(result.errorCode)
                ProtoWriteError.ClosedStream -> throw WriteError.ClosedStream()
            }
        }
    }

    /**
     * Notify the peer that no more data will ever be written to this stream (send_stream.rs:138). It is an error to
     * write to a finished stream. No new data may be written after calling this; the stream is finished once all
     * previously written data has been acknowledged by the peer. Throws [ClosedStream] if the stream was already
     * finished or reset.
     */
    fun finish() {
        try {
            conn.inner.sendStream(id).finish()
            conn.wake()
        } catch (e: FinishError.ClosedStream) {
            throw ClosedStream()
        } catch (e: FinishError.Stopped) {
            // Harmless. If the application needs to know about stopped streams at this point, it should call
            // `stopped`.
        }
    }

    /**
     * Close the send stream immediately (send_stream.rs:163). No new data can be written after calling this; data
     * that is not yet delivered will not be retransmitted. Throws [ClosedStream] if the stream was already finished
     * or reset.
     */
    fun reset(errorCode: VarInt) {
        if (is0rtt && !conn.check0rtt()) return
        conn.inner.sendStream(id).reset(errorCode)
        conn.wake()
    }

    /** Set the priority of the send stream: higher first, round-robin among equals. Throws [ClosedStream]. */
    fun setPriority(priority: Int) {
        conn.inner.sendStream(id).setPriority(priority)
    }

    /** Get the priority of the send stream. Throws [ClosedStream]. */
    fun priority(): Int = conn.inner.sendStream(id).priority()

    /**
     * Completes when the peer stops the stream or reads the stream to completion (send_stream.rs:208).
     *
     * Returns the error code if the peer stopped the stream, `null` if the stream was finished or reset and all
     * its data has been dealt with. Throws [StoppedError] if the connection was lost or 0-RTT rejected. Still usable
     * after [close].
     */
    suspend fun stopped(): VarInt? {
        while (true) {
            if (is0rtt && !conn.check0rtt()) throw StoppedError.ZeroRttRejected()
            try {
                conn.inner.sendStream(id).stopped()?.let { return it }
            } catch (e: ClosedStream) {
                return null
            }
            conn.error?.let { throw StoppedError.ConnectionLost(it) }
            conn.awaitStopped(id)
        }
    }

    /**
     * ⚖️ quinn's `Drop`: finish the stream (or reset it with the peer's code if it was stopped) unless the connection
     * is gone or it already was finished or reset. Idempotent.
     */
    override fun close() {
        // Clean up any previously registered wakers (a write still waiting is resumed and fails)
        conn.releaseWaiter(id, conn.blockedWriters)

        if (conn.error != null || (is0rtt && !conn.check0rtt())) return
        try {
            conn.inner.sendStream(id).finish()
            conn.wake()
        } catch (e: FinishError.Stopped) {
            try {
                conn.inner.sendStream(id).reset(e.errorCode)
                conn.wake()
            } catch (_: ClosedStream) {
            }
        } catch (e: FinishError.ClosedStream) {
            // Already finished or reset, which is fine
        }
    }

    override fun toString(): String = "SendStream($id)"
}

/** Writes that complete without suspending before a writer yields to the reactor (see [SendStream.write]). */
private const val COOP_WRITES = 32

