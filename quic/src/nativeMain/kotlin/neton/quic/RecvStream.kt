package neton.quic

import neton.io.bytes.Bytes
import neton.quic.proto.Chunk
import neton.quic.proto.Chunks
import neton.quic.proto.ClosedStream
import neton.quic.proto.ReadResult
import neton.quic.proto.ReadableError
import neton.quic.proto.StreamId
import neton.quic.proto.VarInt
import neton.quic.proto.ReadError as ProtoReadError

/**
 * A stream that can only be used to receive data (recv_stream.rs:16).
 *
 * `stop(0)` is implicitly called on close unless all data has been read or the stream was reset, so that the peer
 * stops sending. When data has been read in full the stream need not be closed, though closing is harmless.
 *
 * ⚖️ quinn stops an unfinished `RecvStream` with code 0 in `Drop`; here [close] does that. Reads that find no data
 * suspend until the peer sends more.
 */
class RecvStream internal constructor(
    private val conn: ConnectionState,
    /** The identity of this stream. */
    val id: StreamId,
    private val is0rtt: Boolean,
) : AutoCloseable {
    private var allDataRead = false

    /** Whether a read (or [receivedReset]) is in progress (quinn's `&mut self` makes a second one impossible). */
    private var reading = false

    /** A reset returned together with data by an earlier read, reported by the next one (quinn `reset`). */
    private var reset: VarInt? = null

    /**
     * Read data contiguously from the stream into `buf[from, to)` (recv_stream.rs:57). Yields the number of bytes
     * read, or -1 once the stream is finished (⚖️ quinn's `Ok(None)`: -1 instead of a boxed `null`). Throws
     * [ReadError]. An empty range reads 0 bytes.
     */
    suspend fun read(buf: ByteArray, from: Int = 0, to: Int = buf.size): Int {
        if (from == to) return 0
        return exclusive { readLoop(buf, from, to) }
    }

    private suspend fun readLoop(buf: ByteArray, from: Int, to: Int): Int {
        while (true) {
            if (allDataRead) return -1
            beginRead()

            var read = 0
            var status: ReadResult? = null // null: the buffer was filled (quinn `ReadStatus::Readable`)
            val code = reset
            if (code != null) {
                status = ProtoReadError.Reset(code)
            } else {
                val chunks = openChunks(true)
                try {
                    while (from + read < to) {
                        val r = chunks.next(to - from - read)
                        if (r !is Chunk) {
                            status = r
                            break
                        }
                        r.bytes.copyInto(buf, from + read)
                        read += r.bytes.size
                    }
                } finally {
                    if (chunks.finalize().shouldTransmit) conn.wake()
                }
            }

            when (status) {
                null -> return read
                ReadResult.Finished -> {
                    allDataRead = true
                    return if (read > 0) read else -1
                }
                ProtoReadError.Blocked -> {
                    if (read > 0) return read
                    awaitData()
                }
                is ProtoReadError.Reset -> return resetWith(status.errorCode, read > 0).let { read }
                is Chunk -> throw IllegalStateException("unreachable")
            }
        }
    }

    /**
     * Read an exact number of bytes contiguously from the stream, filling `buf[from, to)` (recv_stream.rs:73). Throws
     * [ReadExactError.FinishedEarly] if the stream ends first, [ReadExactError.Read] on a read error.
     */
    suspend fun readExact(buf: ByteArray, from: Int = 0, to: Int = buf.size) {
        var pos = from
        while (pos < to) {
            val n = try {
                read(buf, pos, to)
            } catch (e: ReadError) {
                throw ReadExactError.Read(e)
            }
            if (n < 0) throw ReadExactError.FinishedEarly(pos - from)
            pos += n
        }
    }

    /**
     * Read the next segment of data (recv_stream.rs:134). Yields `null` if the stream was finished, otherwise a chunk
     * of at most [maxLength] bytes and its offset in the stream. If [ordered] is true, the chunk's offset will be
     * immediately after the last data yielded by [read] or [readChunk]; if false, segments may be received in any
     * order and the chunk's offset indicates where it fits. Slightly more efficient than [read] due to not copying.
     * Throws [ReadError].
     */
    suspend fun readChunk(maxLength: Int = Int.MAX_VALUE, ordered: Boolean = true): Chunk? =
        exclusive { readChunkLoop(maxLength, ordered) }

    private suspend fun readChunkLoop(maxLength: Int, ordered: Boolean): Chunk? {
        while (true) {
            if (allDataRead) return null
            beginRead()

            val code = reset
            val status = if (code != null) {
                ProtoReadError.Reset(code)
            } else {
                val chunks = openChunks(ordered)
                try {
                    chunks.next(maxLength)
                } finally {
                    if (chunks.finalize().shouldTransmit) conn.wake()
                }
            }

            when (status) {
                is Chunk -> return status
                ReadResult.Finished -> {
                    allDataRead = true
                    return null
                }
                ProtoReadError.Blocked -> awaitData()
                is ProtoReadError.Reset -> {
                    resetWith(status.errorCode, false)
                    return null
                }
            }
        }
    }

    /**
     * Read the next segments of data (recv_stream.rs:170): fills [bufs] with the segments that are available, up to
     * its size, and yields how many; -1 if the stream was finished (⚖️ quinn's `Ok(None)`). Slightly more efficient
     * than [read] due to not copying. Throws [ReadError].
     */
    suspend fun readChunks(bufs: Array<Bytes>): Int {
        if (bufs.isEmpty()) return 0
        return exclusive { readChunksLoop(bufs) }
    }

    private suspend fun readChunksLoop(bufs: Array<Bytes>): Int {
        while (true) {
            if (allDataRead) return -1
            beginRead()

            var read = 0
            var status: ReadResult? = null
            val code = reset
            if (code != null) {
                status = ProtoReadError.Reset(code)
            } else {
                val chunks = openChunks(true)
                try {
                    while (read < bufs.size) {
                        val r = chunks.next(Int.MAX_VALUE)
                        if (r !is Chunk) {
                            status = r
                            break
                        }
                        bufs[read] = r.bytes
                        read += 1
                    }
                } finally {
                    if (chunks.finalize().shouldTransmit) conn.wake()
                }
            }

            when (status) {
                null -> return read
                ReadResult.Finished -> {
                    allDataRead = true
                    return if (read > 0) read else -1
                }
                ProtoReadError.Blocked -> {
                    if (read > 0) return read
                    awaitData()
                }
                is ProtoReadError.Reset -> return resetWith(status.errorCode, read > 0).let { read }
                is Chunk -> throw IllegalStateException("unreachable")
            }
        }
    }

    /**
     * Convenience method to read all remaining data into a buffer (recv_stream.rs:212). Throws
     * [ReadToEndError.TooLong] if more than [sizeLimit] bytes arrive (the stream is then left partly read), and
     * [ReadToEndError.Read] on a read error. Uses unordered reads to be more efficient than using [read].
     */
    suspend fun readToEnd(sizeLimit: Int = Int.MAX_VALUE): ByteArray {
        val buffer = ReadToEndBuffer(sizeLimit.toLong())
        while (true) {
            val chunk = try {
                readChunk(Int.MAX_VALUE, false)
            } catch (e: ReadError) {
                throw ReadToEndError.Read(e)
            } ?: return buffer.finish()
            buffer.push(chunk)
        }
    }

    /**
     * Stop accepting data (recv_stream.rs:234). Discards unread data and notifies the peer to stop transmitting.
     * Throws [ClosedStream] if the stream was already stopped, finished, or reset.
     */
    fun stop(errorCode: VarInt) {
        if (is0rtt && !conn.check0rtt()) return
        conn.inner.recvStream(id).stop(errorCode)
        conn.wake()
        allDataRead = true
        // Clean up shared state that might be left over from a cancelled read operation, so `close` doesn't have to
        // (a read still waiting is resumed and finds the stream stopped)
        conn.releaseWaiter(id, conn.blockedReaders)
    }

    /** Check if this stream has been opened during 0-RTT (and may therefore be replayed by an attacker). */
    fun is0rtt(): Boolean = is0rtt

    /**
     * Completes when the stream has been reset by the peer or otherwise closed (recv_stream.rs:271). Yields the reset
     * error code if the stream was reset, `null` if it was otherwise closed (finished, or stopped by us). Throws
     * [ResetError].
     */
    suspend fun receivedReset(): VarInt? = exclusive { receivedResetLoop() }

    private suspend fun receivedResetLoop(): VarInt? {
        while (true) {
            if (is0rtt && !conn.check0rtt()) throw ResetError.ZeroRttRejected()
            reset?.let { return it }
            val code = try {
                conn.inner.recvStream(id).receivedReset()
            } catch (e: ClosedStream) {
                return null
            }
            if (code != null) {
                // Stream state has just now been freed, so the connection may need to issue new stream ID flow
                // control credit
                conn.wake()
                return code
            }
            conn.error?.let { throw ResetError.ConnectionLost(it) }
            // Resets always notify readers, since a reset is an immediate read error
            conn.awaitReadable(id)
        }
    }

    /**
     * ⚖️ quinn's `Drop`: unless all data was read (or the stream was stopped or reset), stop it with code 0 so that
     * the peer stops sending. Idempotent.
     */
    override fun close() {
        // Clean up any previously registered wakers (a read still waiting is resumed and finds the stream closed)
        conn.releaseWaiter(id, conn.blockedReaders)
        if (allDataRead) return

        if (conn.error != null || (is0rtt && !conn.check0rtt())) return
        try {
            conn.inner.recvStream(id).stop(VarInt(0))
        } catch (_: ClosedStream) {
            // Ignore ClosedStream errors
        }
        allDataRead = true
        conn.wake()
    }

    override fun toString(): String = "RecvStream($id)"

    // ---- quinn `poll_read_generic` ----

    /**
     * ⚖️ One read at a time: quinn's reads borrow the stream mutably; here a second concurrent read throws
     * [IllegalStateException] (it would otherwise replace the first one's wake-up and leave it waiting forever).
     */
    private inline fun <T> exclusive(body: () -> T): T {
        check(!reading) { "concurrent read on $this" }
        reading = true
        try {
            return body()
        } finally {
            reading = false
        }
    }

    private fun beginRead() {
        if (is0rtt && !conn.check0rtt()) throw ReadError.ZeroRttRejected()
    }

    private fun openChunks(ordered: Boolean): Chunks = try {
        conn.inner.recvStream(id).read(ordered)
    } catch (e: ReadableError) {
        throw when (e) {
            ReadableError.ClosedStream -> ReadError.ClosedStream()
            ReadableError.IllegalOrderedRead -> ReadError.IllegalOrderedRead()
        }
    }

    /** Nothing to read: fail if the connection is gone, else wait for the stream to become readable. */
    private suspend fun awaitData() {
        conn.error?.let { throw ReadError.ConnectionLost(it) }
        conn.awaitReadable(id)
    }

    /** The peer reset the stream: report it now, or after the data read along with it ([withData]). */
    private fun resetWith(code: VarInt, withData: Boolean) {
        reset = code
        if (!withData) {
            allDataRead = true
            throw ReadError.Reset(code)
        }
    }
}

/**
 * The chunks collected by [RecvStream.readToEnd] (quinn `ReadToEndBuffer`): unordered reads may arrive in any order,
 * so the buffer is assembled once the stream ends.
 */
internal class ReadToEndBuffer(private val sizeLimit: Long) {
    internal val read = ArrayList<Chunk>()
    private var start = Long.MAX_VALUE
    private var end = 0L

    fun push(chunk: Chunk) {
        start = minOf(start, chunk.offset)
        end = maxOf(end, chunk.bytes.size + chunk.offset)
        if (end - start > sizeLimit) throw ReadToEndError.TooLong()
        read.add(chunk)
    }

    fun finish(): ByteArray {
        if (end == 0L) return ByteArray(0)
        val buffer = ByteArray((end - start).toInt())
        for (chunk in read) chunk.bytes.copyInto(buffer, (chunk.offset - start).toInt())
        read.clear()
        return buffer
    }
}
