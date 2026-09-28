package neton.quic

import neton.io.bytes.Buffer
import neton.io.core.ClosedException
import neton.io.core.IoException
import neton.io.core.IoStream
import neton.io.core.StreamCapability
import neton.quic.proto.ClosedStream

/**
 * A bidirectional QUIC stream as a neton-io [IoStream] (SPEC §3; quinn implements `futures-io` / `tokio` `AsyncRead`
 * and `AsyncWrite` for its streams), so that protocols built on neton-io's `Framed` / codecs run over QUIC.
 *
 * - [read] reads from [recv]: bytes are appended to `dst`; -1 once the peer has finished the stream.
 * - [write] writes all of `src` to [send], suspending while flow control blocks it (backpressure).
 * - [flush] does nothing (quinn: `poll_flush` is always ready); data goes out as the connection's driver sends it.
 * - [shutdownOutput] finishes [send] (quinn's `poll_close` / `poll_shutdown`).
 * - [close] closes both halves by the lifecycle rules: [send] is finished (reset with the peer's code if the peer
 *   stopped it), [recv] is stopped with code 0 unless it was read to its end. It does not close the connection.
 *
 * Errors surface as [QuicStreamException], an [IoException] carrying the stream error (quinn maps them to
 * `io::Error`: a peer's reset or stop is `ConnectionReset`, a lost connection `NotConnected`); after [close], and for
 * operations parked when it is called, as [ClosedException].
 *
 * Capabilities (neton-io SPEC §28.6): [StreamCapability.HalfClose] and [StreamCapability.ResumableAfterCancel] — a
 * cancelled read loses no data and a cancelled write has advanced `src` by exactly what the stream accepted. No
 * timeouts (use `withTimeout`; the QUIC connection has its own idle timeout) and no [StreamCapability.AnyThread]: like
 * its connection, the stream belongs to the endpoint's reactor.
 */
class QuicStream(
    /** The sending half. */
    val send: SendStream,
    /** The receiving half. */
    val recv: RecvStream,
) : IoStream {
    override val capabilities: Set<StreamCapability> get() = CAPABILITIES

    private var closed = false
    private var reading = false
    private var writing = false

    override suspend fun read(dst: Buffer): Int {
        checkOpen()
        check(!reading) { "concurrent read on $this" }
        reading = true
        try {
            dst.reserve(READ_RESERVE)
            val array = dst.backingArray()
            val start = dst.writerIndex()
            val n = try {
                recv.read(array, start, array.size)
            } catch (e: ReadError) {
                if (closed) throw ClosedException()
                throw QuicStreamException(e)
            }
            if (n > 0) {
                dst.commitWrite(n)
                return n
            }
            // A read parked when the stream is closed is resumed and finds it stopped
            if (closed) throw ClosedException()
            return -1
        } finally {
            reading = false
        }
    }

    override suspend fun write(src: Buffer): Int {
        checkOpen()
        check(!writing) { "concurrent write on $this" }
        writing = true
        try {
            val total = src.readableBytes
            while (src.readableBytes > 0) {
                val from = src.readerIndex()
                val n = try {
                    send.write(src.backingArray(), from, from + src.readableBytes)
                } catch (e: WriteError) {
                    if (closed) throw ClosedException()
                    throw QuicStreamException(e)
                }
                // The stream copied the bytes: `src` is advanced by what it accepted, and is reusable at once
                src.consume(n)
            }
            return total
        } finally {
            writing = false
        }
    }

    override suspend fun flush() {}

    override suspend fun shutdownOutput() {
        checkOpen()
        try {
            send.finish()
        } catch (e: ClosedStream) {
            throw QuicStreamException(e)
        }
    }

    /** Idempotent. Operations parked on the stream end with [ClosedException]. */
    override fun close() {
        if (closed) return
        closed = true
        send.close()
        recv.close()
    }

    private fun checkOpen() {
        if (closed) throw ClosedException()
    }

    override fun toString(): String = "QuicStream(${send.id})"

    private companion object {
        val CAPABILITIES = setOf(StreamCapability.HalfClose, StreamCapability.ResumableAfterCancel)

        /** Room made in the read buffer for one read. */
        const val READ_RESERVE = 16 * 1024
    }
}

/** A stream error surfaced through [QuicStream]: [error] is the [WriteError], [ReadError] or [ClosedStream]. */
class QuicStreamException(val error: Exception) : IoException(error.message ?: error.toString())

/** Open a bidirectional stream as an [IoStream] ([Connection.openBi]). */
suspend fun Connection.openBiStream(): QuicStream {
    val (send, recv) = openBi()
    return QuicStream(send, recv)
}

/** Accept a bidirectional stream as an [IoStream] ([Connection.acceptBi]). */
suspend fun Connection.acceptBiStream(): QuicStream {
    val (send, recv) = acceptBi()
    return QuicStream(send, recv)
}
