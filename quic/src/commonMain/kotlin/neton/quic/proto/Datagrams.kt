package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes

// Unreliable datagrams, RFC 9221 (quinn-proto `connection/datagrams.rs`).
//
// ⚖️ quinn's `Datagrams<'a>` view reads the connection's config, path MTU and peer transport parameters; its logic is
// here as `DatagramState` methods taking those values ([DatagramState.send], [DatagramState.maxSize],
// [DatagramState.sendBufferSpace], [DatagramState.dropOversizedAndUnblock]), so the connection's view only forwards.
// Sizes are `Long`, with -1 standing for quinn's `None` (no boxing on the per-datagram paths), and the queues hold the
// payload `Bytes` directly (quinn's `Datagram { data }` wrapper adds nothing).

/**
 * Per-datagram bookkeeping charged against the datagram buffers: quinn uses `size_of::<Datagram>()`, which is 32 on
 * 64-bit platforms (a `Bytes`). ⚖️ Fixed at that value so buffer limits behave identically on every target.
 */
const val DATAGRAM_OVERHEAD: Long = 32

/** Errors that can arise when sending a datagram (datagrams.rs:337). */
sealed class SendDatagramError {
    /** The peer does not support receiving datagram frames. */
    data object UnsupportedByPeer : SendDatagramError() {
        override fun toString(): String = "datagrams not supported by peer"
    }

    /** Datagram support is disabled locally. */
    data object Disabled : SendDatagramError() {
        override fun toString(): String = "datagram support disabled"
    }

    /**
     * The datagram is larger than the connection can currently accommodate: the path MTU minus overhead or the
     * limit advertised by the peer has been exceeded.
     */
    data object TooLarge : SendDatagramError() {
        override fun toString(): String = "datagram too large"
    }

    /** Send would block; carries the datagram back. */
    data class Blocked(val data: Bytes) : SendDatagramError() {
        override fun toString(): String = "datagram send blocked"
    }
}

/** Datagram queues of a connection (datagrams.rs:112). */
class DatagramState {
    internal val incoming = DatagramBuffer()
    internal val outgoing = DatagramBuffer()
    internal var sendBlocked = false

    /**
     * Queue an unreliable, unordered datagram for immediate transmission (quinn `Datagrams::send`,
     * datagrams.rs:28). Returns `null` on success.
     *
     * If [drop] is true, previously queued datagrams which are still unsent may be discarded to make space for this
     * datagram, in order of oldest to newest. If [drop] is false, and there isn't enough space due to previously
     * queued datagrams, this returns [SendDatagramError.Blocked]; the connection emits `DatagramsUnblocked` once
     * datagrams have been sent.
     *
     * [receiveBufferSize] is the configured `datagram_receive_buffer_size` (-1: `None`, datagrams disabled),
     * [sendBufferSize] the configured `datagram_send_buffer_size`, [maxSize] the result of [maxSize] (-1: `None`).
     */
    fun send(data: Bytes, drop: Boolean, receiveBufferSize: Long, sendBufferSize: Long, maxSize: Long): SendDatagramError? {
        if (receiveBufferSize < 0) return SendDatagramError.Disabled
        if (maxSize < 0) return SendDatagramError.UnsupportedByPeer
        val maxBufferPayload = sendBufferSize - DATAGRAM_OVERHEAD
        if (maxBufferPayload < 0) return SendDatagramError.TooLarge
        if (data.size > minOf(maxSize, maxBufferPayload)) return SendDatagramError.TooLarge
        if (drop) {
            makeSpaceFor(data.size.toLong(), sendBufferSize)
        } else if (!hasSendBufferSpace(data.size.toLong(), sendBufferSize)) {
            sendBlocked = true
            return SendDatagramError.Blocked(data)
        }
        outgoing.pushBack(data)
        return null
    }

    /**
     * Discard queued datagrams that no longer fit the active path (quinn `Datagrams::drop_oversized`,
     * datagrams.rs:58). Returns whether blocked senders were woken, i.e. whether the connection must emit
     * `Event::DatagramsUnblocked`. [maxDatagramSize] is [maxSize] (-1: `None`).
     */
    fun dropOversizedAndUnblock(maxDatagramSize: Long): Boolean {
        if (maxDatagramSize < 0) return false
        if (!dropOversized(maxDatagramSize) || !sendBlocked) return false
        sendBlocked = false
        return true
    }

    /**
     * Receive an unreliable, unordered datagram (datagrams.rs:238); `null` when none is queued.
     */
    fun recv(): Bytes? = incoming.popFront()

    /**
     * Bytes available in the outgoing datagram buffer (quinn `Datagrams::send_buffer_space`, datagrams.rs:104). When
     * greater than zero, sending a datagram of at most this size is guaranteed not to cause older datagrams to be
     * dropped.
     */
    fun sendBufferSpace(sendBufferSize: Long): Long =
        maxOf(maxOf(sendBufferSize - outgoing.memoryUsed(), 0L) - DATAGRAM_OVERHEAD, 0L)

    /**
     * Process a received DATAGRAM frame's payload (datagrams.rs:119). [window] is the configured
     * `datagram_receive_buffer_size` (-1: `None`). Returns whether the incoming queue was empty before, i.e. whether
     * the application should be notified. Throws [TransportError].
     */
    internal fun received(data: Bytes, window: Long): Boolean {
        if (window < 0) throw TransportError.PROTOCOL_VIOLATION("unexpected DATAGRAM frame")

        val sizeWithOverhead = data.size + DATAGRAM_OVERHEAD

        if (sizeWithOverhead > window) throw TransportError.PROTOCOL_VIOLATION("oversized datagram")

        val wasEmpty = incoming.isEmpty()
        while (incoming.memoryUsed() + sizeWithOverhead > window) {
            recv() // dropping stale datagram
        }

        incoming.pushBack(data)
        return wasEmpty
    }

    internal fun makeSpaceFor(datagramLen: Long, sendBufferSize: Long) {
        while (!hasSendBufferSpace(datagramLen, sendBufferSize)) {
            outgoing.popFront() ?: break // dropping outgoing datagram
        }
    }

    internal fun hasSendBufferSpace(datagramLen: Long, sendBufferSize: Long): Boolean {
        // checked_add twice: an overflow means there is no space
        val used = outgoing.memoryUsed()
        val total = used + datagramLen
        if (total < used) return false
        val withOverhead = total + DATAGRAM_OVERHEAD
        if (withOverhead < total) return false
        return withOverhead <= sendBufferSize
    }

    /**
     * Discard outgoing datagrams with a payload larger than [maxPayload] bytes; returns whether any were dropped
     * (datagrams.rs:188). Used to ensure that reductions in MTU don't get us stuck with a datagram queued that can't
     * be sent.
     */
    internal fun dropOversized(maxPayload: Long): Boolean = outgoing.removeLargerThan(maxPayload)

    /**
     * Attempt to write a DATAGRAM frame into [buf], consuming it from the outgoing queue (datagrams.rs:211). Returns
     * whether a frame was written. At most [maxSize] bytes will be written, including framing.
     */
    internal fun write(buf: Buffer, maxSize: Int): Boolean {
        val datagram = outgoing.popFront() ?: return false

        if (buf.len + datagramFrameSize(datagram) > maxSize) {
            // Future work: we could be more clever about cramming small datagrams into mostly-full packets when a
            // larger one is queued first
            outgoing.pushFront(datagram)
            return false
        }

        // Frame.Datagram(datagram).encode(true, buf), without allocating the frame
        FrameType(FrameType.DATAGRAM_TYS_START or 1L).encode(buf)
        buf.writeVar(datagram.size.toLong())
        buf.writeBytes(datagram)
        return true
    }

    internal companion object {
        /** Maximum size of datagrams that may be passed to [send] (quinn `Datagrams::max_size`, datagrams.rs:84). */
        fun maxSize(currentMtu: Int, oneRttOverhead: Int, peerMaxDatagramFrameSize: VarInt?): Long {
            // We use the conservative overhead bound for any packet number, reducing the budget by at most 3 bytes,
            // so that PN size fluctuations don't cause users sending maximum-size datagrams to suffer avoidable
            // packet loss.
            val maxSize = currentMtu.toLong() - oneRttOverhead - Frame.Datagram.SIZE_BOUND
            val limit = maxOf((peerMaxDatagramFrameSize ?: return -1).value - Frame.Datagram.SIZE_BOUND, 0L)
            return minOf(limit, maxSize)
        }
    }
}

/** Encoded size of a DATAGRAM frame with an explicit length (quinn `Datagram::size(true)`). */
internal fun datagramFrameSize(data: Bytes): Int = 1 + varIntSize(data.size.toLong()) + data.size

/** A queue of datagram payloads with their memory accounting (datagrams.rs:249). */
internal class DatagramBuffer {
    internal val queue = ArrayDeque<Bytes>()
    internal var payloadBytes = 0L

    fun pushBack(datagram: Bytes) {
        payloadBytes += datagram.size
        queue.addLast(datagram)
    }

    fun popFront(): Bytes? {
        val datagram = queue.removeFirstOrNull() ?: return null
        payloadBytes -= datagram.size
        return datagram
    }

    fun pushFront(datagram: Bytes) {
        payloadBytes += datagram.size
        queue.addFirst(datagram)
    }

    fun memoryUsed(): Long {
        val r = payloadBytes + queue.size * DATAGRAM_OVERHEAD
        return if (r < payloadBytes) Long.MAX_VALUE else r // saturating_add
    }

    fun canSend1rtt(maxSize: Int): Boolean {
        val front = queue.firstOrNull() ?: return false
        return datagramFrameSize(front) <= maxSize
    }

    fun isEmpty(): Boolean = queue.isEmpty()

    /** quinn's `queue.retain(|d| d.len() <= max_payload)` with the accounting of `drop_oversized`. */
    fun removeLargerThan(maxPayload: Long): Boolean {
        var droppedAny = false
        val it = queue.iterator()
        while (it.hasNext()) {
            val d = it.next()
            if (d.size > maxPayload) {
                payloadBytes -= d.size
                it.remove()
                droppedAny = true
            }
        }
        return droppedAny
    }
}
