package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import neton.io.net.EcnCodepoint

// QUIC frames (quinn-proto `frame.rs`; RFC 9000 §19, RFC 9221 DATAGRAM, draft-ietf-quic-ack-frequency).

/** A QUIC frame type (frame.rs:23). */
value class FrameType(val value: Long) {

    fun encode(buf: Buffer) = buf.writeVar(value)

    internal val isStream: Boolean get() = value in STREAM_TYS_START..STREAM_TYS_END
    internal val isDatagram: Boolean get() = value in DATAGRAM_TYS_START..DATAGRAM_TYS_END

    /** quinn's `Display`: the constant's name, `STREAM`, `DATAGRAM` or `<unknown xx>`. */
    val displayName: String
        get() = NAMES[value] ?: when {
            isStream -> "STREAM"
            isDatagram -> "DATAGRAM"
            else -> "<unknown ${hex2(value)}>"
        }

    /** quinn's `Debug`: the constant's name or `Type(xx)`. */
    override fun toString(): String = NAMES[value] ?: "Type(${hex2(value)})"

    companion object {
        val PADDING = FrameType(0x00)
        val PING = FrameType(0x01)
        val ACK = FrameType(0x02)
        val ACK_ECN = FrameType(0x03)
        val RESET_STREAM = FrameType(0x04)
        val STOP_SENDING = FrameType(0x05)
        val CRYPTO = FrameType(0x06)
        val NEW_TOKEN = FrameType(0x07)
        // STREAM: 0x08..0x0f
        val MAX_DATA = FrameType(0x10)
        val MAX_STREAM_DATA = FrameType(0x11)
        val MAX_STREAMS_BIDI = FrameType(0x12)
        val MAX_STREAMS_UNI = FrameType(0x13)
        val DATA_BLOCKED = FrameType(0x14)
        val STREAM_DATA_BLOCKED = FrameType(0x15)
        val STREAMS_BLOCKED_BIDI = FrameType(0x16)
        val STREAMS_BLOCKED_UNI = FrameType(0x17)
        val NEW_CONNECTION_ID = FrameType(0x18)
        val RETIRE_CONNECTION_ID = FrameType(0x19)
        val PATH_CHALLENGE = FrameType(0x1a)
        val PATH_RESPONSE = FrameType(0x1b)
        val CONNECTION_CLOSE = FrameType(0x1c)
        val APPLICATION_CLOSE = FrameType(0x1d)
        val HANDSHAKE_DONE = FrameType(0x1e)
        // ACK Frequency
        val ACK_FREQUENCY = FrameType(0xaf)
        val IMMEDIATE_ACK = FrameType(0x1f)
        // DATAGRAM: 0x30..0x31

        internal const val STREAM_TYS_START = 0x08L
        internal const val STREAM_TYS_END = 0x0fL
        internal const val DATAGRAM_TYS_START = 0x30L
        internal const val DATAGRAM_TYS_END = 0x31L

        fun decode(r: Reader): FrameType = FrameType(r.getVar())

        private val NAMES: Map<Long, String> = mapOf(
            0x00L to "PADDING", 0x01L to "PING", 0x02L to "ACK", 0x03L to "ACK_ECN", 0x04L to "RESET_STREAM",
            0x05L to "STOP_SENDING", 0x06L to "CRYPTO", 0x07L to "NEW_TOKEN", 0x10L to "MAX_DATA",
            0x11L to "MAX_STREAM_DATA", 0x12L to "MAX_STREAMS_BIDI", 0x13L to "MAX_STREAMS_UNI",
            0x14L to "DATA_BLOCKED", 0x15L to "STREAM_DATA_BLOCKED", 0x16L to "STREAMS_BLOCKED_BIDI",
            0x17L to "STREAMS_BLOCKED_UNI", 0x18L to "NEW_CONNECTION_ID", 0x19L to "RETIRE_CONNECTION_ID",
            0x1aL to "PATH_CHALLENGE", 0x1bL to "PATH_RESPONSE", 0x1cL to "CONNECTION_CLOSE",
            0x1dL to "APPLICATION_CLOSE", 0x1eL to "HANDSHAKE_DONE", 0xafL to "ACK_FREQUENCY", 0x1fL to "IMMEDIATE_ACK",
        )

        private fun hex2(v: Long): String = v.toString(16).padStart(2, '0')
    }
}

/** ECN counts carried by ACK_ECN (frame.rs:418). Mutable, like quinn's `AddAssign<EcnCodepoint>`. */
data class EcnCounts(var ect0: Long = 0, var ect1: Long = 0, var ce: Long = 0) {

    /** Count one packet received with [codepoint] (quinn `+=`). */
    fun add(codepoint: EcnCodepoint) {
        when (codepoint) {
            EcnCodepoint.Ect0 -> ect0 += 1
            EcnCodepoint.Ect1 -> ect1 += 1
            EcnCodepoint.Ce -> ce += 1
        }
    }

    fun encode(out: Buffer) {
        out.writeVar(ect0)
        out.writeVar(ect1)
        out.writeVar(ce)
    }

    companion object {
        /** A fresh all-zero instance (quinn `EcnCounts::ZERO`). */
        val ZERO: EcnCounts get() = EcnCounts()
    }
}

/** Metadata of a STREAM frame being written (frame.rs:468): the stream, the byte range `[start, end)`, FIN. */
data class StreamMeta(val id: StreamId = StreamId(0), val start: Long = 0, val end: Long = 0, val fin: Boolean = false) {

    /** Write the STREAM frame header; the caller appends `end - start` bytes of data (frame.rs:486). */
    fun encode(length: Boolean, out: Buffer) = encodeStreamHeader(id, start, end, fin, length, out)
}

/** [StreamMeta.encode] without a `StreamMeta` object, for the send path (one STREAM frame header per call). */
internal fun encodeStreamHeader(id: StreamId, start: Long, end: Long, fin: Boolean, length: Boolean, out: Buffer) {
    var ty = FrameType.STREAM_TYS_START
    if (start != 0L) ty = ty or 0x04
    if (length) ty = ty or 0x02
    if (fin) ty = ty or 0x01
    out.writeVar(ty)             // 1 byte
    out.writeVar(id.value)       // <= 8 bytes
    if (start != 0L) out.writeVar(start) // <= 8 bytes
    if (length) out.writeVar(end - start) // <= 8 bytes
}

/** A QUIC frame (frame.rs:143). */
sealed class Frame {

    /** The wire type of this frame (frame.rs:170). */
    abstract val ty: FrameType

    /** Whether receiving this frame obliges the peer to acknowledge (frame.rs:211). */
    open val isAckEliciting: Boolean get() = true

    /** Append the wire encoding of this frame (every variant; STREAM and DATAGRAM with an explicit length). */
    abstract fun encode(out: Buffer)

    data object Padding : Frame() {
        override val ty get() = FrameType.PADDING
        override val isAckEliciting get() = false
        override fun encode(out: Buffer) = out.writeByte(0)
    }

    data object Ping : Frame() {
        override val ty get() = FrameType.PING
        override fun encode(out: Buffer) = FrameType.PING.encode(out)
    }

    /**
     * ACK / ACK_ECN (frame.rs:342). [additional] holds the still-encoded ACK ranges (first range length, then
     * gap / length pairs), validated by the parser; iterate them with [iterator] or [ranges].
     */
    class Ack(val largest: Long, val delay: Long, val additional: Bytes, val ecn: EcnCounts?) : Frame(), Iterable<LongRange> {
        override val ty get() = FrameType.ACK
        override val isAckEliciting get() = false

        /** Acknowledged packet number ranges, highest first (quinn `AckIter`, frame.rs:813). */
        override fun iterator(): Iterator<LongRange> = AckIter(largest, additional)

        fun ranges(): List<LongRange> = iterator().asSequence().toList()

        /**
         * Visit the acknowledged ranges, highest first, as closed `[first, last]` (the order of [iterator]) without
         * allocating: the connection walks every received ACK this way.
         */
        inline fun forEachRange(action: (first: Long, last: Long) -> Unit) {
            val data = additional
            var pos = 0
            var top = largest
            while (pos < data.size) {
                val block = ackVarAt(data, pos)
                pos += ackVarLen(data, pos)
                action(top - block, top)
                if (pos >= data.size) break
                val gap = ackVarAt(data, pos)
                pos += ackVarLen(data, pos)
                top -= block + gap + 2
            }
        }

        override fun encode(out: Buffer) {
            (if (ecn != null) FrameType.ACK_ECN else FrameType.ACK).encode(out)
            out.writeVar(largest)
            out.writeVar(delay)
            // ACK Range Count: the ranges after the first one.
            var count = 0L
            val it = AckIter(largest, additional)
            while (it.hasNext()) { it.next(); count++ }
            out.writeVar(count - 1)
            out.writeBytes(additional)
            ecn?.encode(out)
        }

        override fun equals(other: Any?): Boolean =
            other is Ack && other.largest == largest && other.delay == delay && other.additional == additional && other.ecn == ecn

        override fun hashCode(): Int = (largest.hashCode() * 31 + delay.hashCode()) * 31 + additional.hashCode()

        override fun toString(): String =
            "Ack(largest=$largest, delay=$delay, ecn=$ecn, ranges=${ranges().joinToString(",", "[", "]") { "${it.first}..=${it.last}" }})"

        companion object {
            /** Encoded size of the frame [encode] writes for the same arguments. */
            fun encodedSize(delay: Long, ranges: ArrayRangeSet, ecn: EcnCounts?): Int {
                val n = ranges.len
                val firstStart = ranges.startAt(n - 1)
                val firstEnd = ranges.endAt(n - 1)
                var size = 1 + varIntSize(firstEnd - 1) + varIntSize(delay) + varIntSize(n.toLong() - 1) +
                    varIntSize(firstEnd - firstStart - 1)
                var prev = firstStart
                for (i in n - 2 downTo 0) {
                    val s = ranges.startAt(i)
                    val e = ranges.endAt(i)
                    size += varIntSize(prev - e - 1) + varIntSize(e - s - 1)
                    prev = s
                }
                if (ecn != null) size += varIntSize(ecn.ect0) + varIntSize(ecn.ect1) + varIntSize(ecn.ce)
                return size
            }

            /** Write an ACK (or ACK_ECN when [ecn] is set) for [ranges] (frame.rs:381). [ranges] must not be empty. */
            fun encode(delay: Long, ranges: ArrayRangeSet, ecn: EcnCounts?, buf: Buffer) {
                val n = ranges.len
                val firstStart = ranges.startAt(n - 1)
                val firstEnd = ranges.endAt(n - 1)
                val largest = firstEnd - 1
                val firstSize = firstEnd - firstStart
                (if (ecn != null) FrameType.ACK_ECN else FrameType.ACK).encode(buf)
                buf.writeVar(largest)
                buf.writeVar(delay)
                buf.writeVar(n.toLong() - 1)
                buf.writeVar(firstSize - 1)
                var prev = firstStart
                for (i in n - 2 downTo 0) {
                    val s = ranges.startAt(i)
                    val e = ranges.endAt(i)
                    buf.writeVar(prev - e - 1)
                    buf.writeVar(e - s - 1)
                    prev = s
                }
                ecn?.encode(buf)
            }
        }
    }

    data class ResetStream(val id: StreamId, val errorCode: VarInt, val finalOffset: VarInt) : Frame() {
        override val ty get() = FrameType.RESET_STREAM
        override fun encode(out: Buffer) {
            FrameType.RESET_STREAM.encode(out) // 1 byte
            out.writeVar(id.value)            // <= 8 bytes
            out.writeVar(errorCode)           // <= 8 bytes
            out.writeVar(finalOffset)         // <= 8 bytes
        }

        companion object { const val SIZE_BOUND: Int = 1 + 8 + 8 + 8 }
    }

    data class StopSending(val id: StreamId, val errorCode: VarInt) : Frame() {
        override val ty get() = FrameType.STOP_SENDING
        override fun encode(out: Buffer) {
            FrameType.STOP_SENDING.encode(out)
            out.writeVar(id.value)
            out.writeVar(errorCode)
        }

        companion object { const val SIZE_BOUND: Int = 1 + 8 + 8 }
    }

    data class Crypto(val offset: Long, val data: Bytes) : Frame() {
        override val ty get() = FrameType.CRYPTO
        override fun encode(out: Buffer) {
            FrameType.CRYPTO.encode(out)
            out.writeVar(offset)
            out.writeVar(data.size.toLong())
            out.writeBytes(data)
        }

        companion object { const val SIZE_BOUND: Int = 17 }
    }

    data class NewToken(val token: Bytes) : Frame() {
        override val ty get() = FrameType.NEW_TOKEN
        override fun encode(out: Buffer) {
            FrameType.NEW_TOKEN.encode(out)
            out.writeVar(token.size.toLong())
            out.writeBytes(token)
        }

        /** Encoded size (frame.rs:540). */
        fun size(): Int = 1 + varIntSize(token.size.toLong()) + token.size
    }

    data class Stream(val id: StreamId, val offset: Long, val fin: Boolean, val data: Bytes) : Frame() {
        override val ty: FrameType
            get() {
                var t = FrameType.STREAM_TYS_START
                if (fin) t = t or 0x01
                if (offset != 0L) t = t or 0x04
                return FrameType(t)
            }

        override fun encode(out: Buffer) {
            StreamMeta(id, offset, offset + data.size, fin).encode(true, out)
            out.writeBytes(data)
        }

        companion object { const val SIZE_BOUND: Int = 1 + 8 + 8 + 8 }
    }

    data class MaxData(val value: VarInt) : Frame() {
        override val ty get() = FrameType.MAX_DATA
        override fun encode(out: Buffer) { FrameType.MAX_DATA.encode(out); out.writeVar(value) }
    }

    data class MaxStreamData(val id: StreamId, val offset: Long) : Frame() {
        override val ty get() = FrameType.MAX_STREAM_DATA
        override fun encode(out: Buffer) { FrameType.MAX_STREAM_DATA.encode(out); out.writeVar(id.value); out.writeVar(offset) }
    }

    data class MaxStreams(val dir: Dir, val count: Long) : Frame() {
        override val ty get() = if (dir == Dir.Bi) FrameType.MAX_STREAMS_BIDI else FrameType.MAX_STREAMS_UNI
        override fun encode(out: Buffer) { ty.encode(out); out.writeVar(count) }
    }

    data class DataBlocked(val offset: Long) : Frame() {
        override val ty get() = FrameType.DATA_BLOCKED
        override fun encode(out: Buffer) { FrameType.DATA_BLOCKED.encode(out); out.writeVar(offset) }
    }

    data class StreamDataBlocked(val id: StreamId, val offset: Long) : Frame() {
        override val ty get() = FrameType.STREAM_DATA_BLOCKED
        override fun encode(out: Buffer) { FrameType.STREAM_DATA_BLOCKED.encode(out); out.writeVar(id.value); out.writeVar(offset) }
    }

    data class StreamsBlocked(val dir: Dir, val limit: Long) : Frame() {
        override val ty get() = if (dir == Dir.Bi) FrameType.STREAMS_BLOCKED_BIDI else FrameType.STREAMS_BLOCKED_UNI
        override fun encode(out: Buffer) { ty.encode(out); out.writeVar(limit) }
    }

    data class NewConnectionId(val sequence: Long, val retirePriorTo: Long, val id: ConnectionId, val resetToken: ResetToken) : Frame() {
        override val ty get() = FrameType.NEW_CONNECTION_ID
        override fun encode(out: Buffer) {
            FrameType.NEW_CONNECTION_ID.encode(out)
            out.writeVar(sequence)
            out.writeVar(retirePriorTo)
            out.writeByte(id.size.toByte())
            id.encode(out)
            resetToken.encode(out)
        }

        companion object { const val SIZE_BOUND: Int = 1 + 8 + 8 + 1 + MAX_CID_SIZE + RESET_TOKEN_SIZE }
    }

    data class RetireConnectionId(val sequence: Long) : Frame() {
        override val ty get() = FrameType.RETIRE_CONNECTION_ID
        override fun encode(out: Buffer) { FrameType.RETIRE_CONNECTION_ID.encode(out); out.writeVar(sequence) }

        companion object {
            /** frame.rs:892 `RETIRE_CONNECTION_ID_SIZE_BOUND`. */
            const val SIZE_BOUND: Int = 9
        }
    }

    data class PathChallenge(val token: Long) : Frame() {
        override val ty get() = FrameType.PATH_CHALLENGE
        override fun encode(out: Buffer) { FrameType.PATH_CHALLENGE.encode(out); out.writeLong(token) }
    }

    data class PathResponse(val token: Long) : Frame() {
        override val ty get() = FrameType.PATH_RESPONSE
        override fun encode(out: Buffer) { FrameType.PATH_RESPONSE.encode(out); out.writeLong(token) }
    }

    /** CONNECTION_CLOSE (0x1c) or APPLICATION_CLOSE (0x1d) (quinn `frame::Close`, frame.rs:217). */
    sealed class Close : Frame() {
        override val isAckEliciting get() = false

        /** Write the frame, truncating the reason so the frame fits in [maxLen] bytes (frame.rs:223). */
        abstract fun encode(out: Buffer, maxLen: Int)

        override fun encode(out: Buffer) = encode(out, Int.MAX_VALUE)

        val isTransportLayer: Boolean get() = this is ConnectionClose

        companion object {
            fun from(error: TransportError): Close = ConnectionClose.from(error)
        }
    }

    /** Reason given by the transport for closing the connection (frame.rs:253). */
    data class ConnectionClose(
        /** Class of error as encoded in the specification. */
        val errorCode: TransportErrorCode,
        /** Type of frame that caused the close. */
        val frameType: FrameType?,
        /** Human-readable reason for the close. */
        val reason: Bytes,
    ) : Close() {
        override val ty get() = FrameType.CONNECTION_CLOSE

        override fun encode(out: Buffer, maxLen: Int) {
            FrameType.CONNECTION_CLOSE.encode(out) // 1 byte
            errorCode.encode(out)                  // <= 8 bytes
            val t = frameType?.value ?: 0L
            out.writeVar(t)                        // <= 8 bytes
            val limit = maxLen.toLong() - 3 - varIntSize(t) - varIntSize(reason.size.toLong())
            val actualLen = minOf(reason.size.toLong(), limit).toInt()
            out.writeVar(actualLen.toLong())       // <= 8 bytes
            out.writeBytes(reason.slice(0, actualLen)) // whatever's left
        }

        override fun toString(): String =
            if (reason.isEmpty) code() else "${code()}: ${reason.decodeToString()}"

        private fun code(): String = errorCode.description

        companion object {
            const val SIZE_BOUND: Int = 1 + 8 + 8 + 8

            fun from(e: TransportError): ConnectionClose =
                ConnectionClose(e.code, e.frame, Bytes.wrap(e.reason.encodeToByteArray()))
        }
    }

    /** Reason given by an application for closing the connection (frame.rs:305). */
    data class ApplicationClose(
        /** Application-specific reason code. */
        val errorCode: VarInt,
        /** Human-readable reason for the close. */
        val reason: Bytes,
    ) : Close() {
        override val ty get() = FrameType.APPLICATION_CLOSE

        override fun encode(out: Buffer, maxLen: Int) {
            FrameType.APPLICATION_CLOSE.encode(out) // 1 byte
            out.writeVar(errorCode)                 // <= 8 bytes
            val limit = maxLen.toLong() - 3 - varIntSize(reason.size.toLong())
            val actualLen = minOf(reason.size.toLong(), limit).toInt()
            out.writeVar(actualLen.toLong())        // <= 8 bytes
            out.writeBytes(reason.slice(0, actualLen))
        }

        override fun toString(): String =
            if (reason.isEmpty) errorCode.toString() else "${reason.decodeToString()} (code $errorCode)"

        companion object { const val SIZE_BOUND: Int = 1 + 8 + 8 }
    }

    /** An unreliable datagram (frame.rs:896). */
    data class Datagram(val data: Bytes) : Frame() {
        override val ty get() = FrameType(FrameType.DATAGRAM_TYS_START)

        /** Write the frame; with [length] the payload length is explicit (type 0x31), else it runs to the end. */
        fun encode(length: Boolean, out: Buffer) {
            FrameType(FrameType.DATAGRAM_TYS_START or (if (length) 1L else 0L)).encode(out) // 1 byte
            if (length) out.writeVar(data.size.toLong()) // <= 8 bytes
            out.writeBytes(data)
        }

        override fun encode(out: Buffer) = encode(true, out)

        fun size(length: Boolean): Int = 1 + (if (length) varIntSize(data.size.toLong()) else 0) + data.size

        companion object { const val SIZE_BOUND: Int = 1 + 8 }
    }

    /** ACK_FREQUENCY (draft-ietf-quic-ack-frequency, frame.rs:925). */
    data class AckFrequency(
        val sequence: VarInt,
        val ackElicitingThreshold: VarInt,
        val requestMaxAckDelay: VarInt,
        val reorderingThreshold: VarInt,
    ) : Frame() {
        override val ty get() = FrameType.ACK_FREQUENCY
        override fun encode(out: Buffer) {
            FrameType.ACK_FREQUENCY.encode(out)
            out.writeVar(sequence)
            out.writeVar(ackElicitingThreshold)
            out.writeVar(requestMaxAckDelay)
            out.writeVar(reorderingThreshold)
        }
    }

    data object ImmediateAck : Frame() {
        override val ty get() = FrameType.IMMEDIATE_ACK
        override fun encode(out: Buffer) = FrameType.IMMEDIATE_ACK.encode(out)
    }

    data object HandshakeDone : Frame() {
        override val ty get() = FrameType.HANDSHAKE_DONE
        override fun encode(out: Buffer) = FrameType.HANDSHAKE_DONE.encode(out)
    }
}

/** The varint at [pos] of validated ACK range bytes. */
@PublishedApi
internal fun ackVarAt(data: Bytes, pos: Int): Long {
    val first = data[pos].toInt() and 0xFF
    val len = 1 shl (first ushr 6)
    var v = (first and 0x3F).toLong()
    for (i in 1 until len) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
    return v
}

/** Encoded length of the varint at [pos]. */
@PublishedApi
internal fun ackVarLen(data: Bytes, pos: Int): Int = 1 shl ((data[pos].toInt() and 0xFF) ushr 6)

/**
 * Iterator over the ranges of an ACK frame, highest first, as closed ranges (frame.rs:802).
 * [data] was validated by the frame parser.
 */
class AckIter internal constructor(private var largest: Long, private val data: Bytes) : Iterator<LongRange> {
    private var pos = 0

    override fun hasNext(): Boolean = pos < data.size

    override fun next(): LongRange {
        if (pos >= data.size) throw NoSuchElementException()
        val block = readVar() ?: throw IllegalStateException("malformed ACK ranges")
        val l = largest
        val gap = readVar()
        if (gap != null) largest -= block + gap + 2
        return (l - block)..l
    }

    private fun readVar(): Long? {
        if (pos >= data.size) return null
        val first = data[pos].toInt() and 0xFF
        val len = 1 shl (first ushr 6)
        if (data.size - pos < len) return null
        var v = (first and 0x3F).toLong()
        for (i in 1 until len) v = (v shl 8) or (data[pos + i].toLong() and 0xFF)
        pos += len
        return v
    }
}

/**
 * A frame that failed to parse (frame.rs:751): the frame type read, if any, and the reason. Converts to a
 * FRAME_ENCODING_ERROR [TransportError] with that frame type (frame.rs:756).
 */
class InvalidFrame(val ty: FrameType?, val reason: String) : Exception(reason) {
    fun toTransportError(): TransportError = TransportError.FRAME_ENCODING_ERROR(reason).also { it.frame = ty }
}

/**
 * Iterates the frames of a decrypted packet payload `payload[start, end)` (quinn `frame::Iter`, frame.rs:545).
 *
 * Zero-copy: data-carrying frames (CRYPTO, STREAM, NEW_TOKEN, DATAGRAM, close reasons, ACK ranges) get
 * [Bytes] slices of [payload], which the caller therefore must not modify afterwards.
 *
 * [next] throws [InvalidFrame] for a corrupt frame and then skips everything that follows, as quinn does.
 * The constructor throws PROTOCOL_VIOLATION for an empty payload (RFC 9000 §12.4).
 */
class FrameIter(private val payload: ByteArray, start: Int = 0, end: Int = payload.size) : Iterator<Frame> {
    private val r = Reader(payload, start, end)
    private val base = Bytes.wrap(payload)

    /** Type of the last frame read (for error reporting). */
    var lastType: FrameType? = null
        private set

    init {
        if (start == end) {
            // "An endpoint MUST treat receipt of a packet containing no frames as a connection error of type
            // PROTOCOL_VIOLATION." (RFC 9000 §12.4)
            throw TransportError.PROTOCOL_VIOLATION("packet payload is empty")
        }
    }

    override fun hasNext(): Boolean = r.hasRemaining()

    override fun next(): Frame {
        if (!r.hasRemaining()) throw NoSuchElementException()
        try {
            return tryNext()
        } catch (e: IterErr) {
            r.clear() // corrupt frame: skip it and everything that follows
            throw InvalidFrame(lastType, e.reason)
        } catch (e: UnexpectedEnd) {
            r.clear()
            throw InvalidFrame(lastType, "unexpected end")
        }
    }

    private fun slice(from: Int, to: Int): Bytes = if (from == to) Bytes.EMPTY else base.slice(from, to)

    private fun takeLen(): Bytes {
        val len = r.getVar()
        if (len > r.remaining) throw UnexpectedEnd
        val from = r.pos
        r.skip(len.toInt())
        return slice(from, r.pos)
    }

    private fun takeRemaining(): Bytes {
        val from = r.pos
        r.clear()
        return slice(from, r.pos)
    }

    private fun tryNext(): Frame {
        val t = FrameType.decode(r)
        lastType = t
        return when (t) {
            FrameType.PADDING -> Frame.Padding
            FrameType.RESET_STREAM -> Frame.ResetStream(StreamId(r.getVar()), r.getVarInt(), r.getVarInt())
            FrameType.CONNECTION_CLOSE -> {
                val code = TransportErrorCode.decode(r)
                val x = r.getVar()
                Frame.ConnectionClose(code, if (x == 0L) null else FrameType(x), takeLen())
            }
            FrameType.APPLICATION_CLOSE -> Frame.ApplicationClose(r.getVarInt(), takeLen())
            FrameType.MAX_DATA -> Frame.MaxData(r.getVarInt())
            FrameType.MAX_STREAM_DATA -> Frame.MaxStreamData(StreamId(r.getVar()), r.getVar())
            FrameType.MAX_STREAMS_BIDI -> Frame.MaxStreams(Dir.Bi, r.getVar())
            FrameType.MAX_STREAMS_UNI -> Frame.MaxStreams(Dir.Uni, r.getVar())
            FrameType.PING -> Frame.Ping
            FrameType.DATA_BLOCKED -> Frame.DataBlocked(r.getVar())
            FrameType.STREAM_DATA_BLOCKED -> Frame.StreamDataBlocked(StreamId(r.getVar()), r.getVar())
            FrameType.STREAMS_BLOCKED_BIDI -> Frame.StreamsBlocked(Dir.Bi, r.getVar())
            FrameType.STREAMS_BLOCKED_UNI -> Frame.StreamsBlocked(Dir.Uni, r.getVar())
            FrameType.STOP_SENDING -> Frame.StopSending(StreamId(r.getVar()), r.getVarInt())
            FrameType.RETIRE_CONNECTION_ID -> Frame.RetireConnectionId(r.getVar())
            FrameType.ACK, FrameType.ACK_ECN -> {
                val largest = r.getVar()
                val delay = r.getVar()
                val extraBlocks = r.getVar()
                val n = scanAckBlocks(largest, extraBlocks)
                val from = r.pos
                r.skip(n)
                val additional = slice(from, r.pos)
                val ecn = if (t != FrameType.ACK_ECN) null else EcnCounts(r.getVar(), r.getVar(), r.getVar())
                Frame.Ack(largest, delay, additional, ecn)
            }
            FrameType.PATH_CHALLENGE -> Frame.PathChallenge(r.getU64())
            FrameType.PATH_RESPONSE -> Frame.PathResponse(r.getU64())
            FrameType.NEW_CONNECTION_ID -> {
                val sequence = r.getVar()
                val retirePriorTo = r.getVar()
                if (retirePriorTo > sequence) throw IterErr.Malformed
                val length = r.getU8()
                if (length > MAX_CID_SIZE || length == 0) throw IterErr.Malformed
                if (length > r.remaining) throw UnexpectedEnd
                val id = ConnectionId.fromReader(r, length)
                if (r.remaining < RESET_TOKEN_SIZE) throw UnexpectedEnd
                Frame.NewConnectionId(sequence, retirePriorTo, id, ResetToken.fromReader(r))
            }
            FrameType.CRYPTO -> Frame.Crypto(r.getVar(), takeLen())
            FrameType.NEW_TOKEN -> Frame.NewToken(takeLen())
            FrameType.HANDSHAKE_DONE -> Frame.HandshakeDone
            FrameType.ACK_FREQUENCY -> Frame.AckFrequency(r.getVarInt(), r.getVarInt(), r.getVarInt(), r.getVarInt())
            FrameType.IMMEDIATE_ACK -> Frame.ImmediateAck
            else -> when {
                t.isStream -> {
                    val bits = t.value.toInt()
                    val id = StreamId(r.getVar())
                    val offset = if (bits and 0x04 != 0) r.getVar() else 0L
                    val data = if (bits and 0x02 != 0) takeLen() else takeRemaining()
                    Frame.Stream(id, offset, bits and 0x01 != 0, data)
                }
                t.isDatagram -> Frame.Datagram(if (t.value and 0x01 != 0L) takeLen() else takeRemaining())
                else -> throw IterErr.InvalidFrameId
            }
        }
    }

    /** Validate exactly [n] extra ACK ranges at the cursor and return the number of bytes they cover (frame.rs:765). */
    private fun scanAckBlocks(largest: Long, n: Long): Int {
        val scan = Reader(payload, r.pos, r.end)
        val firstBlock = scan.getVar()
        var smallest = largest - firstBlock
        if (smallest < 0) throw IterErr.Malformed
        var i = 0L
        while (i < n) {
            val gap = scan.getVar()
            smallest -= gap + 2
            if (smallest < 0) throw IterErr.Malformed
            val block = scan.getVar()
            smallest -= block
            if (smallest < 0) throw IterErr.Malformed
            i++
        }
        return scan.pos - r.pos
    }

    /** quinn `IterErr` (frame.rs:778); UnexpectedEnd is the shared [UnexpectedEnd]. */
    private sealed class IterErr(val reason: String) : Exception(reason) {
        object InvalidFrameId : IterErr("invalid frame ID")
        object Malformed : IterErr("malformed")
    }
}

/**
 * Frames allowed in Initial and Handshake packets (quinn `Connection::process_early_payload`,
 * connection/mod.rs:2715-2733): PADDING, PING, CRYPTO, ACK and either CONNECTION_CLOSE. Returns the
 * PROTOCOL_VIOLATION quinn raises for any other frame (carrying that frame's type), or `null` when allowed.
 */
fun Frame.handshakeSpaceViolation(): TransportError? = when (this) {
    Frame.Padding, Frame.Ping, is Frame.Crypto, is Frame.Ack, is Frame.Close -> null
    else -> TransportError.PROTOCOL_VIOLATION("illegal frame type in handshake").also { it.frame = ty }
}

/**
 * Frames forbidden in 0-RTT packets (quinn `Connection::process_payload`, connection/mod.rs:2786-2793): CRYPTO and
 * APPLICATION_CLOSE. Returns quinn's PROTOCOL_VIOLATION (no frame type attached, as in quinn) or `null`.
 */
fun Frame.zeroRttViolation(): TransportError? = when (this) {
    is Frame.Crypto, is Frame.ApplicationClose -> TransportError.PROTOCOL_VIOLATION("illegal frame type in 0-RTT")
    else -> null
}
