package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.net.EcnCodepoint
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

// Shared protocol types and constants (quinn-proto `lib.rs:159-336`, `shared.rs`).

/** The QUIC versions implemented: v1 and drafts 29-34 (quinn `DEFAULT_SUPPORTED_VERSIONS`, lib.rs:160). */
val DEFAULT_SUPPORTED_VERSIONS: IntArray = intArrayOf(
    0x00000001,
    0xff00_001d.toInt(),
    0xff00_001e.toInt(),
    0xff00_001f.toInt(),
    0xff00_0020.toInt(),
    0xff00_0021.toInt(),
    0xff00_0022.toInt(),
)

/** The maximum number of CIDs we bother to issue per connection (lib.rs:327). */
const val LOC_CID_COUNT: Long = 8
const val RESET_TOKEN_SIZE: Int = 16
const val MAX_CID_SIZE: Int = 20
const val MIN_INITIAL_SIZE: Int = 1200

/** RFC 9000 §14 "Datagram size". */
const val INITIAL_MTU: Int = 1200
const val MAX_UDP_PAYLOAD: Int = 65527
val TIMER_GRANULARITY: Duration = 1.milliseconds

/** Maximum number of streams that can be uniquely identified by a stream ID. */
const val MAX_STREAM_COUNT: Long = 1L shl 60

/** Whether an endpoint was the initiator of a connection (lib.rs:173). */
enum class Side {
    /** The initiator of a connection. */
    Client,

    /** The acceptor of a connection. */
    Server;

    val isClient: Boolean get() = this == Client
    val isServer: Boolean get() = this == Server
    operator fun not(): Side = if (this == Client) Server else Client
}

/** Whether a stream communicates data in both directions or only from the initiator (lib.rs:207). */
enum class Dir {
    /** Data flows in both directions. */
    Bi,

    /** Data flows only from the stream's initiator. */
    Uni;

    override fun toString(): String = if (this == Bi) "bidirectional" else "unidirectional"
}

/** Identifier for a stream within a particular connection (lib.rs:233). */
value class StreamId(val value: Long) : Comparable<StreamId> {
    /** Which side of a connection initiated the stream. */
    val initiator: Side get() = if (value and 1L == 0L) Side.Client else Side.Server

    /** Which directions data flows in. */
    val dir: Dir get() = if (value and 2L == 0L) Dir.Bi else Dir.Uni

    /** Distinguishes streams of the same initiator and directionality. */
    val index: Long get() = value ushr 2

    override fun compareTo(other: StreamId): Int = value.compareTo(other.value)

    override fun toString(): String =
        "${if (initiator == Side.Client) "client" else "server"} ${if (dir == Dir.Uni) "uni" else "bi"}directional stream $index"

    companion object {
        fun of(initiator: Side, dir: Dir, index: Long): StreamId =
            StreamId((index shl 2) or (dir.ordinal.toLong() shl 1) or initiator.ordinal.toLong())
    }
}

/**
 * Protocol-level identifier for a connection: 0 to [MAX_CID_SIZE] bytes (shared.rs:64).
 *
 * Immutable; ordering and equality are by content (length first, like quinn's derived impls on
 * `{ len, bytes }`).
 */
class ConnectionId private constructor(private val bytes: ByteArray) : Comparable<ConnectionId> {

    val size: Int get() = bytes.size
    fun isEmpty(): Boolean = bytes.isEmpty()

    operator fun get(i: Int): Byte = bytes[i]

    /** A copy of the bytes. */
    fun toByteArray(): ByteArray = bytes.copyOf()

    fun copyInto(dst: ByteArray, dstOffset: Int) { bytes.copyInto(dst, dstOffset) }

    /** Whether this equals `src[offset, offset + size)`. */
    fun contentEquals(src: ByteArray, offset: Int, length: Int): Boolean {
        if (length != bytes.size) return false
        for (i in bytes.indices) if (bytes[i] != src[offset + i]) return false
        return true
    }

    /** Append the raw bytes. */
    fun encode(buf: Buffer) = buf.writeBytes(bytes)

    /** Encode in long header format: a length byte then the bytes (shared.rs:106). */
    fun encodeLong(buf: Buffer) {
        buf.writeByte(bytes.size.toByte())
        buf.writeBytes(bytes)
    }

    override fun equals(other: Any?): Boolean = other is ConnectionId && bytes.contentEquals(other.bytes)
    override fun hashCode(): Int = bytes.contentHashCode()

    override fun compareTo(other: ConnectionId): Int {
        if (bytes.size != other.bytes.size) return bytes.size.compareTo(other.bytes.size)
        for (i in bytes.indices) {
            val c = (bytes[i].toInt() and 0xFF).compareTo(other.bytes[i].toInt() and 0xFF)
            if (c != 0) return c
        }
        return 0
    }

    /** Lower-case hex, as quinn's `Display`. */
    override fun toString(): String = bytes.toHex()

    companion object {
        val EMPTY: ConnectionId = ConnectionId(ByteArray(0))

        /** Construct from a byte array (copied). */
        fun of(bytes: ByteArray, from: Int = 0, to: Int = bytes.size): ConnectionId {
            require(to - from in 0..MAX_CID_SIZE) { "connection ID longer than $MAX_CID_SIZE bytes" }
            return if (from == to) EMPTY else ConnectionId(bytes.copyOfRange(from, to))
        }

        /** Read [len] bytes from [r]; the caller ensures `r.remaining >= len` (quinn `from_buf`). */
        fun fromReader(r: Reader, len: Int): ConnectionId {
            require(len in 0..MAX_CID_SIZE)
            if (len == 0) return EMPTY
            return ConnectionId(r.getBytes(len))
        }

        /** Decode from long header format; `null` when malformed (quinn `decode_long`, shared.rs:97). */
        fun decodeLong(r: Reader): ConnectionId? {
            if (!r.hasRemaining()) return null
            val len = r.getU8()
            if (len > MAX_CID_SIZE || r.remaining < len) return null
            return fromReader(r, len)
        }
    }
}

/**
 * Stateless reset token (quinn `token.rs:367`): 16 bytes, compared in constant time.
 */
class ResetToken(bytes: ByteArray) {
    private val bytes: ByteArray

    init {
        require(bytes.size == RESET_TOKEN_SIZE) { "a reset token has $RESET_TOKEN_SIZE bytes" }
        this.bytes = bytes.copyOf()
    }

    fun toByteArray(): ByteArray = bytes.copyOf()
    fun copyInto(dst: ByteArray, dstOffset: Int) { bytes.copyInto(dst, dstOffset) }
    fun encode(buf: Buffer) = buf.writeBytes(bytes)

    /** Constant-time equality (quinn `constant_time::eq`). */
    override fun equals(other: Any?): Boolean = other is ResetToken && constantTimeEquals(bytes, other.bytes)

    /** Constant-time comparison against `src[offset, offset + 16)`. */
    fun matches(src: ByteArray, offset: Int): Boolean {
        var tmp = 0
        for (i in 0 until RESET_TOKEN_SIZE) tmp = tmp or (bytes[i].toInt() xor src[offset + i].toInt())
        return tmp and 0xFF == 0
    }

    override fun hashCode(): Int = bytes.contentHashCode()
    override fun toString(): String = bytes.toHex()

    companion object {
        /** Derive a reset token for [id] from an HMAC key (quinn `ResetToken::new`, token.rs:370). */
        fun derive(key: HmacKey, id: ConnectionId): ResetToken {
            val signature = ByteArray(key.signatureLen)
            val data = id.toByteArray()
            key.sign(data, 0, data.size, signature, 0)
            return ResetToken(signature.copyOf(RESET_TOKEN_SIZE))
        }

        fun fromReader(r: Reader): ResetToken = ResetToken(r.getBytes(RESET_TOKEN_SIZE))
    }
}

/** Compares byte arrays in constant time (quinn `constant_time.rs`). */
fun constantTimeEquals(a: ByteArray, b: ByteArray): Boolean {
    if (a.size != b.size) return false
    var tmp = 0
    for (i in a.indices) tmp = tmp or (a[i].toInt() xor b[i].toInt())
    return tmp and 0xFF == 0
}

/** Whether the codepoint is CE, signalling that congestion was experienced (shared.rs:170). */
val EcnCodepoint.isCe: Boolean get() = this == EcnCodepoint.Ce

/** A connection ID issued to the peer, with its sequence number and reset token (shared.rs:176). */
class IssuedCid(val sequence: Long, val id: ConnectionId, val resetToken: ResetToken)
