package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes

// QUIC packet headers (quinn-proto `packet.rs`; RFC 9000 §17, RFC 8999 invariants, RFC 9287 GREASE bit).
//
// Buffers: a received datagram is one `ByteArray`; packets are regions `[start, end)` of it. Header protection and
// payload decryption run in place, so that array belongs to the packet from the moment it is handed to
// [PartialDecode.decode] (quinn takes ownership of a `BytesMut`); zero-copy slices (the Initial token, frame
// payloads) point into it.

const val LONG_HEADER_FORM: Int = 0x80
const val FIXED_BIT: Int = 0x40
const val SPIN_BIT: Int = 0x20
internal const val SHORT_RESERVED_BITS: Int = 0x18
internal const val LONG_RESERVED_BITS: Int = 0x0c
const val KEY_PHASE_BIT: Int = 0x04

/** Packet number space identifiers (packet.rs:885). */
enum class SpaceId {
    /** Unprotected packets, used to bootstrap the handshake. */
    Initial,
    Handshake,

    /** Application data space, used for 0-RTT and post-handshake/1-RTT packets. */
    Data;

    companion object {
        val ALL: List<SpaceId> = entries
    }
}

/** Long packet types with uniform header structure (packet.rs:845). */
enum class LongType {
    /** Handshake packet. */
    Handshake,

    /** 0-RTT packet. */
    ZeroRtt,
}

/** Long packet type including the non-uniform cases (packet.rs:811), as the two type bits of the first byte. */
internal object LongHeaderType {
    const val INITIAL = 0x0
    const val ZERO_RTT = 0x1
    const val HANDSHAKE = 0x2
    const val RETRY = 0x3

    fun fromByte(b: Int): Int = (b and 0x30) shr 4

    /** First byte (without packet number length bits) for a long header type (packet.rs:831). */
    fun toByte(type: Int): Int = LONG_HEADER_FORM or FIXED_BIT or (type shl 4)

    fun of(ty: LongType): Int = if (ty == LongType.ZeroRtt) ZERO_RTT else HANDSHAKE
}

/** Packet decode error (packet.rs:854). */
sealed class PacketDecodeError(message: String) : Exception(message) {
    /** Packet uses a QUIC version that is not supported. */
    data class UnsupportedVersion(val srcCid: ConnectionId, val dstCid: ConnectionId, val version: Int) :
        PacketDecodeError("unsupported version ${version.toUInt().toString(16)}")

    /** The packet header is invalid. */
    data class InvalidHeader(val reason: String) : PacketDecodeError("invalid header: $reason")
}

/**
 * An encoded (truncated) packet number of 1-4 bytes (packet.rs:682): `U8`, `U16`, `U24` or `U32`.
 * Packed into one Long (value in the low 32 bits, length above) so it never allocates.
 */
value class PacketNumber private constructor(private val raw: Long) {

    /** Encoded length in bytes, 1..4. */
    val len: Int get() = (raw ushr 32).toInt()

    /** The truncated value as encoded. */
    val truncated: Long get() = raw and 0xFFFF_FFFFL

    /** The two packet number length bits of the first header byte (packet.rs:741). */
    internal val tag: Int get() = len - 1

    fun encode(w: Buffer) = w.writeUInt(truncated, len)

    /**
     * Recover the full packet number given the next expected one (RFC 9000 Appendix A.3; packet.rs:751).
     */
    fun expand(expected: Long): Long {
        val nbits = len * 8
        val win = 1L shl nbits
        val hwin = win / 2
        val mask = win - 1
        // The incoming packet number should be greater than expected - hwin and less than or equal to
        // expected + hwin; compute a candidate and move it into that window.
        val candidate = (expected and mask.inv()) or truncated
        return if (expected >= hwin && candidate <= expected - hwin) {
            candidate + win
        } else if (candidate > expected + hwin && candidate > win) {
            candidate - win
        } else {
            candidate
        }
    }

    override fun toString(): String = when (len) {
        1 -> "U8($truncated)"
        2 -> "U16($truncated)"
        3 -> "U24($truncated)"
        else -> "U32($truncated)"
    }

    companion object {
        private fun of(len: Int, value: Long) = PacketNumber((len.toLong() shl 32) or value)

        fun U8(x: Int): PacketNumber = of(1, x.toLong() and 0xFF)
        fun U16(x: Int): PacketNumber = of(2, x.toLong() and 0xFFFF)
        fun U24(x: Int): PacketNumber = of(3, x.toLong() and 0xFF_FFFF)
        fun U32(x: Long): PacketNumber = of(4, x and 0xFFFF_FFFFL)

        /**
         * Encode [n] with enough bits for the peer to recover it given [largestAcked]
         * (RFC 9000 §17.1, Appendix A.2; packet.rs:690).
         */
        fun new(n: Long, largestAcked: Long): PacketNumber {
            val range = (n - largestAcked) * 2
            return when {
                range < (1L shl 8) -> of(1, n and 0xFF)
                range < (1L shl 16) -> of(2, n and 0xFFFF)
                range < (1L shl 24) -> of(3, n and 0xFF_FFFF)
                range < (1L shl 32) -> of(4, n and 0xFFFF_FFFFL)
                else -> throw IllegalStateException("packet number too large to encode")
            }
        }

        /** Read a [len]-byte packet number (packet.rs:725). */
        fun decode(len: Int, r: Reader): PacketNumber {
            require(len in 1..4)
            return of(len, r.getUInt(len))
        }

        /** Packet number length from the (unprotected) first byte (packet.rs:737). */
        fun decodeLen(tag: Int): Int = 1 + (tag and 0x03)
    }
}

/** Parses the connection ID of a short header packet (packet.rs:804). */
fun interface ConnectionIdParser {
    /** Read the destination connection ID; throws [PacketDecodeError] if it cannot. */
    fun parse(r: Reader): ConnectionId
}

/** A [ConnectionIdParser] for connection IDs of a fixed length (packet.rs:784). */
class FixedLengthConnectionIdParser(private val expectedLen: Int) : ConnectionIdParser {
    override fun parse(r: Reader): ConnectionId {
        if (r.remaining < expectedLen) throw PacketDecodeError.InvalidHeader("packet too small")
        return ConnectionId.fromReader(r, expectedLen)
    }
}

/** A packet header before header protection is removed (packet.rs:506). */
sealed class ProtectedHeader {
    /** The destination connection ID of the packet. */
    abstract val dstCid: ConnectionId

    /** Length of the packet payload, including the packet number, for Initial / Long packets. */
    internal open val payloadLen: kotlin.Long? get() = null

    /** An Initial packet header. [tokenStart]/[tokenEnd] locate the token relative to the packet's first byte. */
    data class Initial(
        override val dstCid: ConnectionId,
        val srcCid: ConnectionId,
        val tokenStart: Int,
        val tokenEnd: Int,
        /** Length of the packet payload. */
        val len: kotlin.Long,
        val version: Int,
    ) : ProtectedHeader() {
        override val payloadLen: kotlin.Long get() = len
    }

    /** A long packet header, as used during the handshake (Handshake, 0-RTT). */
    data class Long(
        val ty: LongType,
        override val dstCid: ConnectionId,
        val srcCid: ConnectionId,
        /** Length of the packet payload. */
        val len: kotlin.Long,
        val version: Int,
    ) : ProtectedHeader() {
        override val payloadLen: kotlin.Long get() = len
    }

    /** A Retry packet header. */
    data class Retry(override val dstCid: ConnectionId, val srcCid: ConnectionId, val version: Int) : ProtectedHeader()

    /** A short packet header, as used during the data phase. */
    data class Short(val spin: Boolean, override val dstCid: ConnectionId) : ProtectedHeader()

    /** A Version Negotiation packet header. */
    data class VersionNegotiate(val random: Int, override val dstCid: ConnectionId, val srcCid: ConnectionId) : ProtectedHeader()

    companion object {
        /**
         * Decode a plain header from [r], positioned at the packet's first byte at absolute index [packetStart]
         * (packet.rs:578). Leaves [r] after the header (before the packet number for protected packets).
         */
        fun decode(
            r: Reader,
            packetStart: Int,
            cidParser: ConnectionIdParser,
            supportedVersions: IntArray,
            greaseQuicBit: Boolean,
        ): ProtectedHeader {
            try {
                val first = r.getU8()
                if (!greaseQuicBit && first and FIXED_BIT == 0) throw PacketDecodeError.InvalidHeader("fixed bit unset")
                if (first and LONG_HEADER_FORM == 0) {
                    val spin = first and SPIN_BIT != 0
                    return Short(spin, cidParser.parse(r))
                }
                val version = r.getI32()
                val dstCid = ConnectionId.decodeLong(r) ?: throw PacketDecodeError.InvalidHeader("malformed cid")
                val srcCid = ConnectionId.decodeLong(r) ?: throw PacketDecodeError.InvalidHeader("malformed cid")

                // TODO (as in quinn): support long CIDs for compatibility with future QUIC versions
                if (version == 0) return VersionNegotiate(first and LONG_HEADER_FORM.inv(), dstCid, srcCid)

                if (version !in supportedVersions) throw PacketDecodeError.UnsupportedVersion(srcCid, dstCid, version)

                return when (LongHeaderType.fromByte(first)) {
                    LongHeaderType.INITIAL -> {
                        val tokenLen = r.getVar()
                        val tokenStart = r.pos - packetStart
                        if (tokenLen > r.remaining) throw PacketDecodeError.InvalidHeader("token out of bounds")
                        r.skip(tokenLen.toInt())
                        val len = r.getVar()
                        Initial(dstCid, srcCid, tokenStart, tokenStart + tokenLen.toInt(), len, version)
                    }
                    LongHeaderType.RETRY -> Retry(dstCid, srcCid, version)
                    LongHeaderType.ZERO_RTT -> Long(LongType.ZeroRtt, dstCid, srcCid, r.getVar(), version)
                    else -> Long(LongType.Handshake, dstCid, srcCid, r.getVar(), version)
                }
            } catch (e: UnexpectedEnd) {
                throw PacketDecodeError.InvalidHeader("unexpected end of packet")
            }
        }
    }
}

/**
 * Decodes a QUIC packet's invariant header (packet.rs:26).
 *
 * Header protection hides the packet number, so without the crypto context only the invariant header can be
 * read: the destination CID, version and packet type. That is enough to route the packet and pick the keys, and
 * [finish] then removes header protection and completes the header.
 */
class PartialDecode private constructor(
    val plainHeader: ProtectedHeader,
    /** The datagram; this packet is `data[start, end)`. */
    val data: ByteArray,
    val start: Int,
    val end: Int,
    /** Absolute read position after the plain header. */
    private val headerEnd: Int,
    /** Start of the coalesced packets that follow this one in the datagram, or -1 (quinn's `Option<BytesMut>`). */
    val restStart: Int,
    /** End of the datagram (end of the rest, when there is one). */
    val restEnd: Int,
) {
    /** Whether more (coalesced) packets follow this one in the datagram. */
    val hasRest: Boolean get() = restStart >= 0

    /** Length of the QUIC packet being decoded. */
    val len: Int get() = end - start

    val initialHeader: ProtectedHeader.Initial? get() = plainHeader as? ProtectedHeader.Initial

    val hasLongHeader: Boolean get() = plainHeader !is ProtectedHeader.Short

    val isInitial: Boolean get() = space == SpaceId.Initial

    val space: SpaceId?
        get() = when (val h = plainHeader) {
            is ProtectedHeader.Initial -> SpaceId.Initial
            is ProtectedHeader.Long -> if (h.ty == LongType.Handshake) SpaceId.Handshake else SpaceId.Data
            is ProtectedHeader.Short -> SpaceId.Data
            else -> null
        }

    val is0rtt: Boolean get() = (plainHeader as? ProtectedHeader.Long)?.ty == LongType.ZeroRtt

    /** The destination connection ID of the packet. */
    val dstCid: ConnectionId get() = plainHeader.dstCid

    /**
     * Remove header protection with [headerCrypto] (required for every packet type except Retry and Version
     * Negotiation) and complete the header (packet.rs:112). Mutates [data] in place.
     */
    fun finish(headerCrypto: HeaderKey?): Packet {
        val r = Reader(data, headerEnd, end)
        val header: Header = when (val h = plainHeader) {
            is ProtectedHeader.Initial -> {
                val number = decryptHeader(r, headerCrypto!!)
                val token = if (h.tokenStart == h.tokenEnd) Bytes.EMPTY else Bytes.wrap(data).slice(start + h.tokenStart, start + h.tokenEnd)
                InitialHeader(h.dstCid, h.srcCid, token, number, h.version)
            }
            is ProtectedHeader.Long -> Header.Long(h.ty, h.dstCid, h.srcCid, decryptHeader(r, headerCrypto!!), h.version)
            is ProtectedHeader.Retry -> Header.Retry(h.dstCid, h.srcCid, h.version)
            is ProtectedHeader.Short -> {
                val number = decryptHeader(r, headerCrypto!!)
                val keyPhase = data[start].toInt() and KEY_PHASE_BIT != 0
                Header.Short(h.spin, keyPhase, h.dstCid, number)
            }
            is ProtectedHeader.VersionNegotiate -> Header.VersionNegotiate(h.random, h.srcCid, h.dstCid)
        }
        val headerLen = r.pos - start
        return Packet(header, data, start, headerLen, start + headerLen, end - start - headerLen)
    }

    private fun decryptHeader(r: Reader, headerCrypto: HeaderKey): PacketNumber {
        val packetLength = end - start
        val pnOffset = r.pos - start
        if (packetLength < pnOffset + 4 + headerCrypto.sampleSize) {
            throw PacketDecodeError.InvalidHeader("packet too short to extract header protection sample")
        }
        headerCrypto.decrypt(pnOffset, data, start, end)
        val len = PacketNumber.decodeLen(data[start].toInt())
        return try {
            PacketNumber.decode(len, r)
        } catch (e: UnexpectedEnd) {
            throw PacketDecodeError.InvalidHeader("unexpected end of packet")
        }
    }

    override fun toString(): String = "PartialDecode($plainHeader, len=$len)"

    companion object {
        /**
         * Begin decoding the QUIC packet at `data[start, end)` (packet.rs:34). When the datagram holds more
         * (coalesced) packets after it, [restStart] locates them. Takes ownership of [data] (see the file comment).
         */
        fun decode(
            data: ByteArray,
            start: Int,
            end: Int,
            cidParser: ConnectionIdParser,
            supportedVersions: IntArray,
            greaseQuicBit: Boolean,
        ): PartialDecode {
            val r = Reader(data, start, end)
            val plainHeader = ProtectedHeader.decode(r, start, cidParser, supportedVersions, greaseQuicBit)
            val dgramLen = (end - start).toLong()
            val packetLen = plainHeader.payloadLen?.let { (r.pos - start) + it } ?: dgramLen
            return when {
                dgramLen == packetLen -> PartialDecode(plainHeader, data, start, end, r.pos, -1, end)
                dgramLen < packetLen -> throw PacketDecodeError.InvalidHeader("packet too short to contain payload length")
                else -> {
                    val packetEnd = start + packetLen.toInt()
                    PartialDecode(plainHeader, data, start, packetEnd, r.pos, packetEnd, end)
                }
            }
        }

        fun decode(
            data: ByteArray,
            cidParser: ConnectionIdParser,
            supportedVersions: IntArray,
            greaseQuicBit: Boolean,
        ): PartialDecode = decode(data, 0, data.size, cidParser, supportedVersions, greaseQuicBit)
    }
}

/**
 * A packet whose header protection has been removed (packet.rs:222): the header, and the header bytes and
 * payload as regions of [data]. The payload is still AEAD-protected; decrypt it in place and update [payloadLen].
 */
class Packet(
    val header: Header,
    val data: ByteArray,
    val headerStart: Int,
    val headerLen: Int,
    val payloadStart: Int,
    var payloadLen: Int,
) {
    /** A copy of the header bytes. */
    fun headerData(): ByteArray = data.copyOfRange(headerStart, headerStart + headerLen)

    /** A copy of the payload bytes. */
    fun payload(): ByteArray = data.copyOfRange(payloadStart, payloadStart + payloadLen)

    /** Whether the reserved header bits are zero, as they must be once protection is removed (packet.rs:229). */
    fun reservedBitsValid(): Boolean {
        val mask = if (header is Header.Short) SHORT_RESERVED_BITS else LONG_RESERVED_BITS
        return data[headerStart].toInt() and mask == 0
    }
}

/** A plain packet header (packet.rs:256). */
sealed class Header {

    /** The packet number, for packets that have one. */
    abstract val number: PacketNumber?

    /** Append the header, with a placeholder for the length of long packets (packet.rs:284). */
    abstract fun encode(w: Buffer): PartialEncode

    abstract val dstCid: ConnectionId

    /** Whether the packet is encrypted on the wire. */
    val isProtected: Boolean get() = this !is Retry && this !is VersionNegotiate

    val space: SpaceId
        get() = when (this) {
            is Short -> SpaceId.Data
            is Long -> if (ty == LongType.ZeroRtt) SpaceId.Data else SpaceId.Handshake
            else -> SpaceId.Initial
        }

    /** The key phase bit (short headers only). */
    open val keyPhase: Boolean get() = false

    val isShort: Boolean get() = this is Short
    val is1rtt: Boolean get() = isShort
    val is0rtt: Boolean get() = this is Long && ty == LongType.ZeroRtt

    /** Whether the payload of this packet contains QUIC frames. */
    val hasFrames: Boolean get() = this !is Retry && this !is VersionNegotiate

    data class Long(
        val ty: LongType,
        override val dstCid: ConnectionId,
        val srcCid: ConnectionId,
        override val number: PacketNumber,
        val version: Int,
    ) : Header() {
        override fun encode(w: Buffer): PartialEncode {
            val start = w.len
            w.writeByte((LongHeaderType.toByte(LongHeaderType.of(ty)) or number.tag).toByte())
            w.writeInt(version)
            dstCid.encodeLong(w)
            srcCid.encodeLong(w)
            w.writeShort(0) // placeholder for the payload length, see PartialEncode.finish
            number.encode(w)
            return PartialEncode(start, w.len - start, number.len, true)
        }
    }

    data class Retry(override val dstCid: ConnectionId, val srcCid: ConnectionId, val version: Int) : Header() {
        override val number: PacketNumber? get() = null
        override fun encode(w: Buffer): PartialEncode {
            val start = w.len
            w.writeByte(LongHeaderType.toByte(LongHeaderType.RETRY).toByte())
            w.writeInt(version)
            dstCid.encodeLong(w)
            srcCid.encodeLong(w)
            return PartialEncode(start, w.len - start, -1, false)
        }
    }

    data class Short(
        val spin: Boolean,
        override val keyPhase: Boolean,
        override val dstCid: ConnectionId,
        override val number: PacketNumber,
    ) : Header() {
        override fun encode(w: Buffer): PartialEncode {
            val start = w.len
            w.writeByte((FIXED_BIT or (if (keyPhase) KEY_PHASE_BIT else 0) or (if (spin) SPIN_BIT else 0) or number.tag).toByte())
            dstCid.encode(w)
            number.encode(w)
            return PartialEncode(start, w.len - start, number.len, false)
        }
    }

    data class VersionNegotiate(val random: Int, val srcCid: ConnectionId, override val dstCid: ConnectionId) : Header() {
        override val number: PacketNumber? get() = null
        override fun encode(w: Buffer): PartialEncode {
            val start = w.len
            w.writeByte((0x80 or random).toByte())
            w.writeInt(0)
            dstCid.encodeLong(w)
            srcCid.encodeLong(w)
            return PartialEncode(start, w.len - start, -1, false)
        }
    }
}

/** An Initial packet header (packet.rs:672; quinn's `Header::Initial(InitialHeader)`). */
data class InitialHeader(
    override val dstCid: ConnectionId,
    val srcCid: ConnectionId,
    val token: Bytes,
    override val number: PacketNumber,
    val version: Int,
) : Header() {
    override fun encode(w: Buffer): PartialEncode {
        val start = w.len
        w.writeByte((LongHeaderType.toByte(LongHeaderType.INITIAL) or number.tag).toByte())
        w.writeInt(version)
        dstCid.encodeLong(w)
        srcCid.encodeLong(w)
        w.writeVar(token.size.toLong())
        w.writeBytes(token)
        w.writeShort(0) // placeholder for the payload length, see PartialEncode.finish
        number.encode(w)
        return PartialEncode(start, w.len - start, number.len, true)
    }
}

/**
 * A header written by [Header.encode] whose length field and protection are still to be filled in
 * (packet.rs:463). [start] and [headerLen] are relative to the output buffer's readable bytes.
 */
class PartialEncode internal constructor(
    val start: Int,
    val headerLen: Int,
    /** Packet number length, or -1 for packets without one (Retry, Version Negotiation). */
    private val pnLen: Int,
    /** Whether the long header length field must be written. */
    private val writeLen: Boolean,
) {
    /**
     * Complete the packet `packet[packetStart, packetEnd)` (whose header this is): write the length field,
     * encrypt the payload with [crypto] under [packetNumber] (when given), then apply header protection
     * (packet.rs:471; RFC 9001 §5: AEAD first, header protection second). The region must already include
     * room for the AEAD tag.
     */
    fun finish(
        packet: ByteArray,
        packetStart: Int,
        packetEnd: Int,
        headerCrypto: HeaderKey,
        crypto: PacketKey?,
        packetNumber: Long,
    ) {
        if (pnLen < 0) return
        val pnPos = headerLen - pnLen
        if (writeLen) {
            val len = (packetEnd - packetStart) - headerLen + pnLen
            check(len < (1 shl 14)) { "packet length $len does not fit the reserved 2-byte field" }
            val v = len or (0b01 shl 14)
            packet[packetStart + pnPos - 2] = (v ushr 8).toByte()
            packet[packetStart + pnPos - 1] = v.toByte()
        }
        crypto?.encrypt(packetNumber, packet, packetStart, packetEnd, headerLen)
        check(pnPos + 4 + headerCrypto.sampleSize <= packetEnd - packetStart) {
            "packet must be padded to at least ${pnPos + 4 + headerCrypto.sampleSize} bytes for header protection sampling"
        }
        headerCrypto.encrypt(pnPos, packet, packetStart, packetEnd)
    }

    /**
     * [finish] for a packet written into [buf] starting at this header: the packet is the rest of [buf]'s
     * readable bytes.
     */
    fun finish(buf: Buffer, headerCrypto: HeaderKey, crypto: PacketKey?, packetNumber: Long) {
        val base = buf.readerIndex()
        finish(buf.backingArray(), base + start, base + buf.len, headerCrypto, crypto, packetNumber)
    }
}
