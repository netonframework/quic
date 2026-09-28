package neton.quic.proto

import neton.io.bytes.Buffer

// Building one outgoing QUIC packet (quinn-proto `connection/packet_builder.rs`).
//
// ⚖️ quinn creates a `PacketBuilder` per packet and keeps it in an `Option`; the connection builds one packet at a
// time, so here it owns a single builder that [begin] resets ([active] stands for `Some`). 1-RTT headers are written
// directly and protected with [protectPacket], without the `Header` / `PartialEncode` objects the long headers of the
// handshake use, so a 1-RTT packet is built without allocating. Positions are relative to the buffer's first readable
// byte (quinn's `Vec` index); the caller passes a buffer with nothing readable.

internal class PacketBuilder {
    /** Whether a packet is being built (quinn's `builder_storage.is_some()`). */
    var active = false
        private set

    var datagramStart = 0
        private set
    var space = SpaceId.Initial
        private set

    /** Start of the packet's header; with [headerLen], [pnLen] and [writeLen] quinn's `PartialEncode`. */
    var headerStart = 0
        private set
    private var headerLen = 0
    private var pnLen = 0
    private var writeLen = false

    var ackEliciting = false
        private set
    var exactNumber = 0L
        private set
    var shortHeader = false
        private set

    /** Smallest position in the buffer that must be occupied by this packet's frames. */
    var minSize = 0
        private set

    /** Largest position in the buffer that may be occupied by this packet's frames. */
    var maxSize = 0
        private set
    var tagLen = 0
        private set

    /** Whether the last [finish] added padding (quinn returns it with the length). */
    private var padded = false

    /**
     * Write a new packet header to [buffer] and determine the packet's properties (packet_builder.rs:32). Returns
     * `false` (quinn `None`), after marking the connection drained, if the confidentiality limit would be violated.
     */
    fun begin(
        now: Instant,
        spaceId: SpaceId,
        dstCid: ConnectionId,
        buffer: Buffer,
        bufferCapacity: Int,
        datagramStart: Int,
        ackEliciting: Boolean,
        conn: Connection,
    ): Boolean {
        check(!active) { "previous packet must have been finished" }
        val version = conn.version
        // Initiate key update if we're approaching the confidentiality limit
        val sentWithKeys = conn.spaces[spaceId].sentWithKeys
        if (spaceId == SpaceId.Data) {
            if (sentWithKeys >= conn.keyPhaseSize) {
                // routine key update due to phase exhaustion
                conn.forceKeyUpdate()
            }
        } else {
            val confidentialityLimit = (conn.spaces[spaceId].crypto?.packet?.local ?: conn.zeroRttCrypto!!.packet).confidentialityLimit
            if (saturatingAddU(sentWithKeys, 1) == confidentialityLimit) {
                // We still have time to attempt a graceful close
                conn.closeInner(
                    now,
                    Frame.ConnectionClose(TransportErrorCode.AEAD_LIMIT_REACHED, null, CONFIDENTIALITY_LIMIT_REASON),
                )
            } else if (sentWithKeys > confidentialityLimit) {
                // Confidentiality limited violated and there's nothing we can do
                conn.kill(ConnectionError.Transport(TransportError.AEAD_LIMIT_REACHED("confidentiality limit reached")))
                return false
            }
        }

        val space = conn.spaces[spaceId]
        val exactNumber = if (spaceId == SpaceId.Data) conn.packetNumberFilter.allocate(conn.rng, space) else space.getTxNumber()

        val number = PacketNumber.new(exactNumber, if (space.largestAckedPacket < 0) 0 else space.largestAckedPacket)
        val start = buffer.len
        val isShort = spaceId == SpaceId.Data && space.crypto != null
        if (isShort) {
            // Header.Short(spin, keyPhase, dstCid, number).encode(buffer), without the header object
            val spin = if (conn.spinEnabled) conn.spin else conn.rng.nextBoolean()
            var first = FIXED_BIT or number.tag
            if (conn.keyPhase) first = first or KEY_PHASE_BIT
            if (spin) first = first or SPIN_BIT
            buffer.writeByte(first.toByte())
            dstCid.encode(buffer)
            number.encode(buffer)
            headerStart = start
            headerLen = buffer.len - start
            pnLen = number.len
            writeLen = false
        } else {
            val header: Header = when (spaceId) {
                SpaceId.Data -> Header.Long(LongType.ZeroRtt, dstCid, conn.handshakeCid, number, version)
                SpaceId.Handshake -> Header.Long(LongType.Handshake, dstCid, conn.handshakeCid, number, version)
                SpaceId.Initial -> InitialHeader(dstCid, conn.handshakeCid, conn.clientToken(), number, version)
            }
            val partialEncode = header.encode(buffer)
            headerStart = partialEncode.start
            headerLen = partialEncode.headerLen
            pnLen = partialEncode.pnLen
            writeLen = partialEncode.writeLen
        }
        if (conn.peerParams.greaseQuicBit && conn.rng.nextBoolean()) {
            val array = buffer.backingArray()
            val at = buffer.readerIndex() + headerStart
            array[at] = (array[at].toInt() xor FIXED_BIT).toByte()
        }

        val sampleSize: Int
        val tagLen: Int
        val crypto = space.crypto
        if (crypto != null) {
            sampleSize = crypto.header.local.sampleSize
            tagLen = crypto.packet.local.tagLen
        } else if (spaceId == SpaceId.Data) {
            val zeroRtt = conn.zeroRttCrypto!!
            sampleSize = zeroRtt.header.sampleSize
            tagLen = zeroRtt.packet.tagLen
        } else {
            error("unreachable")
        }

        // Each packet must be large enough for header protection sampling, i.e. the combined lengths of the encoded
        // packet number and protected payload must be at least 4 bytes longer than the sample required for header
        // protection. Further, each packet should be at least tag_len + 6 bytes larger than the destination CID on
        // incoming packets so that the peer may send stateless resets that are indistinguishable from regular traffic.

        // pn_len + payload_len + tag_len >= sample_size + 4
        // payload_len >= sample_size + 4 - pn_len - tag_len
        val minSize = maxOf(
            buffer.len + maxOf(sampleSize + 4 - (number.len + tagLen), 0),
            headerStart + dstCid.size + 6,
        )
        val maxSize = bufferCapacity - tagLen
        debugAssert(maxSize >= minSize) { "assertion failed: max_size >= min_size" }

        active = true
        this.datagramStart = datagramStart
        this.space = spaceId
        this.exactNumber = exactNumber
        this.shortHeader = isShort
        this.minSize = minSize
        this.maxSize = maxSize
        this.tagLen = tagLen
        this.ackEliciting = ackEliciting
        return true
    }

    /**
     * Append the minimum amount of padding to the packet such that, after encryption, the enclosing datagram will
     * occupy at least [minSize] bytes (packet_builder.rs:163).
     */
    fun padTo(minSize: Int) {
        // The datagram might already have a larger minimum size than the caller is requesting, if e.g. we're
        // coalescing packets and have populated more than `min_size` bytes with packets already.
        this.minSize = maxOf(this.minSize, datagramStart + minSize - tagLen)
    }

    /**
     * Finish the packet and, when [sent] is set, track it as sent with the frames recorded in [sent]
     * (packet_builder.rs:173; quinn's `Option<SentFrames>`).
     */
    fun finishAndTrack(now: Instant, conn: Connection, sent: SentFrames?, buffer: Buffer) {
        val ackEliciting = ackEliciting
        val exactNumber = exactNumber
        val spaceId = space
        val len = finish(conn, now, buffer)
        if (sent == null) return

        val size = if (padded || ackEliciting) len else 0

        val packet = conn.sentPacketScratch
        packet.pathGeneration = conn.path.generation()
        packet.largestAcked = sent.largestAcked
        packet.timeSent = now
        packet.size = size
        packet.ackEliciting = ackEliciting
        packet.retransmits.set(sent.retransmits.take())
        packet.streamFrames = sent.streamFrames
        sent.streamFrames = StreamMetaVec.EMPTY

        conn.path.sent(exactNumber, packet, conn.spaces[spaceId])
        conn.stats.path.sentPackets += 1
        conn.resetKeepAlive(now)
        if (size != 0) {
            if (ackEliciting) {
                conn.spaces[spaceId].timeOfLastAckElicitingPacket = now
                if (conn.permitIdleReset) conn.resetIdleTimeout(now, spaceId)
                conn.permitIdleReset = false
            }
            conn.setLossDetectionTimer(now)
            conn.path.pacing.onTransmit(size)
        }
    }

    /** Encrypt the packet; returns its length (packet_builder.rs:220). [padded] tells whether padding was added. */
    fun finish(conn: Connection, @Suppress("UNUSED_PARAMETER") now: Instant, buffer: Buffer): Int {
        check(active)
        active = false
        val pad = buffer.len < minSize
        if (pad) buffer.writeZeros(minSize - buffer.len)
        padded = pad

        val space = conn.spaces[space]
        val crypto = space.crypto
        val headerCrypto: HeaderKey
        val packetCrypto: PacketKey
        if (crypto != null) {
            headerCrypto = crypto.header.local
            packetCrypto = crypto.packet.local
        } else if (this.space == SpaceId.Data) {
            val zeroRtt = conn.zeroRttCrypto!!
            headerCrypto = zeroRtt.header
            packetCrypto = zeroRtt.packet
        } else {
            error("tried to send ${this.space} packet without keys")
        }

        debugAssert(packetCrypto.tagLen == tagLen) { "Mismatching crypto tag len" }

        buffer.writeZeros(packetCrypto.tagLen)
        val base = buffer.readerIndex()
        protectPacket(
            buffer.backingArray(), base + headerStart, base + buffer.len,
            headerLen, pnLen, writeLen, headerCrypto, packetCrypto, exactNumber,
        )
        // ⛔ quinn's qlog `emit_packet_sent` (SPEC §8)
        return buffer.len - headerStart
    }

    private companion object {
        val CONFIDENTIALITY_LIMIT_REASON = neton.io.bytes.Bytes.wrap("confidentiality limit reached".encodeToByteArray())
    }
}

/** Append [n] zero bytes (quinn's `Vec::resize(len + n, 0)`). */
internal fun Buffer.writeZeros(n: Int) {
    if (n <= 0) return
    reserve(n)
    val start = writerIndex()
    backingArray().fill(0, start, start + n)
    commitWrite(n)
}
