package neton.quic.proto

import neton.io.bytes.Bytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class FrameTest {

    private fun frames(buf: ByteArray): List<Frame> = FrameIter(buf).asSequence().toList()

    private fun b(s: String) = Bytes.wrap(s.encodeToByteArray())

    // ---- frame.rs tests ----

    @Test
    fun ackCoding() {
        val packets = longArrayOf(1, 2, 3, 5, 10, 11, 14)
        val ranges = ArrayRangeSet()
        for (p in packets) ranges.insert(p, p + 1)
        val ecn = EcnCounts(42, 24, 12)
        val buf = encoded { Frame.Ack.encode(42, ranges, ecn, it) }
        val frames = frames(buf)
        assertEquals(1, frames.size)
        val ack = assertIs<Frame.Ack>(frames[0])
        val got = ack.flatMap { it.toList() }.sorted()
        assertEquals(packets.toList(), got)
        assertEquals(ecn, ack.ecn)
    }

    @Test
    fun ackFrequencyCoding() {
        val original = Frame.AckFrequency(VarInt(42), VarInt(20), VarInt(50_000), VarInt(1))
        val frames = frames(encoded { original.encode(it) })
        assertEquals(1, frames.size)
        assertEquals(original, frames[0])
    }

    @Test
    fun immediateAckCoding() {
        val frames = frames(encoded { FrameType.IMMEDIATE_ACK.encode(it) })
        assertEquals(1, frames.size)
        assertEquals(Frame.ImmediateAck, frames[0])
    }

    // ---- round trips of every frame type ----

    private fun roundTrip(f: Frame) {
        val bytes = encoded { f.encode(it) }
        val back = frames(bytes)
        assertEquals(listOf(f), back, "round trip of ${f.ty}")
        assertEquals(f.ty, back[0].ty)
    }

    @Test
    fun everyFrameTypeRoundTrips() {
        val cid = ConnectionId.of(hex("0102030405060708"))
        val token = ResetToken(ByteArray(16) { it.toByte() })
        val all = listOf(
            Frame.Padding,
            Frame.Ping,
            Frame.ResetStream(StreamId(4), VarInt(7), VarInt(1_000_000)),
            Frame.StopSending(StreamId(3), VarInt(0x1234)),
            Frame.Crypto(0, b("client hello")),
            Frame.Crypto(1L shl 40, b("more")),
            Frame.NewToken(b("opaque token")),
            Frame.Stream(StreamId(0), 0, false, b("hello")),
            Frame.Stream(StreamId(1), 0, true, b("fin only offset 0")),
            Frame.Stream(StreamId(2), 99, false, b("offset")),
            Frame.Stream(StreamId(6), 1L shl 50, true, Bytes.EMPTY),
            Frame.MaxData(VarInt(1L shl 40)),
            Frame.MaxStreamData(StreamId(8), 65536),
            Frame.MaxStreams(Dir.Bi, 100),
            Frame.MaxStreams(Dir.Uni, 3),
            Frame.DataBlocked(12345),
            Frame.StreamDataBlocked(StreamId(9), 777),
            Frame.StreamsBlocked(Dir.Bi, 10),
            Frame.StreamsBlocked(Dir.Uni, 11),
            Frame.NewConnectionId(5, 2, cid, token),
            Frame.RetireConnectionId(3),
            Frame.PathChallenge(0x0123456789abcdefL),
            Frame.PathResponse(-1L),
            Frame.ConnectionClose(TransportErrorCode.PROTOCOL_VIOLATION, FrameType.STREAM_DATA_BLOCKED, b("bad")),
            Frame.ConnectionClose(TransportErrorCode.NO_ERROR, null, Bytes.EMPTY),
            Frame.ConnectionClose(TransportErrorCode.crypto(0x2a), FrameType.CRYPTO, b("tls alert")),
            Frame.ApplicationClose(VarInt(0x100), b("bye")),
            Frame.HandshakeDone,
            Frame.AckFrequency(VarInt(1), VarInt(2), VarInt(3), VarInt(4)),
            Frame.ImmediateAck,
            Frame.Datagram(b("unreliable")),
            Frame.Datagram(Bytes.EMPTY),
        )
        for (f in all) roundTrip(f)

        // Every frame in one payload, then parsed back in order.
        val bytes = encoded { out -> all.forEach { it.encode(out) } }
        assertEquals(all, frames(bytes))
    }

    @Test
    fun ackAndAckEcnRoundTrip() {
        for (ecn in listOf(null, EcnCounts(1, 2, 3))) {
            val ranges = ArrayRangeSet()
            ranges.insert(0, 3); ranges.insert(10, 20); ranges.insert(1000, 1001)
            val bytes = encoded { Frame.Ack.encode(25, ranges, ecn, it) }
            assertEquals(if (ecn == null) 0x02 else 0x03, bytes[0].toInt())
            val ack = assertIs<Frame.Ack>(frames(bytes).single())
            assertEquals(1000L, ack.largest)
            assertEquals(25L, ack.delay)
            assertEquals(ecn, ack.ecn)
            assertEquals(listOf(1000L..1000L, 10L..19L, 0L..2L), ack.ranges())
            // Re-encoding a parsed ACK reproduces the wire bytes.
            assertContentEquals(bytes, encoded { ack.encode(it) })
        }
    }

    @Test
    fun streamAndDatagramWithoutLengthRunToTheEnd() {
        val bytes = encoded {
            Frame.Ping.encode(it)
            StreamMeta(StreamId(4), 10, 15, true).encode(false, it)
            it.writeBytes("abcde".encodeToByteArray())
        }
        val fs = frames(bytes)
        assertEquals(Frame.Ping, fs[0])
        assertEquals(Frame.Stream(StreamId(4), 10, true, b("abcde")), fs[1])
        assertEquals(0x0d, bytes[1].toInt()) // STREAM with OFF and FIN, no LEN

        val d = Frame.Datagram(b("xyz"))
        val dBytes = encoded { d.encode(false, it) }
        assertEquals(0x30, dBytes[0].toInt())
        assertEquals(d.size(false), dBytes.size)
        assertEquals(d.size(true), encoded { d.encode(true, it) }.size)
        assertEquals(listOf<Frame>(d), frames(dBytes))
    }

    @Test
    fun streamMetaTypeBits() {
        assertEquals(0x08, encoded { StreamMeta(StreamId(0), 0, 0, false).encode(false, it) }[0].toInt())
        assertEquals(0x0a, encoded { StreamMeta(StreamId(0), 0, 3, false).encode(true, it) }[0].toInt())
        assertEquals(0x0f, encoded { StreamMeta(StreamId(0), 1, 3, true).encode(true, it) }[0].toInt())
        // Frame.ty mirrors quinn: FIN and OFF bits, never LEN.
        assertEquals(FrameType(0x0d), Frame.Stream(StreamId(0), 5, true, Bytes.EMPTY).ty)
    }

    @Test
    fun closeReasonIsTruncatedToMaxLen() {
        val close = Frame.ConnectionClose(TransportErrorCode.INTERNAL_ERROR, null, b("0123456789"))
        val bytes = encoded { close.encode(it, 10) }
        // 1 type + 1 code + 1 frame type + 1 length, and max_len - 3 - 1 - 1 = 5 reason bytes.
        val parsed = assertIs<Frame.ConnectionClose>(frames(bytes).single())
        assertEquals(b("01234"), parsed.reason)
        val app = Frame.ApplicationClose(VarInt(1), b("0123456789"))
        val appParsed = assertIs<Frame.ApplicationClose>(frames(encoded { app.encode(it, 8) }).single())
        assertEquals(b("0123"), appParsed.reason)
    }

    @Test
    fun closeFromTransportError() {
        val err = TransportError.FLOW_CONTROL_ERROR("too much").also { it.frame = FrameType.STREAM_DATA_BLOCKED }
        val close = Frame.Close.from(err)
        assertEquals(Frame.ConnectionClose(TransportErrorCode.FLOW_CONTROL_ERROR, FrameType.STREAM_DATA_BLOCKED, b("too much")), close)
        assertTrue(close.isTransportLayer)
        assertFalse(close.isAckEliciting)
    }

    @Test
    fun sizeBounds() {
        val cid = ConnectionId.of(ByteArray(MAX_CID_SIZE) { 1 })
        val maxNcid = Frame.NewConnectionId(VarInt.MAX.value, VarInt.MAX.value, cid, ResetToken(ByteArray(16)))
        assertTrue(encoded { maxNcid.encode(it) }.size <= Frame.NewConnectionId.SIZE_BOUND)
        val rs = Frame.ResetStream(StreamId(VarInt.MAX.value), VarInt.MAX, VarInt.MAX)
        assertTrue(encoded { rs.encode(it) }.size <= Frame.ResetStream.SIZE_BOUND)
        assertTrue(encoded { Frame.RetireConnectionId(VarInt.MAX.value).encode(it) }.size <= Frame.RetireConnectionId.SIZE_BOUND)
        val nt = Frame.NewToken(b("tok"))
        assertEquals(nt.size(), encoded { nt.encode(it) }.size)
    }

    @Test
    fun ackElicitingAndTypes() {
        assertFalse(Frame.Padding.isAckEliciting)
        assertFalse(Frame.Ack(0, 0, Bytes.wrap(byteArrayOf(0)), null).isAckEliciting)
        assertFalse(Frame.ApplicationClose(VarInt(0), Bytes.EMPTY).isAckEliciting)
        assertTrue(Frame.Ping.isAckEliciting)
        assertTrue(Frame.Datagram(Bytes.EMPTY).isAckEliciting)
        assertEquals("STREAM", FrameType(0x0b).displayName)
        assertEquals("DATAGRAM", FrameType(0x31).displayName)
        assertEquals("<unknown 21>", FrameType(0x21).displayName)
        assertEquals("Type(21)", FrameType(0x21).toString())
        assertEquals("ACK_FREQUENCY", FrameType.ACK_FREQUENCY.toString())
    }

    // ---- iterator errors ----

    @Test
    fun emptyPayloadIsProtocolViolation() {
        val e = assertFailsWith<TransportError> { FrameIter(ByteArray(0)) }
        assertEquals(TransportErrorCode.PROTOCOL_VIOLATION, e.code)
        assertEquals("packet payload is empty", e.reason)
    }

    private fun invalid(bytes: ByteArray): InvalidFrame {
        val it = FrameIter(bytes)
        var err: InvalidFrame? = null
        while (it.hasNext()) {
            try { it.next() } catch (e: InvalidFrame) { err = e }
        }
        assertFalse(it.hasNext(), "the rest of the packet is skipped after an error")
        return err ?: throw AssertionError("expected an invalid frame")
    }

    @Test
    fun unknownFrameType() {
        val e = invalid(hex("01 21 01 01"))
        assertEquals(FrameType(0x21), e.ty)
        assertEquals("invalid frame ID", e.reason)
        val te = e.toTransportError()
        assertEquals(TransportErrorCode.FRAME_ENCODING_ERROR, te.code)
        assertEquals(FrameType(0x21), te.frame)
    }

    @Test
    fun truncatedFrames() {
        for (h in listOf("04 01", "06 00 05 6869", "18 01 00 08 0102", "1a 0102030405", "11", "40")) {
            val e = invalid(hex(h))
            assertEquals("unexpected end", e.reason, h)
        }
        // A truncated frame type varint has no type.
        assertNull(invalid(hex("40")).ty)
    }

    @Test
    fun malformedFrames() {
        // NEW_CONNECTION_ID with retire_prior_to > sequence
        assertEquals("malformed", invalid(hex("18 01 02 01 aa" + "00".repeat(16))).reason)
        // NEW_CONNECTION_ID with a zero-length and an over-long connection ID
        assertEquals("malformed", invalid(hex("18 01 00 00" + "00".repeat(16))).reason)
        assertEquals("malformed", invalid(hex("18 01 00 15" + "00".repeat(21 + 16))).reason)
        // ACK whose first range goes below zero, and whose gap does
        assertEquals("malformed", invalid(hex("02 05 00 00 06")).reason)
        assertEquals("malformed", invalid(hex("02 05 00 01 01 04 00")).reason)
        // ACK claiming more ranges than present
        assertEquals("unexpected end", invalid(hex("02 05 00 02 00 00 00")).reason)
    }

    @Test
    fun zeroCopySlices() {
        val payload = encoded { Frame.Crypto(0, b("abc")).encode(it) }
        val f = assertIs<Frame.Crypto>(FrameIter(payload).next())
        payload[payload.size - 1] = 'z'.code.toByte()
        assertEquals(b("abz"), f.data, "the slice views the payload array")
    }

    // ---- per-space frame validity (connection/mod.rs:2715-2733, 2786-2793) ----

    @Test
    fun handshakeSpaceAllowsOnlyPaddingPingCryptoAckClose() {
        val allowed = listOf(
            Frame.Padding, Frame.Ping, Frame.Crypto(0, Bytes.EMPTY), Frame.Ack(0, 0, Bytes.wrap(byteArrayOf(0)), null),
            Frame.ConnectionClose(TransportErrorCode.NO_ERROR, null, Bytes.EMPTY), Frame.ApplicationClose(VarInt(0), Bytes.EMPTY),
        )
        for (f in allowed) assertNull(f.handshakeSpaceViolation(), "$f")
        val forbidden = listOf(
            Frame.Stream(StreamId(0), 0, false, Bytes.EMPTY), Frame.NewToken(Bytes.EMPTY), Frame.HandshakeDone,
            Frame.MaxData(VarInt(1)), Frame.Datagram(Bytes.EMPTY), Frame.ImmediateAck, Frame.PathChallenge(1),
            Frame.RetireConnectionId(0),
        )
        for (f in forbidden) {
            val e = f.handshakeSpaceViolation() ?: throw AssertionError("$f must be illegal in handshake")
            assertEquals(TransportErrorCode.PROTOCOL_VIOLATION, e.code)
            assertEquals("illegal frame type in handshake", e.reason)
            assertEquals(f.ty, e.frame)
        }
    }

    @Test
    fun zeroRttForbidsCryptoAndApplicationClose() {
        for (f in listOf(Frame.Crypto(0, Bytes.EMPTY), Frame.ApplicationClose(VarInt(0), Bytes.EMPTY))) {
            val e = f.zeroRttViolation() ?: throw AssertionError("$f must be illegal in 0-RTT")
            assertEquals(TransportErrorCode.PROTOCOL_VIOLATION, e.code)
            assertEquals("illegal frame type in 0-RTT", e.reason)
            assertNull(e.frame)
        }
        for (f in listOf(
            Frame.Stream(StreamId(0), 0, false, Bytes.EMPTY), Frame.Ping, Frame.Padding,
            Frame.ConnectionClose(TransportErrorCode.NO_ERROR, null, Bytes.EMPTY), Frame.Datagram(Bytes.EMPTY),
        )) assertNull(f.zeroRttViolation(), "$f")
    }

    @Test
    fun ecnCountsAdd() {
        val c = EcnCounts.ZERO
        c.add(neton.io.net.EcnCodepoint.Ect0)
        c.add(neton.io.net.EcnCodepoint.Ect0)
        c.add(neton.io.net.EcnCodepoint.Ect1)
        c.add(neton.io.net.EcnCodepoint.Ce)
        assertEquals(EcnCounts(2, 1, 1), c)
        assertEquals(EcnCounts(), EcnCounts.ZERO)
    }
}
