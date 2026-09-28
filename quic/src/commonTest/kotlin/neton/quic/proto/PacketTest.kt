package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

class PacketTest {

    private val v1 = DEFAULT_SUPPORTED_VERSIONS[0]

    private fun checkPn(typed: PacketNumber, encoded: ByteArray) {
        val buf = encoded { typed.encode(it) }
        assertContentEquals(encoded, buf)
        val decoded = PacketNumber.decode(typed.len, Reader(buf))
        assertEquals(typed, decoded)
    }

    // ---- packet.rs tests ----

    @Test
    fun roundtripPacketNumbers() {
        checkPn(PacketNumber.U8(0x7f), hex("7f"))
        checkPn(PacketNumber.U16(0x80), hex("0080"))
        checkPn(PacketNumber.U16(0x3fff), hex("3fff"))
        checkPn(PacketNumber.U32(0x0000_4000), hex("0000 4000"))
        checkPn(PacketNumber.U32(0xffff_ffffL), hex("ffff ffff"))
    }

    @Test
    fun pnEncode() {
        checkPn(PacketNumber.new(0x10, 0), hex("10"))
        checkPn(PacketNumber.new(0x100, 0), hex("0100"))
        checkPn(PacketNumber.new(0x10000, 0), hex("010000"))
    }

    @Test
    fun pnExpandRoundtrip() {
        for (expected in 0L until 1024) {
            for (actual in expected until 1024) {
                assertEquals(actual, PacketNumber.new(actual, expected).expand(expected))
            }
        }
    }

    /**
     * packet.rs `header_encoding`, minus the cryptography: the reference protects the packet with the real
     * RFC 9001 Initial keys and compares ciphertext, which needs the crypto layer. Here the header layout, the
     * length field and the decode path are checked with header protection and AEAD left out; the expected
     * bytes are the reference's unprotected header (`c000...402100`). The protection step itself is covered by
     * the RFC 9001 Appendix A vectors below.
     */
    @Test
    fun headerEncoding() {
        val dcid = ConnectionId.of(hex("06b858ec6f80452b"))
        val header = InitialHeader(dcid, ConnectionId.of(ByteArray(0)), Bytes.EMPTY, PacketNumber.U8(0), v1)
        val buf = Buffer(128)
        val encode = header.encode(buf)
        val headerLen = buf.len
        val tagLen = 16
        buf.writeBytes(ByteArray(16 + tagLen))
        encode.finish(buf, NoHeaderProtection(), null, 0)
        val bytes = buf.bytes()
        assertContentEquals(hex("c0000000010806b858ec6f80452b0000402100"), bytes.copyOf(headerLen))

        val decode = PartialDecode.decode(bytes, FixedLengthConnectionIdParser(0), DEFAULT_SUPPORTED_VERSIONS, false)
        assertFalse(decode.hasRest)
        val packet = decode.finish(NoHeaderProtection())
        assertContentEquals(hex("c0000000010806b858ec6f80452b0000402100"), packet.headerData())
        assertContentEquals(ByteArray(32), packet.payload())
        val h = assertIs<InitialHeader>(packet.header)
        assertEquals(PacketNumber.U8(0), h.number)
    }

    // ---- RFC 9000 Appendix A ----

    @Test
    fun rfc9000AppendixA2Encoding() {
        // Largest acked 0xabe8b3, sending 0xac5c02: 29,519 outstanding, 16 bits needed.
        val pn = PacketNumber.new(0xac5c02, 0xabe8b3)
        assertEquals(2, pn.len)
        assertEquals(0x5c02L, pn.truncated)
        // Sending 0xace8fe: 131,222 outstanding, 18 bits needed, so 24 are used.
        val pn2 = PacketNumber.new(0xace8fe, 0xabe8b3)
        assertEquals(3, pn2.len)
        assertEquals(0xace8feL, pn2.truncated)
        assertEquals(0xace8feL, pn2.expand(0xabe8b4))
        assertFailsWith<IllegalStateException> { PacketNumber.new(1L shl 32, 0) }
    }

    @Test
    fun rfc9000AppendixA3Decoding() {
        // Highest authenticated 0xa82f30ea; a 16-bit 0x9b32 decodes to 0xa82f9b32.
        assertEquals(0xa82f9b32L, PacketNumber.U16(0x9b32).expand(0xa82f30ea + 1))
        // Window edges: wrap forwards and backwards.
        assertEquals(0x100L, PacketNumber.U8(0x00).expand(0xff))
        assertEquals(0x1ffL, PacketNumber.U8(0xff).expand(0x201))
        assertEquals(0xffL, PacketNumber.U8(0xff).expand(0))
    }

    // ---- header forms ----

    private val dcid = ConnectionId.of(hex("0011223344556677"))
    private val scid = ConnectionId.of(hex("a1a2a3a4"))

    /** Encode [header] followed by [payloadLen] payload bytes, finish it without protection, and decode it back. */
    private fun roundTrip(header: Header, payloadLen: Int = 32, cidLen: Int = dcid.size): Pair<ByteArray, Packet> {
        val buf = Buffer(256)
        val enc = header.encode(buf)
        val payload = ByteArray(payloadLen) { (it + 1).toByte() }
        buf.writeBytes(payload)
        enc.finish(buf, NoHeaderProtection(), null, 0)
        val bytes = buf.bytes()
        val decode = PartialDecode.decode(bytes, FixedLengthConnectionIdParser(cidLen), DEFAULT_SUPPORTED_VERSIONS, false)
        assertFalse(decode.hasRest)
        assertEquals(bytes.size, decode.len)
        assertEquals(header.dstCid, decode.dstCid)
        val packet = decode.finish(if (header.isProtected) NoHeaderProtection() else null)
        assertEquals(header, packet.header)
        assertEquals(enc.headerLen, packet.headerLen)
        assertContentEquals(payload, packet.payload())
        assertTrue(packet.reservedBitsValid())
        return bytes to packet
    }

    @Test
    fun initialHeaderRoundTrip() {
        val token = Bytes.wrap(hex("deadbeef"))
        val header = InitialHeader(dcid, scid, token, PacketNumber.U16(0x1234), v1)
        val (bytes, packet) = roundTrip(header)
        assertEquals(0xc1, bytes[0].toInt() and 0xFF)
        assertEquals(SpaceId.Initial, packet.header.space)
        assertEquals(token, (packet.header as InitialHeader).token)
        val decode = PartialDecode.decode(bytes, FixedLengthConnectionIdParser(8), DEFAULT_SUPPORTED_VERSIONS, false)
        assertTrue(decode.isInitial)
        assertTrue(decode.hasLongHeader)
        val ih = decode.initialHeader!!
        assertContentEquals(hex("deadbeef"), bytes.copyOfRange(ih.tokenStart, ih.tokenEnd))
    }

    @Test
    fun handshakeAndZeroRttHeaderRoundTrip() {
        for ((ty, pn) in listOf(LongType.Handshake to PacketNumber.U24(0xabcdef), LongType.ZeroRtt to PacketNumber.U32(0x89abcdefL))) {
            val header = Header.Long(ty, dcid, scid, pn, v1)
            val (bytes, packet) = roundTrip(header)
            val type = (bytes[0].toInt() and 0x30) shr 4
            assertEquals(if (ty == LongType.ZeroRtt) 1 else 2, type)
            assertEquals(if (ty == LongType.ZeroRtt) SpaceId.Data else SpaceId.Handshake, packet.header.space)
            assertEquals(ty == LongType.ZeroRtt, packet.header.is0rtt)
            val decode = PartialDecode.decode(bytes, FixedLengthConnectionIdParser(8), DEFAULT_SUPPORTED_VERSIONS, false)
            assertEquals(ty == LongType.ZeroRtt, decode.is0rtt)
            assertEquals(packet.header.space, decode.space)
        }
    }

    @Test
    fun retryHeaderRoundTrip() {
        // Retry: no packet number and no length; the token and the integrity tag run to the end of the datagram.
        val header = Header.Retry(dcid, scid, v1)
        val (bytes, packet) = roundTrip(header, payloadLen = 20)
        assertEquals(0xf0, bytes[0].toInt() and 0xFF)
        assertNull(packet.header.number)
        assertFalse(packet.header.isProtected)
        assertFalse(packet.header.hasFrames)
        assertNull(PartialDecode.decode(bytes, FixedLengthConnectionIdParser(8), DEFAULT_SUPPORTED_VERSIONS, false).space)
    }

    @Test
    fun shortHeaderRoundTrip() {
        for (spin in listOf(false, true)) for (keyPhase in listOf(false, true)) {
            val header = Header.Short(spin, keyPhase, dcid, PacketNumber.U8(0x42))
            val (bytes, packet) = roundTrip(header)
            val first = bytes[0].toInt() and 0xFF
            assertEquals(0, first and LONG_HEADER_FORM)
            assertEquals(FIXED_BIT, first and FIXED_BIT)
            assertEquals(spin, first and SPIN_BIT != 0)
            assertEquals(keyPhase, first and KEY_PHASE_BIT != 0)
            assertEquals(keyPhase, packet.header.keyPhase)
            assertTrue(packet.header.is1rtt)
            assertEquals(SpaceId.Data, packet.header.space)
        }
    }

    @Test
    fun versionNegotiationRoundTrip() {
        val header = Header.VersionNegotiate(0x4a, scid, dcid)
        val buf = Buffer(64)
        header.encode(buf)
        // Supported versions follow the header.
        buf.writeInt(v1); buf.writeInt(0x0a0a0a0a)
        val bytes = buf.bytes()
        assertEquals(0xca, bytes[0].toInt() and 0xFF)
        val decode = PartialDecode.decode(bytes, FixedLengthConnectionIdParser(8), intArrayOf(), false)
        val plain = assertIs<ProtectedHeader.VersionNegotiate>(decode.plainHeader)
        assertEquals(0x4a, plain.random)
        val packet = decode.finish(null)
        assertEquals(header, packet.header)
        assertContentEquals(hex("000000010a0a0a0a"), packet.payload())
    }

    @Test
    fun coalescedPacketsAreSplit() {
        val buf = Buffer(512)
        val headers = listOf(
            InitialHeader(dcid, scid, Bytes.EMPTY, PacketNumber.U8(1), v1),
            Header.Long(LongType.Handshake, dcid, scid, PacketNumber.U8(2), v1),
            Header.Short(false, false, dcid, PacketNumber.U8(3)),
        )
        val payloads = listOf(ByteArray(30) { 1 }, ByteArray(25) { 2 }, ByteArray(40) { 3 })
        for ((h, p) in headers.zip(payloads)) {
            val packetStart = buf.len
            val enc = h.encode(buf)
            buf.writeBytes(p)
            enc.finish(buf.backingArray(), buf.readerIndex() + packetStart, buf.readerIndex() + buf.len, NoHeaderProtection(), null, 0)
        }
        val bytes = buf.bytes()
        var start = 0
        val parser = FixedLengthConnectionIdParser(8)
        for ((i, h) in headers.withIndex()) {
            val d = PartialDecode.decode(bytes, start, bytes.size, parser, DEFAULT_SUPPORTED_VERSIONS, false)
            val packet = d.finish(NoHeaderProtection())
            assertEquals(h, packet.header)
            assertContentEquals(payloads[i], packet.payload())
            if (i < headers.size - 1) {
                assertTrue(d.hasRest)
                assertEquals(bytes.size, d.restEnd)
                start = d.restStart
            } else {
                assertFalse(d.hasRest) // a short header packet takes the rest of the datagram
            }
        }
    }

    @Test
    fun fixedBitGrease() {
        val buf = Buffer(64)
        Header.Short(false, false, dcid, PacketNumber.U8(1)).encode(buf)
        buf.writeBytes(ByteArray(24))
        val bytes = buf.bytes()
        bytes[0] = (bytes[0].toInt() and FIXED_BIT.inv()).toByte()
        val parser = FixedLengthConnectionIdParser(8)
        val e = assertFailsWith<PacketDecodeError.InvalidHeader> {
            PartialDecode.decode(bytes, parser, DEFAULT_SUPPORTED_VERSIONS, false)
        }
        assertEquals("fixed bit unset", e.reason)
        // With the grease_quic_bit transport parameter negotiated, any fixed bit value is accepted.
        val d = PartialDecode.decode(bytes, parser, DEFAULT_SUPPORTED_VERSIONS, true)
        assertIs<ProtectedHeader.Short>(d.plainHeader)
    }

    @Test
    fun decodeErrors() {
        val parser = FixedLengthConnectionIdParser(8)
        // Unsupported version, reported with both connection IDs.
        val unsupported = encoded {
            it.writeByte(0xc0.toByte()); it.writeInt(0x1a2a3a4a); dcid.encodeLong(it); scid.encodeLong(it); it.writeBytes(ByteArray(20))
        }
        assertEquals(
            PacketDecodeError.UnsupportedVersion(scid, dcid, 0x1a2a3a4a),
            assertFailsWith<PacketDecodeError.UnsupportedVersion> { PartialDecode.decode(unsupported, parser, DEFAULT_SUPPORTED_VERSIONS, false) },
        )
        fun reason(bytes: ByteArray) = assertFailsWith<PacketDecodeError.InvalidHeader> {
            PartialDecode.decode(bytes, parser, DEFAULT_SUPPORTED_VERSIONS, false)
        }.reason
        assertEquals("unexpected end of packet", reason(hex("c0000000")))
        assertEquals("malformed cid", reason(hex("c000000001 15" + "00".repeat(21) + "00")))
        assertEquals("token out of bounds", reason(hex("c000000001 00 00 05 0102")))
        assertEquals("packet too short to contain payload length", reason(hex("e000000001 00 00 10 01020304")))
        assertEquals("packet too small", reason(hex("40 0102")))
        // Too short to sample for header protection.
        val tiny = PartialDecode.decode(hex("e000000001 00 00 03 010203"), parser, DEFAULT_SUPPORTED_VERSIONS, false)
        assertEquals(
            "packet too short to extract header protection sample",
            assertFailsWith<PacketDecodeError.InvalidHeader> { tiny.finish(NoHeaderProtection()) }.reason,
        )
    }

    @Test
    fun reservedBits() {
        val buf = Buffer(64)
        Header.Short(false, false, dcid, PacketNumber.U8(1)).encode(buf)
        buf.writeBytes(ByteArray(24))
        val bytes = buf.bytes()
        bytes[0] = (bytes[0].toInt() or 0x08).toByte()
        val p = PartialDecode.decode(bytes, FixedLengthConnectionIdParser(8), DEFAULT_SUPPORTED_VERSIONS, false).finish(NoHeaderProtection())
        assertFalse(p.reservedBitsValid())
    }

    // ---- header protection layout: RFC 9001 Appendix A vectors ----

    /** Returns the mask the crypto layer would compute for [expectedSample] (checked), as in the RFC example. */
    private class FixedMask(private val expectedSample: ByteArray, private val mask: ByteArray) : HeaderProtection() {
        override val sampleSize: Int get() = 16
        override fun mask(sample: ByteArray, sampleOffset: Int, out: ByteArray) {
            assertContentEquals(expectedSample, sample.copyOfRange(sampleOffset, sampleOffset + 16), "sample location")
            mask.copyInto(out)
        }
    }

    private fun checkProtection(unprotected: String, protected: String, pnOffset: Int, sample: String, mask: String) {
        val header = hex(unprotected)
        val samplePos = HeaderProtection.sampleOffset(pnOffset)
        val packet = ByteArray(samplePos + 16 + 4)
        header.copyInto(packet)
        hex(sample).copyInto(packet, samplePos)
        val key = FixedMask(hex(sample), hex(mask))
        key.encrypt(pnOffset, packet, 0, packet.size)
        assertContentEquals(hex(protected), packet.copyOf(header.size))
        key.decrypt(pnOffset, packet, 0, packet.size)
        assertContentEquals(header, packet.copyOf(header.size))
    }

    @Test
    fun rfc9001ClientInitialHeaderProtection() = checkProtection(
        unprotected = "c300000001088394c8f03e5157080000449e00000002",
        protected = "c000000001088394c8f03e5157080000449e7b9aec34",
        pnOffset = 18,
        sample = "d1b1c98dd7689fb8ec11d242b123dc9b",
        mask = "437b9aec36",
    )

    @Test
    fun rfc9001ServerInitialHeaderProtection() = checkProtection(
        unprotected = "c1000000010008f067a5502a4262b50040750001",
        protected = "cf000000010008f067a5502a4262b5004075c0d9",
        pnOffset = 18,
        sample = "2cd0991cd25b0aac406a5816b6394100",
        mask = "2ec0d8356a",
    )

    @Test
    fun rfc9001ShortHeaderHeaderProtection() = checkProtection(
        unprotected = "4200bff4",
        protected = "4cfe4189",
        pnOffset = 1,
        sample = "5e5cd55c41f69080575d7999c25a5bfb",
        mask = "aefefe7d03",
    )

    @Test
    fun protectedPacketRoundTrip() {
        // Encode with a (fake) mask-based header key, then decode: the decoder must unmask the first byte before
        // reading the packet number length.
        val key = object : HeaderProtection() {
            override val sampleSize: Int get() = 16
            override fun mask(sample: ByteArray, sampleOffset: Int, out: ByteArray) {
                for (i in 0 until 5) out[i] = (sample[sampleOffset + i].toInt() xor 0x5a).toByte()
            }
        }
        val header = Header.Long(LongType.Handshake, dcid, scid, PacketNumber.U16(0x0102), v1)
        val buf = Buffer(128)
        val enc = header.encode(buf)
        buf.writeBytes(ByteArray(40) { (it * 7).toByte() })
        enc.finish(buf, key, null, 0x0102)
        val bytes = buf.bytes()
        val packet = PartialDecode.decode(bytes, FixedLengthConnectionIdParser(8), DEFAULT_SUPPORTED_VERSIONS, false).finish(key)
        assertEquals(header, packet.header)
    }

    @Test
    fun packetKeyIsAppliedBeforeHeaderProtection() {
        val calls = mutableListOf<String>()
        val packetKey = object : PacketKey {
            override fun encrypt(packetNumber: Long, packet: ByteArray, start: Int, end: Int, headerLen: Int) {
                calls += "aead pn=$packetNumber headerLen=$headerLen len=${end - start}"
            }
            override fun decrypt(packetNumber: Long, header: ByteArray, headerStart: Int, headerEnd: Int, payload: ByteArray, payloadStart: Int, payloadEnd: Int) =
                payloadEnd - payloadStart - tagLen
            override val tagLen: Int get() = 16
            override val confidentialityLimit: Long get() = Long.MAX_VALUE
            override val integrityLimit: Long get() = Long.MAX_VALUE
        }
        val headerKey = object : HeaderKey {
            override val sampleSize: Int get() = 16
            override fun decrypt(pnOffset: Int, packet: ByteArray, start: Int, end: Int) {}
            override fun encrypt(pnOffset: Int, packet: ByteArray, start: Int, end: Int) { calls += "hp pnOffset=$pnOffset" }
        }
        val buf = Buffer(128)
        val enc = Header.Short(false, false, dcid, PacketNumber.U8(9)).encode(buf)
        buf.writeBytes(ByteArray(20 + 16))
        enc.finish(buf, headerKey, packetKey, 9)
        assertEquals(listOf("aead pn=9 headerLen=10 len=46", "hp pnOffset=9"), calls)
    }
}
