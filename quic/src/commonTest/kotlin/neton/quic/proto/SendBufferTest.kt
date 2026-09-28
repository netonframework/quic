package neton.quic.proto

import neton.io.bytes.Bytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

/** quinn's `poll_transmit` result: `(start..end, encode_length)`. */
internal fun SendBuffer.poll(maxLen: Int): Triple<Long, Long, Boolean> {
    pollTransmit(maxLen)
    return Triple(polledStart, polledEnd, polledEncodeLength)
}

// send_buffer.rs tests
class SendBufferTest {

    private fun b(s: String): Bytes = Bytes.wrap(s.encodeToByteArray())

    private fun aggregateUnacked(buf: SendBuffer): String {
        val sb = StringBuilder()
        for ((i, segment) in buf.unackedSegments.withIndex()) {
            val from = if (i == 0) buf.frontTrimmed else 0
            sb.append(segment.slice(from).decodeToString())
        }
        return sb.toString()
    }

    @Test
    fun fragmentWithLength() {
        val buf = SendBuffer()
        val msg = "Hello, world!"
        buf.write(b(msg))
        // 0 byte offset => 19 bytes left => 13 byte data isn't enough
        // with 8 bytes reserved for length 11 payload bytes will fit
        assertEquals(Triple(0L, 11L, true), buf.poll(19))
        assertEquals(Triple(11L, msg.length.toLong(), true), buf.poll(msg.length + 16 - 11))
        assertEquals(Triple(msg.length.toLong(), msg.length.toLong(), true), buf.poll(58))
    }

    @Test
    fun fragmentWithoutLength() {
        val buf = SendBuffer()
        val msg = "Hello, world with some extra data!"
        buf.write(b(msg))
        // 0 byte offset => 19 bytes left => can be filled by 34 bytes payload
        assertEquals(Triple(0L, 19L, false), buf.poll(19))
        assertEquals(Triple(19L, msg.length.toLong(), false), buf.poll(msg.length - 19 + 1))
        assertEquals(Triple(msg.length.toLong(), msg.length.toLong(), true), buf.poll(58))
    }

    @Test
    fun reservesEncodedOffset() {
        val buf = SendBuffer()

        // Pretend we have more than 1 GB of data in the buffer
        val chunk = Bytes.wrap(ByteArray(1024 * 1024))
        repeat(1025) { buf.write(chunk) }

        val size1 = 64L
        val size2 = 16L * 1024
        val size3 = 1024L * 1024 * 1024

        // Offset 0 requires no space
        assertEquals(Triple(0L, 16L, false), buf.poll(16))
        buf.retransmit(0, 16)
        assertEquals(Triple(0L, 16L, false), buf.poll(16))
        var transmitted = 16L

        // Offset 16 requires 1 byte
        assertEquals(Triple(transmitted, size1, false), buf.poll((size1 - transmitted + 1).toInt()))
        buf.retransmit(transmitted, size1)
        assertEquals(Triple(transmitted, size1, false), buf.poll((size1 - transmitted + 1).toInt()))
        transmitted = size1

        // Offset 64 requires 2 bytes
        assertEquals(Triple(transmitted, size2, false), buf.poll((size2 - transmitted + 2).toInt()))
        buf.retransmit(transmitted, size2)
        assertEquals(Triple(transmitted, size2, false), buf.poll((size2 - transmitted + 2).toInt()))
        transmitted = size2

        // Offset 16384 requires requires 4 bytes
        assertEquals(Triple(transmitted, size3, false), buf.poll((size3 - transmitted + 4).toInt()))
        buf.retransmit(transmitted, size3)
        assertEquals(Triple(transmitted, size3, false), buf.poll((size3 - transmitted + 4).toInt()))
        transmitted = size3

        // Offset 1GB requires 8 bytes
        assertEquals(Triple(transmitted, transmitted + chunk.size, false), buf.poll(chunk.size + 8))
        buf.retransmit(transmitted, transmitted + chunk.size)
        assertEquals(Triple(transmitted, transmitted + chunk.size, false), buf.poll(chunk.size + 8))
    }

    @Test
    fun multipleSegments() {
        val buf = SendBuffer()
        val msg = "Hello, world!"
        val msgLen = msg.length.toLong()

        val seg1 = "He"
        buf.write(b(seg1))
        val seg2 = "llo,"
        buf.write(b(seg2))
        val seg3 = " w"
        buf.write(b(seg3))
        val seg4 = "o"
        buf.write(b(seg4))
        val seg5 = "rld!"
        buf.write(b(seg5))

        assertEquals(msg, aggregateUnacked(buf))

        assertEquals(Triple(0L, 8L, true), buf.poll(16))
        assertEquals(seg1, buf.get(0, 5).decodeToString())
        assertEquals(seg2, buf.get(2, 8).decodeToString())
        assertEquals(seg3, buf.get(6, 8).decodeToString())

        assertEquals(Triple(8L, msgLen, true), buf.poll(16))
        assertEquals(seg4, buf.get(8, msgLen).decodeToString())
        assertEquals(seg5, buf.get(9, msgLen).decodeToString())

        assertEquals(Triple(msgLen, msgLen, true), buf.poll(42))

        // Now drain the segments
        buf.ack(0, 1)
        assertEquals(msg.substring(1), aggregateUnacked(buf))
        buf.ack(0, 3)
        assertEquals(msg.substring(3), aggregateUnacked(buf))
        buf.ack(3, 5)
        assertEquals(msg.substring(5), aggregateUnacked(buf))
        buf.ack(7, 9)
        assertEquals(msg.substring(5), aggregateUnacked(buf))
        buf.ack(4, 7)
        assertEquals(msg.substring(9), aggregateUnacked(buf))
        buf.ack(0, msgLen)
        assertEquals("", aggregateUnacked(buf))
    }

    @Test
    fun retransmit() {
        val buf = SendBuffer()
        val msg = "Hello, world with extra data!"
        buf.write(b(msg))
        // Transmit two frames
        assertEquals(Triple(0L, 16L, false), buf.poll(16))
        assertEquals(Triple(16L, 23L, true), buf.poll(16))
        // Lose the first, but not the second
        buf.retransmit(0, 16)
        // Ensure we only retransmit the lost frame, then continue sending fresh data
        assertEquals(Triple(0L, 16L, false), buf.poll(16))
        assertEquals(Triple(23L, msg.length.toLong(), true), buf.poll(16))
        // Lose the second frame
        buf.retransmit(16, 23)
        assertEquals(Triple(16L, 23L, true), buf.poll(16))
    }

    @Test
    fun ack() {
        val buf = SendBuffer()
        val msg = "Hello, world!"
        buf.write(b(msg))
        assertEquals(Triple(0L, 8L, true), buf.poll(16))
        buf.ack(0, 8)
        assertEquals(msg.substring(8), aggregateUnacked(buf))
    }

    @Test
    fun reorderedAck() {
        val buf = SendBuffer()
        val msg = "Hello, world with extra data!"
        buf.write(b(msg))
        assertEquals(Triple(0L, 16L, false), buf.poll(16))
        assertEquals(Triple(16L, 23L, true), buf.poll(16))
        buf.ack(16, 23)
        assertEquals(msg, aggregateUnacked(buf))
        buf.ack(0, 16)
        assertEquals(msg.substring(23), aggregateUnacked(buf))
        assertTrue(buf.acks.isEmpty())
    }

    // --- Beyond the reference ---

    /** `get` after partial acknowledgements reads from the live part of the first segment only. */
    @Test
    fun getAfterPartialAck() {
        val buf = SendBuffer()
        buf.write(b("abcdef"))
        buf.write(b("ghij"))
        buf.poll(64)
        buf.ack(0, 4)
        assertEquals(4, buf.frontTrimmed)
        assertEquals(10L, buf.buffered, "trimmed bytes are still retained")
        assertEquals("ef", buf.get(4, 10).decodeToString())
        assertEquals("f", buf.get(5, 6).decodeToString())
        assertEquals("ghij", buf.get(6, 10).decodeToString())
        assertEquals("", buf.get(2, 4).decodeToString(), "acknowledged data is gone")
        buf.ack(4, 7)
        assertEquals(1, buf.frontTrimmed, "first segment released, one byte of the second trimmed")
        assertEquals("hij", buf.get(7, 10).decodeToString())
        assertEquals(4L, buf.buffered)
    }
}
