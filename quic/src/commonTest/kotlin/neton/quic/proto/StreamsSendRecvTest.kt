package neton.quic.proto

import neton.io.bytes.Bytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue

// streams/send.rs and streams/recv.rs tests
class StreamsSendRecvTest {

    private fun b(s: String): Bytes = Bytes.wrap(s.encodeToByteArray())

    // --- send.rs ---

    @Test
    fun bytesArray() {
        val full = "Hello World 123456789 ABCDEFGHJIJKLMNOPQRSTUVWXYZ"
        for (limit in 0 until full.length) {
            val chunks = arrayOf(
                b(""), b("Hello "), b("Wo"), b(""), b("r"), b("ld"), b(""), b(" 12345678"), b("9 ABCDE"), b("F"),
                b("GHJIJKLMNOPQRSTUVWXYZ"),
            )
            val numChunks = chunks.size
            val lastChunkLen = chunks[chunks.size - 1].size

            val array = BytesArray(chunks)

            val buf = StringBuilder()
            var chunksPopped = 0
            var remaining = limit
            while (true) {
                val chunk = array.popChunk(remaining)
                if (!chunk.isEmpty) {
                    buf.append(chunk.decodeToString())
                    remaining -= chunk.size
                    chunksPopped += 1
                } else {
                    break
                }
            }
            val chunksConsumed = array.chunksConsumed

            assertEquals(full.substring(0, limit), buf.toString())

            if (limit == full.length) {
                // Full consumption of the last chunk
                assertEquals(numChunks, chunksConsumed)
                // Since there are empty chunks, we consume more than there are popped
                assertEquals(chunksPopped + 3, chunksConsumed)
            } else if (limit > full.length - lastChunkLen) {
                // Partial consumption of the last chunk
                assertEquals(numChunks - 1, chunksConsumed)
                assertEquals(chunksPopped + 2, chunksConsumed)
            }
        }
    }

    @Test
    fun byteSlice() {
        val full = "Hello World 123456789 ABCDEFGHJIJKLMNOPQRSTUVWXYZ".encodeToByteArray()
        for (limit in 0 until full.size) {
            val array = ByteSlice(full)

            val buf = ArrayList<Byte>()
            var chunksPopped = 0
            var remaining = limit
            while (true) {
                val chunk = array.popChunk(remaining)
                if (!chunk.isEmpty) {
                    buf.addAll(chunk.toByteArray().toList())
                    remaining -= chunk.size
                    chunksPopped += 1
                } else {
                    break
                }
            }
            val chunksConsumed = array.chunksConsumed

            assertEquals(full.copyOfRange(0, limit).toList(), buf)
            if (limit != 0) assertEquals(1, chunksPopped) else assertEquals(0, chunksPopped)

            if (limit == full.size) assertEquals(1, chunksConsumed) else assertEquals(0, chunksConsumed)
        }
    }

    // --- recv.rs ---

    @Test
    fun reorderedFramesWhileStopped() {
        val initialBytes = 3L
        val initialOffset = 3L
        val recvWindow = 8L
        val s = Recv(recvWindow)
        var dataRecvd = 0L
        // Receive bytes 3..6
        var frame = Frame.Stream(StreamId.of(Side.Client, Dir.Uni, 0), initialOffset, false, Bytes.wrap(ByteArray(initialBytes.toInt())))
        var newBytes = s.ingest(frame, 123, dataRecvd, dataRecvd + 1024)
        var isClosed = frame.fin && s.stopped
        dataRecvd += newBytes
        assertEquals(initialOffset + initialBytes, newBytes)
        assertFalse(isClosed)

        val credits = s.stop()
        val transmit = s.isReceiving
        assertTrue(transmit)
        assertEquals(initialOffset + initialBytes, credits, "full connection flow control credit is issued by stop")

        assertFalse(s.maxStreamDataShouldTransmit(recvWindow))
        assertEquals(recvWindow, s.maxStreamData(recvWindow), "stream flow control credit isn't issued by stop")

        // Receive byte 7
        frame = Frame.Stream(StreamId.of(Side.Client, Dir.Uni, 0), recvWindow - 1, false, Bytes.wrap(ByteArray(1)))
        newBytes = s.ingest(frame, 123, dataRecvd, dataRecvd + 1024)
        isClosed = frame.fin && s.stopped
        dataRecvd += newBytes
        assertEquals(recvWindow - (initialOffset + initialBytes), newBytes)
        assertFalse(isClosed)

        assertFalse(s.maxStreamDataShouldTransmit(recvWindow))
        assertEquals(recvWindow, s.maxStreamData(recvWindow), "stream flow control credit isn't issued after stop")

        // Receive bytes 0..3
        frame = Frame.Stream(StreamId.of(Side.Client, Dir.Uni, 0), 0, false, Bytes.wrap(ByteArray(initialOffset.toInt())))
        newBytes = s.ingest(frame, 123, dataRecvd, dataRecvd + 1024)
        isClosed = frame.fin && s.stopped
        assertEquals(0L, newBytes, "reordered frames don't issue connection-level flow control for stopped streams")
        assertFalse(isClosed)

        assertFalse(s.maxStreamDataShouldTransmit(recvWindow))
        assertEquals(recvWindow, s.maxStreamData(recvWindow), "stream flow control credit isn't issued after stop")
    }
}
