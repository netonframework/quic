package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue

// connection/datagrams.rs tests (quinn's `size_of::<Datagram>()` is DATAGRAM_OVERHEAD)
class DatagramsTest {

    @Test
    fun makeSpaceForAccountsForNewDatagram() {
        val state = DatagramState()
        state.outgoing.pushBack(zeros(7))
        state.outgoing.pushBack(zeros(2))
        state.makeSpaceFor(4, 10 + 2 * DATAGRAM_OVERHEAD)

        assertEquals(1, state.outgoing.queue.size)
        assertEquals(2, state.outgoing.queue[0].size)
        assertEquals(2L, state.outgoing.payloadBytes)
    }

    @Test
    fun makeSpaceForHandlesOverflowingCapacityCheck() {
        val state = DatagramState()
        state.outgoing.queue.addLast(zeros(1))
        state.outgoing.payloadBytes = Long.MAX_VALUE - 1

        state.makeSpaceFor(2, Long.MAX_VALUE)

        assertTrue(state.outgoing.isEmpty())
        assertEquals(Long.MAX_VALUE - 2, state.outgoing.payloadBytes)
    }

    @Test
    fun makeSpaceForAccountsForEmptyDatagramMetadata() {
        val state = DatagramState()
        repeat(2) { state.outgoing.pushBack(Bytes.EMPTY) }
        val window = 2 * DATAGRAM_OVERHEAD

        assertFalse(state.hasSendBufferSpace(0, window))
        state.makeSpaceFor(0, window)
        assertEquals(1, state.outgoing.queue.size)
        assertTrue(state.hasSendBufferSpace(0, window))
        state.outgoing.pushBack(Bytes.EMPTY)
        assertEquals(window, state.outgoing.memoryUsed())
    }

    @Test
    fun sendBufferSpaceHandlesMetadataOverflow() {
        assertFalse(DatagramState().hasSendBufferSpace(Long.MAX_VALUE, Long.MAX_VALUE))
    }

    @Test
    fun dropOversizedKeepsDatagramsAtLimit() {
        val state = DatagramState()
        state.outgoing.pushBack(zeros(10))
        state.outgoing.pushBack(zeros(11))

        assertTrue(state.dropOversized(10))

        assertEquals(1, state.outgoing.queue.size)
        assertEquals(10, state.outgoing.queue[0].size)
        assertEquals(10L, state.outgoing.payloadBytes)
    }

    // --- Beyond the reference: the `Datagrams` view logic and the frame writer ---

    @Test
    fun sendChecksConfigurationAndSize() {
        val state = DatagramState()
        val d = zeros(100)
        assertEquals(SendDatagramError.Disabled, state.send(d, true, -1, 1000, 1200))
        assertEquals(SendDatagramError.UnsupportedByPeer, state.send(d, true, 1000, 1000, -1))
        assertEquals(SendDatagramError.TooLarge, state.send(d, true, 1000, 1000, 99))
        assertEquals(SendDatagramError.TooLarge, state.send(d, true, 1000, 100 + DATAGRAM_OVERHEAD - 1, 1200))
        assertEquals(SendDatagramError.TooLarge, state.send(d, true, 1000, DATAGRAM_OVERHEAD - 1, 1200))
        assertNull(state.send(d, true, 1000, 100 + DATAGRAM_OVERHEAD, 1200))
    }

    @Test
    fun sendBlockedThenDropOldest() {
        val state = DatagramState()
        val size = 2 * (100 + DATAGRAM_OVERHEAD)
        assertNull(state.send(zeros(100), false, 1000, size, 1200))
        assertNull(state.send(zeros(100), false, 1000, size, 1200))
        assertEquals(0L, state.sendBufferSpace(size))
        val third = Bytes.wrap(ByteArray(100) { 3 })
        assertEquals(SendDatagramError.Blocked(third), state.send(third, false, 1000, size, 1200))
        assertTrue(state.sendBlocked)
        // drop = true discards the oldest to make room
        assertNull(state.send(third, true, 1000, size, 1200))
        assertEquals(2, state.outgoing.queue.size)
        assertEquals(third, state.outgoing.queue[1])
        // an MTU drop below the queued size wakes the blocked sender
        assertTrue(state.dropOversizedAndUnblock(99))
        assertFalse(state.sendBlocked)
        assertTrue(state.outgoing.isEmpty())
        assertFalse(state.dropOversizedAndUnblock(-1))
    }

    @Test
    fun receivedDropsStaleAndRejectsOversized() {
        val state = DatagramState()
        val window = 2 * (10 + DATAGRAM_OVERHEAD)
        assertEquals(
            TransportErrorCode.PROTOCOL_VIOLATION,
            assertFailsWith<TransportError> { state.received(zeros(1), -1) }.code,
        )
        assertEquals(
            TransportErrorCode.PROTOCOL_VIOLATION,
            assertFailsWith<TransportError> { state.received(zeros(window.toInt()), window) }.code,
        )
        assertTrue(state.received(Bytes.wrap(ByteArray(10) { 1 }), window))
        assertFalse(state.received(Bytes.wrap(ByteArray(10) { 2 }), window))
        assertFalse(state.received(Bytes.wrap(ByteArray(10) { 3 }), window)) // drops the first
        assertEquals(2, state.recv()!![0].toInt())
        assertEquals(3, state.recv()!![0].toInt())
        assertNull(state.recv())
    }

    @Test
    fun writeEncodesDatagramFrame() {
        val state = DatagramState()
        val payload = Bytes.wrap("hello".encodeToByteArray())
        assertNull(state.send(payload, true, 1000, 1000, 1200))
        val buf = Buffer(64)
        assertFalse(state.write(buf, 6), "does not fit: 1 + 1 + 5 bytes")
        assertEquals(1, state.outgoing.queue.size)
        assertTrue(state.outgoing.canSend1rtt(7))
        assertTrue(state.write(buf, 7))
        assertFalse(state.write(buf, 100))
        val frame = assertIs<Frame.Datagram>(FrameIter(buf.bytes()).next())
        assertEquals(payload, frame.data)
    }

    @Test
    fun maxSizeUsesPathAndPeerLimit() {
        assertEquals(-1L, DatagramState.maxSize(1200, 30, null))
        assertEquals(1200L - 30 - Frame.Datagram.SIZE_BOUND, DatagramState.maxSize(1200, 30, VarInt(65535)))
        assertEquals(500L - Frame.Datagram.SIZE_BOUND, DatagramState.maxSize(1200, 30, VarInt(500)))
        assertEquals(0L, DatagramState.maxSize(1200, 30, VarInt(3)))
    }
}
