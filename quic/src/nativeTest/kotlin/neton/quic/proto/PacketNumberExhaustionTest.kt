package neton.quic.proto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

/**
 * ⚖️ RFC 9000 §12.3: a sender whose packet numbers run out closes the connection without sending anything more (not
 * even CONNECTION_CLOSE). quinn 0.11 asserts instead; here the connection is closed and nothing is sent.
 */
class PacketNumberExhaustionTest {
    @Test
    fun runningOutOfPacketNumbersClosesWithoutSending() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()
        val s = pair.clientStreams(clientCh).open(Dir.Bi)!!
        pair.clientSend(clientCh, s).writeOk("before".encodeToByteArray())
        pair.drive()
        val serverStream = pair.serverStreams(serverCh).accept(Dir.Bi)!!

        // The next packet would need 2^62 - 2 or 2^62 - 1 (one may be skipped): too close to the end.
        val client = pair.clientConn(clientCh)
        // A real connection gets here with its acks keeping pace; keep the number encodable as one would be.
        client.spaces[SpaceId.Data].nextPacketNumber = MAX_PACKET_NUMBER - 2
        client.spaces[SpaceId.Data].largestAckedPacket = MAX_PACKET_NUMBER - 100
        pair.clientSend(clientCh, s).writeOk("after".encodeToByteArray())
        pair.drive()

        assertTrue(client.isClosed, "the client closes its connection")
        val lost = client.drainEvents().filterIsInstance<Event.ConnectionLost>().single()
        val error = assertIs<ConnectionError.Transport>(lost.reason)
        assertEquals(TransportErrorCode.INTERNAL_ERROR, error.error.code)
        // Nothing went out: the server got neither the data nor a CONNECTION_CLOSE.
        val server = pair.serverConn(serverCh)
        assertFalse(server.isClosed, "no CONNECTION_CLOSE was sent")
        assertEquals("before", streamChunks(pair.serverRecv(serverCh, serverStream)).decodeToString())
    }
}
