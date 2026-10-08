package neton.quic.proto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * Packets that arrive during the handshake before their keys are kept and used once the keys are there (SPEC §11.15,
 * RFC 9001 §5.7), on real TLS, whose flights span several datagrams.
 */
class UndecryptablePacketsTest {
    private fun realClient() = ClientConfig(TestTls.clientCrypto())

    /**
     * The server's first datagram (its Initial with the ServerHello, then the start of its Handshake flight) is
     * overtaken by the rest of the flight. The client keeps those Handshake packets and uses them when the Initial
     * arrives, so the handshake completes when the Initial arrives (42.5 ms here; 70 ms when they are dropped and the
     * server has to send them again).
     */
    @Test
    fun handshakePacketsOvertakingTheInitialAreKept() {
        val pair = ConnPair.real()
        pair.latency = 10.milliseconds
        pair.serverToClient = LinkImpairment(1).also { it.hold = { _, index -> if (index == 0L) 30.milliseconds else null } }
        val clientCh = pair.beginConnect(realClient())
        val start = pair.time
        assertTrue(pair.driveUntil(5.seconds) { !pair.clientConn(clientCh).isHandshaking })
        val elapsed = pair.time - start
        val conn = pair.clientConn(clientCh)
        assertTrue(conn.undecryptableKept > 0, "the client kept the early Handshake packets")
        assertEquals(conn.undecryptableKept, conn.undecryptableReplayed)
        assertTrue(elapsed < 50.milliseconds, "handshake took $elapsed")
    }

    /**
     * The client's Finished is lost and its first 1-RTT data reaches the server before the retransmitted Finished. The
     * server keeps those packets and processes them once the Finished brings its 1-RTT keys: the data is there without
     * the client resending it (when they are dropped, the client declares 7 packets lost and sends the data twice).
     */
    @Test
    fun oneRttPacketsBeforeTheFinishedAreKept() {
        val pair = ConnPair.real()
        pair.latency = 10.milliseconds
        var droppedFinished = false
        pair.clientToServer = LinkImpairment(2).also {
            it.drop = { data, _ ->
                if (!droppedFinished && hasHandshake(data)) {
                    droppedFinished = true
                    true
                } else {
                    false
                }
            }
        }
        val clientCh = pair.beginConnect(realClient())
        assertTrue(pair.driveUntil(5.seconds) { !pair.clientConn(clientCh).isHandshaking })
        assertTrue(droppedFinished)
        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        val data = ByteArray(6_000) { (it * 7).toByte() }
        val written = pair.clientSend(clientCh, s).write(data)
        assertEquals(data.size, (written as Written).bytes)
        pair.clientSend(clientCh, s).finish()
        pair.drive()
        val serverCh = pair.server.assertAccept()
        val server = pair.serverConn(serverCh)
        assertTrue(server.undecryptableKept > 0, "the server kept the early 1-RTT packets")
        assertEquals(server.undecryptableKept, server.undecryptableReplayed)
        server.drainEvents()
        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Uni))
        val chunks = pair.serverRecv(serverCh, s).read(true)
        var got = ByteArray(0)
        while (true) {
            val c = chunks.next(Int.MAX_VALUE) as? Chunk ?: break
            got += c.bytes.toByteArray()
        }
        chunks.finalize()
        assertContentEquals(data, got)
        assertEquals(0L, pair.clientConn(clientCh).stats().path.lostPackets)
    }

    /** Kept packets are bounded, and dropped when the handshake ends without their keys. */
    @Test
    fun keptPacketsAreBounded() {
        val pair = ConnPair.real()
        pair.latency = 10.milliseconds
        // Hold the server's first datagram long enough for many retransmitted Handshake datagrams to arrive first
        pair.serverToClient = LinkImpairment(3).also { it.hold = { _, index -> if (index == 0L) 3.seconds else null } }
        val clientCh = pair.beginConnect(realClient())
        assertTrue(pair.driveUntil(10.seconds) { !pair.clientConn(clientCh).isHandshaking })
        val conn = pair.clientConn(clientCh)
        assertTrue(conn.undecryptableKept in 1..16, "kept ${conn.undecryptableKept}")
    }
}
