package neton.quic.proto

import neton.quic.testkit.*

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue

// Regression tests for stream bugs found by the lossy scenarios (SPEC §11.9), beyond quinn-proto's own tests.

class StreamRegressionTest {
    /**
     * A write on a stream the peer stopped must fail with `Stopped` even while the connection-level window is
     * exhausted. Before: the connection limit was checked first, the write reported `Blocked`, the stream went on the
     * connection-blocked list, and when `MAX_DATA` came the stream was not reported writable because its own credit
     * was used up (and never comes back, the peer stopped reading) — the writer waited forever and the connection idled
     * out (found by `LossyDriverChaosTest`). quinn 0.11.12 checks in the same order.
     */
    @Test
    fun writeOnStoppedStreamFailsWhileConnectionBlocked() {
        val window = 4096L
        val cfg = serverConfig()
        cfg.transport = TransportConfig().streamReceiveWindow(VarInt(window)).receiveWindow(VarInt(2 * window))
        val pair = ConnPair.new(EndpointConfig.default(), cfg)
        val (clientCh, serverCh) = pair.connect()

        val a = pair.clientStreams(clientCh).open(Dir.Uni)!!
        val b = pair.clientStreams(clientCh).open(Dir.Uni)!!
        // A uses up its own window, B the rest of the connection's
        assertEquals(window.toInt(), pair.clientSend(clientCh, a).writeOk(ByteArray(window.toInt())))
        assertEquals(window.toInt(), pair.clientSend(clientCh, b).writeOk(ByteArray(window.toInt())))
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, a).write(ByteArray(1)))
        pair.drive()

        // The server stops A without reading it
        while (pair.serverStreams(serverCh).accept(Dir.Uni) != null) {}
        pair.serverRecv(serverCh, a).stop(VarInt(9))
        pair.drive()
        val events = pair.clientConn(clientCh).drainEvents()
        assertTrue(StreamEvent.Stopped(a, VarInt(9)) in events, "no Stopped event: $events")

        // Stopping returned A's unread bytes as connection credit; another writer takes it before A's writer runs
        // again (in the driver: the writers woken by the same MAX_DATA run first)
        val c = pair.clientStreams(clientCh).open(Dir.Uni)!!
        var taken = 0
        while (true) {
            val r = pair.clientSend(clientCh, c).write(ByteArray(1024))
            if (r is Written) taken += r.bytes else break
        }
        assertTrue(taken > 0, "stopping A returned no connection credit")

        // The writer woken by the Stopped event must learn about it, although the connection window is full again
        assertEquals(WriteError.Stopped(VarInt(9)), pair.clientSend(clientCh, a).write(ByteArray(1)))
    }
}
