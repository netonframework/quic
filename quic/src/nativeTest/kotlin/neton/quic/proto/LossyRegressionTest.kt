package neton.quic.proto

import neton.quic.testkit.*

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

// Regression tests for bugs found by the lossy scenarios (SPEC §11.9), beyond quinn-proto's own tests.

class LossyRegressionTest {
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

    /**
     * RFC 9001 §6.1: an endpoint must not initiate a key update before a packet it sent with the current keys has
     * been acknowledged. Before: only retained previous keys blocked an update. A client that adopted the server's
     * update (K1), and whose K1 packets were all lost, dropped its previous keys on the discard timer and could then
     * start K2; the server, still waiting for K1 from it, decrypted K2 packets with K0 and failed every one of them
     * until the connection idled out (found by `LossyDriverChaosTest`). quinn 0.11.12 has the same check.
     */
    @Test
    fun keyUpdateWaitsForAnAcknowledgedPacketOfTheCurrentPhase() {
        val pair = ConnPair.default()
        pair.latency = 10.milliseconds
        val (clientCh, serverCh) = pair.connect()
        val client = pair.clientConn(clientCh)
        val server = pair.serverConn(serverCh)
        val c2s = LinkImpairment(0)
        pair.clientToServer = c2s

        // The server updates (K0 → K1); the client adopts K1, but none of its K1 packets reaches the server
        c2s.blackhole = true
        server.forceKeyUpdate()
        val s = server.streams().open(Dir.Uni)!!
        pair.serverSend(serverCh, s).writeOk("in K1".encodeToByteArray())
        assertTrue(pair.driveUntil(1.seconds) { client.keyPhase }, "the client did not adopt the server's update")
        // Past the client's key discard timer (3 PTO), still losing everything it sends
        pair.driveUntil(3.seconds) { false }

        // A forced update now would leave the server unable to decrypt anything from the client
        client.forceKeyUpdate()
        c2s.blackhole = false
        val c = client.streams().open(Dir.Uni)!!
        val data = ByteArray(10_000) { it.toByte() }
        pair.clientSend(clientCh, c).writeOk(data)
        pair.clientSend(clientCh, c).finish()
        var received = 0
        val ok = pair.driveUntil(20.seconds) {
            client.drainEvents(); server.drainEvents()
            while (server.streams().accept(Dir.Uni) != null) {}
            val chunks = try { server.recvStream(c).read(true) } catch (e: ReadableError) { null }
            if (chunks != null) {
                while (true) received += (chunks.next(Int.MAX_VALUE) as? Chunk ?: break).bytes.size
                chunks.finalize()
            }
            received == data.size
        }
        assertTrue(ok, "the server could not read the client's data after its key update: $received bytes; " +
            "client closed ${client.isClosed}, server closed ${server.isClosed}")
        assertTrue(!client.isClosed && !server.isClosed)
    }
}
