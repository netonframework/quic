package neton.quic.proto

import kotlinx.cinterop.toKString
import neton.io.bytes.Bytes
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes

// Everything at once, per seed, in virtual time: random loss, duplication and reordering in both directions; streams
// in both directions under small windows, some reset by their sender and some stopped by their receiver at random
// offsets; random key updates and datagrams; then a close under the same link, draining, and the native key count.
// A failure names its seed, which reproduces it exactly.

class LossyChaosTest {
    private class Stream(val data: ByteArray, val resetAt: Int, val stopAt: Int, val code: VarInt) {
        var id: StreamId? = null
        var written = 0
        var finished = false
        var resetSent = false
        var stoppedByPeer = false
        var received = 0
        val buffer = ByteArray(data.size)
        var recvFinished = false
        var recvReset: VarInt? = null
        var stopSent = false
        var accepted = false

        /** Resolved on the receiving side: read to the end, reset (with the right code), or stopped by us. */
        val resolved: Boolean get() = recvFinished || recvReset != null || stopSent
    }

    private fun scenario(seed: Long) {
        val rng = Random(seed)
        val loss = rng.nextDouble(0.0, 0.2)
        val duplicate = rng.nextDouble(0.0, 0.15)
        val reorder = rng.nextDouble(0.0, 0.3)
        val window = 8 * 1024 + rng.nextInt(64 * 1024)
        fun transport() = TransportConfig()
            .streamReceiveWindow(VarInt(window.toLong()))
            .receiveWindow(VarInt(window * 2L))
            .maxConcurrentUniStreams(VarInt(4))
        val cfg = serverConfig()
        cfg.transport = transport()
        val pair = ConnPair.new(EndpointConfig.default(), cfg)
        pair.latency = (1 + rng.nextInt(20)).milliseconds
        pair.clientToServer = LinkImpairment.lossy(seed * 2, loss, duplicate, reorder).also { it.reorderDelay = (1 + rng.nextInt(30)).milliseconds }
        pair.serverToClient = LinkImpairment.lossy(seed * 2 + 1, loss, duplicate, reorder).also { it.reorderDelay = (1 + rng.nextInt(30)).milliseconds }
        val describe = "seed $seed: loss $loss dup $duplicate reorder $reorder window $window latency ${pair.latency}"

        val clientCh = pair.beginConnect(clientConfig().transportConfig(transport()))
        var serverCh: ConnectionHandle? = null
        assertTrue(pair.driveUntil(5.minutes) {
            if (serverCh == null) serverCh = pair.server.connections.keys.firstOrNull()
            serverCh != null && !pair.clientConn(clientCh).isHandshaking && !pair.serverConn(serverCh!!).isHandshaking
        }, "$describe: no handshake")
        val client = pair.clientConn(clientCh)
        val server = pair.serverConn(serverCh!!)
        client.drainEvents(); server.drainEvents()

        fun streams(n: Int): List<Stream> = List(n) {
            val size = rng.nextInt(1, 150_000)
            val fate = rng.nextInt(10)
            Stream(
                data = rng.nextBytes(size),
                resetAt = if (fate == 0) rng.nextInt(size) else -1,
                stopAt = if (fate == 1) rng.nextInt(size) else -1,
                code = VarInt(1000L + it),
            )
        }
        val up = streams(12)   // client → server
        val down = streams(12) // server → client
        var datagramsSent = 0
        var datagramsReceived = 0

        fun send(conn: Connection, list: List<Stream>) {
            while (true) {
                val next = list.firstOrNull { it.id == null } ?: break
                next.id = conn.streams().open(Dir.Uni) ?: break
            }
            for (s in list) {
                val id = s.id ?: continue
                if (s.finished || s.resetSent || s.stoppedByPeer) continue
                val stream = conn.sendStream(id)
                val limit = if (s.resetAt >= 0) s.resetAt else s.data.size
                while (s.written < limit) {
                    when (val r = stream.write(s.data, s.written, minOf(limit, s.written + 16_384))) {
                        is Written -> s.written += r.bytes
                        WriteError.Blocked -> break
                        is WriteError.Stopped -> { s.stoppedByPeer = true; assertEquals(s.code, r.errorCode, describe); break }
                        WriteError.ClosedStream -> fail("$describe: write on a closed stream ${s.id}")
                    }
                }
                if (s.stoppedByPeer) {
                    runCatching { stream.reset(s.code) }
                    continue
                }
                if (s.written == limit) {
                    if (s.resetAt >= 0) { stream.reset(s.code); s.resetSent = true } else { stream.finish(); s.finished = true }
                }
            }
        }

        fun receive(conn: Connection, list: List<Stream>) {
            while (true) {
                val id = conn.streams().accept(Dir.Uni) ?: break
                val s = list.firstOrNull { it.id == id } ?: fail("$describe: unknown stream $id")
                s.accepted = true
            }
            for (s in list) {
                if (!s.accepted || s.resolved) continue
                val recv = conn.recvStream(s.id!!)
                val chunks = recv.read(true)
                try {
                    while (true) {
                        when (val r = chunks.next(Int.MAX_VALUE)) {
                            is Chunk -> {
                                assertEquals(s.received.toLong(), r.offset, describe)
                                r.bytes.copyInto(s.buffer, s.received)
                                s.received += r.bytes.size
                            }
                            ReadResult.Finished -> { s.recvFinished = true; break }
                            ReadError.Blocked -> break
                            is ReadError.Reset -> { s.recvReset = r.errorCode; break }
                        }
                    }
                } finally {
                    chunks.finalize()
                }
                assertContentEquals(s.data.copyOf(s.received), s.buffer.copyOf(s.received), "$describe: stream ${s.id} corrupted")
                if (s.stopAt >= 0 && !s.resolved && s.received >= s.stopAt) {
                    recv.stop(s.code)
                    s.stopSent = true
                }
            }
        }

        val ok = pair.driveUntil(30.minutes) {
            client.drainEvents(); server.drainEvents()
            send(client, up); send(server, down)
            receive(server, up); receive(client, down)
            if (rng.nextInt(200) == 0) (if (rng.nextBoolean()) client else server).forceKeyUpdate()
            if (datagramsSent < 300 && rng.nextInt(4) == 0) {
                if (client.datagrams().send(Bytes.wrap(ByteArray(1 + rng.nextInt(1000)) { datagramsSent.toByte() }), true) == null) datagramsSent++
            }
            while (server.datagrams().recv() != null) datagramsReceived++
            (up + down).all { it.resolved } && client.streams().sendStreams() == 0 && server.streams().sendStreams() == 0
        }
        assertTrue(ok, "$describe: stalled at ${pair.time - TEST_EPOCH}; up ${up.map { "${it.received}/${it.data.size}${if (it.resolved) "✓" else ""}" }} " +
            "down ${down.map { "${it.received}/${it.data.size}${if (it.resolved) "✓" else ""}" }}; client ${client.isClosed} server ${server.isClosed}; ${pair.clientToServer} / ${pair.serverToClient}")
        for (s in up + down) {
            when {
                s.resetAt >= 0 -> assertTrue(s.recvReset == s.code || s.recvFinished.not(), "$describe: reset stream ${s.id} ended as ${s.recvReset}")
                s.stopAt >= 0 -> assertTrue(s.stopSent || s.recvFinished, describe)
                else -> {
                    assertTrue(s.recvFinished, "$describe: stream ${s.id} not finished")
                    assertContentEquals(s.data, s.buffer, "$describe: stream ${s.id} corrupted")
                }
            }
        }
        assertTrue(datagramsReceived <= datagramsSent, describe)

        (if (seed % 2 == 0L) client else server).close(pair.time, VarInt(0), Bytes.EMPTY)
        assertTrue(pair.driveUntil(5.minutes) {
            pair.client.endpoint.openConnections() == 0 && pair.server.endpoint.openConnections() == 0
        }, "$describe: did not drain")
    }

    /**
     * Seeds 0 until 12 by default; `QUIC_CHAOS_SEEDS=from:until` runs another range (a soak run: every seed is an
     * independent, reproducible scenario).
     */
    @OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)
    private fun seeds(): LongRange {
        val spec = platform.posix.getenv("QUIC_CHAOS_SEEDS")?.toKString()
            ?: return 0L until 12L
        val (from, until) = spec.split(":").map { it.trim().toLong() }
        return from until until
    }

    @Test
    fun chaos() {
        val baseline = settledNativeKeys()
        for (seed in seeds()) scenario(seed)
        assertEquals(baseline, NativeKeys.live, "native key contexts left after the connections drained")
    }
}
