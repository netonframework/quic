package neton.quic

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeoutOrNull
import neton.io.bytes.Bytes
import neton.quic.proto.ConnectionError
import neton.quic.proto.IdleTimeout
import neton.quic.proto.LinkImpairment
import neton.quic.proto.NativeKeys
import neton.quic.proto.TransportConfig
import neton.quic.proto.VarInt
import neton.quic.proto.hasHandshake
import neton.quic.proto.isInitial
import neton.quic.proto.isShortHeader
import neton.quic.proto.settledNativeKeys
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.TimeSource

// Combined verification of the driver on an impaired link: the real endpoints, their timers, pacing and budgets, on
// loopback UDP through a `LossyRelay` that loses, duplicates, reorders and delays datagrams with a seeded generator.
// Every scenario checks integrity, completion within a (generous, the test host may be loaded) time bound, stats,
// and that every native key is released once both endpoints are idle.

/** A server endpoint, a client endpoint that reaches it through a relay, and the relay. */
private class Link(val server: Endpoint, val client: Endpoint, val relay: LossyRelay) {
    val c2s: LinkImpairment get() = relay.clientToServer
    val s2c: LinkImpairment get() = relay.serverToClient

    suspend fun connect(): Pair<Connection, Connection> = kotlinx.coroutines.coroutineScope {
        val serverSide = async { assertNotNull(server.accept()).await() }
        val client = client.connect(relay.address, "localhost").await()
        client to serverSide.await()
    }

    /** Close both endpoints and wait until every connection has drained (their keys are then released). */
    suspend fun shutdown() {
        client.shutdown()
        server.shutdown()
        client.waitIdle()
        server.waitIdle()
        relay.close()
    }
}

class LossyDriverTest {
    private suspend fun link(
        seed: Long,
        loss: Double,
        duplicate: Double = 0.0,
        reorder: Double = 0.0,
        latency: Duration = 2.milliseconds,
        transport: TransportConfig = TransportConfig(),
    ): Link {
        val factory = EndpointFactory()
        val server = factory.endpointWithConfig(transport)
        val client = factory.endpointWithConfig(transport)
        val relay = LossyRelay.start(
            server.localAddr(),
            LinkImpairment.lossy(seed, loss, duplicate, reorder),
            LinkImpairment.lossy(seed xor 0x5DEECE66DL, loss, duplicate, reorder),
            latency,
        )
        return Link(server, client, relay)
    }

    /**
     * A scenario on a fresh reactor with a time bound; afterwards (still inside, while everything is reachable) the
     * native key count must be back where it was.
     */
    private fun lossyTest(timeout: Duration, block: suspend CoroutineScope.() -> Unit) {
        val baseline = settledNativeKeys()
        quicTest(timeout) {
            block()
            assertEquals(baseline, NativeKeys.live, "native key contexts left after both endpoints went idle")
        }
    }

    /** Send [data] on a new uni stream and read it on the other side; returns once the sender knows all was acked. */
    private suspend fun transfer(from: Connection, to: Connection, data: ByteArray) = kotlinx.coroutines.coroutineScope {
        val sender = async {
            val s = from.openUni()
            s.writeAll(data)
            s.finish()
            assertNull(s.stopped(), "stream stopped") // completes once every byte is acknowledged
        }
        val received = to.acceptUni().readToEnd()
        assertEquals(data.size, received.size)
        assertContentEquals(data, received)
        sender.await()
    }

    private fun assertLossCounted(sender: Connection, link: Link) {
        val path = sender.stats().path
        assertTrue(path.lostPackets > 0, "no lost packets counted; ${link.relay}")
        assertTrue(path.lostPackets <= path.sentPackets)
        assertTrue(path.congestionEvents > 0)
    }

    // ---- bulk transfer ----

    private fun bulk(loss: Double, size: Int, seed: Long, timeout: Duration) = lossyTest(timeout) {
        val link = link(seed, loss)
        val (client, server) = link.connect()
        val start = TimeSource.Monotonic.markNow()
        transfer(client, server, genData(size, seed))
        val took = start.elapsedNow()
        assertTrue(link.c2s.dropped > 0)
        assertLossCounted(client, link)
        println("driver bulk ${size shr 20} MiB at ${(loss * 100).toInt()}% loss: $took, lost ${client.stats().path.lostPackets}; ${link.relay}")
        link.shutdown()
    }

    @Test fun bulkTransferUnder1PercentLoss() = bulk(0.01, 4 shl 20, 1, 120.seconds)

    @Test fun bulkTransferUnder5PercentLoss() = bulk(0.05, 4 shl 20, 5, 120.seconds)

    @Test fun bulkTransferUnder20PercentLoss() = bulk(0.20, 2 shl 20, 20, 180.seconds)

    @Test
    fun bulkTransferUnderHeavyReordering() = lossyTest(120.seconds) {
        val link = link(7, loss = 0.0, reorder = 0.3)
        link.c2s.reorderDelay = 15.milliseconds
        link.s2c.reorderDelay = 15.milliseconds
        val (client, server) = link.connect()
        transfer(client, server, genData(4 shl 20, 7))
        assertTrue(link.c2s.reordered > 100)
        println("driver reordering: lost ${client.stats().path.lostPackets}; ${link.relay}")
        link.shutdown()
    }

    @Test
    fun bulkTransferWithDuplication() = lossyTest(120.seconds) {
        val link = link(11, loss = 0.02, duplicate = 0.25, reorder = 0.1)
        val (client, server) = link.connect()
        transfer(client, server, genData(4 shl 20, 11))
        transfer(server, client, genData(1 shl 20, 12))
        assertTrue(link.c2s.duplicated > 100 && link.s2c.duplicated > 100)
        assertTrue(server.stats().udpRx.datagrams > client.stats().udpTx.datagrams, "duplicates did not arrive")
        link.shutdown()
    }

    // ---- handshake loss ----

    @Test
    fun handshakeSurvivesLossOfEachFlight() = lossyTest(180.seconds) {
        data class Case(val name: String, val clientSide: Boolean, val kind: (ByteArray) -> Boolean)
        val cases = listOf(
            Case("client Initial", true, ::isInitial),
            Case("server Initial + Handshake", false, ::isInitial),
            Case("client Handshake (final flight)", true, ::hasHandshake),
            Case("server first 1-RTT (HANDSHAKE_DONE)", false, ::isShortHeader),
        )
        for (case in cases) {
            val link = link(0, loss = 0.0)
            var left = 2
            val impairment = if (case.clientSide) link.c2s else link.s2c
            impairment.drop = { data, _ -> if (left > 0 && case.kind(data)) { left--; true } else false }
            val start = TimeSource.Monotonic.markNow()
            val (client, server) = link.connect()
            transfer(client, server, genData(10_000, 1))
            transfer(server, client, genData(10_000, 2))
            assertEquals(2L, impairment.droppedByRule, "${case.name}: not every targeted datagram was sent")
            println("driver handshake, ${case.name} ×2 lost: ${start.elapsedNow()}")
            link.shutdown()
        }
    }

    @Test
    fun blackholedHandshakeFailsOnBothSides() = lossyTest(60.seconds) {
        // The server's replies never arrive: the client's attempt and the server's accepted connection both end by
        // idle timeout, with every key released
        val idle = IdleTimeout.of(2.seconds)
        val link = link(8, loss = 0.0, transport = TransportConfig().maxIdleTimeout(idle))
        link.s2c.blackhole = true
        val serverSide = async {
            val connecting = assertNotNull(link.server.accept()).accept()
            assertFailsWith<ConnectionError.TimedOut> { connecting.await() }
        }
        val start = TimeSource.Monotonic.markNow()
        assertFailsWith<ConnectionError.TimedOut> { link.client.connect(link.relay.address, "localhost").await() }
        serverSide.await()
        println("driver blackholed handshake: failed after ${start.elapsedNow()}")
        link.shutdown()
    }

    @Test
    fun handshakeUnderRandomLoss() = lossyTest(300.seconds) {
        for (seed in 0L until 10L) {
            val link = link(seed, loss = 0.3)
            val (client, server) = link.connect()
            link.c2s.loss = 0.05
            link.s2c.loss = 0.05
            transfer(client, server, genData(20_000, seed))
            link.shutdown()
        }
    }

    @Test
    fun lostFinalAcksAreRecovered() = lossyTest(60.seconds) {
        val link = link(3, loss = 0.0)
        val (client, server) = link.connect()
        val data = genData(200_000, 3)
        val s = client.openUni()
        s.writeAll(data)
        // Everything the server sends from now on is lost for 6 datagrams: its ACKs of the tail of the data
        var toDrop = 6
        link.s2c.drop = { _, _ -> if (toDrop > 0) { toDrop--; true } else false }
        s.finish()
        val reader = async { server.acceptUni().readToEnd() }
        assertNull(s.stopped()) // the sender learns that everything arrived despite the lost ACKs
        assertContentEquals(data, reader.await())
        assertEquals(0, toDrop)
        link.shutdown()
    }

    // ---- key update under loss ----

    @Test
    fun keyUpdatesUnderLoss() = lossyTest(180.seconds) {
        val link = link(21, loss = 0.05, reorder = 0.1)
        val (client, server) = link.connect()
        var updates = 0
        val updater = launch {
            while (true) {
                delay(20.milliseconds)
                if (updates % 2 == 0) client.forceKeyUpdate() else server.forceKeyUpdate()
                updates++
            }
        }
        transfer(client, server, genData(3 shl 20, 21))
        transfer(server, client, genData(1 shl 20, 22))
        updater.cancel()
        assertTrue(updates >= 5, "only $updates key updates")
        assertNull(client.closeReason())
        assertNull(server.closeReason())
        link.shutdown()
    }

    // ---- cancellation under loss ----

    @Test
    fun resetStreamLostAndRetransmitted() = lossyTest(60.seconds) {
        val link = link(31, loss = 0.05)
        val (client, server) = link.connect()
        val s = client.openUni()
        s.writeAll(genData(256 * 1024, 31))
        val reader = async {
            val r = server.acceptUni()
            val buf = ByteArray(64 * 1024)
            var total = 0
            val e = assertFailsWith<ReadError.Reset> {
                while (true) {
                    val n = r.read(buf)
                    if (n < 0) fail("finished instead of reset")
                    total += n
                }
            }
            e.errorCode
        }
        var toDrop = 3 // the datagrams carrying RESET_STREAM (and its first retransmissions) are lost
        link.c2s.drop = { _, _ -> if (toDrop > 0) { toDrop--; true } else false }
        s.reset(VarInt(77))
        assertEquals(VarInt(77), reader.await())
        assertTrue(client.stats().frameTx.resetStream >= 2, "RESET_STREAM was not retransmitted")
        // The connection still works
        transfer(client, server, genData(50_000, 32))
        link.shutdown()
    }

    @Test
    fun stopSendingLostAndRetransmitted() = lossyTest(60.seconds) {
        val link = link(41, loss = 0.05)
        val (client, server) = link.connect()
        val s = client.openUni()
        val writer = async {
            val chunk = genData(4096, 41)
            var written = 0L
            val e = assertFailsWith<WriteError.Stopped> {
                while (true) {
                    s.writeAll(chunk)
                    written += chunk.size
                    if (written > (64L shl 20)) fail("never stopped")
                }
            }
            e.errorCode
        }
        val r = server.acceptUni()
        r.readExact(ByteArray(128 * 1024))
        var toDrop = 3 // STOP_SENDING and its first retransmissions are lost
        link.s2c.drop = { _, _ -> if (toDrop > 0) { toDrop--; true } else false }
        r.stop(VarInt(9))
        assertEquals(VarInt(9), writer.await())
        assertEquals(VarInt(9), s.stopped())
        s.close() // resets with the peer's code (quinn's drop)
        assertTrue(server.stats().frameTx.stopSending >= 2, "STOP_SENDING was not retransmitted")
        transfer(server, client, genData(50_000, 42))
        link.shutdown()
    }

    @Test
    fun cancelledReadersAndWritersUnderLoss() = lossyTest(90.seconds) {
        // Coroutines blocked on flow control or on data are cancelled mid-transfer; the streams are then disposed of
        // (the writer's with close, which finishes; the reader's with close, which stops) and the connection carries on.
        val transport = TransportConfig().streamReceiveWindow(VarInt(32 * 1024))
        val link = link(51, loss = 0.05, reorder = 0.05, transport = transport)
        val (client, server) = link.connect()
        repeat(10) { round ->
            val s = client.openUni()
            val writer = launch { s.writeAll(genData(1 shl 20, round.toLong())) } // blocks on the 32 KiB window
            val r = server.acceptUni()
            val readerStarted = kotlinx.coroutines.CompletableDeferred<Unit>()
            val reader = launch(start = CoroutineStart.UNDISPATCHED) {
                val buf = ByteArray(1000)
                r.read(buf)
                readerStarted.complete(Unit)
                while (true) r.read(buf)
            }
            readerStarted.await()
            delay(5.milliseconds)
            writer.cancel()
            reader.cancel()
            writer.join()
            reader.join()
            r.close()  // stop(0): the writer side sees STOP_SENDING
            s.close()  // stopped by the peer: reset with its code, or finish if the stop has not arrived yet
            // Cancelled operations left nothing behind: new operations on other streams work
            transfer(client, server, genData(20_000, 100L + round))
        }
        assertNull(client.closeReason())
        link.shutdown()
    }

    // ---- close under loss ----

    @Test
    fun lostConnectionCloseEndsInIdleTimeout() = lossyTest(60.seconds) {
        val idle = IdleTimeout.of(3.seconds)
        val link = link(61, loss = 0.0, transport = TransportConfig().maxIdleTimeout(idle))
        val (client, server) = link.connect()
        transfer(client, server, genData(50_000, 61))
        link.c2s.blackhole = true // every CONNECTION_CLOSE from the client is lost
        val start = TimeSource.Monotonic.markNow()
        client.close(VarInt(5), ByteArray(0))
        link.client.waitIdle() // the closer drains (3 PTO) without hearing back
        val drained = start.elapsedNow()
        assertEquals(ConnectionError.TimedOut, server.closed()) // the peer ends by idle timeout
        val timedOut = start.elapsedNow()
        println("driver lost close: closer drained after $drained, peer timed out after $timedOut")
        // The peer's idle timer started at its last receipt, just before `start`, and timers have millisecond
        // granularity: 2.99994 s was seen on Linux. Well short of 3 s would mean an early close.
        assertTrue(timedOut >= 3.seconds - 100.milliseconds, "idle timeout after only $timedOut")
        link.shutdown()
    }

    @Test
    fun lostConnectionCloseIsRepeated() = lossyTest(60.seconds) {
        val link = link(62, loss = 0.0)
        val (client, server) = link.connect()
        val s = server.openUni()
        val writer = launch { runCatching { s.writeAll(genData(8 shl 20, 62)) } }
        val r = client.acceptUni()
        r.readExact(ByteArray(256 * 1024))
        var toDrop = 1 // the first CONNECTION_CLOSE is lost; the server keeps sending, the client answers again
        link.c2s.drop = { _, _ -> if (toDrop > 0) { toDrop--; true } else false }
        client.close(VarInt(6), "bye".encodeToByteArray())
        val reason = assertIs<ConnectionError.ApplicationClosed>(server.closed())
        assertEquals(VarInt(6), reason.reason.errorCode)
        assertEquals(0, toDrop)
        writer.join()
        link.shutdown()
    }

    @Test
    fun closeUnderHeavyLossBothSidesEnd() = lossyTest(120.seconds) {
        for (seed in 70L until 76L) {
            val idle = IdleTimeout.of(3.seconds)
            val link = link(seed, loss = 0.05, transport = TransportConfig().maxIdleTimeout(idle))
            val (client, server) = link.connect()
            val s = client.openUni()
            val writer = launch { runCatching { s.writeAll(genData(4 shl 20, seed)) } }
            val r = server.acceptUni()
            r.readExact(ByteArray(128 * 1024))
            link.c2s.loss = 0.5
            link.s2c.loss = 0.5
            val (closer, other) = if (seed % 2 == 0L) client to server else server to client
            closer.close(VarInt(1), ByteArray(0))
            val reason = withTimeoutOrNull(20.seconds) { other.closed() } ?: fail("the peer never ended")
            assertTrue(reason is ConnectionError.ApplicationClosed || reason == ConnectionError.TimedOut ||
                reason == ConnectionError.Reset, "unexpected end: $reason")
            writer.join()
            link.shutdown()
        }
    }

    // ---- flow-control credit exhaustion under loss ----

    @Test
    fun exhaustedWindowsUnderLossRecover() = lossyTest(120.seconds) {
        val transport = TransportConfig().streamReceiveWindow(VarInt(16 * 1024)).receiveWindow(VarInt(24 * 1024))
        val link = link(71, loss = 0.08, transport = transport)
        val (client, server) = link.connect()
        val data = List(3) { genData(512 * 1024, 71L + it) }
        val senders = data.map { d -> async { val s = client.openUni(); s.writeAll(d); s.finish(); assertNull(s.stopped()) } }
        val received = List(3) {
            async {
                val r = server.acceptUni()
                var all = ByteArray(0)
                val buf = ByteArray(4096)
                while (true) {
                    val n = r.read(buf)
                    if (n < 0) break
                    all += buf.copyOf(n)
                    delay(1.milliseconds) // a slow reader: credit is granted a little at a time
                }
                all
            }
        }.awaitAll()
        senders.awaitAll()
        assertEquals(data.map { it.toList() }.toSet(), received.map { it.toList() }.toSet())
        val tx = server.stats().frameTx
        val rx = client.stats().frameRx
        assertTrue(tx.maxStreamData > 20 && tx.maxData > 5, "credit was not granted repeatedly: $tx")
        assertTrue(rx.maxStreamData + rx.maxData < tx.maxStreamData + tx.maxData, "no credit frame was lost")
        link.shutdown()
    }

    // ---- many concurrent streams ----

    @Test
    fun manyConcurrentStreamsUnderLoss() = lossyTest(120.seconds) {
        val transport = TransportConfig().maxConcurrentBidiStreams(VarInt(16))
        val link = link(81, loss = 0.05, reorder = 0.05, transport = transport)
        val (client, server) = link.connect()
        val echo = launch {
            while (true) {
                val (send, recv) = try { server.acceptBi() } catch (e: ConnectionError) { break }
                launch {
                    val bytes = recv.readToEnd()
                    send.writeAll(bytes)
                    send.finish()
                }
            }
        }
        (0 until 100).map { i ->
            async {
                val (send, recv) = client.openBi() // waits for stream credit (MAX_STREAMS, possibly lost)
                val data = genData(10_000 + i * 97, 810L + i)
                send.writeAll(data)
                send.finish()
                assertContentEquals(data, recv.readToEnd())
            }
        }.awaitAll()
        assertTrue(server.stats().frameTx.maxStreamsBidi > 5)
        echo.cancel()
        link.shutdown()
    }

    // ---- datagrams ----

    @Test
    fun datagramsUnderLossDuplicationAndReordering() = lossyTest(60.seconds) {
        val link = link(91, loss = 0.1, duplicate = 0.1, reorder = 0.2)
        val (client, server) = link.connect()
        val count = 2000
        fun payload(i: Int): ByteArray = genData(200 + i % 800, i.toLong()).also { it[0] = (i shr 8).toByte(); it[1] = i.toByte() }
        val seen = HashSet<Int>()
        val receiver = launch {
            while (true) {
                val d = server.readDatagram().toByteArray()
                val i = ((d[0].toInt() and 0xff) shl 8) or (d[1].toInt() and 0xff)
                assertContentEquals(payload(i), d, "datagram $i corrupted")
                assertTrue(seen.add(i), "datagram $i delivered twice")
            }
        }
        val emptySpace = client.datagramSendBufferSpace()
        for (i in 0 until count) client.sendDatagramWait(Bytes.wrap(payload(i)))
        // Sending only queues (up to the 1 MiB send buffer): wait until all went out, then for what is in flight
        while (client.datagramSendBufferSpace() < emptySpace) delay(10.milliseconds)
        delay(500.milliseconds)
        assertEquals(count.toLong(), client.stats().frameTx.datagram)
        receiver.cancel()
        println("driver datagrams: ${seen.size} of $count delivered; ${link.relay}; client frameTx.datagram=${client.stats().frameTx.datagram} udpTx=${client.stats().udpTx.datagrams} server frameRx.datagram=${server.stats().frameRx.datagram} udpRx=${server.stats().udpRx.datagrams} lost=${client.stats().path.lostPackets} fwd=${link.relay.forwardedToServer}")
        // About the link's delivery rate (10% loss; a lost packet may carry several datagrams); never all, never twice
        assertTrue(seen.size in (count * 7 / 10) until count, "${seen.size} of $count delivered")
        assertTrue(client.stats().path.lostPackets > 0)
        assertNull(client.closeReason())
        link.shutdown()
    }
}
