package neton.quic.proto

import neton.io.bytes.Bytes
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.minutes
import kotlin.time.Duration.Companion.seconds

// Combined verification on an impaired link, in virtual time (the pair simulation of `PairUtil` with a
// `LinkImpairment` per direction): loss, reordering, duplication, targeted loss of handshake packets, final ACKs,
// RESET_STREAM / STOP_SENDING, CONNECTION_CLOSE and flow-control credit, together with key updates, cancellation,
// exhausted windows and many streams. Every scenario checks integrity, completion within a virtual-time bound (and
// that the connection never stalls: nothing in flight, no timer, work left), consistent stats, and that every native
// key is released once both sides have drained.

/** An application on one side of a pair: its connection, and the events it polled. */
private class App(val pair: ConnPair, val ch: ConnectionHandle, val client: Boolean) {
    val conn: Connection get() = if (client) pair.clientConn(ch) else pair.serverConn(ch)
    val events = ArrayList<Event>()

    fun poll(): List<Event> {
        val start = events.size
        while (true) events.add(conn.poll() ?: break)
        return events.subList(start, events.size)
    }

    fun lost(): ConnectionError? = events.firstNotNullOfOrNull { (it as? Event.ConnectionLost)?.reason }
    fun finished(id: StreamId): Boolean = events.any { it == StreamEvent.Finished(id) }
    fun stopped(id: StreamId): VarInt? = events.firstNotNullOfOrNull { e -> (e as? StreamEvent.Stopped)?.takeIf { it.id == id }?.errorCode }
}

/**
 * One stream's data from a sender to a receiver: written as credit allows, read in order (at most [readBudget] bytes
 * per pump, for a slow reader) into its place, finished when all is written.
 */
private class Transfer(val data: ByteArray) {
    var id: StreamId? = null
    var written = 0
    var finishCalled = false
    val received = ByteArray(data.size)
    var receivedBytes = 0
    var recvFinished = false
    var reset: VarInt? = null

    /** Write what credit allows; returns whether anything was written. */
    fun write(send: SendStream, chunk: Int = 64 * 1024): Boolean {
        var any = false
        while (written < data.size) {
            when (val r = send.write(data, written, minOf(data.size, written + chunk))) {
                is Written -> { written += r.bytes; any = true }
                WriteError.Blocked -> return any
                else -> fail("write failed: $r")
            }
        }
        if (!finishCalled) {
            send.finish()
            finishCalled = true
        }
        return any
    }

    /** Read in order what is available, up to [budget] bytes. */
    fun read(recv: RecvStream, budget: Int = Int.MAX_VALUE) {
        if (recvFinished || reset != null) return
        val chunks = recv.read(true)
        var left = budget
        try {
            while (left > 0) {
                when (val r = chunks.next(left)) {
                    is Chunk -> {
                        assertEquals(receivedBytes.toLong(), r.offset, "ordered read at the wrong offset")
                        assertTrue(r.offset + r.bytes.size <= data.size, "more data than was sent")
                        r.bytes.copyInto(received, receivedBytes)
                        receivedBytes += r.bytes.size
                        left -= r.bytes.size
                    }
                    ReadResult.Finished -> { recvFinished = true; return }
                    ReadError.Blocked -> return
                    is ReadError.Reset -> { reset = r.errorCode; return }
                }
            }
        } finally {
            chunks.finalize()
        }
    }

    fun assertIntact() {
        assertTrue(recvFinished, "stream $id not finished: $receivedBytes of ${data.size} bytes")
        assertEquals(data.size, receivedBytes)
        assertContentEquals(data, received, "stream $id corrupted")
    }
}

class LossyPairTest {
    /**
     * Run a scenario and check that every native key it created was released once its connections drained (checked
     * while they are still reachable, so that no cleaner can have done it).
     */
    private fun keysChecked(block: () -> Unit) {
        val baseline = settledNativeKeys()
        block()
        assertEquals(baseline, NativeKeys.live, "native key contexts left after the connections drained")
    }

    private fun lossyPair(
        seed: Long,
        loss: Double,
        duplicate: Double = 0.0,
        reorder: Double = 0.0,
        latency: Duration = 10.milliseconds,
        server: TransportConfig = TransportConfig(),
        client: TransportConfig = TransportConfig(),
    ): Triple<ConnPair, App, App> {
        val cfg = serverConfig()
        cfg.transport = server
        val pair = ConnPair.new(EndpointConfig.default(), cfg)
        pair.latency = latency
        pair.clientToServer = LinkImpairment.lossy(seed, loss, duplicate, reorder)
        pair.serverToClient = LinkImpairment.lossy(seed xor 0x5DEECE66DL, loss, duplicate, reorder)
        val (clientCh, serverCh) = connectLossy(pair, clientConfig().transportConfig(client))
        return Triple(pair, App(pair, clientCh, true), App(pair, serverCh, false))
    }

    /** Connect over whatever the link does (quinn's `connect` drives until idle, which loss can reach early). */
    private fun connectLossy(pair: ConnPair, config: ClientConfig, limit: Duration = 2.minutes): Pair<ConnectionHandle, ConnectionHandle> {
        val clientCh = pair.beginConnect(config)
        var serverCh: ConnectionHandle? = null
        val ok = pair.driveUntil(limit) {
            if (serverCh == null) serverCh = pair.server.connections.keys.firstOrNull()
            val s = serverCh
            !pair.clientConn(clientCh).isHandshaking && s != null && !pair.serverConn(s).isHandshaking
        }
        assertTrue(ok, "handshake did not complete at ${pair.time - TEST_EPOCH}: ${pair.clientToServer} / ${pair.serverToClient}")
        val s = checkNotNull(serverCh)
        for (conn in listOf(pair.clientConn(clientCh), pair.serverConn(s))) {
            val events = conn.drainEvents()
            assertTrue(Event.Connected in events, "no Connected event: $events")
        }
        return clientCh to s
    }

    /** Transfer [data] over a new uni stream from [from] to [to]; returns the transfer once it is read to the end. */
    private fun transfer(pair: ConnPair, from: App, to: App, data: ByteArray, limit: Duration, readBudget: Int = Int.MAX_VALUE,
                         onPump: (Transfer) -> Unit = {}): Transfer {
        val t = Transfer(data)
        val id = from.conn.streams().open(Dir.Uni) ?: fail("no stream credit")
        t.id = id
        var accepted = false
        val ok = pair.driveUntil(limit) {
            from.poll()
            to.poll()
            t.write(from.conn.sendStream(id))
            if (!accepted) accepted = to.conn.streams().accept(Dir.Uni)?.also { assertEquals(id, it) } != null
            if (accepted) t.read(to.conn.recvStream(id), readBudget)
            onPump(t)
            t.recvFinished && from.finished(id)
        }
        assertTrue(ok, "transfer stalled or too slow at ${pair.time - TEST_EPOCH}: ${t.receivedBytes} of ${data.size} bytes read, " +
            "${t.written} written, accepted $accepted, sender lost ${from.lost()} closed ${from.conn.isClosed} idle ${from.conn.isIdle()}, " +
            "receiver lost ${to.lost()} closed ${to.conn.isClosed} idle ${to.conn.isIdle()}; ${pair.clientToServer} / ${pair.serverToClient}")
        t.assertIntact()
        return t
    }

    /** Close from [closer] and drive until both endpoints forgot their connections. */
    private fun closeAndDrain(pair: ConnPair, closer: App, limit: Duration = 2.minutes) {
        closer.conn.close(pair.time, VarInt(0), Bytes.EMPTY)
        val ok = pair.driveUntil(limit) {
            pair.client.endpoint.openConnections() == 0 && pair.server.endpoint.openConnections() == 0
        }
        assertTrue(ok, "connections did not drain: ${pair.client.endpoint.openConnections()} / ${pair.server.endpoint.openConnections()}")
    }

    private fun assertLossCounted(pair: ConnPair, sender: App, direction: LinkImpairment) {
        val path = sender.conn.stats().path
        assertTrue(path.lostPackets > 0, "no lost packets counted with ${direction.dropped} dropped")
        assertTrue(path.lostPackets <= path.sentPackets)
        assertTrue(path.lostBytes > 0)
        assertTrue(path.congestionEvents > 0, "loss without a congestion event")
    }

    // ---- bulk transfer under loss, reordering, duplication ----

    private fun bulk(loss: Double, size: Int, seed: Long, limit: Duration) {
        val (pair, client, server) = lossyPair(seed, loss)
        val data = Random(seed).nextBytes(size)
        transfer(pair, client, server, data, limit)
        val c2s = pair.clientToServer!!
        assertTrue(c2s.dropped > 0)
        assertLossCounted(pair, client, c2s)
        // Pure loss (no reordering): a packet is only declared lost if its datagram was dropped (an ACK covers every
        // received packet until acknowledged), give or take coalesced handshake packets.
        val lost = client.conn.stats().path.lostPackets
        assertTrue(lost <= pair.clientToServer!!.dropped + 4, "$lost lost packets, ${pair.clientToServer!!.dropped} dropped")
        println("bulk ${size shr 20} MiB at ${(loss * 100).toInt()}% loss: ${pair.time - TEST_EPOCH} virtual, lost $lost, " +
            "c→s $c2s, s→c ${pair.serverToClient}")
        closeAndDrain(pair, client)
    }

    @Test fun bulkTransferUnder1PercentLoss() = keysChecked { bulk(0.01, 4 shl 20, 1, 2.minutes) }

    @Test fun bulkTransferUnder5PercentLoss() = keysChecked { bulk(0.05, 4 shl 20, 5, 5.minutes) }

    @Test fun bulkTransferUnder20PercentLoss() = keysChecked { bulk(0.20, 2 shl 20, 20, 30.minutes) }

    @Test
    fun bulkTransferUnderHeavyReordering() = keysChecked {
        val (pair, client, server) = lossyPair(7, loss = 0.0, reorder = 0.3)
        pair.clientToServer!!.reorderDelay = 30.milliseconds
        pair.serverToClient!!.reorderDelay = 30.milliseconds
        val t = transfer(pair, client, server, Random(7).nextBytes(4 shl 20), 5.minutes)
        assertTrue(pair.clientToServer!!.reordered > 100)
        // Reordering beyond the thresholds makes packets look lost (spuriously): counted, then acknowledged anyway.
        println("reordering: ${pair.time - TEST_EPOCH} virtual, lost ${client.conn.stats().path.lostPackets}, ${pair.clientToServer}")
        t.assertIntact()
        closeAndDrain(pair, server)
    }

    @Test
    fun bulkTransferWithDuplication() = keysChecked {
        val (pair, client, server) = lossyPair(11, loss = 0.02, duplicate = 0.25, reorder = 0.1)
        transfer(pair, client, server, Random(11).nextBytes(4 shl 20), 5.minutes)
        // And back, so that both directions carry data over the duplicating link
        transfer(pair, server, client, Random(12).nextBytes(1 shl 20), 5.minutes)
        assertTrue(pair.clientToServer!!.duplicated > 100 && pair.serverToClient!!.duplicated > 100)
        // A duplicate is received, not processed twice: the receiver saw more datagrams than the sender sent packets
        val rx = server.conn.stats().udpRx.datagrams
        val tx = client.conn.stats().udpTx.datagrams
        assertTrue(rx > tx * 1.1, "duplicates did not arrive: $rx received, $tx sent")
        closeAndDrain(pair, client)
    }

    // ---- handshake loss ----

    @Test
    fun handshakeSurvivesLossOfEachFlight() = keysChecked {
        // Lose the first N datagrams of a given kind in one direction, for each kind and N ∈ 1..3
        data class Case(val name: String, val clientSide: Boolean, val kind: (ByteArray) -> Boolean)
        val cases = listOf(
            Case("client Initial", true, ::isInitial),
            Case("server Initial", false, ::isInitial),
            Case("server Handshake", false, ::hasHandshake),
            Case("client Handshake (final flight)", true, ::hasHandshake),
            Case("client first 1-RTT", true, ::isShortHeader),
            Case("server first 1-RTT (HANDSHAKE_DONE)", false, ::isShortHeader),
        )
        for (case in cases) for (n in 1..3) {
            val pair = ConnPair.default()
            pair.latency = 10.milliseconds
            val link = LinkImpairment(0)
            var left = n
            link.drop = { data, _ -> if (left > 0 && case.kind(data)) { left--; true } else false }
            if (case.clientSide) pair.clientToServer = link else pair.serverToClient = link
            val (clientCh, serverCh) = connectLossy(pair, clientConfig(), 2.minutes)
            val client = App(pair, clientCh, true)
            val server = App(pair, serverCh, false)
            // The connection is usable in both directions afterwards
            transfer(pair, client, server, Random(n.toLong()).nextBytes(10_000), 1.minutes)
            transfer(pair, server, client, Random(n.toLong() + 1).nextBytes(10_000), 1.minutes)
            // (the rule may also have caught datagrams sent after the handshake, e.g. the third short-header one)
            assertEquals(n.toLong(), link.droppedByRule, "${case.name} ×$n: not every targeted datagram was sent")
            closeAndDrain(pair, if (n % 2 == 0) client else server)
        }
    }

    @Test
    fun handshakeUnderRandomLoss() = keysChecked {
        // 30% loss both ways, 50 seeds: the handshake always completes and the keys are released
        var total = Duration.ZERO
        for (seed in 0L until 50L) {
            val (pair, client, server) = lossyPair(seed, loss = 0.3, latency = 5.milliseconds)
            total += pair.time - TEST_EPOCH
            // Then a usable link: at 30% loss both ways the PTO backoff (with RTT samples inflated by retransmitted
            // handshake packets) can outgrow the 30 s idle timeout, which ends the connection as RFC 9002 prescribes
            pair.clientToServer!!.loss = 0.05
            pair.serverToClient!!.loss = 0.05
            try {
                transfer(pair, client, server, Random(seed).nextBytes(20_000), 5.minutes)
            } catch (e: AssertionError) {
                throw AssertionError("seed $seed: ${e.message}", e)
            }
            closeAndDrain(pair, if (seed % 2 == 0L) client else server)
        }
        println("handshake at 30% loss: mean ${total / 50} virtual")
    }

    // ---- final ACKs ----

    @Test
    fun lostFinalAcksAreRecovered() = keysChecked {
        val (pair, client, server) = lossyPair(3, loss = 0.0)
        val t = Transfer(Random(3).nextBytes(200_000))
        val id = client.conn.streams().open(Dir.Uni)!!
        t.id = id
        // The next 10 server → client datagrams are lost from the moment the client has written everything and
        // finished: the ACKs of the last data (and those answering the client's PTO probes) are lost.
        var toDrop = -1
        pair.serverToClient!!.drop = { _, _ -> if (toDrop > 0) { toDrop--; true } else false }
        var accepted = false
        val ok = pair.driveUntil(2.minutes) {
            client.poll(); server.poll()
            t.write(client.conn.sendStream(id))
            if (!accepted) accepted = server.conn.streams().accept(Dir.Uni) != null
            if (accepted) t.read(server.conn.recvStream(id))
            if (t.finishCalled && toDrop < 0) toDrop = 10
            t.recvFinished && client.finished(id)
        }
        assertTrue(ok, "the sender never learned that its data arrived")
        assertEquals(0, toDrop)
        t.assertIntact()
        // The client probed (PTO) until an ACK got through
        assertTrue(client.conn.stats().frameTx.ping > 0 || client.conn.stats().path.lostPackets > 0)
        closeAndDrain(pair, client)
    }

    // ---- key update under loss ----

    @Test
    fun keyUpdatesUnderLossAndReordering() = keysChecked {
        val (pair, client, server) = lossyPair(21, loss = 0.05, reorder = 0.1)
        var updates = 0
        var next = 256 * 1024
        transfer(pair, client, server, Random(21).nextBytes(3 shl 20), 10.minutes) { t ->
            if (t.receivedBytes >= next) {
                next += 256 * 1024
                // Alternate sides; an update is refused while the previous one is unconfirmed, as in quinn
                if (updates % 2 == 0) client.conn.forceKeyUpdate() else server.conn.forceKeyUpdate()
                updates++
            }
        }
        assertTrue(updates >= 10)
        assertNull(client.lost())
        assertNull(server.lost())
        closeAndDrain(pair, server)
    }

    // ---- cancellation under loss ----

    @Test
    fun resetStreamLostAndRetransmitted() = keysChecked {
        val (pair, client, server) = lossyPair(31, loss = 0.05)
        val data = Random(31).nextBytes(1 shl 20)
        val t = Transfer(data)
        val id = client.conn.streams().open(Dir.Uni)!!
        t.id = id
        var accepted = false
        var resetDone = false
        var dropAfterReset = 0
        pair.clientToServer!!.drop = { _, _ -> if (dropAfterReset > 0) { dropAfterReset--; true } else false }
        val ok = pair.driveUntil(5.minutes) {
            client.poll(); server.poll()
            if (!resetDone) {
                t.write(client.conn.sendStream(id))
                if (t.written >= 256 * 1024) {
                    client.conn.sendStream(id).reset(VarInt(77))
                    resetDone = true
                    dropAfterReset = 3 // the datagrams carrying RESET_STREAM (and its first retransmissions) are lost
                }
            }
            if (!accepted) accepted = server.conn.streams().accept(Dir.Uni) != null
            if (accepted) t.read(server.conn.recvStream(id))
            t.reset != null
        }
        assertTrue(ok, "RESET_STREAM never arrived")
        assertEquals(VarInt(77), t.reset)
        assertTrue(t.receivedBytes < data.size)
        assertContentEquals(data.copyOf(t.receivedBytes), t.received.copyOf(t.receivedBytes))
        assertTrue(client.conn.stats().frameTx.resetStream >= 2, "RESET_STREAM was not retransmitted")
        // The stream's resources are released on both sides once the reset is acknowledged
        assertTrue(pair.driveUntil(1.minutes) { client.conn.streams().sendStreams() == 0 })
        closeAndDrain(pair, client)
    }

    @Test
    fun stopSendingLostAndRetransmitted() = keysChecked {
        val (pair, client, server) = lossyPair(41, loss = 0.05)
        val data = Random(41).nextBytes(4 shl 20)
        val t = Transfer(data)
        val id = client.conn.streams().open(Dir.Uni)!!
        t.id = id
        var accepted = false
        var stopped = false
        var dropAfterStop = 0
        pair.serverToClient!!.drop = { _, _ -> if (dropAfterStop > 0) { dropAfterStop--; true } else false }
        var writeError: WriteError? = null
        val ok = pair.driveUntil(5.minutes) {
            client.poll(); server.poll()
            if (writeError == null) {
                val r = client.conn.sendStream(id).write(data, t.written, minOf(data.size, t.written + 4096))
                when (r) {
                    is Written -> t.written += r.bytes
                    WriteError.Blocked -> {}
                    else -> writeError = r as WriteError
                }
            }
            if (!accepted) accepted = server.conn.streams().accept(Dir.Uni) != null
            if (accepted && !stopped) {
                t.read(server.conn.recvStream(id))
                if (t.receivedBytes >= 128 * 1024) {
                    server.conn.recvStream(id).stop(VarInt(9))
                    stopped = true
                    dropAfterStop = 3
                }
            }
            writeError != null && client.stopped(id) != null
        }
        assertTrue(ok, "STOP_SENDING never arrived")
        assertEquals(WriteError.Stopped(VarInt(9)), writeError)
        assertEquals(VarInt(9), client.stopped(id))
        assertTrue(server.conn.stats().frameTx.stopSending >= 2, "STOP_SENDING was not retransmitted")
        assertTrue(t.written < data.size)
        // quinn resets a stopped stream when its sender learns about it (the application does here, as the driver's
        // `SendStream.close` would): the receiver sees the stream end and both sides free it
        client.conn.sendStream(id).reset(VarInt(9))
        assertTrue(pair.driveUntil(1.minutes) { client.conn.streams().sendStreams() == 0 })
        closeAndDrain(pair, server)
    }

    // ---- close under loss ----

    @Test
    fun lostConnectionCloseEndsInIdleTimeout() = keysChecked {
        val idle = IdleTimeout.of(10.seconds)
        val (pair, client, server) = lossyPair(51, loss = 0.0,
            server = TransportConfig().maxIdleTimeout(idle), client = TransportConfig().maxIdleTimeout(idle))
        transfer(pair, client, server, Random(51).nextBytes(50_000), 1.minutes)
        // Every CONNECTION_CLOSE is lost: the closer drains (3 PTO) and the peer times out
        pair.clientToServer!!.blackhole = true
        val closedAt = pair.time
        client.conn.close(pair.time, VarInt(5), Bytes.EMPTY)
        assertTrue(pair.driveUntil(1.minutes) { pair.client.endpoint.openConnections() == 0 }, "the closer never drained")
        val clientDrained = pair.time - closedAt
        assertTrue(pair.driveUntil(1.minutes) { pair.server.endpoint.openConnections() == 0 }, "the peer never timed out")
        val serverGone = pair.time - closedAt
        server.poll()
        assertEquals(ConnectionError.TimedOut, server.lost())
        assertTrue(clientDrained < 5.seconds, "draining took $clientDrained")
        assertTrue(serverGone >= 10.seconds && serverGone < 12.seconds, "idle timeout after $serverGone")
    }

    @Test
    fun lostConnectionCloseIsRepeatedForLatePackets() = keysChecked {
        val (pair, client, server) = lossyPair(52, loss = 0.0)
        val t = Transfer(Random(52).nextBytes(4 shl 20))
        val id = server.conn.streams().open(Dir.Uni)!!
        t.id = id
        // The server is sending when the client closes; the client's first CONNECTION_CLOSE is lost
        assertTrue(pair.driveUntil(1.minutes) { server.poll(); t.write(server.conn.sendStream(id)); t.written >= 1 shl 20 })
        var dropNext = 1
        pair.clientToServer!!.drop = { _, _ -> if (dropNext > 0) { dropNext--; true } else false }
        client.conn.close(pair.time, VarInt(6), Bytes.wrap("bye".encodeToByteArray()))
        assertTrue(pair.driveUntil(1.minutes) { server.poll(); server.lost() != null }, "the peer never learned of the close")
        val reason = assertIs<ConnectionError.ApplicationClosed>(server.lost())
        assertEquals(VarInt(6), reason.reason.errorCode)
        assertEquals(0, dropNext)
        assertTrue(pair.driveUntil(1.minutes) {
            pair.client.endpoint.openConnections() == 0 && pair.server.endpoint.openConnections() == 0
        })
    }

    @Test
    fun closeUnderHeavyLossBothSidesEnd() = keysChecked {
        // 50% loss both ways while closing mid-transfer: whatever gets through, both sides end (closed, drained or
        // timed out) within the idle timeout plus draining
        for (seed in 60L until 70L) {
            val idle = IdleTimeout.of(5.seconds)
            val (pair, client, server) = lossyPair(seed, loss = 0.05,
                server = TransportConfig().maxIdleTimeout(idle), client = TransportConfig().maxIdleTimeout(idle))
            val t = Transfer(Random(seed).nextBytes(1 shl 20))
            val id = client.conn.streams().open(Dir.Uni)!!
            t.id = id
            var accepted = false
            pair.driveUntil(1.minutes) {
                client.poll(); server.poll()
                t.write(client.conn.sendStream(id))
                if (!accepted) accepted = server.conn.streams().accept(Dir.Uni) != null
                if (accepted) t.read(server.conn.recvStream(id))
                t.receivedBytes > 256 * 1024
            }
            pair.clientToServer!!.loss = 0.5
            pair.serverToClient!!.loss = 0.5
            val closer = if (seed % 2 == 0L) client else server
            closeAndDrain(pair, closer, 20.seconds)
            val other = if (closer === client) server else client
            other.poll()
            val reason = other.lost()
            // A stateless reset is a valid end too: once the closer drained, its endpoint answers late packets with one
            assertTrue(reason is ConnectionError.ApplicationClosed || reason == ConnectionError.TimedOut ||
                reason == ConnectionError.Reset, "unexpected end: $reason")
        }
    }

    // ---- flow-control credit exhaustion under loss ----

    @Test
    fun exhaustedWindowsUnderLossRecover() = keysChecked {
        // Small stream and connection windows and a slow reader: the sender is blocked on credit most of the time,
        // and the datagrams right after the reader grants credit (MAX_STREAM_DATA / MAX_DATA) are lost besides random
        // loss both ways.
        val server = TransportConfig().streamReceiveWindow(VarInt(16 * 1024)).receiveWindow(VarInt(24 * 1024))
        val (pair, client, srv) = lossyPair(71, loss = 0.05, server = server)
        var dropCredit = 0
        pair.serverToClient!!.drop = { _, _ -> if (dropCredit > 0) { dropCredit--; true } else false }
        val data = listOf(Random(71).nextBytes(512 * 1024), Random(72).nextBytes(512 * 1024))
        val transfers = data.map { Transfer(it) }
        for (t in transfers) t.id = client.conn.streams().open(Dir.Uni)!!
        val accepted = HashSet<StreamId>()
        var reads = 0
        val ok = pair.driveUntil(10.minutes) {
            client.poll(); srv.poll()
            for (t in transfers) t.write(client.conn.sendStream(t.id!!))
            while (true) accepted.add(srv.conn.streams().accept(Dir.Uni) ?: break)
            for (t in transfers) if (t.id in accepted) {
                val before = t.receivedBytes
                t.read(srv.conn.recvStream(t.id!!), 4096)
                if (t.receivedBytes > before && ++reads % 3 == 0) dropCredit = 1
            }
            transfers.all { it.recvFinished && client.finished(it.id!!) }
        }
        assertTrue(ok, "deadlock or stall: ${transfers.map { it.receivedBytes }} read; ${pair.serverToClient}")
        transfers.forEach { it.assertIntact() }
        val sent = srv.conn.stats().frameTx
        val recv = client.conn.stats().frameRx
        assertTrue(sent.maxStreamData > 20 && sent.maxData > 5, "credit was not granted repeatedly: $sent")
        assertTrue(recv.maxStreamData < sent.maxStreamData, "no MAX_STREAM_DATA was lost")
        assertTrue(client.conn.stats().frameTx.streamDataBlocked > 0 || client.conn.stats().frameTx.dataBlocked > 0,
            "the sender never reported being blocked")
        closeAndDrain(pair, client)
    }

    @Test
    fun exhaustedStreamCountUnderLoss() = keysChecked {
        // 200 streams through a limit of 4 concurrent ones at 10% loss: MAX_STREAMS is lost now and then
        val server = TransportConfig().maxConcurrentUniStreams(VarInt(4))
        val (pair, client, srv) = lossyPair(81, loss = 0.10, server = server)
        val pending = ArrayDeque((0 until 200).map { Transfer(Random(81L + it).nextBytes(1000 + it * 37)) })
        val active = HashMap<StreamId, Transfer>()
        val done = ArrayList<Transfer>()
        val serverSide = HashMap<StreamId, Transfer>()
        val ok = pair.driveUntil(10.minutes) {
            client.poll(); srv.poll()
            while (pending.isNotEmpty()) {
                val id = client.conn.streams().open(Dir.Uni) ?: break
                val t = pending.removeFirst()
                t.id = id
                active[id] = t
            }
            for (t in active.values) t.write(client.conn.sendStream(t.id!!))
            while (true) {
                val id = srv.conn.streams().accept(Dir.Uni) ?: break
                serverSide[id] = active[id] ?: fail("unknown stream $id")
            }
            for (t in serverSide.values.toList()) {
                t.read(srv.conn.recvStream(t.id!!))
                if (t.recvFinished) { serverSide.remove(t.id); active.remove(t.id); done.add(t) }
            }
            done.size == 200
        }
        assertTrue(ok, "stalled with ${done.size} of 200 streams done, ${active.size} active")
        done.forEach { it.assertIntact() }
        assertTrue(srv.conn.stats().frameTx.maxStreamsUni > 10)
        closeAndDrain(pair, srv)
    }

    // ---- many concurrent streams, both directions ----

    @Test
    fun manyConcurrentStreamsUnderLoss() = keysChecked {
        val (pair, client, server) = lossyPair(91, loss = 0.05, reorder = 0.05)
        val up = (0 until 50).map { Transfer(Random(910L + it).nextBytes(40_000 + it * 101)) }
        val down = (0 until 50).map { Transfer(Random(960L + it).nextBytes(30_000 + it * 53)) }
        for (t in up) t.id = client.conn.streams().open(Dir.Uni)!!
        for (t in down) t.id = server.conn.streams().open(Dir.Uni)!!
        val ok = pair.driveUntil(10.minutes) {
            client.poll(); server.poll()
            for (t in up) t.write(client.conn.sendStream(t.id!!))
            for (t in down) t.write(server.conn.sendStream(t.id!!))
            while (server.conn.streams().accept(Dir.Uni) != null) {}
            while (client.conn.streams().accept(Dir.Uni) != null) {}
            for (t in up) if (!t.recvFinished) t.read(server.conn.recvStream(t.id!!))
            for (t in down) if (!t.recvFinished) t.read(client.conn.recvStream(t.id!!))
            up.all { it.recvFinished } && down.all { it.recvFinished }
        }
        assertTrue(ok, "stalled: ${up.count { it.recvFinished }} up, ${down.count { it.recvFinished }} down")
        (up + down).forEach { it.assertIntact() }
        closeAndDrain(pair, client)
    }

    // ---- datagrams under loss ----

    @Test
    fun datagramsUnderLossDuplicationAndReordering() = keysChecked {
        val (pair, client, server) = lossyPair(101, loss = 0.1, duplicate = 0.1, reorder = 0.2)
        val count = 2000
        var sent = 0
        val seen = HashSet<Int>()
        val emptySpace = client.conn.datagrams().sendBufferSpace()
        fun payload(i: Int): ByteArray = Random(i).nextBytes(200 + i % 800).also { it[0] = (i shr 8).toByte(); it[1] = i.toByte() }
        val ok = pair.driveUntil(5.minutes) {
            client.poll(); server.poll()
            while (sent < count && client.conn.datagrams().sendBufferSpace() > 1000) {
                assertNull(client.conn.datagrams().send(Bytes.wrap(payload(sent)), false))
                sent++
            }
            while (true) {
                val d = server.conn.datagrams().recv() ?: break
                val arr = d.toByteArray()
                val i = ((arr[0].toInt() and 0xff) shl 8) or (arr[1].toInt() and 0xff)
                assertContentEquals(payload(i), arr, "datagram $i corrupted")
                assertTrue(seen.add(i), "datagram $i delivered twice")
            }
            sent == count && client.conn.datagrams().sendBufferSpace() == emptySpace // all queued ones went out
        }
        assertTrue(ok, "datagrams stalled at $sent sent")
        // Settle: whatever is in flight arrives or is lost
        pair.driveUntil(10.seconds) { false }
        while (true) {
            val d = server.conn.datagrams().recv() ?: break
            val arr = d.toByteArray()
            assertTrue(seen.add(((arr[0].toInt() and 0xff) shl 8) or (arr[1].toInt() and 0xff)))
        }
        println("datagrams: ${seen.size} of $count delivered; ${pair.clientToServer}")
        assertTrue(seen.size in (count * 6 / 10) until count, "${seen.size} of $count delivered")
        // Lost datagrams are not retransmitted, but their packets count as lost
        assertTrue(client.conn.stats().path.lostPackets > 0)
        assertNull(client.lost())
        closeAndDrain(pair, client)
    }
}
