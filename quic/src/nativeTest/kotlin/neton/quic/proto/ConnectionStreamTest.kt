package neton.quic.proto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

// quinn-proto `tests/mod.rs`, part 2: streams, flow control, DATA_BLOCKED / STREAM_DATA_BLOCKED, key updates and
// stream finishing.

class ConnectionStreamTest {
    private val msg = "hello".encodeToByteArray()
    private val error42 = VarInt(42)

    // mod.rs:385
    @Test
    fun finishStreamSimple() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!

        pair.clientSend(clientCh, s).writeOk(msg)
        assertEquals(1, pair.clientStreams(clientCh).sendStreams())
        pair.clientSend(clientCh, s).finish()
        pair.drive()

        assertEquals(StreamEvent.Finished(s), pair.clientConn(clientCh).poll())
        assertNull(pair.clientConn(clientCh).poll())
        assertEquals(0, pair.clientStreams(clientCh).sendStreams())
        assertEquals(0, pair.serverConn(serverCh).streams().sendStreams())
        assertEquals(StreamEvent.Opened(Dir.Uni), pair.serverConn(serverCh).poll())
        // Receive-only streams do not get `StreamFinished` events
        assertEquals(0, pair.serverConn(serverCh).streams().sendStreams())
        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Uni))
        assertNull(pair.serverConn(serverCh).poll())

        val chunks = pair.serverRecv(serverCh, s).read(false)
        assertChunk(chunks.next(Int.MAX_VALUE), 0, msg)
        assertEquals(ReadResult.Finished, chunks.next(Int.MAX_VALUE))
        chunks.finalize()
    }

    // mod.rs:425
    @Test
    fun resetStream() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!

        pair.clientSend(clientCh, s).writeOk(msg)
        pair.drive()

        // resetting stream
        pair.clientSend(clientCh, s).reset(error42)
        pair.drive()

        assertEquals(StreamEvent.Opened(Dir.Uni), pair.serverConn(serverCh).poll())
        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Uni))
        val chunks = pair.serverRecv(serverCh, s).read(false)
        assertEquals(ReadError.Reset(error42), chunks.next(Int.MAX_VALUE))
        chunks.finalize()
        assertNull(pair.clientConn(clientCh).poll())
    }

    // mod.rs:454
    @Test
    fun stopStream() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        pair.clientSend(clientCh, s).writeOk(msg)
        pair.drive()

        // stopping stream
        pair.serverRecv(serverCh, s).stop(error42)
        pair.drive()

        assertEquals(StreamEvent.Opened(Dir.Uni), pair.serverConn(serverCh).poll())
        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Uni))

        assertEquals(WriteError.Stopped(error42), pair.clientSend(clientCh, s).write("foo".encodeToByteArray()))
        val e = assertFailsWith<FinishError.Stopped> { pair.clientSend(clientCh, s).finish() }
        assertEquals(error42, e.errorCode)
    }

    // mod.rs:572
    @Test
    fun congestion() {
        val pair = ConnPair.default()
        val (clientCh, _) = pair.connect()

        val target = 2048L
        assertTrue(pair.clientConn(clientCh).congestionWindow() > target)
        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        // Send data without receiving ACKs until the congestion state falls below target
        while (pair.clientConn(clientCh).congestionWindow() > target) {
            val n = pair.clientSend(clientCh, s).writeOk(ByteArray(1024) { 42 })
            assertEquals(1024, n)
            pair.driveClient()
        }
        // Ensure that the congestion state recovers after receiving the ACKs
        pair.drive()
        assertTrue(pair.clientConn(clientCh).congestionWindow() >= target)
        pair.clientSend(clientCh, s).writeOk(ByteArray(1024) { 42 })
    }

    // mod.rs:961
    @Test
    fun streamIdLimit() {
        val server = serverConfig()
        server.transport = TransportConfig().maxConcurrentUniStreams(VarInt(1))
        val pair = ConnPair.new(EndpointConfig.default(), server)
        val (clientCh, serverCh) = pair.connect()

        val s = pair.clientStreams(clientCh).open(Dir.Uni) ?: fail("couldn't open first stream")
        assertNull(pair.clientStreams(clientCh).open(Dir.Uni), "only one stream is permitted at a time")
        // Generate some activity to allow the server to see the stream
        pair.clientSend(clientCh, s).writeOk(msg)
        pair.clientSend(clientCh, s).finish()
        pair.drive()
        assertEquals(StreamEvent.Finished(s), pair.clientConn(clientCh).poll())
        assertNull(pair.clientStreams(clientCh).open(Dir.Uni), "server does not immediately grant additional credit")
        assertEquals(StreamEvent.Opened(Dir.Uni), pair.serverConn(serverCh).poll())
        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Uni))

        var chunks = pair.serverRecv(serverCh, s).read(false)
        assertChunk(chunks.next(Int.MAX_VALUE), 0, msg)
        assertEquals(ReadResult.Finished, chunks.next(Int.MAX_VALUE))
        chunks.finalize()

        // Server will only send MAX_STREAM_ID now that the application's been notified
        pair.drive()
        assertEquals(StreamEvent.Available(Dir.Uni), pair.clientConn(clientCh).poll())
        assertNull(pair.clientConn(clientCh).poll())

        // Try opening the second stream again, now that we've made room
        val s2 = pair.clientStreams(clientCh).open(Dir.Uni) ?: fail("didn't get stream id budget")
        pair.clientSend(clientCh, s2).finish()
        pair.drive()
        // Make sure the server actually processes data on the newly-available stream
        assertEquals(StreamEvent.Opened(Dir.Uni), pair.serverConn(serverCh).poll())
        assertEquals(s2, pair.serverStreams(serverCh).accept(Dir.Uni))
        assertNull(pair.serverConn(serverCh).poll())

        chunks = pair.serverRecv(serverCh, s2).read(false)
        assertEquals(ReadResult.Finished, chunks.next(Int.MAX_VALUE))
        chunks.finalize()
    }

    private fun pairWithServerTransport(transport: TransportConfig): ConnPair {
        val server = serverConfig()
        server.transport = transport
        return ConnPair.new(EndpointConfig.default(), server)
    }

    private val twelve = "0123456789ab".encodeToByteArray()

    // mod.rs:1049
    @Test
    fun dataBlocked() {
        val pair = pairWithServerTransport(TransportConfig().receiveWindow(VarInt(10)))
        val (clientCh, serverCh) = pair.connect()

        // Fill the connection-level window, then run into the limit
        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        assertEquals(10, pair.clientSend(clientCh, s).writeOk(twelve))
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, s).write("c".encodeToByteArray()))
        pair.drive()
        assertEquals(1L, pair.clientConn(clientCh).stats().frameTx.dataBlocked)
        assertEquals(1L, pair.serverConn(serverCh).stats().frameRx.dataBlocked)

        // Being refused again at the same limit does not repeat the frame
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, s).write("c".encodeToByteArray()))
        pair.drive()
        assertEquals(1L, pair.clientConn(clientCh).stats().frameTx.dataBlocked)

        // Running into the raised limit is reported again
        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Uni))
        val chunks = pair.serverRecv(serverCh, s).read(true)
        assertEquals(10, chunks.nextChunk().bytes.size)
        chunks.finalize()
        pair.drive()
        assertEquals(10, pair.clientSend(clientCh, s).writeOk(twelve))
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, s).write("c".encodeToByteArray()))
        pair.drive()
        val stats = pair.clientConn(clientCh).stats()
        assertEquals(2L, stats.frameTx.dataBlocked)
        assertEquals(0L, stats.frameTx.streamDataBlocked)
    }

    // mod.rs:1127
    @Test
    fun streamDataBlocked() {
        val pair = pairWithServerTransport(TransportConfig().streamReceiveWindow(VarInt(10)))
        val (clientCh, serverCh) = pair.connect()

        // Fill the stream-level window, then run into the limit
        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        assertEquals(10, pair.clientSend(clientCh, s).writeOk(twelve))
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, s).write("c".encodeToByteArray()))
        pair.drive()
        assertEquals(1L, pair.clientConn(clientCh).stats().frameTx.streamDataBlocked)
        assertEquals(1L, pair.serverConn(serverCh).stats().frameRx.streamDataBlocked)

        // Being refused again at the same limit does not repeat the frame
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, s).write("c".encodeToByteArray()))
        pair.drive()
        assertEquals(1L, pair.clientConn(clientCh).stats().frameTx.streamDataBlocked)

        // Running into the raised limit is reported again
        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Uni))
        val chunks = pair.serverRecv(serverCh, s).read(true)
        assertEquals(10, chunks.nextChunk().bytes.size)
        chunks.finalize()
        pair.drive()
        assertEquals(10, pair.clientSend(clientCh, s).writeOk(twelve))
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, s).write("c".encodeToByteArray()))
        pair.drive()
        val stats = pair.clientConn(clientCh).stats()
        assertEquals(2L, stats.frameTx.streamDataBlocked)
        assertEquals(0L, stats.frameTx.dataBlocked)
    }

    // mod.rs:1205
    @Test
    fun dataBlockedNotSentUnderLimit() {
        val pair = ConnPair.default()
        val (clientCh, _) = pair.connect()

        // Default windows are far larger than this write, so nothing is blocked
        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        pair.clientSend(clientCh, s).writeOk("hi".encodeToByteArray())
        pair.drive()

        val stats = pair.clientConn(clientCh).stats()
        assertEquals(0L, stats.frameTx.dataBlocked)
        assertEquals(0L, stats.frameTx.streamDataBlocked)
    }

    // mod.rs:1221
    @Test
    fun dataBlockedNotSentForLocalSendWindow() {
        val pair = ConnPair.default()
        val (clientCh, _) = pair.connect()

        // Running out of our own send window is not the peer's flow control limit
        pair.clientConn(clientCh).setSendWindow(5)
        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        assertEquals(5, pair.clientSend(clientCh, s).writeOk("0123456789".encodeToByteArray()))
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, s).write("x".encodeToByteArray()))
        pair.drive()

        assertEquals(0L, pair.clientConn(clientCh).stats().frameTx.dataBlocked)
    }

    // mod.rs:1249
    @Test
    fun dataBlockedDroppedWhenLimitRaised() {
        val pair = pairWithServerTransport(TransportConfig().receiveWindow(VarInt(10)))
        val (clientCh, serverCh) = pair.connect()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        assertEquals(10, pair.clientSend(clientCh, s).writeOk(twelve))
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, s).write("c".encodeToByteArray()))

        // The peer raises the limit before the queued frame gets transmitted
        pair.serverConn(serverCh).setReceiveWindow(VarInt(100))
        pair.driveServer()
        pair.drive()

        assertEquals(0L, pair.clientConn(clientCh).stats().frameTx.dataBlocked)
    }

    // mod.rs:1289
    @Test
    fun streamDataBlockedNotSentAfterReset() {
        val pair = pairWithServerTransport(TransportConfig().streamReceiveWindow(VarInt(10)))
        val (clientCh, _) = pair.connect()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        assertEquals(10, pair.clientSend(clientCh, s).writeOk(twelve))
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, s).write("c".encodeToByteArray()))

        // Resetting the stream before the queued frame gets transmitted discards it
        pair.clientSend(clientCh, s).reset(VarInt(0))
        pair.drive()

        val stats = pair.clientConn(clientCh).stats()
        assertEquals(0L, stats.frameTx.streamDataBlocked)
        assertEquals(1L, stats.frameTx.resetStream)
    }

    // mod.rs:1323
    @Test
    fun dataBlockedRetransmit() {
        val pair = pairWithServerTransport(TransportConfig().receiveWindow(VarInt(10)))
        val (clientCh, serverCh) = pair.connect()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        assertEquals(10, pair.clientSend(clientCh, s).writeOk(twelve))
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, s).write("c".encodeToByteArray()))
        pair.driveClient()
        pair.server.inbound.clear() // Lose the packet carrying the frame
        pair.drive()

        // Still blocked at the same limit, so the frame is sent again. A PTO may send several probes, each carrying
        // the frame, so only check that it was repeated and got through.
        assertTrue(pair.clientConn(clientCh).stats().frameTx.dataBlocked > 1)
        assertTrue(pair.serverConn(serverCh).stats().frameRx.dataBlocked > 0)
    }

    // mod.rs:1369
    @Test
    fun keyUpdateSimple() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()
        val s = pair.clientStreams(clientCh).open(Dir.Bi) ?: fail("couldn't open first stream")

        val msg1 = "hello1".encodeToByteArray()
        pair.clientSend(clientCh, s).writeOk(msg1)
        pair.drive()

        assertEquals(StreamEvent.Opened(Dir.Bi), pair.serverConn(serverCh).poll())
        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Bi))
        assertNull(pair.serverConn(serverCh).poll())
        var chunks = pair.serverRecv(serverCh, s).read(false)
        assertChunk(chunks.next(Int.MAX_VALUE), 0, msg1)
        chunks.finalize()

        // initiating key update
        pair.clientConn(clientCh).forceKeyUpdate()

        val msg2 = "hello2".encodeToByteArray()
        pair.clientSend(clientCh, s).writeOk(msg2)
        pair.drive()

        assertEquals(StreamEvent.Readable(s), pair.serverConn(serverCh).poll())
        assertNull(pair.serverConn(serverCh).poll())
        chunks = pair.serverRecv(serverCh, s).read(false)
        assertChunk(chunks.next(Int.MAX_VALUE), 6, msg2)
        chunks.finalize()

        assertEquals(0L, pair.clientConn(clientCh).stats().path.lostPackets)
        assertEquals(0L, pair.serverConn(serverCh).stats().path.lostPackets)
    }

    // mod.rs:1422
    @Test
    fun keyUpdateReordered() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()
        val s = pair.clientStreams(clientCh).open(Dir.Bi) ?: fail("couldn't open first stream")

        val msg1 = "1".encodeToByteArray()
        pair.clientSend(clientCh, s).writeOk(msg1)
        pair.client.drive(pair.time, pair.server.addr)
        assertTrue(pair.client.outbound.isNotEmpty())
        pair.client.delayOutbound()

        pair.clientConn(clientCh).forceKeyUpdate()
        // updated keys

        val msg2 = "two".encodeToByteArray()
        pair.clientSend(clientCh, s).writeOk(msg2)
        pair.client.drive(pair.time, pair.server.addr)
        pair.client.finishDelay()
        pair.drive()

        assertEquals(0L, pair.clientConn(clientCh).stats().path.lostPackets)
        assertEquals(StreamEvent.Opened(Dir.Bi), pair.serverConn(serverCh).poll())
        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Bi))

        val chunks = pair.serverRecv(serverCh, s).read(true)
        assertContentEquals(msg1, chunks.nextChunk().bytes.toByteArray())
        assertContentEquals(msg2, chunks.nextChunk().bytes.toByteArray())
        chunks.finalize()

        assertEquals(0L, pair.clientConn(clientCh).stats().path.lostPackets)
        assertEquals(0L, pair.serverConn(serverCh).stats().path.lostPackets)
    }

    /** Read in order until blocked; fails on the end of the stream or an error. Returns the bytes read. */
    private fun readUntilBlocked(chunks: Chunks): Int {
        var cursor = 0
        while (true) {
            when (val r = chunks.next(Int.MAX_VALUE)) {
                is Chunk -> cursor += r.bytes.size
                ReadResult.Finished -> fail("end of stream")
                ReadError.Blocked -> return cursor
                else -> fail("$r")
            }
        }
    }

    private fun testFlowControl(config: TransportConfig, windowSize: Int) {
        val pair = pairWithServerTransport(config)
        val (clientCh, serverCh) = pair.connect()
        val msg = ByteArray(windowSize + 10) { 0xAB.toByte() }

        // Stream reset before read
        var s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        assertEquals(windowSize, pair.clientSend(clientCh, s).writeOk(msg))
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, s).write(msg, windowSize))
        pair.drive()
        pair.clientSend(clientCh, s).reset(VarInt(42))
        pair.drive()

        var chunks = pair.serverRecv(serverCh, s).read(true)
        assertEquals(ReadError.Reset(VarInt(42)), chunks.next(Int.MAX_VALUE))
        chunks.finalize()

        // Happy path
        s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        assertEquals(windowSize, pair.clientSend(clientCh, s).writeOk(msg))
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, s).write(msg, windowSize))

        pair.drive()
        chunks = pair.serverRecv(serverCh, s).read(true)
        var cursor = readUntilBlocked(chunks)
        chunks.finalize()

        // finished reading
        assertEquals(windowSize, cursor)
        pair.drive()
        assertEquals(windowSize, pair.clientSend(clientCh, s).writeOk(msg))
        assertEquals(WriteError.Blocked, pair.clientSend(clientCh, s).write(msg, windowSize))

        pair.drive()
        chunks = pair.serverRecv(serverCh, s).read(true)
        cursor = readUntilBlocked(chunks)
        assertEquals(windowSize, cursor)
        chunks.finalize()
    }

    // mod.rs:1797
    @Test
    fun streamFlowControl() = testFlowControl(TransportConfig().streamReceiveWindow(VarInt(2000)), 2000)

    // mod.rs:1808
    @Test
    fun connFlowControl() = testFlowControl(TransportConfig().receiveWindow(VarInt(2000)), 2000)

    // mod.rs:1819
    @Test
    fun stopOpensBidi() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()
        assertEquals(0, pair.clientStreams(clientCh).sendStreams())
        val s = pair.clientStreams(clientCh).open(Dir.Bi)!!
        assertEquals(1, pair.clientStreams(clientCh).sendStreams())
        pair.clientConn(clientCh).recvStream(s).stop(error42)
        pair.drive()

        assertEquals(StreamEvent.Opened(Dir.Bi), pair.serverConn(serverCh).poll())
        assertEquals(0, pair.serverConn(serverCh).streams().sendStreams())
        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Bi))
        assertEquals(1, pair.serverConn(serverCh).streams().sendStreams())

        val chunks = pair.serverRecv(serverCh, s).read(false)
        assertEquals(ReadError.Blocked, chunks.next(Int.MAX_VALUE))
        chunks.finalize()

        assertEquals(WriteError.Stopped(error42), pair.serverSend(serverCh, s).write("foo".encodeToByteArray()))
        val stopped = pair.serverConn(serverCh).poll() as StreamEvent.Stopped
        assertEquals(error42, stopped.errorCode)
        assertNull(pair.serverConn(serverCh).poll())
    }

    // mod.rs:1864
    @Test
    fun implicitOpen() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()
        val s1 = pair.clientStreams(clientCh).open(Dir.Uni)!!
        val s2 = pair.clientStreams(clientCh).open(Dir.Uni)!!
        pair.clientSend(clientCh, s2).writeOk(msg)
        pair.drive()
        assertEquals(StreamEvent.Opened(Dir.Uni), pair.serverConn(serverCh).poll())
        assertEquals(s1, pair.serverStreams(serverCh).accept(Dir.Uni))
        assertEquals(s2, pair.serverStreams(serverCh).accept(Dir.Uni))
        assertNull(pair.serverStreams(serverCh).accept(Dir.Uni))
    }

    // mod.rs:2033
    @Test
    fun finishStreamFlowControlReordered() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!

        pair.clientSend(clientCh, s).writeOk(msg)
        pair.driveClient() // Send stream data
        pair.server.drive(pair.time, pair.client.addr) // Receive

        // Issue flow control credit
        var chunks = pair.serverRecv(serverCh, s).read(false)
        assertChunk(chunks.next(Int.MAX_VALUE), 0, msg)
        chunks.finalize()

        pair.server.drive(pair.time, pair.client.addr)
        pair.server.delayOutbound() // Delay it

        pair.clientSend(clientCh, s).finish()
        pair.driveClient() // Send FIN
        pair.server.drive(pair.time, pair.client.addr) // Acknowledge
        pair.server.finishDelay() // Add flow control packets after
        pair.drive()

        assertEquals(StreamEvent.Finished(s), pair.clientConn(clientCh).poll())
        assertNull(pair.clientConn(clientCh).poll())
        assertEquals(StreamEvent.Opened(Dir.Uni), pair.serverConn(serverCh).poll())
        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Uni))

        chunks = pair.serverRecv(serverCh, s).read(false)
        assertEquals(ReadResult.Finished, chunks.next(Int.MAX_VALUE))
        chunks.finalize()
    }

    // mod.rs:2116
    @Test
    fun stopBeforeFinish() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        pair.clientSend(clientCh, s).writeOk(msg)
        pair.drive()

        // stopping stream
        pair.serverRecv(serverCh, s).stop(error42)
        pair.drive()

        val e = assertFailsWith<FinishError.Stopped> { pair.clientSend(clientCh, s).finish() }
        assertEquals(error42, e.errorCode)
    }

    // mod.rs:2138
    @Test
    fun stopDuringFinish() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        pair.clientSend(clientCh, s).writeOk(msg)
        pair.drive()

        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Uni))
        // stopping and finishing stream
        pair.serverRecv(serverCh, s).stop(error42)
        pair.driveServer()
        pair.clientSend(clientCh, s).finish()
        pair.driveClient()
        assertEquals(StreamEvent.Stopped(s, error42), pair.clientConn(clientCh).poll())
    }

    /** Ensure that we don't yield a finish event before the actual FIN is acked so the peer isn't left hanging (mod.rs:2580). */
    @Test
    fun finishAcked() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!

        pair.clientSend(clientCh, s).writeOk(msg)
        // client sends data to server
        pair.driveClient() // send data to server
        // server acknowledges data
        pair.driveServer() // process data and send data ack

        // Receive data
        assertEquals(StreamEvent.Opened(Dir.Uni), pair.serverConn(serverCh).poll())
        assertNull(pair.serverConn(serverCh).poll())

        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Uni))

        var chunks = pair.serverRecv(serverCh, s).read(false)
        assertChunk(chunks.next(Int.MAX_VALUE), 0, msg)
        assertEquals(ReadError.Blocked, chunks.next(Int.MAX_VALUE))
        chunks.finalize()

        // Finish before receiving data ack
        pair.clientSend(clientCh, s).finish()
        // Send FIN, receive data ack
        // client receives ACK, sends FIN
        pair.driveClient()
        // Check for premature finish from data ack
        assertNull(pair.clientConn(clientCh).poll())
        // Process FIN ack
        // server ACKs FIN
        pair.drive()
        assertEquals(StreamEvent.Finished(s), pair.clientConn(clientCh).poll())

        chunks = pair.serverRecv(serverCh, s).read(false)
        assertEquals(ReadResult.Finished, chunks.next(Int.MAX_VALUE))
        chunks.finalize()
    }

    /** Ensure that we don't yield a finish event while there's still unacknowledged data (mod.rs:2636). */
    @Test
    fun finishRetransmit() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!

        pair.clientSend(clientCh, s).writeOk(msg)
        pair.driveClient() // send data to server
        pair.server.inbound.clear() // Lose it

        // Send FIN
        pair.clientSend(clientCh, s).finish()
        pair.driveClient()
        // Process FIN
        pair.driveServer()
        // Receive FIN ack, but no data ack
        pair.driveClient()
        // Check for premature finish from FIN ack
        assertNull(pair.clientConn(clientCh).poll())
        // Recover
        pair.drive()
        assertEquals(StreamEvent.Finished(s), pair.clientConn(clientCh).poll())

        assertEquals(StreamEvent.Opened(Dir.Uni), pair.serverConn(serverCh).poll())

        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Uni))

        val chunks = pair.serverRecv(serverCh, s).read(false)
        assertChunk(chunks.next(Int.MAX_VALUE), 0, msg)
        assertEquals(ReadResult.Finished, chunks.next(Int.MAX_VALUE))
        chunks.finalize()
    }

    /**
     * Ensures that exchanging data on a client-initiated bidirectional stream works past the initial stream window
     * (mod.rs:2683).
     */
    @Test
    fun repeatedRequestResponse() {
        val pair = pairWithServerTransport(TransportConfig().maxConcurrentBidiStreams(VarInt(1)))
        val (clientCh, serverCh) = pair.connect()
        val request = "hello".encodeToByteArray()
        val response = "world".encodeToByteArray()
        repeat(3) {
            val s = pair.clientStreams(clientCh).open(Dir.Bi)!!

            pair.clientSend(clientCh, s).writeOk(request)
            pair.clientSend(clientCh, s).finish()

            pair.drive()

            assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Bi))
            var chunks = pair.serverRecv(serverCh, s).read(false)
            assertChunk(chunks.next(Int.MAX_VALUE), 0, request)

            assertEquals(ReadResult.Finished, chunks.next(Int.MAX_VALUE))
            chunks.finalize()
            pair.serverSend(serverCh, s).writeOk(response)
            pair.serverSend(serverCh, s).finish()

            pair.drive()

            chunks = pair.clientRecv(clientCh, s).read(false)
            assertChunk(chunks.next(Int.MAX_VALUE), 0, response)
            assertEquals(ReadResult.Finished, chunks.next(Int.MAX_VALUE))
            chunks.finalize()
        }
    }
}
