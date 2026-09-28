package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import neton.io.net.SocketAddress
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds

// quinn-proto `tests/mod.rs`, part 1: handshake, lifecycle, version negotiation, stateless resets, 0-RTT, ALPN,
// closing, idle timeout, migration and connection IDs. The TLS layer is the test double of `MockTls.kt` (SPEC §4);
// tests that need real TLS behaviour are listed in the SPEC record, not ported.

private fun bytes(s: String): Bytes = Bytes.wrap(s.encodeToByteArray())

internal fun SendStream.writeOk(data: ByteArray): Int = when (val r = write(data)) {
    is Written -> r.bytes
    is WriteError -> fail("write failed: $r")
}

internal fun Chunks.nextChunk(): Chunk = next(Int.MAX_VALUE) as? Chunk ?: fail("expected a chunk")

internal fun ConnPair.assertClientConnectedAfterDrive(clientCh: ConnectionHandle) {
    assertEquals(Event.HandshakeDataReady, clientConn(clientCh).poll())
    assertEquals(Event.Connected, clientConn(clientCh).poll())
}

class ConnectionTest {

    // mod.rs:48
    @Test
    fun pendingIncomingSurvivesServerConfigChange() {
        for (replacement in listOf(null, serverConfigWithAlpn("replacement-only"))) {
            val pair = ConnPair.default()
            val clientCh = pair.beginConnect(clientConfig())
            pair.driveClient()
            val (received, ecn, data) = pair.server.inbound.removeFirst()
            val response = Buffer(1500)
            val incoming = (pair.server.endpoint.handle(received, pair.client.addr, null, ecn, data.copyOf(), response)
                as? DatagramEvent.NewConnection ?: fail("expected an incoming connection")).incoming

            pair.server.endpoint.setServerConfig(replacement)
            // Retransmitted Initials must still be buffered after the configuration changes.
            assertNull(pair.server.endpoint.handle(received, pair.client.addr, null, ecn, data, response))
            val serverCh = pair.server.tryAccept(incoming, pair.time)!!
            pair.drive()
            for ((endpoint, ch) in listOf(pair.client to clientCh, pair.server to serverCh)) {
                assertTrue(endpoint.connections[ch]!!.drainEvents().any { it == Event.Connected })
            }
        }
    }

    // mod.rs:89
    @Test
    fun pendingIncomingCanRetryAfterDisablingServer() {
        val config = serverConfig()
        val pair = ConnPair.new(EndpointConfig.default(), config)
        pair.server.handleIncoming = { IncomingConnectionBehavior.Wait }
        val clientCh = pair.beginConnect(clientConfig())
        pair.driveClient()
        pair.server.driveIncoming(pair.time, pair.client.addr)
        val incoming = pair.server.waitingIncoming.removeAt(pair.server.waitingIncoming.size - 1)

        pair.server.endpoint.setServerConfig(null)
        pair.server.retry(incoming)
        pair.server.endpoint.setServerConfig(config)
        pair.server.handleIncoming = { incoming ->
            assertTrue(incoming.remoteAddressValidated())
            IncomingConnectionBehavior.Accept
        }
        pair.drive()
        pair.server.assertAccept()
        assertTrue(pair.clientConn(clientCh).drainEvents().any { it == Event.Connected })
    }

    // mod.rs:115
    @Test
    fun versionNegotiateServer() {
        val clientAddr = SocketAddress.of(ByteArray(16).also { it[15] = 2 }, 7890)
        val server = Endpoint(EndpointConfig.default(), serverConfig(), true)
        val now = TEST_EPOCH
        val buf = Buffer(server.config().getMaxUdpPayloadSize().toInt())
        // Long-header packet with reserved version number
        val header = hex("80 0a1a2a3a 04 00000000 04 00000000 00")

        // RFC 9000 §5.2.2: packets too small to initiate a connection are dropped
        val event = server.handle(now, clientAddr, null, null, header.copyOf(), buf)
        assertNull(event)
        assertTrue(buf.isEmpty)

        val packet = header.copyOf(MIN_INITIAL_SIZE)
        assertIs<DatagramEvent.Response>(server.handle(now, clientAddr, null, null, packet, buf))

        val out = buf.peekAll()
        assertNotEquals(0, out[0].toInt() and 0x80)
        assertContentEquals(hex("00000000 04 00000000 04 00000000"), out.copyOfRange(1, 15))
        assertTrue((15 until out.size step 4).any { at ->
            val v = ((out[at].toInt() and 0xFF) shl 24) or ((out[at + 1].toInt() and 0xFF) shl 16) or
                ((out[at + 2].toInt() and 0xFF) shl 8) or (out[at + 3].toInt() and 0xFF)
            v in DEFAULT_SUPPORTED_VERSIONS
        })
    }

    // mod.rs:149
    @Test
    fun versionNegotiateClient() {
        val serverAddr = SocketAddress.of(ByteArray(16).also { it[15] = 2 }, 7890)
        // Configure client to use empty CIDs so we can easily hardcode a server version negotiation packet
        val client = Endpoint(EndpointConfig.default().cidGenerator { RandomConnectionIdGenerator(0) }, null, true)
        val (_, clientConn) = client.connect(TEST_EPOCH, clientConfig(), serverAddr, "localhost")
        val now = TEST_EPOCH
        val buf = Buffer(client.config().getMaxUdpPayloadSize().toInt())
        val event = client.handle(
            now,
            serverAddr,
            null,
            null,
            // Version negotiation packet for reserved version, with empty DCID
            hex("80 00000000 00 04 00000000 0a1a2a3a"),
            buf,
        )
        if (event is DatagramEvent.ConnectionEvent) clientConn.handleEvent(event.event)
        assertEquals(Event.ConnectionLost(ConnectionError.VersionMismatch), clientConn.poll())
    }

    private fun checkLifecycle(pair: ConnPair, clientCh: ConnectionHandle, serverCh: ConnectionHandle) {
        assertNull(pair.clientConn(clientCh).poll())
        assertTrue(pair.clientConn(clientCh).usingEcn())
        assertTrue(pair.serverConn(serverCh).usingEcn())

        val reason = bytes("whee")
        pair.clientConn(clientCh).close(pair.time, VarInt(42), reason)
        pair.drive()
        assertEquals(
            Event.ConnectionLost(ConnectionError.ApplicationClosed(Frame.ApplicationClose(VarInt(42), reason))),
            pair.serverConn(serverCh).poll(),
        )
        assertNull(pair.clientConn(clientCh).poll())
        assertEquals(0, pair.client.endpoint.knownConnections())
        assertEquals(0, pair.client.endpoint.knownCids())
        assertEquals(0, pair.server.endpoint.knownConnections())
        assertEquals(0, pair.server.endpoint.knownCids())
    }

    // mod.rs:195
    @Test
    fun lifecycle() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()
        checkLifecycle(pair, clientCh, serverCh)
    }

    // mod.rs:223
    @Test
    fun draftVersionCompat() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connectWith(clientConfig().version(0xff00_0020.toInt()))
        checkLifecycle(pair, clientCh, serverCh)
    }

    private fun resetKeyEndpointConfig(): EndpointConfig {
        val keyMaterial = ByteArray(64).also { kotlin.random.Random.nextBytes(it) }
        return EndpointConfig(HmacSha256Key(keyMaterial)).cidGenerator { HashedConnectionIdGenerator(key = 0) }
    }

    // mod.rs:256
    @Test
    fun serverStatelessReset() {
        val endpointConfig = resetKeyEndpointConfig()
        val pair = ConnPair.new(endpointConfig, serverConfig())
        val (clientCh, _) = pair.connect()
        pair.drive() // Flush any post-handshake frames
        pair.server.endpoint = Endpoint(endpointConfig, serverConfig(), true)
        // Force the server to generate the smallest possible stateless reset
        pair.clientConn(clientCh).ping()
        pair.drive()
        assertEquals(Event.ConnectionLost(ConnectionError.Reset), pair.clientConn(clientCh).poll())
    }

    // mod.rs:286
    @Test
    fun clientStatelessReset() {
        val endpointConfig = resetKeyEndpointConfig()
        val pair = ConnPair.new(endpointConfig, serverConfig())
        val (_, serverCh) = pair.connect()
        pair.client.endpoint = Endpoint(endpointConfig, serverConfig(), true)
        // Send something big enough to allow room for a smaller stateless reset.
        pair.serverConn(serverCh).close(pair.time, VarInt(42), Bytes.wrap(ByteArray(128) { 0xab.toByte() }))
        pair.drive()
        assertEquals(Event.ConnectionLost(ConnectionError.Reset), pair.serverConn(serverCh).poll())
    }

    /** Verify that stateless resets are rate-limited (mod.rs:319). */
    @Test
    fun statelessResetLimit() {
        val remote = SocketAddress.ipv4(127, 0, 0, 1, 42)
        val endpointConfig = EndpointConfig.default().cidGenerator { RandomConnectionIdGenerator(8) }
        val endpoint = Endpoint(endpointConfig, serverConfig(), true)
        val time = TEST_EPOCH
        val buf = Buffer(1500)
        assertIs<DatagramEvent.Response>(endpoint.handle(time, remote, null, null, ByteArray(1024), buf))
        buf.clear()
        assertNull(endpoint.handle(time, remote, null, null, ByteArray(1024), buf))
        assertNull(endpoint.handle(time + (endpointConfig.minResetInterval - 1.nanoseconds), remote, null, null, ByteArray(1024), buf))
        assertIs<DatagramEvent.Response>(endpoint.handle(time + endpointConfig.minResetInterval, remote, null, null, ByteArray(1024), buf))
    }

    // mod.rs:359
    @Test
    fun exportKeyingMaterial() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        val label = "test_label".encodeToByteArray()
        val context = "test_context".encodeToByteArray()

        // client keying material
        val clientBuf = ByteArray(64)
        pair.clientConn(clientCh).cryptoSession().exportKeyingMaterial(clientBuf, label, context)

        // server keying material
        val serverBuf = ByteArray(64)
        pair.serverConn(serverCh).cryptoSession().exportKeyingMaterial(serverBuf, label, context)

        assertContentEquals(clientBuf, serverBuf)
    }

    // mod.rs:593
    @Test
    fun highLatencyHandshake() {
        val pair = ConnPair.default()
        pair.latency = 200.milliseconds
        val (clientCh, serverCh) = pair.connect()
        assertEquals(0L, pair.clientConn(clientCh).bytesInFlight())
        assertEquals(0L, pair.serverConn(serverCh).bytesInFlight())
        assertTrue(pair.clientConn(clientCh).usingEcn())
        assertTrue(pair.serverConn(serverCh).usingEcn())
    }

    // mod.rs:605
    @Test
    fun zeroRttHappypath() {
        val pair = ConnPair.default()
        pair.server.handleIncoming = ::validateIncoming
        val config = clientConfig()

        // Establish normal connection
        val firstCh = pair.beginConnect(config.copy())
        pair.drive()
        pair.server.assertAccept()
        pair.clientConn(firstCh).close(pair.time, VarInt(0), Bytes.EMPTY)
        pair.drive()

        pair.client.addr = localhostV6(nextClientPort())
        // resuming session
        val clientCh = pair.beginConnect(config)
        assertTrue(pair.clientConn(clientCh).has0rtt())
        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        val msg = "Hello, 0-RTT!".encodeToByteArray()
        pair.clientSend(clientCh, s).writeOk(msg)
        pair.drive()

        pair.assertClientConnectedAfterDrive(clientCh)

        assertTrue(pair.clientConn(clientCh).accepted0rtt())
        val serverCh = pair.server.assertAccept()

        assertEquals(Event.HandshakeDataReady, pair.serverConn(serverCh).poll())
        // We don't currently preserve stream event order wrt. connection events
        assertEquals(Event.Connected, pair.serverConn(serverCh).poll())
        assertEquals(StreamEvent.Opened(Dir.Uni), pair.serverConn(serverCh).poll())

        val chunks = pair.serverRecv(serverCh, s).read(false)
        assertChunk(chunks.next(Int.MAX_VALUE), 0, msg)
        chunks.finalize()
        assertEquals(0L, pair.clientConn(clientCh).stats().path.lostPackets)
    }

    // mod.rs:671
    @Test
    fun zeroRttRejection() {
        val pair = ConnPair.new(EndpointConfig.default(), serverConfigWithAlpn("foo", "bar"))
        val clientCrypto = MockClientCrypto(alpn = listOf("foo".encodeToByteArray()))

        // Establish normal connection
        val firstCh = pair.beginConnect(clientConfig(clientCrypto))
        pair.drive()
        val firstServerCh = pair.server.assertAccept()
        assertEquals(Event.HandshakeDataReady, pair.serverConn(firstServerCh).poll())
        assertEquals(Event.Connected, pair.serverConn(firstServerCh).poll())
        assertNull(pair.serverConn(firstServerCh).poll())
        pair.clientConn(firstCh).close(pair.time, VarInt(0), Bytes.EMPTY)
        pair.drive()
        assertIs<Event.ConnectionLost>(pair.serverConn(firstServerCh).poll())
        assertNull(pair.serverConn(firstServerCh).poll())
        pair.client.connections.clear()
        pair.server.connections.clear()

        // We want the existing session cache (so resumption could happen), but different ALPN protocols (so that the
        // server must reject it).
        clientCrypto.alpn = listOf("bar".encodeToByteArray())

        // Changing protocols invalidates 0-RTT
        // resuming session
        val clientCh = pair.beginConnect(clientConfig(clientCrypto))
        assertTrue(pair.clientConn(clientCh).has0rtt())
        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        val msg = "Hello, 0-RTT!".encodeToByteArray()
        pair.clientConn(clientCh).setSendWindow(msg.size.toLong())
        pair.clientSend(clientCh, s).writeOk(msg)
        pair.drive()
        assertFalse(pair.clientConn(clientCh).accepted0rtt())
        val serverCh = pair.server.assertAccept()
        assertEquals(Event.HandshakeDataReady, pair.serverConn(serverCh).poll())
        assertEquals(Event.Connected, pair.serverConn(serverCh).poll())
        assertNull(pair.serverConn(serverCh).poll())
        val s2 = pair.clientStreams(clientCh).open(Dir.Uni)!!
        assertEquals(s, s2)

        var chunks = pair.serverRecv(serverCh, s2).read(false)
        assertEquals(ReadError.Blocked, chunks.next(Int.MAX_VALUE))
        chunks.finalize()
        assertEquals(0L, pair.clientConn(clientCh).stats().path.lostPackets)

        // Rejecting early data must release the entire send window for 1-RTT traffic.
        assertEquals(msg.size, pair.clientSend(clientCh, s2).writeOk(msg))
        pair.clientSend(clientCh, s2).finish()
        pair.drive()
        chunks = pair.serverRecv(serverCh, s2).read(false)
        assertContentEquals(msg, chunks.nextChunk().bytes.toByteArray())
        assertEquals(ReadResult.Finished, chunks.next(Int.MAX_VALUE))
        chunks.finalize()
    }

    private fun testZeroRttIncomingLimit(configureServer: (ServerConfig) -> Unit) {
        // caller sets the server limit to 4000 bytes; the client writes 8000 bytes, split across 8 packets: the first
        // packet is stored in the Incoming, the next three are incoming-buffered, bringing the incoming buffer size to
        // 3600 bytes, and the last four are dropped due to the buffering limit and must be retransmitted
        val clientWrites = 8000
        val expectedDropped = 4L

        val config = serverConfig()
        configureServer(config)
        val pair = ConnPair.new(EndpointConfig.default(), config)
        val clientConfig = clientConfig()

        // Establish normal connection
        val firstCh = pair.beginConnect(clientConfig.copy())
        pair.drive()
        pair.server.assertAccept()
        pair.clientConn(firstCh).close(pair.time, VarInt(0), Bytes.EMPTY)
        pair.drive()

        pair.client.addr = localhostV6(nextClientPort())
        // resuming session
        pair.server.handleIncoming = { IncomingConnectionBehavior.Wait }
        val clientCh = pair.beginConnect(clientConfig)
        assertTrue(pair.clientConn(clientCh).has0rtt())
        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        pair.clientSend(clientCh, s).writeOk(ByteArray(clientWrites))
        pair.drive()
        val incoming = pair.server.waitingIncoming.removeAt(pair.server.waitingIncoming.size - 1)
        assertTrue(pair.server.waitingIncoming.isEmpty())
        pair.server.tryAccept(incoming, pair.time)
        pair.drive()

        pair.assertClientConnectedAfterDrive(clientCh)

        assertTrue(pair.clientConn(clientCh).accepted0rtt())
        val serverCh = pair.server.assertAccept()

        assertEquals(Event.HandshakeDataReady, pair.serverConn(serverCh).poll())
        // We don't currently preserve stream event order wrt. connection events
        assertEquals(Event.Connected, pair.serverConn(serverCh).poll())
        assertEquals(StreamEvent.Opened(Dir.Uni), pair.serverConn(serverCh).poll())

        val chunks = pair.serverRecv(serverCh, s).read(false)
        var offset = 0
        loop@ while (true) {
            when (val r = chunks.next(Int.MAX_VALUE)) {
                is Chunk -> {
                    assertEquals(offset.toLong(), r.offset)
                    offset += r.bytes.size
                }
                ReadError.Blocked -> break@loop
                ReadResult.Finished -> fail("unexpected stream end")
                else -> fail("$r")
            }
        }
        assertEquals(clientWrites, offset)
        chunks.finalize()
        assertEquals(expectedDropped, pair.clientConn(clientCh).stats().path.lostPackets)
    }

    // mod.rs:854
    @Test
    fun zeroRttIncomingBufferSize() = testZeroRttIncomingLimit { it.incomingBufferSize(4000) }

    // mod.rs:861
    @Test
    fun zeroRttIncomingBufferSizeTotal() = testZeroRttIncomingLimit { it.incomingBufferSizeTotal(4000) }

    // mod.rs:868. With the mock TLS layer this checks that the negotiated protocol reaches the application through
    // the session's handshake data; ALPN itself is verified with real TLS (SPEC §4).
    @Test
    fun alpnSuccess() {
        val pair = ConnPair.new(EndpointConfig.default(), serverConfigWithAlpn("foo", "bar", "baz"))
        val clientCh = pair.beginConnect(clientConfigWithAlpn("bar", "quux", "corge"))
        pair.drive()
        val serverCh = pair.server.assertAccept()
        assertEquals(Event.HandshakeDataReady, pair.serverConn(serverCh).poll())
        assertEquals(Event.Connected, pair.serverConn(serverCh).poll())

        val hd = pair.clientConn(clientCh).cryptoSession().handshakeData() as MockHandshakeData
        assertContentEquals("bar".encodeToByteArray(), hd.protocol)
    }

    // mod.rs:1470
    @Test
    fun initialRetransmit() {
        val pair = ConnPair.default()
        val clientCh = pair.beginConnect(clientConfig())
        pair.client.drive(pair.time, pair.server.addr)
        pair.client.outbound.clear() // Drop initial
        pair.drive()
        pair.assertClientConnectedAfterDrive(clientCh)
    }

    // mod.rs:1488
    @Test
    fun instantClose1() {
        val pair = ConnPair.default()
        val clientCh = pair.beginConnect(clientConfig())
        pair.clientConn(clientCh).close(pair.time, VarInt(0), Bytes.EMPTY)
        pair.drive()
        val serverCh = pair.server.assertAccept()
        assertNull(pair.clientConn(clientCh).poll())
        val lost = pair.serverConn(serverCh).poll() as Event.ConnectionLost
        assertEquals(TransportErrorCode.APPLICATION_ERROR, (lost.reason as ConnectionError.ConnectionClosed).reason.errorCode)
    }

    // mod.rs:1513
    @Test
    fun instantClose2() {
        val pair = ConnPair.default()
        val clientCh = pair.beginConnect(clientConfig())
        // Unlike `instant_close`, the server sees a valid Initial packet first.
        pair.driveClient()
        pair.clientConn(clientCh).close(pair.time, VarInt(42), Bytes.EMPTY)
        pair.drive()
        assertNull(pair.clientConn(clientCh).poll())
        val serverCh = pair.server.assertAccept()
        assertEquals(Event.HandshakeDataReady, pair.serverConn(serverCh).poll())
        val lost = pair.serverConn(serverCh).poll() as Event.ConnectionLost
        assertEquals(TransportErrorCode.APPLICATION_ERROR, (lost.reason as ConnectionError.ConnectionClosed).reason.errorCode)
    }

    // mod.rs:1544
    @Test
    fun instantServerClose() {
        val pair = ConnPair.default()
        val clientCh = pair.beginConnect(clientConfig())
        pair.driveClient()
        pair.server.driveIncoming(pair.time, pair.client.addr)
        val serverCh = pair.server.assertAccept()
        pair.serverConn(serverCh).close(pair.time, VarInt(42), Bytes.EMPTY)
        pair.drive()
        val lost = pair.clientConn(clientCh).poll() as Event.ConnectionLost
        assertEquals(TransportErrorCode.APPLICATION_ERROR, (lost.reason as ConnectionError.ConnectionClosed).reason.errorCode)
    }

    /** quinn's loop for tests that run past idle points: step, or jump to the next wakeup. */
    private fun ConnPair.stepOrJump() {
        if (!step()) {
            val t = minOpt(client.nextWakeup(), server.nextWakeup())
            if (t.isSome) time = t
        }
    }

    // mod.rs:1571
    @Test
    fun idleTimeout() {
        val idleTimeout = 100L
        val server = serverConfig()
        server.transport = TransportConfig().maxIdleTimeout(IdleTimeout(VarInt(idleTimeout)))
        val pair = ConnPair.new(EndpointConfig.default(), server)
        val (clientCh, serverCh) = pair.connect()
        pair.clientConn(clientCh).ping()
        val start = pair.time

        while (!pair.clientConn(clientCh).isClosed || !pair.serverConn(serverCh).isClosed) {
            pair.stepOrJump()
            pair.client.inbound.clear() // Simulate total S->C packet loss
        }

        assertTrue(pair.time - start < (2 * idleTimeout).milliseconds)
        assertEquals(Event.ConnectionLost(ConnectionError.TimedOut), pair.clientConn(clientCh).poll())
        assertEquals(Event.ConnectionLost(ConnectionError.TimedOut), pair.serverConn(serverCh).poll())
    }

    // mod.rs:1613
    @Test
    fun connectionCloseSendsAcks() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        val clientAcks = pair.clientConn(clientCh).stats().frameRx.acks

        pair.clientConn(clientCh).ping()
        pair.driveClient()

        pair.serverConn(serverCh).close(pair.time, VarInt(42), Bytes.EMPTY)

        pair.drive()

        val clientAcks2 = pair.clientConn(clientCh).stats().frameRx.acks
        assertTrue(clientAcks2 > clientAcks, "Connection close should send pending ACKs")
    }

    // mod.rs:1637
    @Test
    fun serverHsRetransmit() {
        val pair = ConnPair.default()
        val clientCh = pair.beginConnect(clientConfig())
        pair.step()
        assertTrue(pair.client.inbound.isNotEmpty()) // Initial + Handshakes
        pair.client.inbound.clear()
        pair.drive()
        pair.assertClientConnectedAfterDrive(clientCh)
    }

    // mod.rs:1656
    @Test
    fun migration() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()
        pair.drive()

        val clientStatsAfterConnect = pair.clientConn(clientCh).stats()

        pair.client.addr = SocketAddress.ipv4(127, 0, 0, 1, nextClientPort())
        pair.clientConn(clientCh).ping()

        // Assert that just receiving the ping message is accounted into the servers anti-amplification budget
        pair.driveClient()
        pair.driveServer()
        assertNotEquals(0L, pair.serverConn(serverCh).totalRecvd())

        pair.drive()
        assertNull(pair.clientConn(clientCh).poll())
        assertEquals(pair.client.addr, pair.serverConn(serverCh).remoteAddress())

        // Assert that the client's response to the PATH_CHALLENGE was an IMMEDIATE_ACK, instead of a second ping
        val clientStatsAfterMigrate = pair.clientConn(clientCh).stats()
        assertEquals(1L, clientStatsAfterMigrate.frameTx.ping - clientStatsAfterConnect.frameTx.ping)
        assertEquals(1L, clientStatsAfterMigrate.frameTx.immediateAck - clientStatsAfterConnect.frameTx.immediateAck)
    }

    // mod.rs:1882
    @Test
    fun zeroLengthCid() {
        val pair = ConnPair.new(EndpointConfig.default().cidGenerator { RandomConnectionIdGenerator(0) }, serverConfig())
        val (clientCh, serverCh) = pair.connect()
        // Ensure we can reconnect after a previous connection is cleaned up
        pair.clientConn(clientCh).close(pair.time, VarInt(42), Bytes.EMPTY)
        pair.drive()
        pair.serverConn(serverCh).close(pair.time, VarInt(42), Bytes.EMPTY)
        pair.connect()
    }

    // mod.rs:1911
    @Test
    fun keepAlive() {
        val idleTimeout = 10L
        val server = serverConfig()
        server.transport = TransportConfig()
            .keepAliveInterval((idleTimeout / 2).milliseconds)
            .maxIdleTimeout(IdleTimeout(VarInt(idleTimeout)))
        val pair = ConnPair.new(EndpointConfig.default(), server)
        val (clientCh, serverCh) = pair.connect()
        // Run a good while longer than the idle timeout
        val end = pair.time + (20 * idleTimeout).milliseconds
        while (pair.time < end) {
            pair.stepOrJump()
            assertFalse(pair.clientConn(clientCh).isClosed)
            assertFalse(pair.serverConn(serverCh).isClosed)
        }
    }

    // mod.rs:1938
    @Test
    fun cidRotation() {
        val cidTimeout = 2.seconds

        // Only test cid rotation on server side to have a clear output trace
        val server = Endpoint(
            EndpointConfig.default().cidGenerator { RandomConnectionIdGenerator(8).setLifetime(cidTimeout) },
            serverConfig(),
            true,
        )
        val client = Endpoint(EndpointConfig.default(), null, true)

        val pair = ConnPair.newFromEndpoint(client, server)
        val (_, serverCh) = pair.connect()

        var stop = pair.time
        val end = pair.time + cidTimeout * 5

        // ⚖️ quinn computes `min(CidQueue::LEN + 1, LOC_CID_COUNT)` bounds but asserts them with
        // `assert_matches!(seq, _bound)`, where `_bound` is a binding pattern that matches anything. Running the
        // reference test shows its implementation at (0, 4), (5, 9), (10, 14), ...: the CidQueue::LEN CIDs issued per
        // round. Those are the values asserted here.
        val activeCidNum = minOf(CidQueue.LEN.toLong(), LOC_CID_COUNT)
        var leftBound = 0L
        var rightBound = activeCidNum - 1

        while (pair.time < end) {
            stop += cidTimeout
            // Run a while until PushNewCID timer fires
            while (pair.time < stop) pair.stepOrJump()
            // Checking active cid sequence range
            assertEquals(leftBound to rightBound, pair.serverConn(serverCh).activeLocalCidSeq())
            leftBound += activeCidNum
            rightBound += activeCidNum
            pair.driveServer()
        }
    }

    // mod.rs:1998
    @Test
    fun cidRetirement() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        // Server retires current active remote CIDs
        pair.serverConn(serverCh).rotateLocalCid(1, pair.time)
        pair.drive()
        // Any unexpected behavior may trigger TransportError::CONNECTION_ID_LIMIT_ERROR
        assertFalse(pair.clientConn(clientCh).isClosed)
        assertFalse(pair.serverConn(serverCh).isClosed)
        assertEquals(1L, pair.clientConn(clientCh).activeRemCidSeq())

        val activeCidNum = minOf(CidQueue.LEN.toLong(), LOC_CID_COUNT)

        val nextRetirePriorTo = activeCidNum + 1
        pair.clientConn(clientCh).ping()
        // Server retires all valid remote CIDs
        pair.serverConn(serverCh).rotateLocalCid(nextRetirePriorTo, pair.time)
        pair.drive()
        assertFalse(pair.clientConn(clientCh).isClosed)
        assertFalse(pair.serverConn(serverCh).isClosed)

        assertEquals(nextRetirePriorTo, pair.clientConn(clientCh).activeRemCidSeq())
    }

    // mod.rs:2081
    @Test
    fun handshake1rttHandling() {
        val pair = ConnPair.default()
        val clientCh = pair.beginConnect(clientConfig())
        pair.driveClient()
        pair.driveServer()
        val serverCh = pair.server.assertAccept()
        // Server now has 1-RTT keys, but remains in Handshake state until the TLS CFIN has authenticated the client.
        // Delay the final client handshake flight so that doesn't happen yet.
        pair.client.drive(pair.time, pair.server.addr)
        pair.client.delayOutbound()

        // Send some 1-RTT data which will be received first.
        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        val msg = "hello".encodeToByteArray()
        pair.clientSend(clientCh, s).writeOk(msg)
        pair.clientSend(clientCh, s).finish()
        pair.client.drive(pair.time, pair.server.addr)

        // Add the handshake flight back on.
        pair.client.finishDelay()

        pair.drive()

        assertTrue(pair.clientConn(clientCh).stats().path.lostPackets != 0L)
        val chunks = pair.serverRecv(serverCh, s).read(false)
        assertChunk(chunks.next(Int.MAX_VALUE), 0, msg)
        chunks.finalize()
    }

    // mod.rs:2549
    @Test
    fun largeInitial() {
        val serverConfig = serverConfig(MockServerCrypto(alpn = listOf(byteArrayOf(0, 0, 0, 42))))
        val pair = ConnPair.new(EndpointConfig.default(), serverConfig)
        val protocols = (0 until 1000).map { x -> byteArrayOf((x ushr 24).toByte(), (x ushr 16).toByte(), (x ushr 8).toByte(), x.toByte()) }
        val clientCh = pair.beginConnect(clientConfig(MockClientCrypto(alpn = protocols)))
        pair.drive()
        val serverCh = pair.server.assertAccept()
        pair.assertClientConnectedAfterDrive(clientCh)
        assertEquals(Event.HandshakeDataReady, pair.serverConn(serverCh).poll())
        assertEquals(Event.Connected, pair.serverConn(serverCh).poll())
    }

    /** A server identity that cannot fit inside the initial anti-amplification limit (quinn `big_cert_and_key`). */
    private fun bigIdentityServerConfig(): ServerConfig = serverConfig(MockServerCrypto(identity = ByteArray(10_000) { it.toByte() }))

    /** Ensures that the client sends an anti-deadlock probe after an incomplete server's first flight (mod.rs:2733). */
    @Test
    fun handshakeAntiDeadlockProbe() {
        val pair = ConnPair.new(EndpointConfig.default(), bigIdentityServerConfig())

        val clientCh = pair.beginConnect(clientConfig())
        // Client sends initial
        pair.driveClient()
        // Server sends first flight, gets blocked on anti-amplification
        pair.driveServer()
        // Client acks...
        pair.driveClient()
        // ...but it's lost, so the server doesn't get anti-amplification credit from it
        pair.server.inbound.clear()
        // Client sends an anti-deadlock probe, and the handshake completes as usual.
        pair.drive()
        pair.assertClientConnectedAfterDrive(clientCh)
    }

    /**
     * Ensures that the server can respond with 3 initial packets during the handshake before the anti-amplification
     * limit kicks in when MTUs are similar (mod.rs:2764).
     */
    @Test
    fun serverCanSend3InitalPackets() {
        val pair = ConnPair.new(EndpointConfig.default(), bigIdentityServerConfig())

        val clientCh = pair.beginConnect(clientConfig())
        // Client sends initial
        pair.driveClient()
        // Server sends first flight, gets blocked on anti-amplification
        pair.driveServer()
        // Server should have queued 3 packets at this time
        assertEquals(3, pair.client.inbound.size)

        pair.drive()
        pair.assertClientConnectedAfterDrive(clientCh)
    }

    // mod.rs:2810
    @Test
    fun malformedTokenLen() {
        val clientAddr = SocketAddress.of(ByteArray(16).also { it[15] = 2 }, 7890)
        val server = Endpoint(EndpointConfig.default(), serverConfig(), true)
        val buf = Buffer(server.config().getMaxUdpPayloadSize().toInt())
        server.handle(TEST_EPOCH, clientAddr, null, null, hex("8900 0000 0101 0000 1b1b 841b 0000 0000 3f00"), buf)
    }

    /** This is mostly a sanity check to ensure our testing code is correctly dropping packets above the PMTU (mod.rs:2857). */
    @Test
    fun connectTooLowMtu() {
        val pair = ConnPair.default()

        // The maximum payload size is lower than 1200, so no packages will get through!
        pair.mtu = 1000

        pair.beginConnect(clientConfig())
        pair.drive()
        pair.server.assertNoAccept()
    }

    /**
     * Initials rejected under saturation (here via `max_incoming(0)`) are dropped without sending a response: the
     * client times out rather than receiving a CONNECTION_REFUSED (mod.rs:3651).
     */
    @Test
    fun silentlyDropRejectedInitials() {
        val config = serverConfig().maxIncoming(0)
        val pair = ConnPair.new(EndpointConfig.default(), config)

        val clientCh = pair.beginConnect(clientConfig())
        pair.drive()
        pair.server.assertNoAccept()
        // `drive()` stops once the client's only remaining timer is its idle timeout; advance past it so the
        // unanswered attempt gives up.
        pair.time += 60.seconds
        pair.drive()
        assertEquals(Event.ConnectionLost(ConnectionError.TimedOut), pair.clientConn(clientCh).poll())
    }

    // mod.rs:3675
    @Test
    fun rejectManually() {
        val pair = ConnPair.default()
        pair.server.handleIncoming = { IncomingConnectionBehavior.Reject }

        // The server should now reject incoming connections.
        val clientCh = pair.beginConnect(clientConfig())
        pair.drive()
        pair.server.assertNoAccept()
        val client = pair.clientConn(clientCh)
        assertTrue(client.isClosed)
        val lost = client.poll() as Event.ConnectionLost
        assertEquals(TransportErrorCode.CONNECTION_REFUSED, (lost.reason as ConnectionError.ConnectionClosed).reason.errorCode)
    }

    // mod.rs:3695
    @Test
    fun validateThenRejectManually() {
        val pair = ConnPair.default()
        var i = 0
        pair.server.handleIncoming = { incoming ->
            if (incoming.remoteAddressValidated()) {
                assertEquals(1, i)
                i += 1
                IncomingConnectionBehavior.Reject
            } else {
                assertEquals(0, i)
                i += 1
                IncomingConnectionBehavior.Retry
            }
        }

        // The server should now retry and reject incoming connections.
        val clientCh = pair.beginConnect(clientConfig())
        pair.drive()
        pair.server.assertNoAccept()
        val client = pair.clientConn(clientCh)
        assertTrue(client.isClosed)
        val lost = client.poll() as Event.ConnectionLost
        assertEquals(TransportErrorCode.CONNECTION_REFUSED, (lost.reason as ConnectionError.ConnectionClosed).reason.errorCode)
        pair.drive()
        assertNull(pair.clientConn(clientCh).poll())
        assertEquals(0, pair.client.endpoint.knownConnections())
        assertEquals(0, pair.client.endpoint.knownCids())
        assertEquals(0, pair.server.endpoint.knownConnections())
        assertEquals(0, pair.server.endpoint.knownCids())
    }

    // mod.rs:4151
    @Test
    fun rejectShortIdcid() {
        val clientAddr = SocketAddress.of(ByteArray(16).also { it[15] = 2 }, 7890)
        val server = Endpoint(EndpointConfig.default(), serverConfig(), true)
        val buf = Buffer(server.config().getMaxUdpPayloadSize().toInt())
        // Initial header that has an empty DCID but is otherwise well-formed
        val initial = hex("c4 00000001 00 00 00 3f").copyOf(MIN_INITIAL_SIZE)
        assertIs<DatagramEvent.Response>(server.handle(TEST_EPOCH, clientAddr, null, null, initial, buf), "expected an initial close")
    }

    /**
     * Ensure that a connection can be made when a preferred address is advertised by the server, regardless of whether
     * the address is actually used (mod.rs:4172).
     */
    @Test
    fun preferredAddress() {
        val config = serverConfig().preferredAddressV6(localhostV6(65535))
        val pair = ConnPair.new(EndpointConfig.default(), config)
        pair.connect()
    }
}
