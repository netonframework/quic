package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

// quinn-proto `tests/mod.rs`, part 3: loss recovery, MTU discovery, ACK generation, ACK frequency, datagrams and
// segmentation offload batches.

private fun ByteArray.asBytes(): Bytes = Bytes.wrap(this)

private fun Datagrams.sendOk(data: ByteArray, drop: Boolean) {
    val e = send(data.asBytes(), drop)
    if (e != null) fail("datagram send failed: $e")
}

private fun assertBytes(expected: ByteArray, actual: Bytes?) {
    if (actual == null) fail("expected a datagram")
    assertContentEquals(expected, actual.toByteArray())
}

class ConnectionRecoveryTest {

    // Ensure we can recover from loss of tail packets when the congestion window is full (mod.rs:2162)
    @Test
    fun congestedTailLoss() {
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
        assertTrue(pair.server.inbound.isNotEmpty())
        pair.server.inbound.clear()
        // Ensure that the congestion state recovers after retransmits occur and are ACKed
        pair.drive()
        assertTrue(pair.clientConn(clientCh).congestionWindow() > target)
        pair.clientSend(clientCh, s).writeOk(ByteArray(1024) { 42 })
    }

    // Send a tail-loss probe when GSO segment_size is less than INITIAL_MTU (mod.rs:2187)
    @Test
    fun tailLossSmallSegmentSize() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        // No datagrams frames received in the handshake.
        assertEquals(0L, pair.serverConn(serverCh).stats().frameRx.datagram)

        val dgramLen = 1000 // Below INITIAL_MTU after packet overhead.
        val dgramNum = 5L // Enough to build a GSO batch.

        // Sending an ack-eliciting datagram
        pair.clientConn(clientCh).ping()
        pair.driveClient()

        // Drop these packets on the server side.
        assertTrue(pair.server.inbound.isNotEmpty())
        pair.server.inbound.clear()

        // Doing one step makes the client advance time to the PTO fire time.
        pair.step()

        // Still no datagrams frames received by the server.
        assertEquals(0L, pair.serverConn(serverCh).stats().frameRx.datagram)

        // Now we can send another batch of datagrams, so the PTO can send them instead of sending a ping. These are
        // small enough that the segment_size is less than the INITIAL_MTU.
        repeat(dgramNum.toInt()) { pair.clientDatagrams(clientCh).sendOk(ByteArray(dgramLen), false) }

        // If this succeeds the datagrams are received by the server and the client did not crash.
        pair.drive()

        // Finally the server should have received some datagrams.
        assertEquals(dgramNum, pair.serverConn(serverCh).stats().frameRx.datagram)
    }

    // Respect max_datagrams when TLP happens (mod.rs:2236)
    @Test
    fun tailLossRespectMaxDatagrams() {
        // Disabling GSO, so only a single segment should be sent per iops
        val clientConfig = clientConfig().transportConfig(TransportConfig().enableSegmentationOffload(false))
        val pair = ConnPair.default()
        val (clientCh, _) = pair.connectWith(clientConfig)

        val dgramLen = 1000 // High enough so GSO batch could be built
        val dgramNum = 5 // Enough to build a GSO batch.

        // Sending an ack-eliciting datagram
        pair.clientConn(clientCh).ping()
        pair.driveClient()

        // Drop these packets on the server side.
        assertTrue(pair.server.inbound.isNotEmpty())
        pair.server.inbound.clear()

        // Doing one step makes the client advance time to the PTO fire time.
        pair.step()

        // start sending datagram batches but the first should be a TLP
        repeat(dgramNum) { pair.clientDatagrams(clientCh).sendOk(ByteArray(dgramLen), false) }

        pair.drive()

        // Finally checking the number of sent udp datagrams match the number of iops
        val clientStats = pair.clientConn(clientCh).stats()
        assertEquals(clientStats.udpTx.ios, clientStats.udpTx.datagrams)
    }

    // mod.rs:2281
    @Test
    fun datagramSendRecv() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()
        assertNull(pair.serverConn(serverCh).poll())
        assertTrue((pair.clientDatagrams(clientCh).maxSize() ?: 0) > 0)

        val data = "whee".encodeToByteArray()
        pair.clientDatagrams(clientCh).sendOk(data, true)
        pair.drive()
        assertEquals(Event.DatagramReceived, pair.serverConn(serverCh).poll())
        assertBytes(data, pair.serverDatagrams(serverCh).recv())
        assertNull(pair.serverDatagrams(serverCh).recv())
    }

    // mod.rs:2302
    @Test
    fun datagramRecvBufferOverflow() {
        val payloadWindow = 100L
        val metadataWindow = 2 * DATAGRAM_OVERHEAD
        val window = payloadWindow + metadataWindow
        val server = serverConfig()
        // Account for exactly two datagrams of metadata space
        server.transport = TransportConfig().datagramReceiveBufferSize(window)
        val pair = ConnPair.new(EndpointConfig.default(), server)
        val (clientCh, serverCh) = pair.connect()
        assertNull(pair.serverConn(serverCh).poll())
        assertEquals((window - Frame.Datagram.SIZE_BOUND).toInt(), pair.clientConn(clientCh).datagrams().maxSize())

        val data1 = ByteArray((payloadWindow / 3 + 1).toInt()) { 0xAB.toByte() }
        val data2 = ByteArray((payloadWindow / 3 + 1).toInt()) { 0xBC.toByte() }
        val data3 = ByteArray((payloadWindow / 3 + 1).toInt()) { 0xCD.toByte() }
        pair.clientDatagrams(clientCh).sendOk(data1, true)
        pair.clientDatagrams(clientCh).sendOk(data2, true)
        pair.clientDatagrams(clientCh).sendOk(data3, true)
        pair.drive()
        assertEquals(Event.DatagramReceived, pair.serverConn(serverCh).poll())
        assertBytes(data2, pair.serverDatagrams(serverCh).recv())
        assertBytes(data3, pair.serverDatagrams(serverCh).recv())
        assertNull(pair.serverDatagrams(serverCh).recv())

        pair.clientDatagrams(clientCh).sendOk(data1, true)
        pair.drive()
        assertBytes(data1, pair.serverDatagrams(serverCh).recv())
        assertNull(pair.serverDatagrams(serverCh).recv())
    }

    // mod.rs:2353
    @Test
    fun datagramSendBufferOverflow() {
        val payloadWindow = 100L
        val window = payloadWindow + 2 * DATAGRAM_OVERHEAD
        val clientConfig = clientConfig().transportConfig(TransportConfig().datagramSendBufferSize(window))
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connectWith(clientConfig)
        assertNull(pair.serverConn(serverCh).poll())

        // Keep the send buffer full so most sends evict the oldest queued datagram; `payload_bytes` bookkeeping must
        // survive sustained eviction
        val len = (payloadWindow / 3 + 1).toInt()
        for (i in 0 until 10) pair.clientDatagrams(clientCh).sendOk(ByteArray(len) { i.toByte() }, true)
        pair.drive()

        assertEquals(Event.DatagramReceived, pair.serverConn(serverCh).poll())
        // The window holds two datagrams, including their metadata.
        for (i in 8 until 10) assertBytes(ByteArray(len) { i.toByte() }, pair.serverDatagrams(serverCh).recv())
        assertNull(pair.serverDatagrams(serverCh).recv())
    }

    // mod.rs:2394
    @Test
    fun datagramSendBufferSpacePreservesQueuedDatagrams() {
        val pair = ConnPair.default()
        val clientConfig = clientConfig().transportConfig(TransportConfig().datagramSendBufferSize(100 + 3 * DATAGRAM_OVERHEAD))
        val (clientCh, serverCh) = pair.connectWith(clientConfig)

        val first = ByteArray(7) { 1 }
        val second = ByteArray(2) { 2 }
        for (data in listOf(first, second)) pair.clientDatagrams(clientCh).sendOk(data, true)
        val available = pair.clientDatagrams(clientCh).sendBufferSpace()
        assertTrue(available > 0)
        val third = ByteArray(available.toInt()) { 3 }
        pair.clientDatagrams(clientCh).sendOk(third, true)
        pair.drive()

        for (data in listOf(first, second, third)) assertBytes(data, pair.serverDatagrams(serverCh).recv())
        assertNull(pair.serverDatagrams(serverCh).recv())
    }

    // mod.rs:2425
    @Test
    fun datagramLargerThanSendBufferIsTooLarge() {
        val pair = ConnPair.default()
        val clientConfig = clientConfig().transportConfig(TransportConfig().datagramSendBufferSize(1 + DATAGRAM_OVERHEAD))
        val (clientCh, _) = pair.connectWith(clientConfig)

        assertEquals(SendDatagramError.TooLarge, pair.clientDatagrams(clientCh).send(ByteArray(2).asBytes(), true))
        assertEquals(SendDatagramError.TooLarge, pair.clientDatagrams(clientCh).send(ByteArray(2).asBytes(), false))
    }

    // mod.rs:2447
    @Test
    fun datagramSendBufferMetadataBoundaries() {
        for (window in listOf(0L, DATAGRAM_OVERHEAD - 1, DATAGRAM_OVERHEAD, DATAGRAM_OVERHEAD + 1)) {
            for (drop in listOf(true, false)) {
                val pair = ConnPair.default()
                val clientConfig = clientConfig().transportConfig(TransportConfig().datagramSendBufferSize(window))
                val (clientCh, serverCh) = pair.connectWith(clientConfig)

                val payloadCapacity = window - DATAGRAM_OVERHEAD
                if (payloadCapacity < 0) {
                    assertEquals(SendDatagramError.TooLarge, pair.clientDatagrams(clientCh).send(Bytes.EMPTY, drop))
                    continue
                }

                // An exact fit succeeds, and rejecting a larger datagram preserves the queued one.
                val data = ByteArray(payloadCapacity.toInt()) { 0xAB.toByte() }
                pair.clientDatagrams(clientCh).sendOk(data, drop)
                assertEquals(
                    SendDatagramError.TooLarge,
                    pair.clientDatagrams(clientCh).send(ByteArray(payloadCapacity.toInt() + 1).asBytes(), drop),
                )
                pair.drive()
                assertBytes(data, pair.serverDatagrams(serverCh).recv())
                assertNull(pair.serverDatagrams(serverCh).recv())
            }
        }
    }

    // mod.rs:2489
    @Test
    fun datagramSendBufferBlocksUntilDrained() {
        val len = 4
        val pair = ConnPair.default()
        val clientConfig = clientConfig().transportConfig(TransportConfig().datagramSendBufferSize(2 * (len + DATAGRAM_OVERHEAD)))
        val (clientCh, serverCh) = pair.connectWith(clientConfig)

        for (i in 0 until 2) pair.clientDatagrams(clientCh).sendOk(ByteArray(len) { i.toByte() }, false)
        val data = ByteArray(len) { 2 }
        val blocked = pair.clientDatagrams(clientCh).send(data.asBytes(), false)
        assertIs<SendDatagramError.Blocked>(blocked)
        assertContentEquals(data, blocked.data.toByteArray())
        pair.drive()
        for (i in 0 until 2) assertBytes(ByteArray(len) { i.toByte() }, pair.serverDatagrams(serverCh).recv())
        assertNull(pair.serverDatagrams(serverCh).recv())

        pair.clientDatagrams(clientCh).sendOk(data, false)
        pair.drive()
        assertBytes(data, pair.serverDatagrams(serverCh).recv())
        assertNull(pair.serverDatagrams(serverCh).recv())
    }

    // mod.rs:2527
    @Test
    fun datagramUnsupported() {
        val server = serverConfig()
        server.transport = TransportConfig().datagramReceiveBufferSize(null)
        val pair = ConnPair.new(EndpointConfig.default(), server)
        val (clientCh, serverCh) = pair.connect()
        assertNull(pair.serverConn(serverCh).poll())
        assertNull(pair.clientDatagrams(clientCh).maxSize())

        assertEquals(SendDatagramError.UnsupportedByPeer, pair.clientDatagrams(clientCh).send(Bytes.EMPTY, true))
    }

    // mod.rs:2831
    @Test
    fun lossProbeRequestsImmediateAck() {
        val pair = ConnPair.default()
        val (clientCh, _) = pair.connect()
        pair.drive()

        val statsAfterConnect = pair.clientConn(clientCh).stats()

        // Lose a ping
        val defaultMtu = pair.mtu
        pair.mtu = 0
        pair.clientConn(clientCh).ping()
        pair.driveClient()
        pair.mtu = defaultMtu

        // Drive the connection further so a loss probe is sent
        pair.drive()

        // Assert that two IMMEDIATE_ACKs were sent (two loss probes)
        val statsAfterRecovery = pair.clientConn(clientCh).stats()
        assertEquals(2L, statsAfterRecovery.frameTx.immediateAck - statsAfterConnect.frameTx.immediateAck)
    }

    // mod.rs:2872
    @Test
    fun connectLostMtuProbesDoNotTriggerCongestionControl() {
        val pair = ConnPair.default()
        pair.mtu = 1200

        val (clientCh, serverCh) = pair.connect()
        pair.drive()

        val clientStats = pair.clientConn(clientCh).stats()
        val serverStats = pair.serverConn(serverCh).stats()

        // Sanity check (all MTU probes should have been lost)
        assertEquals(9L, clientStats.path.sentPlpmtudProbes)
        assertEquals(9L, clientStats.path.lostPlpmtudProbes)
        assertEquals(9L, serverStats.path.sentPlpmtudProbes)
        assertEquals(9L, serverStats.path.lostPlpmtudProbes)

        // No congestion events
        assertEquals(0L, clientStats.path.congestionEvents)
        assertEquals(0L, serverStats.path.congestionEvents)
    }

    // mod.rs:2895
    @Test
    fun connectDetectsMtu() {
        for ((pairMaxUdp, expectedMtu) in listOf(1200 to 1200, 1400 to 1389, 1500 to 1452)) {
            val pair = ConnPair.default()
            pair.mtu = pairMaxUdp
            val (clientCh, serverCh) = pair.connect()
            pair.drive()

            assertEquals(expectedMtu, pair.clientConn(clientCh).pathMtu())
            assertEquals(expectedMtu, pair.serverConn(serverCh).pathMtu())
        }
    }

    // mod.rs:2911
    @Test
    fun migrateDetectsNewMtuAndRespectsOriginalPeerMaxUdpPayloadSize() {
        val clientMaxUdpPayloadSize = 1400

        // Set up a client with a max payload size of 1400 (and use the defaults for the server)
        val server = Endpoint(EndpointConfig.default(), serverConfig(), true)
        val client = Endpoint(EndpointConfig.default().maxUdpPayloadSize(clientMaxUdpPayloadSize), null, true)
        val pair = ConnPair.newFromEndpoint(client, server)
        pair.mtu = 1300

        // Connect
        val (clientCh, serverCh) = pair.connect()
        pair.drive()

        // Sanity check: MTUD ran to completion (the numbers differ because binary search stops when changes are
        // smaller than 20, otherwise both endpoints would converge at the same MTU of 1300)
        assertEquals(1293, pair.clientConn(clientCh).pathMtu())
        assertEquals(1300, pair.serverConn(serverCh).pathMtu())

        // Migrate client to a different port (and simulate a higher path MTU)
        pair.mtu = 1500
        pair.client.addr = neton.io.net.SocketAddress.ipv4(127, 0, 0, 1, nextClientPort())
        pair.clientConn(clientCh).ping()
        pair.drive()

        // Sanity check: the server saw that the client address was updated
        assertEquals(pair.client.addr, pair.serverConn(serverCh).remoteAddress())

        // MTU detection has successfully run after migrating
        assertEquals(clientMaxUdpPayloadSize, pair.serverConn(serverCh).pathMtu())

        // Sanity check: the client keeps the old MTU, because migration is triggered by incoming packets from a
        // different address
        assertEquals(1293, pair.clientConn(clientCh).pathMtu())
    }

    // mod.rs:2968
    @Test
    fun connectRunsMtudAgainAfter600Seconds() {
        val serverConfig = serverConfig()
        val clientConfig = clientConfig()

        // Note: we use an infinite idle timeout to ensure we can wait 600 seconds without the connection closing
        serverConfig.transport.maxIdleTimeout(null)
        clientConfig.transport.maxIdleTimeout(null)

        val pair = ConnPair.new(EndpointConfig.default(), serverConfig)
        pair.mtu = 1400
        val (clientCh, serverCh) = pair.connectWith(clientConfig)
        pair.drive()

        // Sanity check: the mtu has been discovered
        val clientConn = pair.clientConn(clientCh)
        assertEquals(1389, clientConn.pathMtu())
        assertEquals(5L, clientConn.stats().path.sentPlpmtudProbes)
        assertEquals(3L, clientConn.stats().path.lostPlpmtudProbes)
        val serverConn = pair.serverConn(serverCh)
        assertEquals(1389, serverConn.pathMtu())
        assertEquals(5L, serverConn.stats().path.sentPlpmtudProbes)
        assertEquals(3L, serverConn.stats().path.lostPlpmtudProbes)

        // Sanity check: the mtu does not change after the fact, even though the link now supports a higher udp
        // payload size
        pair.mtu = 1500
        pair.drive()
        assertEquals(1389, pair.clientConn(clientCh).pathMtu())
        assertEquals(1389, pair.serverConn(serverCh).pathMtu())

        // The MTU changes after 600 seconds, because now MTUD runs for the second time
        pair.time += 600.seconds
        pair.drive()
        assertFalse(pair.clientConn(clientCh).isClosed)
        assertFalse(pair.serverConn(serverCh).isClosed)
        assertEquals(1452, pair.clientConn(clientCh).pathMtu())
        assertEquals(1452, pair.serverConn(serverCh).pathMtu())
    }

    // mod.rs:3014
    @Test
    fun blackholeAfterMtuChangeRepairsItself() {
        val pair = ConnPair.default()
        pair.mtu = 1500
        val (clientCh, serverCh) = pair.connect()
        pair.drive()

        // Sanity check
        assertEquals(1452, pair.clientConn(clientCh).pathMtu())
        assertEquals(1452, pair.serverConn(serverCh).pathMtu())

        // Back to the base MTU
        pair.mtu = 1200

        // The payload will be sent in a single packet, because the detected MTU was 1444, but it will be dropped
        // because the link no longer supports that packet size!
        val payload = ByteArray(1300) { 42 }
        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        pair.clientSend(clientCh, s).writeOk(payload)
        val outOfBounds = pair.driveBounded()

        if (outOfBounds) fail("Connections never reached an idle state")

        val buf = streamChunks(pair.serverRecv(serverCh, s))

        // The whole packet arrived in the end
        assertEquals(1300, buf.size)

        // Sanity checks (black hole detected after 3 lost packets)
        val clientStats = pair.clientConn(clientCh).stats()
        assertTrue(clientStats.path.lostPackets >= 3)
        assertTrue(clientStats.path.congestionEvents >= 3)
        assertEquals(1L, clientStats.path.blackHolesDetected)
    }

    // mod.rs:3053
    @Test
    fun mtudProbesIncludeImmediateAck() {
        val pair = ConnPair.default()
        val (clientCh, _) = pair.connect()
        pair.drive()

        val stats = pair.clientConn(clientCh).stats()
        assertEquals(4L, stats.path.sentPlpmtudProbes)

        // Each probe contains a ping and an immediate ack
        assertEquals(4L, stats.frameTx.ping)
        assertEquals(4L, stats.frameTx.immediateAck)
    }

    // mod.rs:3068
    @Test
    fun packetSplittingWithDefaultMtu() {
        // The payload needs to be split in 2 in order to be sent, because it is higher than the max MTU
        val payload = ByteArray(1300) { 42 }

        val pair = ConnPair.default()
        pair.mtu = 1200
        val (clientCh, _) = pair.connect()
        pair.drive()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!

        pair.clientSend(clientCh, s).writeOk(payload)
        pair.client.drive(pair.time, pair.server.addr)
        assertEquals(2, pair.client.outbound.size)

        pair.driveClient()
        assertEquals(2, pair.server.inbound.size)
    }

    // mod.rs:3090
    @Test
    fun packetSplittingNotNecessaryAfterHigherMtuDiscovered() {
        val payload = ByteArray(1300) { 42 }

        val pair = ConnPair.default()
        pair.mtu = 1500

        val (clientCh, _) = pair.connect()
        pair.drive()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!

        pair.clientSend(clientCh, s).writeOk(payload)
        pair.client.drive(pair.time, pair.server.addr)
        assertEquals(1, pair.client.outbound.size)

        pair.driveClient()
        assertEquals(1, pair.server.inbound.size)
    }

    // mod.rs:3111
    @Test
    fun singleAckElicitingPacketTriggersAckAfterDelay() {
        val pair = ConnPair.defaultWithDeterministicPns()
        val (clientCh, _) = pair.connectWith(clientConfigWithDeterministicPns())
        pair.drive()

        val statsAfterConnect = pair.clientConn(clientCh).stats()

        val start = pair.time
        pair.clientConn(clientCh).ping()
        pair.driveClient() // Send ping
        pair.driveServer() // Process ping
        pair.driveClient() // Give the client a chance to process an ack, so our assertion can fail

        // Sanity check: the time hasn't advanced in the meantime)
        assertEquals(start, pair.time)

        val statsAfterPing = pair.clientConn(clientCh).stats()
        assertEquals(1L, statsAfterPing.frameTx.ping - statsAfterConnect.frameTx.ping)
        assertEquals(0L, statsAfterPing.frameRx.acks - statsAfterConnect.frameRx.acks)

        pair.client.captureInboundPackets = true
        pair.drive()
        val statsAfterDrive = pair.clientConn(clientCh).stats()
        assertEquals(1L, statsAfterDrive.frameRx.acks - statsAfterPing.frameRx.acks)

        // The time is start + max_ack_delay
        val defaultMaxAckDelayMs = TransportParameters.default().maxAckDelay.value
        assertEquals(start + defaultMaxAckDelayMs.milliseconds, pair.time)

        // The ACK delay is properly calculated
        assertEquals(1, pair.client.capturedPackets.size)
        val frames = FrameIter(pair.client.capturedPackets.removeAt(0)).asSequence().toList()
        assertEquals(1, frames.size)
        val ack = frames[0] as? Frame.Ack ?: fail("Expected ACK frame")
        val ackDelayExp = TransportParameters.default().ackDelayExponent
        val delay = ack.delay shl ackDelayExp.value.toInt()
        assertEquals(defaultMaxAckDelayMs * 1000, delay)

        // Sanity check: no loss probe was sent, because the delayed ACK was received on time
        assertEquals(1L, statsAfterDrive.frameTx.ping - statsAfterConnect.frameTx.ping)
    }

    // mod.rs:3176
    @Test
    fun immediateAckTriggersAck() {
        val pair = ConnPair.defaultWithDeterministicPns()
        val (clientCh, _) = pair.connectWith(clientConfigWithDeterministicPns())
        pair.drive()

        val acksAfterConnect = pair.clientConn(clientCh).stats().frameRx.acks

        pair.clientConn(clientCh).immediateAck()
        pair.driveClient() // Send immediate ack
        pair.driveServer() // Process immediate ack
        pair.driveClient() // Give the client a chance to process the ack

        val acksAfterPing = pair.clientConn(clientCh).stats().frameRx.acks

        assertEquals(1L, acksAfterPing - acksAfterConnect)
    }

    // mod.rs:3195
    @Test
    fun outOfOrderAckElicitingPacketTriggersAck() {
        val pair = ConnPair.defaultWithDeterministicPns()
        val (clientCh, serverCh) = pair.connectWith(clientConfigWithDeterministicPns())
        pair.drive()

        val defaultMtu = pair.mtu

        val clientStatsAfterConnect = pair.clientConn(clientCh).stats()
        val serverStatsAfterConnect = pair.serverConn(serverCh).stats()

        // Send a packet that won't arrive right away (it will be dropped and be re-sent later)
        pair.mtu = 0
        pair.clientConn(clientCh).ping()
        pair.driveClient()

        // Sanity check (ping sent, no ACK received)
        val clientStatsAfterFirstPing = pair.clientConn(clientCh).stats()
        assertEquals(1L, clientStatsAfterFirstPing.frameTx.ping - clientStatsAfterConnect.frameTx.ping)
        assertEquals(0L, clientStatsAfterFirstPing.frameRx.acks - clientStatsAfterConnect.frameRx.acks)

        // Restore the default MTU and send another ping, which will arrive earlier than the dropped one
        pair.mtu = defaultMtu
        pair.clientConn(clientCh).ping()
        pair.driveClient()
        pair.driveServer()
        pair.driveClient()

        // Client sanity check (ping sent, one ACK received)
        val clientStatsAfterSecondPing = pair.clientConn(clientCh).stats()
        assertEquals(2L, clientStatsAfterSecondPing.frameTx.ping - clientStatsAfterConnect.frameTx.ping)
        assertEquals(1L, clientStatsAfterSecondPing.frameRx.acks - clientStatsAfterConnect.frameRx.acks)

        // Server checks (single ping received, ACK sent)
        val serverStatsAfterSecondPing = pair.serverConn(serverCh).stats()
        assertEquals(1L, serverStatsAfterSecondPing.frameRx.ping - serverStatsAfterConnect.frameRx.ping)
        assertEquals(1L, serverStatsAfterSecondPing.frameTx.acks - serverStatsAfterConnect.frameTx.acks)
    }

    // mod.rs:3253
    @Test
    fun singleAckElicitingPacketWithCeBitTriggersImmediateAck() {
        val pair = ConnPair.defaultWithDeterministicPns()
        val (clientCh, _) = pair.connectWith(clientConfigWithDeterministicPns())
        pair.drive()

        val statsAfterConnect = pair.clientConn(clientCh).stats()

        val start = pair.time

        pair.clientConn(clientCh).ping()

        pair.congestionExperienced = true
        pair.driveClient() // Send ping
        pair.congestionExperienced = false

        pair.driveServer() // Process ping, send ACK in response to congestion
        pair.driveClient() // Process ACK

        // Sanity check: the time hasn't advanced in the meantime)
        assertEquals(start, pair.time)

        val statsAfterPing = pair.clientConn(clientCh).stats()
        assertEquals(1L, statsAfterPing.frameTx.ping - statsAfterConnect.frameTx.ping)
        assertEquals(1L, statsAfterPing.frameRx.acks - statsAfterConnect.frameRx.acks)
        assertEquals(1L, statsAfterPing.path.congestionEvents - statsAfterConnect.path.congestionEvents)
    }

    private fun setupAckFrequencyTest(maxAckDelay: Duration): Triple<ConnPair, ConnectionHandle, ConnectionHandle> {
        val clientConfig = clientConfigWithDeterministicPns()
        clientConfig.transport
            .ackFrequencyConfig(AckFrequencyConfig().ackElicitingThreshold(VarInt(10)).maxAckDelay(maxAckDelay))
            .mtuDiscoveryConfig(null) // To keep traffic cleaner

        val pair = ConnPair.defaultWithDeterministicPns()
        pair.latency = 10.milliseconds // Need latency to avoid an RTT = 0
        val (clientCh, serverCh) = pair.connectWith(clientConfig)
        pair.drive()

        assertEquals(1L, pair.clientConn(clientCh).stats().frameTx.ackFrequency)
        assertEquals(0L, pair.clientConn(clientCh).stats().frameTx.ping)
        return Triple(pair, clientCh, serverCh)
    }

    /** Server stats deltas across [block]. */
    private inline fun ConnPair.serverDelta(serverCh: ConnectionHandle, block: () -> Unit): Pair<ConnectionStats, ConnectionStats> {
        val before = serverConn(serverCh).stats()
        block()
        return before to serverConn(serverCh).stats()
    }

    /** Verify that max ACK delay is counted from the first ACK-eliciting packet (mod.rs:3318). */
    @Test
    fun ackFrequencyAckDelayedFromFirstOfFlight() {
        val (pair, clientCh, serverCh) = setupAckFrequencyTest(30.milliseconds)

        // The client sends the following frames:
        //
        // * 0 ms: ping
        // * 5 ms: ping x2
        pair.clientConn(clientCh).ping()
        pair.driveClient()

        pair.time += 5.milliseconds
        repeat(2) {
            pair.clientConn(clientCh).ping()
            pair.driveClient()
        }

        pair.time += 5.milliseconds
        // Server: receive the first ping and send no ACK
        var (before, after) = pair.serverDelta(serverCh) { pair.driveServer() }
        assertEquals(1L, after.frameRx.ping - before.frameRx.ping)
        assertEquals(0L, after.frameTx.acks - before.frameTx.acks)

        // Server: receive the second and third pings and send no ACK
        pair.time += 10.milliseconds
        pair.serverDelta(serverCh) { pair.driveServer() }.let { before = it.first; after = it.second }
        assertEquals(2L, after.frameRx.ping - before.frameRx.ping)
        assertEquals(0L, after.frameTx.acks - before.frameTx.acks)

        // Server: Send an ACK after ACK delay expires
        pair.time += 20.milliseconds
        pair.serverDelta(serverCh) { pair.driveServer() }.let { before = it.first; after = it.second }
        assertEquals(1L, after.frameTx.acks - before.frameTx.acks)
    }

    // mod.rs:3376
    @Test
    fun ackFrequencyAckSentAfterMaxAckDelay() {
        val maxAckDelay = 30.milliseconds
        val (pair, clientCh, serverCh) = setupAckFrequencyTest(maxAckDelay)

        // Client sends a ping
        pair.clientConn(clientCh).ping()
        pair.driveClient()

        // Server: receive the ping, send no ACK
        pair.time += pair.latency
        var (before, after) = pair.serverDelta(serverCh) { pair.driveServer() }
        assertEquals(1L, after.frameRx.ping - before.frameRx.ping)
        assertEquals(0L, after.frameTx.acks - before.frameTx.acks)

        // Server: send an ack after max_ack_delay has elapsed
        pair.time += maxAckDelay
        pair.serverDelta(serverCh) { pair.driveServer() }.let { before = it.first; after = it.second }
        assertEquals(0L, after.frameRx.ping - before.frameRx.ping)
        assertEquals(1L, after.frameTx.acks - before.frameTx.acks)
    }

    // mod.rs:3415
    @Test
    fun ackFrequencyAckSentAfterPacketsAboveThreshold() {
        val maxAckDelay = 30.milliseconds
        val (pair, clientCh, serverCh) = setupAckFrequencyTest(maxAckDelay)

        // The client sends the following frames:
        //
        // * 0 ms: ping
        // * 5 ms: ping (11x)
        pair.clientConn(clientCh).ping()
        pair.driveClient()

        pair.time += 5.milliseconds
        repeat(11) {
            pair.clientConn(clientCh).ping()
            pair.driveClient()
        }

        // Server: receive the first ping, send no ACK
        pair.time += 5.milliseconds
        var (before, after) = pair.serverDelta(serverCh) { pair.driveServer() }
        assertEquals(1L, after.frameRx.ping - before.frameRx.ping)
        assertEquals(0L, after.frameTx.acks - before.frameTx.acks)

        // Server: receive the remaining pings, send ACK
        pair.time += 5.milliseconds
        pair.serverDelta(serverCh) { pair.driveServer() }.let { before = it.first; after = it.second }
        assertEquals(11L, after.frameRx.ping - before.frameRx.ping)
        assertEquals(1L, after.frameTx.acks - before.frameTx.acks)
    }

    // mod.rs:3463
    @Test
    fun ackFrequencyAckSentAfterReorderedPacketsBelowThreshold() {
        val maxAckDelay = 30.milliseconds
        val (pair, clientCh, serverCh) = setupAckFrequencyTest(maxAckDelay)

        // The client sends the following frames:
        //
        // * 0 ms: ping
        // * 5 ms: ping (lost)
        // * 5 ms: ping
        pair.clientConn(clientCh).ping()
        pair.driveClient()

        pair.time += 5.milliseconds

        // Send and lose an ack-eliciting packet
        pair.mtu = 0
        pair.clientConn(clientCh).ping()
        pair.driveClient()

        // Restore the default MTU and send another ping, which will arrive earlier than the dropped one
        pair.mtu = DEFAULT_MTU
        pair.clientConn(clientCh).ping()
        pair.driveClient()

        // Server: receive first ping, send no ACK
        pair.time += 5.milliseconds
        var (before, after) = pair.serverDelta(serverCh) { pair.driveServer() }
        assertEquals(1L, after.frameRx.ping - before.frameRx.ping)
        assertEquals(0L, after.frameTx.acks - before.frameTx.acks)

        // Server: receive second ping, send no ACK
        pair.time += 5.milliseconds
        pair.serverDelta(serverCh) { pair.driveServer() }.let { before = it.first; after = it.second }
        assertEquals(1L, after.frameRx.ping - before.frameRx.ping)
        assertEquals(0L, after.frameTx.acks - before.frameTx.acks)
    }

    // mod.rs:3518
    @Test
    fun ackFrequencyAckSentAfterReorderedPacketsAboveThreshold() {
        val maxAckDelay = 30.milliseconds
        val (pair, clientCh, serverCh) = setupAckFrequencyTest(maxAckDelay)

        // Send a ping
        pair.clientConn(clientCh).ping()
        pair.driveClient()

        // Send and lose two ack-eliciting packets
        pair.time += 5.milliseconds
        pair.mtu = 0
        repeat(2) {
            pair.clientConn(clientCh).ping()
            pair.driveClient()
        }

        // Restore the default MTU and send another ping, which will arrive earlier than the dropped ones
        pair.mtu = DEFAULT_MTU
        pair.clientConn(clientCh).ping()
        pair.driveClient()

        // Server: receive first ping, send no ACK
        pair.time += 5.milliseconds
        var (before, after) = pair.serverDelta(serverCh) { pair.driveServer() }
        assertEquals(1L, after.frameRx.ping - before.frameRx.ping)
        assertEquals(0L, after.frameTx.acks - before.frameTx.acks)

        // Server: receive remaining ping, send ACK
        pair.time += 5.milliseconds
        pair.serverDelta(serverCh) { pair.driveServer() }.let { before = it.first; after = it.second }
        assertEquals(1L, after.frameRx.ping - before.frameRx.ping)
        assertEquals(1L, after.frameTx.acks - before.frameTx.acks)
    }

    // mod.rs:3570
    @Test
    fun ackFrequencyUpdateMaxDelay() {
        val (pair, clientCh, serverCh) = setupAckFrequencyTest(200.milliseconds)

        // Ack frequency was sent initially
        assertEquals(1L, pair.serverConn(serverCh).stats().frameRx.ackFrequency)

        // Client sends a PING
        pair.clientConn(clientCh).ping()
        pair.drive()

        // No change in ACK frequency
        assertEquals(1L, pair.serverConn(serverCh).stats().frameRx.ackFrequency)

        // RTT jumps, client sends another ping
        pair.latency *= 10
        pair.clientConn(clientCh).ping()
        pair.drive()

        // ACK frequency updated
        assertTrue(pair.serverConn(serverCh).stats().frameRx.ackFrequency >= 2)
    }

    /**
     * Verify that an endpoint which receives but does not send ACK-eliciting data still receives ACKs occasionally.
     * This is not required for conformance, but makes loss detection more responsive and reduces receiver memory use
     * (mod.rs:3627).
     */
    @Test
    fun pureSenderVoluntarilyAcks() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        val receiverAcksInitial = pair.serverConn(serverCh).stats().frameRx.acks

        val msg = "hello".encodeToByteArray()
        repeat(100) {
            pair.clientDatagrams(clientCh).sendOk(msg, true)
            pair.drive()
            assertBytes(msg, pair.serverDatagrams(serverCh).recv())
        }

        val receiverAcksFinal = pair.serverConn(serverCh).stats().frameRx.acks
        assertTrue(receiverAcksFinal > receiverAcksInitial)
    }

    // mod.rs:3741
    @Test
    fun streamGso() {
        val pair = ConnPair.default()
        val (clientCh, _) = pair.connect()

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!

        val initialIos = pair.clientConn(clientCh).stats().udpTx.ios

        // Send 20KiB of stream data, which comfortably fits inside two `MAX_DATAGRAMS` datagram batches
        repeat(20) { pair.clientSend(clientCh, s).writeOk(ByteArray(1024)) }
        pair.clientSend(clientCh, s).finish()
        pair.drive()
        val finalIos = pair.clientConn(clientCh).stats().udpTx.ios
        assertEquals(2L, finalIos - initialIos)
    }

    // mod.rs:3763
    @Test
    fun datagramGso() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        // Sending ack-eliciting packet from server let client send ACK, which prevents sending bundled ACK for a
        // while.
        pair.serverDatagrams(serverCh).sendOk(ByteArray(0), false)
        pair.drive()

        val initialIos = pair.clientConn(clientCh).stats().udpTx.ios
        val initialBytes = pair.clientConn(clientCh).stats().udpTx.bytes

        // Send 10 datagrams above half the MTU, which fits inside a `MAX_DATAGRAMS` datagram batch
        val datagramLen = 1024
        val datagrams = 10
        repeat(datagrams) { pair.clientDatagrams(clientCh).sendOk(ByteArray(datagramLen), false) }
        pair.drive()
        val finalIos = pair.clientConn(clientCh).stats().udpTx.ios
        val finalBytes = pair.clientConn(clientCh).stats().udpTx.bytes
        assertEquals(1L, finalIos - initialIos)
        // Expected overhead: flags + CID + PN + tag + frame type + frame length = 1 + 8 + 1 + 16 + 1 + 2 = 29
        assertEquals(((29 + datagramLen) * datagrams).toLong(), finalBytes - initialBytes)
    }

    // mod.rs:3800
    @Test
    fun gsoTruncation() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        val initialIos = pair.clientConn(clientCh).stats().udpTx.ios

        // Send three application datagrams such that each is large to be combined with another in a single MTU, and
        // the second datagram would require an unreasonably large amount of padding to produce a QUIC packet of the
        // same length as the first.
        val sizes = intArrayOf(1024, 768, 768)
        for (len in sizes) pair.clientDatagrams(clientCh).sendOk(ByteArray(len), false)
        pair.drive()
        val finalIos = pair.clientConn(clientCh).stats().udpTx.ios
        assertEquals(2L, finalIos - initialIos)
        for (len in sizes) {
            assertEquals(len, (pair.serverDatagrams(serverCh).recv() ?: fail("datagram lost")).size)
        }
    }

    /** Verify that UDP datagrams are padded to MTU if specified in the transport config (mod.rs:3832). */
    @Test
    fun padToMtu() {
        val mtu = 1333
        val clientConfig = clientConfig().transportConfig(
            TransportConfig().initialMtu(mtu).mtuDiscoveryConfig(null).padToMtu(true),
        )
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connectWith(clientConfig)

        val initialIos = pair.clientConn(clientCh).stats().udpTx.ios
        pair.server.captureInboundPackets = true

        // Send two datagrams significantly smaller than MTU, but large enough to require two UDP datagrams.
        val len1 = 800
        val len2 = 600
        pair.clientDatagrams(clientCh).sendOk(ByteArray(len1), false)
        pair.clientDatagrams(clientCh).sendOk(ByteArray(len2), false)
        pair.client.drive(pair.time, pair.server.addr)

        // Check padding
        assertEquals(2, pair.client.outbound.size)
        assertEquals(mtu, pair.client.outbound[0].transmit.size)
        assertEquals(mtu, pair.client.outbound[0].data.size)
        assertEquals(mtu, pair.client.outbound[1].transmit.size)
        assertEquals(mtu, pair.client.outbound[1].data.size)
        pair.driveClient()
        assertEquals(2, pair.server.inbound.size)
        assertEquals(mtu, pair.server.inbound[0].data.size)
        assertEquals(mtu, pair.server.inbound[1].data.size)
        pair.drive()

        // Check that both datagrams ended up in the same GSO batch
        val finalIos = pair.clientConn(clientCh).stats().udpTx.ios
        assertEquals(1L, finalIos - initialIos)

        assertEquals(len1, (pair.serverDatagrams(serverCh).recv() ?: fail("datagram lost")).size)
        assertEquals(len2, (pair.serverDatagrams(serverCh).recv() ?: fail("datagram lost")).size)
    }

    /**
     * Verify that a large application datagram is sent successfully when an ACK frame too large to fit alongside it
     * is also queued, in exactly 2 UDP datagrams (mod.rs:3898).
     */
    @Test
    fun largeDatagramWithAcks() {
        val pair = ConnPair.default()
        val (clientCh, serverCh) = pair.connect()

        // Force the client to generate a large ACK frame by dropping several packets
        repeat(10) {
            pair.serverConn(serverCh).ping()
            pair.driveServer()
            pair.client.inbound.removeLastOrNull()
            pair.serverConn(serverCh).ping()
            pair.driveServer()
        }

        val maxSize = pair.clientDatagrams(clientCh).maxSize()!!
        val msg = ByteArray(maxSize)
        pair.clientDatagrams(clientCh).sendOk(msg, true)
        val initialDatagrams = pair.clientConn(clientCh).stats().udpTx.datagrams
        pair.drive()
        val finalDatagrams = pair.clientConn(clientCh).stats().udpTx.datagrams
        assertBytes(msg, pair.serverDatagrams(serverCh).recv())
        assertEquals(2L, finalDatagrams - initialDatagrams)
    }

    /**
     * Verify that an ACK prompted by receipt of many non-ACK-eliciting packets is sent alongside outgoing application
     * datagrams too large to coexist in the same packet with it (mod.rs:3927).
     */
    @Test
    fun voluntaryAckWithLargeDatagrams() {
        val pair = ConnPair.default()
        val (clientCh, _) = pair.connect()

        // Prompt many large ACKs from the server
        val initialDatagrams = pair.clientConn(clientCh).stats().udpTx.datagrams
        // Send enough packets that we're confident some packet numbers will be skipped, ensuring that larger ACKs
        // occur
        val count = 256
        repeat(count) {
            val maxSize = pair.clientDatagrams(clientCh).maxSize()!!
            pair.clientDatagrams(clientCh).sendOk(ByteArray(maxSize), true)
            pair.drive()
        }
        val finalDatagrams = pair.clientConn(clientCh).stats().udpTx.datagrams
        // Failure may indicate `max_size` is too small and ACKs are reliably being packed into the same datagram, which
        // is reasonable behavior but makes this test ineffective.
        assertNotEquals(count.toLong(), finalDatagrams - initialDatagrams, "client should have sent some ACK-only packets")
    }

    // mod.rs:3957
    @Test
    fun pathChangesUnblockOversizedDatagrams() {
        for (migrate in listOf(false, true)) {
            val pair = ConnPair.default()
            val (clientCh, serverCh) = pair.connect()
            pair.drive()
            val oldMax = pair.serverDatagrams(serverCh).maxSize()!!
            assertTrue(oldMax > 1200)
            val emptySpace = pair.serverDatagrams(serverCh).sendBufferSpace()
            val data = ByteArray(oldMax) { 42 }
            while (true) {
                when (val e = pair.serverDatagrams(serverCh).send(data.asBytes(), false)) {
                    null -> {}
                    is SendDatagramError.Blocked -> break
                    else -> fail("unexpected send error: $e")
                }
            }
            pair.serverConn(serverCh).drainEvents()

            pair.mtu = 1200
            if (migrate) {
                pair.client.addr = localhostV6(nextClientPort())
                pair.clientConn(clientCh).ping()
                pair.driveClient()
                // Process migration without transmitting, so sends cannot free the buffer first.
                val buf = Buffer(1500)
                while (true) {
                    val (received, ecn, packet) = pair.server.inbound.removeFirstOrNull() ?: break
                    val event = pair.server.endpoint.handle(received, pair.client.addr, null, ecn, packet, buf)
                        as? DatagramEvent.ConnectionEvent ?: fail("expected a connection event")
                    assertEquals(serverCh, event.ch)
                    pair.serverConn(event.ch).handleEvent(event.event)
                }
                assertEquals(pair.client.addr, pair.serverConn(serverCh).remoteAddress())
            } else {
                pair.serverConn(serverCh).pathChanged(pair.time)
            }

            assertTrue(pair.serverDatagrams(serverCh).maxSize()!! < oldMax)
            assertEquals(emptySpace, pair.serverDatagrams(serverCh).sendBufferSpace())
            assertTrue(pair.serverConn(serverCh).drainEvents().any { it == Event.DatagramsUnblocked })

            val small = "small".encodeToByteArray()
            pair.serverDatagrams(serverCh).sendOk(small, false)
            pair.drive()
            assertBytes(small, pair.clientDatagrams(clientCh).recv())
            assertNull(pair.clientDatagrams(clientCh).recv())
        }
    }

    /** Verify that dropping oversized datagrams will trigger a DatagramsUnblocked event (mod.rs:4025). */
    @Test
    fun oversizedDatagramsTriggerUnblock() {
        val pair = ConnPair.default()
        // Start the connection with a large MTU.
        val initialMtu = 1300
        pair.mtu = initialMtu

        val transportConfig = TransportConfig()
        val sendBufferSize = transportConfig.datagramSendBufferSize
        transportConfig.initialMtu(initialMtu)
        val (clientCh, _) = pair.connectWith(clientConfig().transportConfig(transportConfig))

        // Send datagrams until the send buffer is full.
        val maxSize = pair.clientDatagrams(clientCh).maxSize()!!
        val data = ByteArray(maxSize)
        while (true) {
            when (val e = pair.clientDatagrams(clientCh).send(data.copyOf().asBytes(), false)) {
                null -> {}
                is SendDatagramError.Blocked -> break
                else -> fail("unexpected error: $e")
            }
        }
        // Set the MTU to a smaller value so the queued datagrams cannot be sent.
        pair.mtu = 1200

        // Drive the pair until black hole detection kicks in and the path MTU is adjusted.
        while (pair.step()) {
            var err: SendDatagramError
            while (true) {
                err = pair.clientDatagrams(clientCh).send(data.copyOf().asBytes(), false) ?: continue
                break
            }
            if (err is SendDatagramError.Blocked) {
                // continue with the next step but drain the DatagramsUnblocked events emitted datagrams were sent out.
                pair.clientConn(clientCh).drainEvents()
            } else if (err == SendDatagramError.TooLarge) {
                // mtu adjusted, break the loop
                break
            } else {
                fail("unexpected error: $err")
            }
        }

        assertEquals(1L, pair.clientConn(clientCh).stats().path.blackHolesDetected, "expected a black hole to have been detected")

        assertEquals(
            sendBufferSize - DATAGRAM_OVERHEAD,
            pair.clientDatagrams(clientCh).sendBufferSpace(),
            "expected the send buffer to be empty after too large datagrams were dropped",
        )
        assertEquals(Event.DatagramsUnblocked, pair.clientConn(clientCh).poll(), "expected DatagramsUnblocked event")
    }

    // mod.rs:4106
    @Test
    fun ackBundledWithDatagrams() {
        val pair = ConnPair.defaultWithDeterministicPns()
        val (clientCh, serverCh) = pair.connectWith(clientConfigWithDeterministicPns())

        // Send packet from client and then send from server. the packet from server should include ACKs
        pair.clientDatagrams(clientCh).sendOk(ByteArray(1), false)
        pair.driveClient()
        pair.driveServer()

        val serverTxAcksBeforeDatagram = pair.serverConn(serverCh).stats().frameTx.acks
        val serverTxPacketsBeforeDatagram = pair.serverConn(serverCh).stats().udpTx.datagrams

        pair.serverDatagrams(serverCh).sendOk(ByteArray(1), false)
        pair.driveServer()

        val serverTxAcksAfterDatagram = pair.serverConn(serverCh).stats().frameTx.acks

        assertEquals(serverTxAcksBeforeDatagram + 1, serverTxAcksAfterDatagram, "server should have sent ACK frame along with DATAGRAM frame")
        assertEquals(
            serverTxPacketsBeforeDatagram + 1,
            pair.serverConn(serverCh).stats().udpTx.datagrams,
            "server should not have sent two or more QUIC packets",
        )

        pair.drive()

        // No more acks should be sent from server since ACK to the first packet has been sent with the datagram
        assertEquals(serverTxAcksAfterDatagram, pair.serverConn(serverCh).stats().frameTx.acks, "server should not sent ACK frames")
    }
}
