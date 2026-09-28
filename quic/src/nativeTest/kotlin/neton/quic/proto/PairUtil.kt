package neton.quic.proto

import neton.quic.testkit.*

import neton.io.bytes.Buffer
import neton.io.net.EcnCodepoint
import neton.io.net.SocketAddress
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration

// The two-endpoint simulation of quinn-proto's tests (`tests/util.rs`): a client and a server endpoint exchanging
// datagrams over a virtual link with configurable latency, MTU (larger datagrams are dropped) and ECN marking, in
// virtual time. ⚖️ The `Pair` type is `ConnPair` (Kotlin's `Pair` is in scope everywhere); connection events go to
// their own connection (quinn's `drive_outgoing` hands all queued events to the first connection it iterates, which is
// the same thing with the one connection per endpoint its tests use); there is no real-socket mirroring
// (`SSLKEYLOGFILE`).

internal const val DEFAULT_MTU = 1452

/** The maximum of datagrams a [TestEndpoint] will produce via `pollTransmit`. */
internal const val MAX_DATAGRAMS = 10

/** The virtual clock's origin; any instant works, quinn uses `Instant::now()`. */
internal val TEST_EPOCH = Instant(1_000_000_000_000_000L)

private var serverPorts = 0
private var clientPorts = 0

/**
 * Server ports from 4433 and client ports from 44433, as quinn's; ⚖️ they wrap around instead of running out (quinn's
 * `RangeFrom<u16>` panics after 64k pairs, which repeated test runs reach). Ports only need to differ within a pair.
 */
internal fun nextServerPort(): Int = 4433 + (serverPorts++ % 40000)
internal fun nextClientPort(): Int = 44433 + (clientPorts++ % 20000)

/** `[::1]:port`. */
internal fun localhostV6(port: Int): SocketAddress = SocketAddress.of(ByteArray(16).also { it[15] = 1 }, port)

internal class ConnPair(val server: TestEndpoint, val client: TestEndpoint) {
    /** Start time. */
    private val epoch = TEST_EPOCH

    /** Current time. */
    var time: Instant = epoch

    /** Simulates the maximum size allowed for UDP payloads by the link (packets exceeding this size will be dropped). */
    var mtu = DEFAULT_MTU

    /** Simulates explicit congestion notification. */
    var congestionExperienced = false

    /** One-way latency. */
    var latency: Duration = Duration.ZERO

    /** Number of spin bit flips. */
    var spins = 0L
    private var lastSpin = false

    /** Returns whether the connection is not idle. */
    fun step(): Boolean {
        driveClient()
        driveServer()
        if (client.isIdle() && server.isIdle()) return false

        val clientT = client.nextWakeup()
        val serverT = server.nextWakeup()
        val t = minOpt(clientT, serverT)
        if (t.isNone) return false
        if (t != time && t > time) time = t
        return true
    }

    /** Advance time until both connections are idle. */
    fun drive() {
        while (step()) {
            // keep going
        }
    }

    /**
     * Advance time until both connections are idle, or after 100 steps have been executed. Returns true if the amount
     * of steps exceeds the bounds, because the connections never became idle.
     */
    fun driveBounded(): Boolean {
        repeat(100) { if (!step()) return false }
        return true
    }

    fun driveClient() {
        client.drive(time, server.addr)
        while (true) {
            val (transmit, buffer) = client.outbound.removeFirstOrNull() ?: break
            if (packetSize(transmit, buffer) > mtu) continue // dropping packet (max size exceeded)
            if (buffer[0].toInt() and LONG_HEADER_FORM == 0) {
                val spin = buffer[0].toInt() and SPIN_BIT != 0
                if (spin == lastSpin) spins += 1
                lastSpin = spin
            }
            if (server.addr == transmit.destination) {
                val ecn = setCongestionExperienced(transmit.ecn, congestionExperienced)
                server.inbound.addLast(Inbound(time + latency, ecn, buffer))
            }
        }
    }

    fun driveServer() {
        server.drive(time, client.addr)
        while (true) {
            val (transmit, buffer) = server.outbound.removeFirstOrNull() ?: break
            if (packetSize(transmit, buffer) > mtu) continue // dropping packet (max size exceeded)
            if (client.addr == transmit.destination) {
                val ecn = setCongestionExperienced(transmit.ecn, congestionExperienced)
                client.inbound.addLast(Inbound(time + latency, ecn, buffer))
            }
        }
    }

    fun connect(): Pair<ConnectionHandle, ConnectionHandle> = connectWith(clientConfig())

    fun connectWith(config: ClientConfig): Pair<ConnectionHandle, ConnectionHandle> {
        val clientCh = beginConnect(config)
        drive()
        val serverCh = server.assertAccept()
        finishConnect(clientCh, serverCh)
        return clientCh to serverCh
    }

    /** Just start connecting the client. */
    fun beginConnect(config: ClientConfig): ConnectionHandle {
        val (clientCh, clientConn) = client.endpoint.connect(time, config, server.addr, "localhost")
        client.connections[clientCh] = clientConn
        return clientCh
    }

    private fun finishConnect(clientCh: ConnectionHandle, serverCh: ConnectionHandle) {
        assertEquals(Event.HandshakeDataReady, clientConn(clientCh).poll())
        assertEquals(Event.Connected, clientConn(clientCh).poll())
        assertEquals(Event.HandshakeDataReady, serverConn(serverCh).poll())
        assertEquals(Event.Connected, serverConn(serverCh).poll())
    }

    fun clientConn(ch: ConnectionHandle): Connection = client.connections[ch] ?: fail("no client connection $ch")
    fun clientStreams(ch: ConnectionHandle): Streams = clientConn(ch).streams()
    fun clientSend(ch: ConnectionHandle, s: StreamId): SendStream = clientConn(ch).sendStream(s)
    fun clientRecv(ch: ConnectionHandle, s: StreamId): RecvStream = clientConn(ch).recvStream(s)
    fun clientDatagrams(ch: ConnectionHandle): Datagrams = clientConn(ch).datagrams()
    fun serverConn(ch: ConnectionHandle): Connection = server.connections[ch] ?: fail("no server connection $ch")
    fun serverStreams(ch: ConnectionHandle): Streams = serverConn(ch).streams()
    fun serverSend(ch: ConnectionHandle, s: StreamId): SendStream = serverConn(ch).sendStream(s)
    fun serverRecv(ch: ConnectionHandle, s: StreamId): RecvStream = serverConn(ch).recvStream(s)
    fun serverDatagrams(ch: ConnectionHandle): Datagrams = serverConn(ch).datagrams()

    companion object {
        fun default(): ConnPair = new(EndpointConfig.default(), serverConfig())

        fun defaultWithDeterministicPns(): ConnPair {
            val cfg = serverConfig()
            cfg.transport = TransportConfig().deterministicPacketNumbers(true)
            return new(EndpointConfig.default(), cfg)
        }

        fun new(endpointConfig: EndpointConfig, serverConfig: ServerConfig): ConnPair {
            val server = Endpoint(endpointConfig, serverConfig, true)
            val client = Endpoint(endpointConfig, null, true)
            return newFromEndpoint(client, server)
        }

        fun newFromEndpoint(client: Endpoint, server: Endpoint): ConnPair = ConnPair(
            server = TestEndpoint(server, localhostV6(nextServerPort())),
            client = TestEndpoint(client, localhostV6(nextClientPort())),
        )
    }
}

/** A datagram in flight towards an endpoint: when it arrives, its ECN marking and its bytes. */
internal data class Inbound(val time: Instant, val ecn: EcnCodepoint?, val data: ByteArray)

/** A datagram an endpoint sent. */
internal data class Outbound(val transmit: Transmit, val data: ByteArray)

internal enum class IncomingConnectionBehavior { Accept, Reject, Retry, Wait }

internal fun validateIncoming(incoming: Incoming): IncomingConnectionBehavior =
    if (incoming.remoteAddressValidated()) IncomingConnectionBehavior.Accept else IncomingConnectionBehavior.Retry

/** The outcome of the last accept attempt (quinn's `Option<Result<ConnectionHandle, ConnectionError>>`). */
internal sealed class Accepted {
    class Ok(val ch: ConnectionHandle) : Accepted()
    class Err(val error: ConnectionError) : Accepted()
}

internal class TestEndpoint(var endpoint: Endpoint, var addr: SocketAddress) {
    private var timeout = Instant.NONE
    val outbound = ArrayDeque<Outbound>()
    private val delayed = ArrayDeque<Outbound>()
    val inbound = ArrayDeque<Inbound>()
    private var accepted: Accepted? = null
    val connections = LinkedHashMap<ConnectionHandle, Connection>()
    private val connEvents = HashMap<ConnectionHandle, ArrayDeque<ConnectionEvent>>()
    val capturedPackets = ArrayList<ByteArray>()
    var captureInboundPackets = false
    var handleIncoming: (Incoming) -> IncomingConnectionBehavior = { IncomingConnectionBehavior.Accept }
    val waitingIncoming = ArrayList<Incoming>()

    fun drive(now: Instant, remote: SocketAddress) {
        driveIncoming(now, remote)
        driveOutgoing(now)
    }

    fun driveIncoming(now: Instant, remote: SocketAddress) {
        val buf = Buffer(endpoint.config().getMaxUdpPayloadSize().toInt())
        while (inbound.isNotEmpty() && inbound.first().time <= now) {
            val (recvTime, ecn, packet) = inbound.removeFirst()
            val event = endpoint.handle(recvTime, remote, null, ecn, packet, buf) ?: continue
            when (event) {
                is DatagramEvent.NewConnection -> when (handleIncoming(event.incoming)) {
                    IncomingConnectionBehavior.Accept -> tryAccept(event.incoming, now)
                    IncomingConnectionBehavior.Reject -> reject(event.incoming)
                    IncomingConnectionBehavior.Retry -> retry(event.incoming)
                    IncomingConnectionBehavior.Wait -> waitingIncoming.add(event.incoming)
                }
                is DatagramEvent.ConnectionEvent -> {
                    if (captureInboundPackets) {
                        val conn = connections[event.ch] ?: fail("no connection for ${event.ch}")
                        conn.decodePacket(event.event)?.let { capturedPackets.add(it) }
                    }
                    connEvents.getOrPut(event.ch) { ArrayDeque() }.addLast(event.event)
                }
                is DatagramEvent.Response -> {
                    outbound.addAll(splitTransmit(event.transmit, buf.peekAll()))
                    buf.clear()
                }
            }
        }
    }

    fun driveOutgoing(now: Instant) {
        val buf = Buffer(endpoint.config().getMaxUdpPayloadSize().toInt())
        while (true) {
            val endpointEvents = ArrayList<Pair<ConnectionHandle, EndpointEvent>>()
            for ((ch, conn) in connections) {
                if (timeout.isSome && timeout <= now) {
                    timeout = Instant.NONE
                    conn.handleTimeout(now)
                }

                connEvents.remove(ch)?.let { events -> for (event in events) conn.handleEvent(event) }

                while (true) endpointEvents.add(ch to (conn.pollEndpointEvents() ?: break))
                while (true) {
                    val transmit = conn.pollTransmit(now, MAX_DATAGRAMS, buf) ?: break
                    outbound.addAll(splitTransmit(transmit, buf.peekAll()))
                    buf.clear()
                }
                timeout = conn.pollTimeout()
            }

            if (endpointEvents.isEmpty()) break

            for ((ch, event) in endpointEvents) {
                val connEvent = endpoint.handleEvent(ch, event) ?: continue
                connections[ch]?.handleEvent(connEvent)
            }
        }
    }

    fun nextWakeup(): Instant {
        val nextInbound = inbound.firstOrNull()?.time ?: Instant.NONE
        return minOpt(timeout, nextInbound)
    }

    fun isIdle(): Boolean = connections.values.all { it.isIdle() }

    fun delayOutbound() {
        check(delayed.isEmpty())
        delayed.addAll(outbound)
        outbound.clear()
    }

    fun finishDelay() {
        outbound.addAll(delayed)
        delayed.clear()
    }

    fun tryAccept(incoming: Incoming, now: Instant): ConnectionHandle? {
        val buf = Buffer(1500)
        return try {
            val (ch, conn) = endpoint.accept(incoming, now, buf, null)
            connections[ch] = conn
            accepted = Accepted.Ok(ch)
            ch
        } catch (e: AcceptError) {
            e.response?.let { outbound.addAll(splitTransmit(it, buf.peekAll())) }
            accepted = Accepted.Err(e.cause)
            null
        }
    }

    fun retry(incoming: Incoming) {
        val buf = Buffer(1500)
        val transmit = endpoint.retry(incoming, buf)
        outbound.addAll(splitTransmit(transmit, buf.peekAll()))
    }

    fun reject(incoming: Incoming) {
        val buf = Buffer(1500)
        val transmit = endpoint.refuse(incoming, buf)
        outbound.addAll(splitTransmit(transmit, buf.peekAll()))
    }

    fun assertAccept(): ConnectionHandle {
        val a = accepted ?: fail("server didn't try connecting")
        accepted = null
        return when (a) {
            is Accepted.Ok -> a.ch
            is Accepted.Err -> fail("server experienced error connecting: ${a.error}")
        }
    }

    fun assertAcceptError(): ConnectionError {
        val a = accepted ?: fail("server didn't try connecting")
        accepted = null
        return when (a) {
            is Accepted.Ok -> fail("server did unexpectedly connect without error")
            is Accepted.Err -> a.error
        }
    }

    fun assertNoAccept() {
        assertNull(accepted, "server did unexpectedly connect")
    }
}

internal fun serverConfig(crypto: MockServerCrypto = MockServerCrypto()): ServerConfig = ServerConfig.withCrypto(crypto)

internal fun serverConfigWithAlpn(vararg alpn: String): ServerConfig =
    serverConfig(MockServerCrypto(alpn = alpn.map { it.encodeToByteArray() }))

internal fun clientConfig(crypto: MockClientCrypto = MockClientCrypto()): ClientConfig = ClientConfig(crypto)

internal fun clientConfigWithAlpn(vararg alpn: String): ClientConfig =
    clientConfig(MockClientCrypto(alpn = alpn.map { it.encodeToByteArray() }))

internal fun clientConfigWithDeterministicPns(): ClientConfig =
    clientConfig().transportConfig(TransportConfig().deterministicPacketNumbers(true))

/** [Instant.NONE]-aware minimum (quinn `min_opt`). */
internal fun minOpt(x: Instant, y: Instant): Instant = when {
    x.isNone -> y
    y.isNone -> x
    x < y -> x
    else -> y
}

private fun splitTransmit(transmit: Transmit, buffer: ByteArray): List<Outbound> {
    val data = buffer.copyOf(transmit.size)
    val segmentSize = transmit.segmentSize ?: return listOf(Outbound(transmit, data))
    val out = ArrayList<Outbound>()
    var at = 0
    while (at < data.size) {
        val end = minOf(at + segmentSize, data.size)
        val contents = data.copyOfRange(at, end)
        out.add(Outbound(Transmit(transmit.destination, transmit.ecn, contents.size, null, transmit.srcIp), contents))
        at = end
    }
    return out
}

private fun packetSize(transmit: Transmit, buffer: ByteArray): Int {
    check(transmit.segmentSize == null) { "This transmit is meant to be split into multiple packets!" }
    return buffer.size
}

private fun setCongestionExperienced(x: EcnCodepoint?, congestionExperienced: Boolean): EcnCodepoint? =
    if (x != null && congestionExperienced) EcnCodepoint.Ce else x

/** All the events a connection has queued. */
internal fun Connection.drainEvents(): List<Event> = buildList { while (true) add(poll() ?: break) }

/** Read everything available on a stream in order (quinn's `stream_chunks`). */
internal fun streamChunks(recv: RecvStream): ByteArray {
    val out = Buffer(64)
    val chunks = recv.read(true)
    while (true) {
        val chunk = chunks.next(Int.MAX_VALUE) as? Chunk ?: break
        out.writeBytes(chunk.bytes)
    }
    chunks.finalize()
    return out.readAll()
}

internal fun assertChunk(result: ReadResult, offset: Long, bytes: ByteArray) {
    val chunk = result as? Chunk ?: fail("expected a chunk, got $result")
    assertEquals(offset, chunk.offset)
    assertTrue(chunk.bytes.toByteArray().contentEquals(bytes), "chunk bytes differ")
}
