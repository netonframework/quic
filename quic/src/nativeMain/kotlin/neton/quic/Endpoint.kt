package neton.quic

import kotlinx.coroutines.CompletableJob
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.launch
import kotlinx.coroutines.sync.Mutex
import kotlinx.coroutines.sync.withLock
import kotlinx.coroutines.yield
import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import neton.io.core.ClosedException
import neton.io.core.IoException
import neton.io.core.monotonicNanos
import neton.io.net.BATCH_SIZE
import neton.io.net.RecvBatch
import neton.io.net.SocketAddress
import neton.io.net.Transmit
import neton.io.net.UdpOptions
import neton.io.net.UdpSocket
import neton.io.net.bindUdp
import neton.quic.proto.AcceptError
import neton.quic.proto.ClientConfig
import neton.quic.proto.ConnectError
import neton.quic.proto.ConnectionError
import neton.quic.proto.ConnectionEvent
import neton.quic.proto.ConnectionHandle
import neton.quic.proto.DatagramEvent
import neton.quic.proto.EndpointConfig
import neton.quic.proto.EndpointEvent
import neton.quic.proto.Instant
import neton.quic.proto.ServerConfig
import neton.quic.proto.TransportError
import neton.quic.proto.VarInt
import neton.quic.proto.default
import neton.quic.proto.Connection as ProtoConnection
import neton.quic.proto.Endpoint as ProtoEndpoint
import neton.quic.proto.Incoming as ProtoIncoming
import neton.quic.proto.Transmit as ProtoTransmit
import kotlin.time.Duration
import kotlin.time.Duration.Companion.microseconds

// The coroutine driver of an endpoint (quinn `endpoint.rs`) on a neton-io reactor.
//
// ⚖️ Concurrency model (SPEC §3, single-reactor endpoint): an endpoint, its UDP socket and all of its connections live
// on the reactor that created the endpoint. There is no state mutex and there are no channels: quinn's endpoint driver
// task and per-connection driver tasks exchange events over unbounded channels under a lock; here the receive loop
// hands a datagram's `ConnectionEvent` straight to its connection's queue and wakes the connection's driver, and a
// connection driver calls the protocol endpoint directly with its `EndpointEvent`s. Each connection still has its own
// driver coroutine (quinn's `ConnectionDriver`). Budgets (SPEC §3): a receive turn handles at most
// `DriverConfig.maxDatagramsPerTurn` messages or `DriverConfig.recvTimeBudget` (quinn's `WorkLimiter`), whichever
// comes first; a connection driver sends at most 20 datagrams per drive in transmits of at most 10 segments. Either
// re-queues itself at the end of the reactor's task queue when its budget is spent, so drivers with work left take
// turns in FIFO order (the round-robin over connections). The one suspending primitive is `sendLock`, the FIFO in
// which connections wait for a full socket (neton-io allows one parked send per socket); it is only ever taken on
// the reactor thread.
//
// ⚖️ Lifetime (SPEC §3): quinn's endpoint driver ends when every `Endpoint` handle is dropped and no connection is
// left. Kotlin has no destructors: [Endpoint.close] with no arguments stands for dropping the last handle. The
// endpoint's coroutines are children of the coroutine that created it, so that scope does not complete before the
// endpoint is closed and idle; cancelling that scope cancels the endpoint.

/**
 * A QUIC endpoint (endpoint.rs:43).
 *
 * An endpoint corresponds to a single UDP socket, may host many connections, and may act as both client and server
 * for different connections. It runs on the neton-io reactor it was created on and must only be used from it.
 */
class Endpoint private constructor(
    config: EndpointConfig,
    serverConfig: ServerConfig?,
    socket: UdpSocket,
    private val driverConfig: DriverConfig,
    private val job: CompletableJob,
    internal val scope: CoroutineScope,
) : AutoCloseable {
    private val maxUdpPayloadSize = config.getMaxUdpPayloadSize().toInt()

    internal val inner = ProtoEndpoint(config, serverConfig, !socket.mayFragment)

    internal var socket: UdpSocket = socket
        private set

    /** During an active migration, the abandoned socket receives traffic until the first packet arrives on the new one. */
    private var prevSocket: UdpSocket? = null
    private var ipv6 = socket.isIpv6

    /** quinn `default_client_config`. */
    private var defaultClientConfig: ClientConfig? = null

    /** Live connections by [ConnectionHandle.index]. */
    private var connections = arrayOfNulls<ConnectionState>(16)
    private var connectionCount = 0

    /** Connection attempts not yet handed to [accept]. */
    private val incoming = ArrayDeque<ProtoIncoming>()

    /** [Incoming]s handed out and not yet accepted, refused, retried or ignored. */
    private val outstandingIncoming = HashSet<Incoming>()

    /** Set if the endpoint has been manually closed (quinn `ConnectionSet::close`). */
    private var closeCode: VarInt? = null
    private var closeReason: Bytes = Bytes.EMPTY

    /** Whether [close] (quinn: dropping the last handle) was called. */
    private var released = false

    /** Whether the receive loop failed (quinn `driver_lost`). */
    private var driverLost = false

    /** Whether the endpoint's resources have been released. */
    private var stopped = false

    private val stats = EndpointStats()

    /** Counters of the driver's budgets, for tests. */
    internal val driverStats = DriverStats()
    private val incomingNotify = Notify()
    private val idleNotify = Notify()

    // Send path. A transmit is copied from [sendBuffer] into a pinned neton-io [Transmit] and sent without suspending;
    // only when the socket is full does a sender wait, in order, on [sendLock] (quinn keeps the transmit buffered and
    // waits for writability).
    internal val sendBuffer = Buffer(16 * 1024)
    private val responseBuffer = Buffer(1500)
    private var transmit = Transmit(TRANSMIT_CAPACITY)
    private var blockedTransmit: Transmit? = null
    private val sendLock = Mutex()
    private var blockedSenders = 0

    // Receive loop clock: time spent parked on an empty socket does not count towards the work limiter's cycle
    // (quinn polls the socket without blocking; a coroutine cannot tell "empty" from "ready" without suspending).
    private var parkedNanos = 0L
    private val busyClock = NanoClock { monotonicNanos() - parkedNanos }

    init {
        job.invokeOnCompletion { releaseResources() }
    }

    /** The current time on the protocol's monotonic timeline. */
    internal fun now(): Instant = Instant(monotonicNanos())

    /** Returns relevant stats from this endpoint (a snapshot). */
    fun stats(): EndpointStats = stats.copy()

    /**
     * Get the next incoming connection attempt from a client (endpoint.rs:174). Returns `null` if the endpoint is
     * [closed][close]. An [Incoming] can be [accepted][Incoming.accept] to obtain a [Connecting], or used to e.g.
     * filter connection attempts or force address validation.
     */
    suspend fun accept(): Incoming? {
        while (true) {
            if (driverLost || stopped) return null
            val next = incoming.removeFirstOrNull()
            if (next != null) return Incoming(next, this).also { outstandingIncoming.add(it) }
            if (closeCode != null || released) return null
            incomingNotify.await()
        }
    }

    /** Set the client configuration used by [connect]. */
    fun setDefaultClientConfig(config: ClientConfig) {
        defaultClientConfig = config
    }

    /**
     * Connect to a remote endpoint (endpoint.rs:194). [serverName] must be covered by the certificate presented by the
     * server. Throws [ConnectError] on configuration errors; the returned [Connecting] fails if the connection could
     * not be established.
     */
    fun connect(address: SocketAddress, serverName: String): Connecting {
        val config = defaultClientConfig ?: throw ConnectError.NoDefaultClientConfig()
        return connectWith(config, address, serverName)
    }

    /** Connect to a remote endpoint using a custom configuration (endpoint.rs:208). Throws [ConnectError]. */
    fun connectWith(config: ClientConfig, address: SocketAddress, serverName: String): Connecting {
        if (driverLost || stopped || released || closeCode != null) throw ConnectError.EndpointStopping()
        if (address.isIpv6 && !ipv6) throw ConnectError.InvalidRemoteAddress(address)
        val remote = if (ipv6) address.toIpv4Mapped() else address

        val (ch, conn) = inner.connect(now(), config, remote, serverName)
        stats.outgoingHandshakes += 1
        return Connecting(insert(ch, conn))
    }

    /**
     * Switch to a new UDP socket (endpoint.rs:253). Allows the endpoint's address to be updated live, affecting all
     * active connections. Incoming connections and connections to servers unreachable from the new address will be
     * lost. [socket] must have been bound on this endpoint's reactor.
     */
    fun rebind(socket: UdpSocket) {
        check(!stopped) { "endpoint stopped" }
        prevSocket?.close()
        prevSocket = this.socket
        this.socket = socket
        ipv6 = socket.isIpv6

        // Update connection socket references
        for (conn in connections) conn?.rebind()
        // Ensure the driver receives on the new socket
        startReceiving(socket)
    }

    /**
     * Replace the server configuration, affecting new incoming connections only (endpoint.rs:275). Useful for e.g.
     * refreshing TLS certificates without disrupting existing connections.
     */
    fun setServerConfig(serverConfig: ServerConfig?) {
        inner.setServerConfig(serverConfig)
    }

    /** The local address the underlying socket is bound to. */
    fun localAddr(): SocketAddress = socket.localAddress

    /** The number of connections that are currently open. */
    fun openConnections(): Int = inner.openConnections()

    /**
     * Close all of this endpoint's connections immediately and cease accepting new connections (endpoint.rs:299). See
     * [Connection.close] for details.
     */
    fun close(errorCode: VarInt, reason: ByteArray) {
        val bytes = Bytes.copyOf(reason)
        closeCode = errorCode
        closeReason = bytes
        for (conn in connections) conn?.close(errorCode, bytes)
        incomingNotify.notifyWaiters()
    }

    /**
     * Wait for all connections on the endpoint to be cleanly shut down (endpoint.rs:323). Waiting for this condition
     * before exiting ensures that a good-faith effort is made to notify peers of recent connection closes, whereas
     * exiting immediately could force them to wait out the idle timeout period.
     *
     * Does not proactively close existing connections or cause incoming connections to be rejected. Consider calling
     * [close] if that is desired.
     */
    suspend fun waitIdle() {
        while (connectionCount > 0) idleNotify.await()
    }

    /**
     * ⚖️ quinn: dropping the last `Endpoint` handle. The endpoint accepts no new connections; once its remaining
     * connections are gone, its receive loop stops, the socket is closed and incoming connection attempts that were
     * never handled are refused. Idempotent.
     */
    override fun close() {
        if (released) return
        released = true
        incomingNotify.notifyWaiters()
        stopIfDone()
    }

    // ---- connections ----

    private fun insert(ch: ConnectionHandle, conn: ProtoConnection): ConnectionState {
        val state = ConnectionState(this, ch, conn)
        if (ch.index >= connections.size) connections = connections.copyOf(maxOf(connections.size * 2, ch.index + 1))
        check(connections[ch.index] == null) { "connection handle ${ch.index} in use" }
        connections[ch.index] = state
        connectionCount += 1
        closeCode?.let { state.close(it, closeReason) }
        scope.launch { state.drive() }
        return state
    }

    /** A connection driver's endpoint event (quinn `State::handle_events`, run by the driver itself). */
    internal fun handleEndpointEvent(conn: ConnectionState, event: EndpointEvent) {
        if (event.isDrained) remove(conn.handle)
        val reply = inner.handleEvent(conn.handle, event) ?: return
        conn.deliver(reply)
    }

    /** Forget a connection whose driver ends without the protocol having drained it (quinn `State::drop`). */
    internal fun forget(conn: ConnectionState) {
        if (connections.getOrNull(conn.handle.index) !== conn) return
        handleEndpointEvent(conn, EndpointEvent.drained())
    }

    private fun remove(ch: ConnectionHandle) {
        if (connections.getOrNull(ch.index) == null) return
        connections[ch.index] = null
        connectionCount -= 1
        if (connectionCount == 0) {
            idleNotify.notifyWaiters()
            stopIfDone()
        }
    }

    // ---- incoming ----

    internal fun acceptIncoming(incoming: Incoming, serverConfig: ServerConfig?): Connecting {
        outstandingIncoming.remove(incoming)
        check(!stopped) { "endpoint stopped" }
        responseBuffer.clear()
        try {
            val (ch, conn) = inner.accept(incoming.inner, now(), responseBuffer, serverConfig)
            stats.acceptedHandshakes += 1
            return Connecting(insert(ch, conn))
        } catch (e: AcceptError) {
            e.response?.let { respond(it, responseBuffer, socket) }
            throw e.cause
        }
    }

    internal fun refuseIncoming(incoming: Incoming) {
        outstandingIncoming.remove(incoming)
        if (stopped) return
        stats.refusedHandshakes += 1
        responseBuffer.clear()
        respond(inner.refuse(incoming.inner, responseBuffer), responseBuffer, socket)
    }

    internal fun retryIncoming(incoming: Incoming) {
        check(!stopped) { "endpoint stopped" }
        responseBuffer.clear()
        // Throws RetryError (and keeps the Incoming outstanding) when a retry is not allowed
        val transmit = inner.retry(incoming.inner, responseBuffer)
        outstandingIncoming.remove(incoming)
        respond(transmit, responseBuffer, socket)
    }

    internal fun ignoreIncoming(incoming: Incoming) {
        outstandingIncoming.remove(incoming)
        if (stopped) return
        stats.ignoredHandshakes += 1
        inner.ignore(incoming.inner)
    }

    // ---- receive ----

    private fun startReceiving(socket: UdpSocket) {
        // UNDISPATCHED: the loop reaches its first receive before this returns, so a socket is never left unread.
        scope.launch(start = CoroutineStart.UNDISPATCHED) { receiveLoop(socket) }
    }

    /**
     * quinn `RecvState::poll_socket` as a loop: receive a batch (suspending while the socket is empty) and route its
     * datagrams, within the receive budget of SPEC §3: a turn handles at most [DriverConfig.maxDatagramsPerTurn]
     * received messages, and ends earlier once quinn's `WorkLimiter` says the turn's [DriverConfig.recvTimeBudget] is
     * spent. The loop then re-queues itself at the end of the reactor's task queue ([yield]) instead of carrying on;
     * messages of the batch left unhandled are handled first in the next turn.
     *
     * ⚖️ quinn starts a new cycle on every poll of its driver, i.e. on every wake-up. A coroutine cannot tell whether
     * [UdpSocket.recv] parked, so here a turn runs from one yield to the next: a park inside it does not start a new
     * turn (and the time parked does not count, see [busyClock]). The budget is therefore an upper bound on the work
     * done per wake-up; a turn that spans a park only yields sooner than quinn would.
     */
    private suspend fun receiveLoop(socket: UdpSocket) {
        val slotSize = (minOf(maxUdpPayloadSize, 64 * 1024) * maxOf(1, socket.groSegments)).coerceAtMost(1 shl 20)
        val batch = RecvBatch(BATCH_SIZE, slotSize)
        val limiter = WorkLimiter(driverConfig.recvTimeBudget.inWholeNanoseconds)
        val maxPerTurn = driverConfig.maxDatagramsPerTurn
        var received = 0 // messages in the batch
        var next = 0 // the first message of the batch not yet handled
        var turn = 0 // messages handled in this turn
        try {
            limiter.startCycle(busyClock)
            while (true) {
                if (next == received) {
                    val parkStart = monotonicNanos()
                    received = try {
                        socket.recv(batch)
                    } catch (e: ClosedException) {
                        return // closed by rebind or shutdown
                    }
                    parkedNanos += monotonicNanos() - parkStart
                    next = 0
                }
                val end = minOf(received, next + (maxPerTurn - turn))
                val now = now()
                var receivedConnectionPacket = false
                var remote: SocketAddress? = null
                for (i in next until end) {
                    if (remote == null || !batch.sourceEquals(i, remote)) remote = batch.source(i)
                    if (handleSlot(batch, i, remote, now, socket)) receivedConnectionPacket = true
                }
                limiter.recordWork(end - next)
                turn += end - next
                driverStats.receivedMessages += end - next
                next = end
                if (incoming.isNotEmpty()) incomingNotify.notifyWaiters()
                if (receivedConnectionPacket && socket === this.socket) {
                    // Traffic has arrived on the new socket, therefore there is no need for the abandoned one anymore.
                    prevSocket?.close()
                    prevSocket = null
                }
                if (turn > driverStats.maxMessagesInTurn) driverStats.maxMessagesInTurn = turn
                if (turn >= maxPerTurn || !limiter.allowWork(busyClock)) {
                    limiter.finishCycle(busyClock)
                    driverStats.receiveYields += 1
                    turn = 0
                    yield()
                    limiter.startCycle(busyClock)
                }
            }
        } catch (e: IoException) {
            if (socket === this.socket) lose(e)
        } finally {
            batch.close()
        }
    }

    /**
     * Route the datagrams of receive slot [i]: with GRO a slot holds several datagrams of `stride` bytes. As in quinn,
     * the slot is copied once into an array the protocol layer then owns (decrypting in place and handing out stream
     * data as views of it); its datagrams share that array. Returns whether a datagram went to a connection.
     */
    private fun handleSlot(batch: RecvBatch, i: Int, remote: SocketAddress, now: Instant, socket: UdpSocket): Boolean {
        val len = batch.length(i)
        if (len == 0) return false
        val stride = batch.stride(i).let { if (it <= 0) len else it }
        val offset = batch.offset(i)
        val data = batch.buffer.copyOfRange(offset, offset + len)
        val localIp = batch.destination(i)
        val ecn = batch.ecn(i)
        var receivedConnectionPacket = false
        var start = 0
        while (start < len) {
            val end = minOf(start + stride, len)
            responseBuffer.clear()
            when (val event = inner.handle(now, remote, localIp, ecn, data, responseBuffer, start, end)) {
                is DatagramEvent.NewConnection -> {
                    if (closeCode == null && !released) {
                        incoming.addLast(event.incoming)
                    } else {
                        responseBuffer.clear()
                        respond(inner.refuse(event.incoming, responseBuffer), responseBuffer, socket)
                    }
                }
                is DatagramEvent.ConnectionEvent -> {
                    receivedConnectionPacket = true
                    // Ignoring datagrams for connections whose driver has already ended
                    connections.getOrNull(event.ch.index)?.deliver(event.event)
                }
                is DatagramEvent.Response -> respond(event.transmit, responseBuffer, socket)
                null -> {}
            }
            start = end
        }
        return receivedConnectionPacket
    }

    /** The receive loop failed: quinn's endpoint driver ends with an I/O error, and its connections with it. */
    private fun lose(e: IoException) {
        driverLost = true
        incomingNotify.notifyWaiters()
        val error = ConnectionError.Transport(TransportError.INTERNAL_ERROR("endpoint driver failed: ${e.message}"))
        for (conn in connections) conn?.endpointLost(error)
    }

    // ---- send ----

    /** quinn `respond`: send if there's kernel buffer space; otherwise, drop it (the peer will retry). */
    private fun respond(t: ProtoTransmit, buf: Buffer, socket: UdpSocket) {
        if (blockedSenders > 0 || stopped) return
        val tx = transmitFor(t.size)
        fill(tx, t, buf.backingArray(), buf.readerIndex())
        try {
            socket.trySend(tx)
        } catch (e: IoException) {
            // As quinn: a failed response is dropped
        }
    }

    /**
     * Send a connection's transmit, whose bytes are the readable part of [buf]. Returns true when it was sent without
     * suspending; otherwise the bytes were copied and the caller waited for its turn on a writable socket.
     */
    internal suspend fun send(t: ProtoTransmit, buf: Buffer): Boolean {
        if (blockedSenders == 0) {
            val tx = transmitFor(t.size)
            fill(tx, t, buf.backingArray(), buf.readerIndex())
            if (socket.trySend(tx)) return true
        }
        // The socket is full (or others are already waiting): keep a copy, since the buffer is shared
        val copy = buf.backingArray().copyOfRange(buf.readerIndex(), buf.readerIndex() + t.size)
        blockedSenders += 1
        try {
            sendLock.withLock {
                val tx = blockedTransmit?.takeIf { it.buffer.size >= t.size }
                    ?: Transmit(maxOf(TRANSMIT_CAPACITY, t.size)).also { blockedTransmit?.close(); blockedTransmit = it }
                fill(tx, t, copy, 0)
                while (true) {
                    val target = socket
                    try {
                        target.send(tx)
                        break
                    } catch (e: ClosedException) {
                        // The abandoned socket of a rebind was closed under the wait: send on the new one (quinn's
                        // connection switches sockets on `ConnectionEvent::Rebind` and retries its buffered transmit).
                        if (target === socket || stopped) throw e
                    }
                }
            }
        } finally {
            blockedSenders -= 1
        }
        return false
    }

    /** The maximum number of datagrams a connection may batch into one transmit (quinn `max_transmit_segments`). */
    internal val maxTransmitSegments: Int get() = minOf(socket.maxGsoSegments, MAX_TRANSMIT_SEGMENTS)

    private fun transmitFor(size: Int): Transmit {
        if (transmit.buffer.size < size) {
            transmit.close()
            transmit = Transmit(size)
        }
        return transmit
    }

    private fun fill(tx: Transmit, t: ProtoTransmit, bytes: ByteArray, offset: Int) {
        bytes.copyInto(tx.buffer, 0, offset, offset + t.size)
        tx.length = t.size
        tx.setDestination(t.destination)
        tx.ecn = t.ecn
        tx.segmentSize = t.segmentSize ?: 0
        tx.setSource(t.srcIp)
    }

    // ---- shutdown ----

    /** Stop once [close]d and idle (quinn's driver completes when no handle and no connection is left). */
    private fun stopIfDone() {
        if (!released || connectionCount > 0 || stopped) return
        // quinn `State::drop` ignores the connection attempts never handed out; an `Incoming` dropped unhandled is refused.
        while (true) inner.ignore(incoming.removeFirstOrNull() ?: break)
        for (incoming in outstandingIncoming.toList()) incoming.close()
        stopped = true
        incomingNotify.notifyWaiters()
        idleNotify.notifyWaiters()
        prevSocket?.close()
        prevSocket = null
        socket.close() // ends the receive loop
        job.complete()
    }

    private fun releaseResources() {
        stopped = true
        prevSocket?.close()
        socket.close()
        transmit.close()
        blockedTransmit?.close()
    }

    companion object {
        /**
         * Helper to construct an endpoint for use with outgoing connections only (endpoint.rs:75). [address] is the
         * *local* address to bind to, usually a wildcard address like `0.0.0.0:0` or `[::]:0`. An IPv6 address makes
         * the socket dual-stack.
         */
        suspend fun client(address: SocketAddress): Endpoint =
            create(EndpointConfig.default(), null, bindUdp(address, UdpOptions(ipv6Only = false)))

        /** Helper to construct an endpoint for use with both incoming and outgoing connections (endpoint.rs:105). */
        suspend fun server(config: ServerConfig, address: SocketAddress): Endpoint =
            create(EndpointConfig.default(), config, bindUdp(address))

        /**
         * Construct an endpoint with arbitrary configuration and socket (quinn `Endpoint::new`). Must be called on the
         * reactor [socket] was bound on; the endpoint's coroutines become children of the calling coroutine.
         */
        suspend fun create(
            config: EndpointConfig,
            serverConfig: ServerConfig?,
            socket: UdpSocket,
            driverConfig: DriverConfig = DriverConfig(),
        ): Endpoint {
            val context = currentCoroutineContext()
            val job = Job(context[Job])
            val endpoint = Endpoint(config, serverConfig, socket, driverConfig, job, CoroutineScope(context + job))
            endpoint.startReceiving(socket)
            return endpoint
        }

        /**
         * The maximum amount of datagrams that are sent in a single transmit (quinn `MAX_TRANSMIT_SEGMENTS`). This can
         * be lower than the maximum platform capabilities, to avoid excessive memory allocations when calling
         * `pollTransmit`; benchmarks have shown that numbers around 10 are a good compromise.
         */
        internal const val MAX_TRANSMIT_SEGMENTS = 10

        private const val TRANSMIT_CAPACITY = 65535
    }
}

/**
 * The receive budget of the endpoint's driver (SPEC §3): the reactor's round budget counts tasks, not how much work one
 * task does, so the receive loop bounds itself. ⚖️ quinn has only the time slice (the constant `RECV_TIME_BOUND`,
 * applied through `WorkLimiter`); the count cap is this library's, sized as quinn's `IO_LOOP_BOUND` (160, the bound
 * of its endpoint-event loop), i.e. five batch receives of 32.
 */
class DriverConfig(
    /** The most received messages (a GRO message may hold several datagrams) handled per turn: 32 × 5. */
    val maxDatagramsPerTurn: Int = 32 * 5,
    /** The time a receive turn may take (quinn `RECV_TIME_BOUND`), enforced by quinn's `WorkLimiter`. */
    val recvTimeBudget: Duration = 50.microseconds,
) {
    init {
        require(maxDatagramsPerTurn > 0) { "maxDatagramsPerTurn must be positive" }
        require(recvTimeBudget.isPositive()) { "recvTimeBudget must be positive" }
    }
}

/** Counters of the driver's budgets (tests check that the budgets hold). */
internal class DriverStats {
    /** Received messages handled. */
    var receivedMessages = 0L

    /** Times the receive loop re-queued itself because its turn's budget was spent. */
    var receiveYields = 0L

    /** The most messages handled in one receive turn. */
    var maxMessagesInTurn = 0

    /** Times a connection driver re-queued itself because its send budget was spent. */
    var transmitYields = 0L

    /** The most datagrams a connection driver sent in one drive. */
    var maxDatagramsInDrive = 0

    /** The most segments in one transmit. */
    var maxSegmentsInTransmit = 0
}

/** Statistics on [Endpoint] activity (endpoint.rs:341). */
class EndpointStats {
    /** Cumulative number of QUIC handshakes accepted by this endpoint. */
    var acceptedHandshakes: Long = 0
        internal set

    /** Cumulative number of QUIC handshakes sent from this endpoint. */
    var outgoingHandshakes: Long = 0
        internal set

    /** Cumulative number of QUIC handshakes refused on this endpoint. */
    var refusedHandshakes: Long = 0
        internal set

    /** Cumulative number of QUIC handshakes ignored on this endpoint. */
    var ignoredHandshakes: Long = 0
        internal set

    internal fun copy(): EndpointStats = EndpointStats().also {
        it.acceptedHandshakes = acceptedHandshakes
        it.outgoingHandshakes = outgoingHandshakes
        it.refusedHandshakes = refusedHandshakes
        it.ignoredHandshakes = ignoredHandshakes
    }

    override fun toString(): String =
        "EndpointStats(acceptedHandshakes=$acceptedHandshakes, outgoingHandshakes=$outgoingHandshakes, " +
            "refusedHandshakes=$refusedHandshakes, ignoredHandshakes=$ignoredHandshakes)"
}
