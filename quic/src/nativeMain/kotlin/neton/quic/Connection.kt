package neton.quic

import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.Delay
import kotlinx.coroutines.DisposableHandle
import kotlinx.coroutines.InternalCoroutinesApi
import kotlinx.coroutines.Runnable
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlinx.coroutines.yield
import neton.io.bytes.Bytes
import neton.io.core.IoException
import neton.io.net.SocketAddress
import neton.quic.proto.ConnectionError
import neton.quic.proto.ConnectionEvent
import neton.quic.proto.ConnectionHandle
import neton.quic.proto.ConnectionStats
import neton.quic.proto.Controller
import neton.quic.proto.Dir
import neton.quic.proto.Event
import neton.quic.proto.Instant
import neton.quic.proto.LongMap
import neton.quic.proto.Side
import neton.quic.proto.StreamEvent
import neton.quic.proto.StreamId
import neton.quic.proto.TransportError
import neton.quic.proto.VarInt
import kotlin.coroutines.ContinuationInterceptor
import kotlin.coroutines.CoroutineContext
import kotlin.coroutines.resume
import kotlin.time.Duration
import neton.quic.proto.Connection as ProtoConnection
import neton.quic.proto.SendDatagramError as ProtoSendDatagramError

// Connections (quinn `connection.rs`): the per-connection driver coroutine and the application's handles.

/**
 * In-progress connection attempt (connection.rs:37). [await] completes when the handshake does.
 *
 * ⚖️ quinn's `Connecting` is a future consumed by `.await` or `into_0rtt`; here those calls hand the connection out
 * once, and later calls throw [IllegalStateException].
 */
class Connecting internal constructor(state: ConnectionState) {
    private var state: ConnectionState? = state

    private fun live(): ConnectionState = state ?: throw IllegalStateException("used after yielding a connection")

    /**
     * Convert into a 0-RTT or 0.5-RTT connection at the cost of weakened security (connection.rs:128).
     *
     * Returns the connection immediately if the local endpoint is able to attempt sending 0/0.5-RTT data, else `null`
     * (this [Connecting] stays usable). For outgoing connections this requires the crypto configuration to resume a
     * previous session, and the server may still reject the 0-RTT data: [ZeroRttAccepted.await] tells. For incoming
     * connections, conversion to 0.5-RTT always succeeds and [ZeroRttAccepted] resolves to true.
     */
    fun into0Rtt(): Pair<Connection, ZeroRttAccepted>? {
        val conn = live()
        if (!(conn.inner.has0rtt() || conn.inner.side() == Side.Server)) return null
        state = null
        return Connection(conn) to ZeroRttAccepted(conn)
    }

    /**
     * Parameters negotiated during the handshake (connection.rs:152). The type is determined by the crypto session.
     * Throws [ConnectionError] if the connection was lost first.
     */
    suspend fun handshakeData(): Any {
        val conn = live()
        while (!conn.handshakeDataSignaled) conn.handshakeDataNotify.await()
        return conn.inner.cryptoSession().handshakeData()
            ?: throw (conn.error ?: throw IllegalStateException("spurious handshake data ready notification"))
    }

    /**
     * The local IP address which was used when the peer established the connection (port 0). `null` for clients, or
     * when the platform does not report it.
     */
    fun localIp(): SocketAddress? = live().inner.localIp()

    /** The peer's UDP address. */
    fun remoteAddress(): SocketAddress = live().inner.remoteAddress()

    /** Wait for the handshake to complete. Throws [ConnectionError] if the connection could not be established. */
    suspend fun await(): Connection {
        val conn = live()
        while (conn.connectedSignal == null) conn.connectedNotify.await()
        state = null
        if (conn.connected) return Connection(conn)
        throw conn.error ?: throw IllegalStateException("connected signaled without connection success or error")
    }
}

/**
 * Completes when a connection is fully established (connection.rs:218). For clients, the result tells whether 0-RTT
 * was accepted; for servers it is meaningless.
 */
class ZeroRttAccepted internal constructor(private val state: ConnectionState) {
    suspend fun await(): Boolean {
        while (state.connectedSignal == null) state.connectedNotify.await()
        return state.connectedSignal == true
    }
}

/**
 * A QUIC connection (connection.rs:285).
 *
 * Closing the connection immediately abandons efforts to deliver data to the peer. Upon receiving CONNECTION_CLOSE
 * the peer *may* drop any stream data not yet delivered to the application. [close] describes in more detail how to
 * gracefully close a connection without losing application data.
 *
 * ⚖️ quinn closes a connection with code 0 when the last handle to it (including its streams) is dropped; Kotlin has
 * no destructors, so [close] with no arguments does that explicitly, and streams do not keep a connection open.
 */
class Connection internal constructor(internal val state: ConnectionState) : AutoCloseable {

    /**
     * Initiate a new outgoing unidirectional stream (connection.rs:292). Streams are cheap and instantaneous to open
     * unless blocked by flow control; the peer won't be notified that a stream has been opened until it is used.
     * Throws [ConnectionError].
     */
    suspend fun openUni(): SendStream {
        val id = open(Dir.Uni)
        return SendStream(state, id, state.inner.side() == Side.Client && state.inner.isHandshaking)
    }

    /**
     * Initiate a new outgoing bidirectional stream (connection.rs:310). The peer can only accept it once something
     * was written to its [SendStream]. Throws [ConnectionError].
     */
    suspend fun openBi(): Pair<SendStream, RecvStream> {
        val id = open(Dir.Bi)
        val is0rtt = state.inner.side() == Side.Client && state.inner.isHandshaking
        return SendStream(state, id, is0rtt) to RecvStream(state, id, is0rtt)
    }

    /** quinn `poll_open`. */
    private suspend fun open(dir: Dir): StreamId {
        while (true) {
            state.error?.let { throw it }
            state.inner.streams().open(dir)?.let { return it }
            state.streamBudgetAvailable[dir.ordinal].await()
        }
    }

    /** Accept the next incoming unidirectional stream (connection.rs:318). Throws [ConnectionError]. */
    suspend fun acceptUni(): RecvStream {
        val id = accept(Dir.Uni)
        return RecvStream(state, id, state.inner.isHandshaking)
    }

    /**
     * Accept the next incoming bidirectional stream (connection.rs:336). The opening side must write to its
     * [SendStream] before the stream can be accepted. Throws [ConnectionError].
     */
    suspend fun acceptBi(): Pair<SendStream, RecvStream> {
        val id = accept(Dir.Bi)
        val is0rtt = state.inner.isHandshaking
        return SendStream(state, id, is0rtt) to RecvStream(state, id, is0rtt)
    }

    /** quinn `poll_accept`. */
    private suspend fun accept(dir: Dir): StreamId {
        while (true) {
            // Check for incoming streams before checking `error` so that already-received streams, which are
            // necessarily finite, can be drained from a closed connection.
            val id = state.inner.streams().accept(dir)
            if (id != null) {
                state.wake() // To send additional stream ID credit
                return id
            }
            state.error?.let { throw it }
            state.streamIncoming[dir.ordinal].await()
        }
    }

    /** Receive an application datagram (connection.rs:344). Throws [ConnectionError]. */
    suspend fun readDatagram(): Bytes {
        while (true) {
            // Buffered datagrams first, so that already-received ones can be drained from a closed connection
            state.inner.datagrams().recv()?.let { return it }
            state.error?.let { throw it }
            state.datagramReceived.await()
        }
    }

    /**
     * Wait for the connection to be closed for any reason (connection.rs:357). Closed connections are often not an
     * error condition at the application layer, e.g. [ConnectionError.LocallyClosed] and
     * [ConnectionError.ApplicationClosed].
     */
    suspend fun closed(): ConnectionError {
        while (true) {
            state.error?.let { return it }
            state.closed.await()
        }
    }

    /** If the connection is closed, the reason why; `null` while it is open. */
    fun closeReason(): ConnectionError? = state.error

    /**
     * Close the connection immediately (connection.rs:418).
     *
     * Pending operations will fail immediately with [ConnectionError.LocallyClosed]. No more data is sent to the peer
     * and the peer may drop buffered data upon receiving the CONNECTION_CLOSE frame. [errorCode] and [reason] are not
     * interpreted, and are provided directly to the peer; [reason] will be truncated to fit in a single packet.
     *
     * Only the peer last receiving application data can be certain that all data is delivered; the only reliable
     * action it can then take is to close the connection, and [Endpoint.waitIdle] gives the final CONNECTION_CLOSE
     * time to be delivered.
     */
    fun close(errorCode: VarInt, reason: ByteArray) {
        state.close(errorCode, Bytes.copyOf(reason))
    }

    /**
     * ⚖️ quinn: dropping the last handle to the connection, which closes it with code 0 and an empty reason unless it
     * is already closed.
     */
    override fun close() {
        if (!state.inner.isClosed) state.implicitClose()
    }

    /**
     * Transmit [data] as an unreliable, unordered application datagram (connection.rs:445). It must fit in a single
     * QUIC packet and be smaller than the maximum dictated by the peer. Previously queued datagrams which are still
     * unsent may be discarded to make space for this datagram, in order of oldest to newest. Throws
     * [SendDatagramError].
     */
    fun sendDatagram(data: Bytes) {
        state.error?.let { throw SendDatagramError.ConnectionLost(it) }
        when (val r = state.inner.datagrams().send(data, true)) {
            null -> state.wake()
            is ProtoSendDatagramError.Blocked -> throw IllegalStateException("unreachable")
            else -> throw r.toDriverError()
        }
    }

    /**
     * Transmit [data] as an unreliable, unordered application datagram, waiting for buffer space during congestion
     * (connection.rs:474), which effectively prioritizes old datagrams over new datagrams. Throws [SendDatagramError].
     */
    suspend fun sendDatagramWait(data: Bytes) {
        while (true) {
            state.error?.let { throw SendDatagramError.ConnectionLost(it) }
            when (val r = state.inner.datagrams().send(data, false)) {
                null -> {
                    state.wake()
                    return
                }
                is ProtoSendDatagramError.Blocked -> state.datagramsUnblocked.await()
                else -> throw r.toDriverError()
            }
        }
    }

    /**
     * The maximum size of datagrams that may be passed to [sendDatagram]; `null` if datagrams are unsupported by the
     * peer or disabled locally (connection.rs:499). Not necessarily the maximum size of received datagrams.
     */
    fun maxDatagramSize(): Int? = state.inner.datagrams().maxSize()

    /**
     * Bytes available in the outgoing datagram buffer. When greater than zero, sending a datagram of at most this
     * size is guaranteed not to cause older datagrams to be dropped.
     */
    fun datagramSendBufferSpace(): Long = state.inner.datagrams().sendBufferSpace()

    /** The side of the connection (client or server). */
    fun side(): Side = state.inner.side()

    /** The peer's UDP address; clients may change addresses at will if the server allows migration. */
    fun remoteAddress(): SocketAddress = state.inner.remoteAddress()

    /**
     * The local IP address which was used when the peer established the connection (port 0); `null` for clients, or
     * when the platform does not report it.
     */
    fun localIp(): SocketAddress? = state.inner.localIp()

    /** Current best estimate of this connection's latency (round-trip-time). */
    fun rtt(): Duration = state.inner.rtt()

    /** Minimum RTT seen on this path, ignoring ack delay. */
    fun minRtt(): Duration = state.inner.minRtt()

    /** Connection statistics. */
    fun stats(): ConnectionStats = state.inner.stats()

    /** Current state of the congestion control algorithm, for debugging purposes (a copy). */
    fun congestionState(): Controller = state.inner.congestionState().cloneBox()

    /**
     * Parameters negotiated during the handshake; guaranteed non-null on fully established connections or after
     * [Connecting.handshakeData] succeeds. The type is determined by the crypto session.
     */
    fun handshakeData(): Any? = state.inner.cryptoSession().handshakeData()

    /** Cryptographic identity of the peer; the type is determined by the crypto session. */
    fun peerIdentity(): Any? = state.inner.cryptoSession().peerIdentity()

    /**
     * A stable identifier for this connection: peer addresses and connection IDs can change, but this value will
     * remain fixed for the lifetime of the connection. ⚖️ quinn uses the address of its shared state; this is that
     * state's identity hash code.
     */
    fun stableId(): Int = state.hashCode()

    /** Update traffic keys spontaneously; this primarily exists for testing purposes. */
    fun forceKeyUpdate() {
        state.inner.forceKeyUpdate()
    }

    /**
     * Derive keying material from this connection's TLS session secrets (RFC 5705). When both peers call this with
     * the same [label] and [context] and outputs of equal length, they get the same bytes. Throws
     * [neton.quic.proto.ExportKeyingMaterialError].
     */
    fun exportKeyingMaterial(output: ByteArray, label: ByteArray, context: ByteArray) {
        state.inner.cryptoSession().exportKeyingMaterial(output, label, context)
    }

    /** Modify the number of remotely initiated unidirectional streams that may be concurrently open. */
    fun setMaxConcurrentUniStreams(count: VarInt) {
        state.inner.setMaxConcurrentStreams(Dir.Uni, count)
        // May need to send MAX_STREAMS to make progress
        state.wake()
    }

    /** Modify the number of remotely initiated bidirectional streams that may be concurrently open. */
    fun setMaxConcurrentBiStreams(count: VarInt) {
        state.inner.setMaxConcurrentStreams(Dir.Bi, count)
        // May need to send MAX_STREAMS to make progress
        state.wake()
    }

    /** See [neton.quic.proto.TransportConfig.sendWindow]. */
    fun setSendWindow(sendWindow: Long) {
        state.inner.setSendWindow(sendWindow)
        state.wake()
    }

    /** See [neton.quic.proto.TransportConfig.receiveWindow]. */
    fun setReceiveWindow(receiveWindow: VarInt) {
        state.inner.setReceiveWindow(receiveWindow)
        state.wake()
    }

    override fun toString(): String = "Connection(${state.handle}, ${state.inner.side()})"
}

private fun ProtoSendDatagramError.toDriverError(): SendDatagramError = when (this) {
    ProtoSendDatagramError.UnsupportedByPeer -> SendDatagramError.UnsupportedByPeer()
    ProtoSendDatagramError.Disabled -> SendDatagramError.Disabled()
    ProtoSendDatagramError.TooLarge -> SendDatagramError.TooLarge()
    is ProtoSendDatagramError.Blocked -> throw IllegalStateException("unreachable")
}

/**
 * The shared state of a connection and its driver (quinn `ConnectionInner` + `State` + `ConnectionDriver`).
 *
 * ⚖️ quinn guards this with a mutex and drives it from a task polled by any runtime thread; here it belongs to the
 * endpoint's reactor thread and needs no lock. The driver is one coroutine per connection ([drive]).
 */
internal class ConnectionState(
    val endpoint: Endpoint,
    val handle: ConnectionHandle,
    val inner: ProtoConnection,
) {
    /** Events from the endpoint (quinn's `conn_events` channel, protocol events only). */
    private val events = ArrayDeque<ConnectionEvent>()

    /** Always set before the connection becomes drained. */
    var error: ConnectionError? = null
        private set

    var connected = false
        private set

    /** quinn's `on_connected` oneshot: the value sent (whether 0-RTT was accepted), `null` until then. */
    var connectedSignal: Boolean? = null
        private set
    val connectedNotify = Notify()

    /** quinn's `on_handshake_data` oneshot. */
    var handshakeDataSignaled = false
        private set
    val handshakeDataNotify = Notify()

    val blockedWriters = LongMap<CancellableContinuation<Unit>>()
    val blockedReaders = LongMap<CancellableContinuation<Unit>>()
    private val stopped = LongMap<Notify>()

    /** Notified when new streams may be locally initiated due to an increase in stream ID flow control budget. */
    val streamBudgetAvailable = arrayOf(Notify(), Notify())

    /** Notified when the peer has initiated a new stream. */
    val streamIncoming = arrayOf(Notify(), Notify())
    val datagramReceived = Notify()
    val datagramsUnblocked = Notify()
    val closed = Notify()

    /** Set when the endpoint's receive loop failed (quinn: the endpoint dropped the connection's channel). */
    private var endpointError: ConnectionError? = null

    // Driver wake-up: the parked driver's continuation, or a pending wake-up while it runs.
    private var driverCont: CancellableContinuation<Unit>? = null
    private var woken = false

    // The protocol timer: armed for [timerDeadline] and re-armed only when the deadline changes (quinn resets its
    // `AsyncTimer` only then). A fired timer wakes the driver, which checks the clock itself.
    private var timerDeadline = Instant.NONE
    private var timerHandle: DisposableHandle? = null
    private val timerFired = Runnable {
        timerHandle = null
        wake()
    }

    /** Wake a parked driver to process I/O (quinn `State::wake`). */
    fun wake() {
        val cont = driverCont
        if (cont != null) {
            driverCont = null
            cont.resume(Unit)
        } else {
            woken = true
        }
    }

    /** An event from the endpoint's receive loop or from the protocol endpoint. */
    fun deliver(event: ConnectionEvent) {
        events.addLast(event)
        wake()
    }

    /** The endpoint switched sockets (quinn's `ConnectionEvent::Rebind`). */
    fun rebind() {
        inner.localAddressChanged()
        wake()
    }

    fun endpointLost(error: ConnectionError) {
        endpointError = error
        wake()
    }

    /**
     * The driver (quinn `ConnectionDriver::poll`), as a loop: process events from the endpoint, send (at most
     * [MAX_TRANSMIT_DATAGRAMS] datagrams), handle an expired timer, forward endpoint and application events; then
     * yield if the send budget ran out, or park until woken or the next timeout. Ends when the connection is drained.
     */
    @OptIn(InternalCoroutinesApi::class)
    suspend fun drive() {
        val context = currentCoroutineContext()
        val delay = context[ContinuationInterceptor] as Delay
        try {
            while (true) {
                woken = false
                endpointError?.let {
                    terminate(it)
                    return
                }
                processConnEvents()
                var keepGoing = driveTransmit()
                // If a timer expires, there might be more to transmit. When we transmit something, we might need to
                // reset a timer. Hence, we must loop until neither happens.
                if (driveTimer(delay, context)) keepGoing = true
                forwardEndpointEvents()
                forwardAppEvents()

                if (inner.isDrained) break
                if (keepGoing) yield() else park()
            }
            checkNotNull(error) { "drained connections always have an error" }
        } catch (e: IoException) {
            // ⚖️ quinn's driver ends with the I/O error and leaves the connection to its handles; here the
            // connection is terminated so that nothing waits on it forever.
            terminate(ConnectionError.Transport(TransportError.INTERNAL_ERROR("I/O error: ${e.message}")))
        } finally {
            timerHandle?.dispose()
            timerHandle = null
            if (error == null) terminate(ConnectionError.Transport(TransportError.INTERNAL_ERROR("connection driver cancelled")))
            endpoint.forget(this)
        }
    }

    private suspend fun park() {
        if (woken) return
        suspendCancellableCoroutine<Unit> { driverCont = it }
    }

    private fun processConnEvents() {
        while (true) inner.handleEvent(events.removeFirstOrNull() ?: return)
    }

    /** quinn `State::drive_transmit`; returns whether the send budget ran out with more to send. */
    private suspend fun driveTransmit(): Boolean {
        var now = endpoint.now()
        var transmits = 0
        val maxDatagrams = endpoint.maxTransmitSegments
        val buf = endpoint.sendBuffer
        while (true) {
            buf.clear()
            // ⚖️ quinn asks for up to `max_datagrams` segments every time and so may overshoot MAX_TRANSMIT_DATAGRAMS by
            // up to 9; asking for no more than what is left keeps the drive's bound exact (SPEC §3).
            val t = inner.pollTransmit(now, minOf(maxDatagrams, MAX_TRANSMIT_DATAGRAMS - transmits), buf) ?: return false
            val segmentSize = t.segmentSize
            val segments = if (segmentSize == null) 1 else (t.size + segmentSize - 1) / segmentSize
            transmits += segments
            val stats = endpoint.driverStats
            if (segments > stats.maxSegmentsInTransmit) stats.maxSegmentsInTransmit = segments
            if (transmits > stats.maxDatagramsInDrive) stats.maxDatagramsInDrive = transmits
            if (!endpoint.send(t, buf)) now = endpoint.now() // waited for the socket

            if (transmits >= MAX_TRANSMIT_DATAGRAMS) {
                // As in quinn: if not all datagrams that could be sent are polled, the connection does not enter the
                // app-limited state and its congestion window keeps growing until the next round (quinn#1126).
                stats.transmitYields += 1
                return true
            }
        }
    }

    /** quinn `State::drive_timer`; returns whether a timeout was handled. */
    @OptIn(InternalCoroutinesApi::class)
    private fun driveTimer(delay: Delay, context: CoroutineContext): Boolean {
        val deadline = inner.pollTimeout()
        if (deadline.isNone) {
            timerDeadline = Instant.NONE
            timerHandle?.dispose()
            timerHandle = null
            return false
        }

        // Use the clock rather than the timer to detect expiry
        val now = endpoint.now()
        if (now >= deadline) {
            inner.handleTimeout(now)
            timerDeadline = Instant.NONE
            return true
        }

        // Avoid resetting the timer when the deadline is unchanged
        if (timerHandle == null || timerDeadline != deadline) {
            timerHandle?.dispose()
            // ⚖️ neton-io's reactor timers have millisecond resolution: round up so that the timer never fires early.
            val millis = (deadline.nanos - now.nanos + 999_999L) / 1_000_000L
            timerHandle = delay.invokeOnTimeout(millis, timerFired, context)
            timerDeadline = deadline
        }
        return false
    }

    private fun forwardEndpointEvents() {
        while (true) endpoint.handleEndpointEvent(this, inner.pollEndpointEvents() ?: return)
    }

    /** quinn `State::forward_app_events`. */
    private fun forwardAppEvents() {
        while (true) {
            when (val event = inner.poll() ?: return) {
                Event.HandshakeDataReady -> signalHandshakeData()
                Event.Connected -> {
                    connected = true
                    signalConnected(inner.accepted0rtt())
                    if (inner.side() == Side.Client && !inner.accepted0rtt()) {
                        // Wake up rejected 0-RTT streams so they can fail immediately with `ZeroRttRejected` errors.
                        wakeAll(blockedWriters)
                        wakeAll(blockedReaders)
                        wakeAllNotify(stopped)
                    }
                }
                is Event.ConnectionLost -> terminate(event.reason)
                is StreamEvent.Writable -> wakeStream(event.id, blockedWriters)
                is StreamEvent.Opened -> streamIncoming[event.dir.ordinal].notifyWaiters()
                Event.DatagramReceived -> datagramReceived.notifyWaiters()
                Event.DatagramsUnblocked -> datagramsUnblocked.notifyWaiters()
                is StreamEvent.Readable -> wakeStream(event.id, blockedReaders)
                // Might mean any number of streams are ready, so we wake up everyone
                is StreamEvent.Available -> streamBudgetAvailable[event.dir.ordinal].notifyWaiters()
                is StreamEvent.Finished -> wakeStreamNotify(event.id, stopped)
                is StreamEvent.Stopped -> {
                    wakeStreamNotify(event.id, stopped)
                    wakeStream(event.id, blockedWriters)
                }
            }
        }
    }

    private fun signalHandshakeData() {
        if (handshakeDataSignaled) return
        handshakeDataSignaled = true
        handshakeDataNotify.notifyWaiters()
    }

    private fun signalConnected(value: Boolean) {
        if (connectedSignal != null) return
        connectedSignal = value
        connectedNotify.notifyWaiters()
    }

    /** Used to wake up all blocked futures when the connection becomes closed for any reason. */
    fun terminate(reason: ConnectionError) {
        error = reason
        signalHandshakeData()
        wakeAll(blockedWriters)
        wakeAll(blockedReaders)
        streamBudgetAvailable[0].notifyWaiters()
        streamBudgetAvailable[1].notifyWaiters()
        streamIncoming[0].notifyWaiters()
        streamIncoming[1].notifyWaiters()
        datagramReceived.notifyWaiters()
        datagramsUnblocked.notifyWaiters()
        signalConnected(false)
        wakeAllNotify(stopped)
        closed.notifyWaiters()
    }

    fun close(errorCode: VarInt, reason: Bytes) {
        inner.close(endpoint.now(), errorCode, reason)
        terminate(ConnectionError.LocallyClosed)
        wake()
    }

    /** Close for a reason other than the application's explicit request. */
    fun implicitClose() {
        close(VarInt(0), Bytes.EMPTY)
    }

    /** Whether a 0-RTT stream may still be used (quinn `check_0rtt`). */
    fun check0rtt(): Boolean = inner.isHandshaking || inner.accepted0rtt() || inner.side() == Side.Server

    // ---- stream waiters ----

    /** Suspend until the stream [id] may be writable again (quinn inserts the task's waker into `blocked_writers`). */
    suspend fun awaitWritable(id: StreamId) {
        suspendCancellableCoroutine { blockedWriters.put(id.value, it) }
    }

    /** Suspend until the stream [id] may be readable again (`blocked_readers`). */
    suspend fun awaitReadable(id: StreamId) {
        suspendCancellableCoroutine { blockedReaders.put(id.value, it) }
    }

    /** Suspend until the stream [id] is stopped or finished (quinn's per-stream `Notify` in `stopped`). */
    suspend fun awaitStopped(id: StreamId) {
        val notify = stopped.get(id.value) ?: Notify().also { stopped.put(id.value, it) }
        notify.await()
    }

    /**
     * A stream handle is closed: forget its waiter in [wakers], resuming it if it is still waiting. quinn only removes
     * the waker, since a Rust stream cannot be dropped while one of its operations borrows it; a Kotlin handle can be
     * closed while another coroutine waits on it, and that coroutine must see the stream closed rather than hang.
     */
    fun releaseWaiter(id: StreamId, wakers: LongMap<CancellableContinuation<Unit>>) {
        wakeStream(id, wakers)
    }

    private fun wakeStream(id: StreamId, wakers: LongMap<CancellableContinuation<Unit>>) {
        val cont = wakers.get(id.value) ?: return
        wakers.remove(id.value)
        cont.resume(Unit)
    }

    private fun wakeAll(wakers: LongMap<CancellableContinuation<Unit>>) {
        if (wakers.size == 0) return
        val all = ArrayList<CancellableContinuation<Unit>>(wakers.size)
        wakers.drainValuesTo(all)
        for (cont in all) cont.resume(Unit)
    }

    private fun wakeStreamNotify(id: StreamId, notifies: LongMap<Notify>) {
        val notify = notifies.get(id.value) ?: return
        notifies.remove(id.value)
        notify.notifyWaiters()
    }

    private fun wakeAllNotify(notifies: LongMap<Notify>) {
        if (notifies.size == 0) return
        val all = ArrayList<Notify>(notifies.size)
        notifies.drainValuesTo(all)
        for (notify in all) notify.notifyWaiters()
    }

    private companion object {
        /**
         * The maximum amount of datagrams which will be produced in a single `driveTransmit` call (quinn
         * `MAX_TRANSMIT_DATAGRAMS`). This limits the amount of CPU resources consumed by datagram generation, and
         * allows other tasks (like receiving ACKs) to run in between.
         */
        const val MAX_TRANSMIT_DATAGRAMS = 20
    }
}
