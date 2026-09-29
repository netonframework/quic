package neton.quic

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.Job
import kotlinx.coroutines.channels.Channel
import kotlinx.coroutines.currentCoroutineContext
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import neton.io.core.ClosedException
import neton.io.net.BATCH_SIZE
import neton.io.net.RecvBatch
import neton.io.net.SocketAddress
import neton.io.net.Transmit
import neton.io.net.UdpOptions
import neton.io.net.UdpSocket
import neton.io.net.bindUdp
import neton.quic.proto.LinkImpairment
import kotlin.time.Duration

/**
 * An impaired link between QUIC endpoints on loopback, for driver tests: a UDP relay on the test's reactor. Clients
 * send to [address]; the relay forwards their datagrams from its back socket to the server, and the server's replies
 * back to the client that last sent (one client per relay). Each direction applies a [LinkImpairment] (seeded loss,
 * duplication, reordering, targeted drops) and a fixed one-way [latency], so the real driver, its timers and its
 * pacing see loss and reordering that loopback never produces.
 *
 * GRO batches are split into their datagrams and GSO is not used on the way out, so every datagram meets its fate on
 * its own. Each direction sends through one coroutine in release order (a UDP socket allows one parked send).
 */
internal class LossyRelay private constructor(
    private val front: UdpSocket,
    private val back: UdpSocket,
    private val server: SocketAddress,
    val clientToServer: LinkImpairment,
    val serverToClient: LinkImpairment,
    private val latency: Duration,
    private val job: Job,
    private val scope: CoroutineScope,
) : AutoCloseable {
    /** Where clients send to reach the server through the relay. */
    val address: SocketAddress = front.localAddress

    private var client: SocketAddress? = null

    /** Datagrams forwarded (copies included), per direction. */
    var forwardedToServer = 0L
        private set
    var forwardedToClient = 0L
        private set

    private val toServer = Channel<ByteArray>(Channel.UNLIMITED)
    private val toClient = Channel<ByteArray>(Channel.UNLIMITED)

    private fun start() {
        scope.launch(start = CoroutineStart.UNDISPATCHED) {
            pump(front, clientToServer, toServer) { src -> client = src }
        }
        scope.launch(start = CoroutineStart.UNDISPATCHED) { pump(back, serverToClient, toClient) {} }
        scope.launch { sender(back, toServer) { server } }
        scope.launch { sender(front, toClient) { client } }
    }

    private suspend fun pump(socket: UdpSocket, impairment: LinkImpairment, out: Channel<ByteArray>, onSource: (SocketAddress) -> Unit) {
        val slot = (65535 * maxOf(1, socket.groSegments)).coerceAtMost(1 shl 20)
        val batch = RecvBatch(minOf(8, BATCH_SIZE), slot)
        try {
            while (true) {
                val n = try {
                    socket.recv(batch)
                } catch (e: ClosedException) {
                    return
                }
                for (i in 0 until n) {
                    val len = batch.length(i)
                    if (len == 0) continue
                    onSource(batch.source(i))
                    val stride = batch.stride(i).let { if (it <= 0) len else it }
                    var start = 0
                    while (start < len) {
                        val end = minOf(start + stride, len)
                        val offset = batch.offset(i)
                        val data = batch.buffer.copyOfRange(offset + start, offset + end)
                        for ((copy, extra) in impairment.fate(data).withIndex()) {
                            val bytes = if (copy == 0) data else data.copyOf()
                            val wait = latency + extra
                            if (wait.isPositive()) {
                                scope.launch {
                                    delay(wait)
                                    out.trySend(bytes)
                                }
                            } else {
                                out.trySend(bytes)
                            }
                        }
                        start = end
                    }
                }
            }
        } finally {
            batch.close()
        }
    }

    private suspend fun sender(socket: UdpSocket, queue: Channel<ByteArray>, destination: () -> SocketAddress?) {
        val tx = Transmit(65535)
        try {
            for (bytes in queue) {
                val to = destination() ?: continue
                bytes.copyInto(tx.buffer)
                tx.length = bytes.size
                tx.segmentSize = 0
                tx.ecn = null
                tx.setDestination(to)
                tx.setSource(null)
                try {
                    if (!socket.trySend(tx)) socket.send(tx)
                } catch (e: ClosedException) {
                    return
                }
                if (socket === back) forwardedToServer++ else forwardedToClient++
            }
        } finally {
            tx.close()
        }
    }

    /** Stop relaying; datagrams in flight are dropped. Idempotent. */
    override fun close() {
        toServer.close()
        toClient.close()
        front.close()
        back.close()
        job.cancel()
    }

    override fun toString(): String = "c→s $clientToServer; s→c $serverToClient"

    companion object {
        /**
         * Start a relay to [server] on the current reactor; its coroutines are children of the caller's. [close] it
         * before the test's scope ends.
         */
        suspend fun start(
            server: SocketAddress,
            clientToServer: LinkImpairment,
            serverToClient: LinkImpairment,
            latency: Duration = Duration.ZERO,
        ): LossyRelay {
            // Large buffers: bursts into the relay are not to become loss the impairment did not decide
            val options = UdpOptions(sendBufferSize = 4 shl 20, receiveBufferSize = 4 shl 20)
            val front = bindUdp(V4_LOCALHOST, options)
            val back = bindUdp(V4_LOCALHOST, options)
            val context = currentCoroutineContext()
            val job = Job(context[Job])
            val relay = LossyRelay(front, back, server, clientToServer, serverToClient, latency, job, CoroutineScope(context + job))
            relay.start()
            return relay
        }
    }
}
