package neton.quic

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Job
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import neton.io.core.monotonicNanos
import neton.quic.proto.ConnectionError
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * SPEC §3 "测试": one connection sending and receiving continuously on an endpoint does not keep the other connections
 * of that endpoint from completing handshakes and small request / response exchanges within a bounded time.
 *
 * Everything runs on one reactor (the single-reactor model of §3): the server endpoint under test, the heavy client's
 * endpoint and the light clients' endpoint, so the heavy flow competes with the light ones for the same thread. The
 * heavy connection uploads and downloads at full speed (flow-controlled only) throughout the light phase; the light
 * connections are opened while it runs, each doing a handshake and [REQUESTS] small requests.
 *
 * What the light latency under load consists of (SPEC §11.8): the light datagrams queue behind the heavy flow's
 * in-flight data (bounded by its stream flow-control window) in the server socket's receive queue and are handled in
 * arrival order, so it is about one window's worth of processing time. The bounds stay well below the 1 s it takes to
 * recover a lost Initial (initial RTT 333 ms) and the seconds a starved connection would wait for the heavy flow to end,
 * so either fails the test. Since the endpoint raises its receive buffer (DriverConfig.receiveBufferSize, SPEC §11.13)
 * the heavy flow no longer loses datagrams and fills its window, so the light requests wait about that long: request
 * p99 up to 298 ms and max 564 ms measured on Windows CI (Linux and macOS up to 193 / 446 ms); handshakes up to 306 ms.
 */
class FairnessTest {

    @Test
    fun heavyConnectionDoesNotStarveOthers() = quicTest(120.seconds) {
        val result = measure(heavy = true)
        println("fairness (heavy load): $result")
        // The load was real and concurrent with the light phase
        assertTrue(result.heavyBytes >= 4L * 1024 * 1024, "the heavy connection moved only ${result.heavyBytes} bytes during the light phase")
        assertTrue(result.handshakes.size == LIGHT_CONNECTIONS, "handshakes completed: ${result.handshakes.size}")
        assertTrue(result.requests.size == LIGHT_CONNECTIONS * REQUESTS, "requests completed: ${result.requests.size}")
        assertTrue(result.handshakeMaxMs <= HANDSHAKE_BOUND_MS, "handshake max ${result.handshakeMaxMs} ms > $HANDSHAKE_BOUND_MS ms")
        assertTrue(result.requestP99Ms <= REQUEST_P99_BOUND_MS, "request p99 ${result.requestP99Ms} ms > $REQUEST_P99_BOUND_MS ms")
        assertTrue(result.requestMaxMs <= REQUEST_MAX_BOUND_MS, "request max ${result.requestMaxMs} ms > $REQUEST_MAX_BOUND_MS ms")
    }

    /** The same light phase without the heavy connection: the reference the bounds are compared with (not asserted). */
    @Test
    fun baselineWithoutHeavyConnection() = quicTest(60.seconds) {
        val result = measure(heavy = false)
        println("fairness (baseline): $result")
        assertTrue(result.requests.size == LIGHT_CONNECTIONS * REQUESTS)
    }

    private class Result(val handshakes: List<Long>, val requests: List<Long>, val heavyBytes: Long, val lightPhaseMs: Long) {
        val handshakeMaxMs get() = ms(handshakes.max())
        val requestP99Ms get() = ms(percentile(requests, 0.99))
        val requestMaxMs get() = ms(requests.max())

        override fun toString(): String =
            "handshake p50 ${ms(percentile(handshakes, 0.5))} / max $handshakeMaxMs ms; " +
                "request p50 ${ms(percentile(requests, 0.5))} / p99 $requestP99Ms / max $requestMaxMs ms " +
                "(${requests.size} requests); heavy ${heavyBytes / (1024 * 1024)} MiB in ${lightPhaseMs} ms"
    }

    private suspend fun CoroutineScope.measure(heavy: Boolean): Result {
        val factory = EndpointFactory()
        val server = factory.endpoint()
        val serverAddr = server.localAddr()
        var heavyBytes = 0L
        val handlers = ArrayList<Job>()

        val acceptor = launch {
            while (true) {
                val incoming = server.accept() ?: break
                // Each handshake in its own coroutine: the acceptor must not serialize them
                handlers += launch { runCatching { incoming.await() }.getOrNull()?.let { serve(it) } }
            }
        }

        // The heavy connection: an upload and a download, both continuous (counted on the client side)
        var heavyConn: Connection? = null
        var heavyClient: Endpoint? = null
        val heavyJobs = ArrayList<Job>()
        if (heavy) {
            val client = factory.endpoint()
            heavyClient = client
            val conn = client.connect(serverAddr, "localhost").await()
            heavyConn = conn
            heavyJobs += launch {
                val chunk = ByteArray(64 * 1024)
                val up = conn.openUni()
                try {
                    while (true) {
                        up.writeAll(chunk)
                        heavyBytes += chunk.size
                    }
                } catch (_: WriteError) {
                }
            }
            heavyJobs += launch {
                try {
                    val down = conn.acceptUni()
                    while (true) heavyBytes += (down.readChunk() ?: break).bytes.size
                } catch (_: Exception) {
                }
            }
            // Warm up: the heavy flow is at full speed before the light phase starts
            while (heavyBytes < 16L * 1024 * 1024) delay(5.milliseconds)
        }

        val lightClient = factory.endpoint()
        val heavyAtStart = heavyBytes
        val start = monotonicNanos()
        val results = List(LIGHT_CONNECTIONS) { i ->
            async {
                delay((i * 20).milliseconds) // arrivals spread over the phase
                val t0 = monotonicNanos()
                val conn = lightClient.connect(serverAddr, "localhost").await()
                val handshake = monotonicNanos() - t0
                val latencies = LongArray(REQUESTS)
                val request = ByteArray(32) { it.toByte() }
                for (r in 0 until REQUESTS) {
                    val t = monotonicNanos()
                    val (send, recv) = conn.openBi()
                    send.writeAll(request)
                    send.finish()
                    val reply = recv.readToEnd(1024)
                    latencies[r] = monotonicNanos() - t
                    check(reply.size == request.size)
                    delay(5.milliseconds)
                }
                conn.close()
                handshake to latencies
            }
        }.awaitAll()
        val lightPhaseMs = (monotonicNanos() - start) / 1_000_000
        val heavyDuring = heavyBytes - heavyAtStart

        heavyConn?.close()
        heavyJobs.forEach { it.cancel() }
        heavyClient?.shutdown()
        lightClient.shutdown()
        server.shutdown()
        acceptor.join()
        handlers.forEach { it.cancel() }

        return Result(results.map { it.first }, results.flatMap { it.second.asList() }, heavyDuring, lightPhaseMs)
    }

    /**
     * The server side of a connection: its uni stream is drained (and answered by a continuous download on a uni
     * stream of its own, the heavy flow); every bi stream is a request echoed back.
     */
    private suspend fun CoroutineScope.serve(conn: Connection) {
        launch {
            try {
                val up = conn.acceptUni()
                launch {
                    val chunk = ByteArray(64 * 1024)
                    try {
                        val down = conn.openUni()
                        while (true) down.writeAll(chunk)
                    } catch (_: Exception) {
                    }
                }
                while (true) up.readChunk() ?: break
            } catch (_: Exception) {
            }
        }
        while (true) {
            val (send, recv) = try {
                conn.acceptBi()
            } catch (_: ConnectionError) {
                return
            }
            launch {
                try {
                    send.writeAll(recv.readToEnd(1024))
                    send.finish()
                } catch (_: Exception) {
                }
            }
        }
    }

    private companion object {
        const val LIGHT_CONNECTIONS = 20
        const val REQUESTS = 20

        // Bounds (SPEC §11.8 records the measured values they were chosen from)
        const val HANDSHAKE_BOUND_MS = 500L
        const val REQUEST_P99_BOUND_MS = 500L
        const val REQUEST_MAX_BOUND_MS = 900L

        fun ms(nanos: Long): Long = nanos / 1_000_000

        fun percentile(values: List<Long>, p: Double): Long {
            val sorted = values.sorted()
            return sorted[((sorted.size - 1) * p).toInt()]
        }
    }
}
