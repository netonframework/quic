@file:OptIn(kotlinx.cinterop.ExperimentalForeignApi::class)

package neton.quic

import kotlinx.cinterop.toKString
import kotlinx.coroutines.async
import platform.posix.getenv
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertNotNull
import kotlin.time.Duration.Companion.minutes
import kotlin.time.TimeSource

/**
 * A measurement, not a check (runs only with `NETON_QUIC_TRANSFER_PROBE=<rounds>`): 4 MiB client → server on one
 * endpoint and one reactor thread, as `DriverBudgetTest.sendDrivesAreBounded`, repeated so that a profiler can sample
 * it. Prints each round's time and the driver's receive counters.
 */
class TransferProbeTest {
    private val rounds = getenv("NETON_QUIC_TRANSFER_PROBE")?.toKString()?.toIntOrNull() ?: 0

    @Test
    fun probe() {
        if (rounds <= 0) return
        quicTest(10.minutes) {
            val endpoint = endpoint()
            val clientD = async { endpoint.connect(endpoint.localAddr(), "localhost").await() }
            val server = assertNotNull(endpoint.accept()).await()
            val client = clientD.await()
            val data = genData(4 * 1024 * 1024, 1)
            repeat(rounds) { round ->
                val stats = endpoint.driverStats
                val messagesBefore = stats.receivedMessages
                val yieldsBefore = stats.receiveYields
                val started = TimeSource.Monotonic.markNow()
                val reader = async { server.acceptUni().readToEnd() }
                val send = client.openUni()
                send.writeAll(data)
                send.finish()
                assertContentEquals(data, reader.await())
                val elapsed = started.elapsedNow()
                val cs = client.stats()
                println(
                    "transfer probe: round $round: 4 MiB in $elapsed; rtt ${cs.path.rtt}; received messages " +
                        "${stats.receivedMessages - messagesBefore}, receive yields ${stats.receiveYields - yieldsBefore}",
                )
            }
            endpoint.shutdown()
        }
    }
}
