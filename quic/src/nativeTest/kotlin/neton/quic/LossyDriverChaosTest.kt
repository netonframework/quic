package neton.quic

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import neton.io.bytes.Bytes
import neton.quic.proto.ConnectionError
import neton.quic.proto.LinkImpairment
import neton.quic.proto.NativeKeys
import neton.quic.proto.TransportConfig
import neton.quic.proto.VarInt
import neton.quic.proto.settledNativeKeys
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.fail
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

// The driver counterpart of `LossyChaosTest`: per seed, a random impairment through `LossyRelay`, concurrent echo
// streams under small windows of which some are cancelled mid-flight (the coroutine), reset by the client, or stopped
// by the server, random key updates and datagrams; the connection must stay up, every intact stream must echo its
// data, and after shutdown every native key must be released. A failure names its seed.

class LossyDriverChaosTest {
    private enum class Fate { Intact, Cancel, Reset, Stop }

    private suspend fun scenario(seed: Long) {
        val rng = Random(seed)
        val loss = rng.nextDouble(0.0, 0.15)
        val duplicate = rng.nextDouble(0.0, 0.1)
        val reorder = rng.nextDouble(0.0, 0.2)
        val window = 16 * 1024 + rng.nextInt(64 * 1024)
        val describe = "seed $seed: loss $loss dup $duplicate reorder $reorder window $window"
        val transport = TransportConfig()
            .streamReceiveWindow(VarInt(window.toLong()))
            .receiveWindow(VarInt(window * 3L))
            .maxConcurrentBidiStreams(VarInt(6))
        val factory = EndpointFactory()
        val serverEp = factory.endpointWithConfig(transport)
        val clientEp = factory.endpointWithConfig(transport)
        val relay = LossyRelay.start(
            serverEp.localAddr(),
            LinkImpairment.lossy(seed * 2, loss, duplicate, reorder),
            LinkImpairment.lossy(seed * 2 + 1, loss, duplicate, reorder),
            (1 + rng.nextInt(5)).milliseconds,
        )
        coroutineScope {
            val serverSide = async { assertNotNull(serverEp.accept()).await() }
            val client = clientEp.connect(relay.address, "localhost").await()
            val server = serverSide.await()
            // The server echoes; a stream whose first byte asks for it is stopped after some data
            val echo = launch {
                while (true) {
                    val (send, recv) = try { server.acceptBi() } catch (e: ConnectionError) { break }
                    launch {
                        try {
                            val head = ByteArray(1)
                            recv.readExact(head)
                            send.writeAll(head)
                            val buf = ByteArray(8192)
                            var total = 0
                            while (true) {
                                val n = recv.read(buf)
                                if (n < 0) break
                                total += n
                                if (head[0].toInt() == 1 && total > 20_000) {
                                    recv.stop(VarInt(9))
                                    send.reset(VarInt(9))
                                    return@launch
                                }
                                send.writeAll(buf, 0, n)
                            }
                            send.finish()
                        } catch (e: ReadError.Reset) {
                            send.reset(VarInt(8))
                        } catch (e: ReadExactError) {
                        } catch (e: WriteError.Stopped) {
                        } finally {
                            // The lifecycle rules (SPEC §3): without these the stream is never freed, the server never
                            // grants more stream credit, and the client's next openBi waits until the idle timeout
                            send.close()
                            recv.close()
                        }
                    }
                }
            }
            val updates = launch {
                while (true) {
                    delay((10 + rng.nextInt(100)).milliseconds)
                    if (rng.nextBoolean()) client.forceKeyUpdate() else server.forceKeyUpdate()
                }
            }
            val datagrams = launch {
                repeat(200) { runCatching { client.sendDatagram(Bytes.wrap(ByteArray(1 + rng.nextInt(900)))) }; delay(2.milliseconds) }
            }
            val drain = launch { while (true) server.readDatagram() }

            val fates = List(24) { Fate.entries[if (rng.nextInt(3) == 0) 1 + rng.nextInt(3) else 0] }
            fates.mapIndexed { i, fate ->
                val size = if (fate == Fate.Stop) 30_000 + rng.nextInt(90_000) else 1 + rng.nextInt(120_000)
                val data = genData(size, seed * 100 + i).also { it[0] = if (fate == Fate.Stop) 1 else 0 }
                val pause = rng.nextInt(50).milliseconds
                async {
                    val (send, recv) = client.openBi()
                    var written: Result<Unit>? = null
                    var read: Result<ByteArray>? = null
                    // Failures are results here, not failures of the scope: a stopped stream is expected to fail
                    val job = launch {
                        val reader = async { runCatching { recv.readToEnd() } }
                        written = runCatching { send.writeAll(data); send.finish() }
                        read = reader.await()
                    }
                    when (fate) {
                        Fate.Intact, Fate.Stop -> job.join()
                        Fate.Cancel, Fate.Reset -> {
                            delay(pause)
                            job.cancel()
                            job.join()
                            if (fate == Fate.Reset) runCatching { send.reset(VarInt(7)) } else send.close()
                            recv.close()
                            return@async
                        }
                    }
                    val w = checkNotNull(written)
                    val r = checkNotNull(read)
                    if (fate == Fate.Intact) {
                        w.getOrElse { fail("$describe: write on stream ${send.id} failed: $it") }
                        assertContentEquals(data, r.getOrElse { fail("$describe: read on stream ${send.id} failed: $it") },
                            "$describe: stream ${send.id} corrupted")
                    } else {
                        val e = r.exceptionOrNull()
                        val reset = ((e as? ReadToEndError.Read)?.error as? ReadError.Reset)?.errorCode
                        assertEquals(VarInt(9), reset, "$describe: stopped stream ${send.id} ended with $e")
                        w.exceptionOrNull()?.let { assertEquals(VarInt(9), (it as? WriteError.Stopped)?.errorCode, "$describe: $it") }
                        send.close()
                    }
                }
            }.awaitAll()
            assertNull(client.closeReason(), describe)
            assertNull(server.closeReason(), describe)
            updates.cancel(); datagrams.cancel(); drain.cancel(); echo.cancel()
            clientEp.shutdown()
            serverEp.shutdown()
            clientEp.waitIdle()
            serverEp.waitIdle()
            relay.close()
        }
    }

    @OptIn(ExperimentalForeignApi::class)
    private fun seeds(): LongRange {
        val spec = platform.posix.getenv("QUIC_DRIVER_CHAOS_SEEDS")?.toKString() ?: return 0L until 4L
        val (from, until) = spec.split(":").map { it.trim().toLong() }
        return from until until
    }

    @Test
    fun chaos() {
        for (seed in seeds()) {
            val baseline = settledNativeKeys()
            quicTest(120.seconds) {
                try {
                    withTimeout(100.seconds) { scenario(seed) }
                } catch (e: Throwable) {
                    throw AssertionError("seed $seed: $e", e)
                }
                assertEquals(baseline, NativeKeys.live, "seed $seed: native key contexts left after both endpoints went idle")
            }
        }
    }
}
