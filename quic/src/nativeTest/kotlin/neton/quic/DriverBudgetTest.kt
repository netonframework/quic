package neton.quic

import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.yield
import neton.io.net.Transmit
import neton.io.net.bindUdp
import neton.quic.proto.EndpointConfig
import neton.quic.proto.ServerConfig
import neton.quic.proto.TransportConfig
import neton.quic.proto.VarInt
import neton.quic.proto.default
import neton.quic.proto.withCrypto
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

/**
 * The driver's budgets and the stream handles' single-operation rule (SPEC §3): not in quinn's `tests.rs`, since
 * quinn's budgets are not observable and Rust's borrow rules make concurrent operations on one stream impossible.
 */
class DriverBudgetTest {

    /** A flood of datagrams is handled in turns of at most `maxDatagramsPerTurn`, each ending in a yield. */
    @Test
    fun receiveTurnsAreBounded() = quicTest {
        val factory = EndpointFactory()
        val limit = 8
        val server = Endpoint.create(
            EndpointConfig.default(),
            ServerConfig.withCrypto(factory.serverCrypto),
            bindLocalV4(),
            DriverConfig(maxDatagramsPerTurn = limit),
        )
        val target = server.localAddr()

        // Junk the protocol endpoint drops at once: the cost is the receive loop's own.
        val flooder = bindLocalV4()
        val tx = Transmit(64)
        tx.length = 20
        tx.setDestination(target)
        // Meanwhile another coroutine counts how often it gets the thread: the receive loop must let it in.
        var otherRuns = 0
        val other = launch {
            while (true) {
                otherRuns += 1
                yield()
            }
        }
        // Bursts well above the turn's limit, small enough for a default receive buffer (Linux keeps a few hundred
        // small datagrams; with a batch size of 32, a turn then ends in the middle of a received batch)
        val stats = server.driverStats
        val count = 2_000
        repeat(count / 100) {
            repeat(100) { flooder.trySend(tx) }
            delay(2.milliseconds)
        }
        val deadline = kotlin.time.TimeSource.Monotonic.markNow() + 5.seconds
        while (stats.receivedMessages < count / 4 && deadline.hasNotPassedNow()) delay(10.milliseconds)
        other.cancel()
        tx.close()
        flooder.close()

        println(
            "receive budget: ${stats.receivedMessages} messages, ${stats.receiveYields} yields, " +
                "max ${stats.maxMessagesInTurn} per turn (limit $limit), other coroutine ran $otherRuns times",
        )
        assertTrue(stats.receivedMessages >= count / 4, "only ${stats.receivedMessages} datagrams arrived")
        assertTrue(stats.maxMessagesInTurn <= limit, "a turn handled ${stats.maxMessagesInTurn} > $limit messages")
        assertTrue(
            stats.receiveYields >= stats.receivedMessages / limit / 2,
            "${stats.receiveYields} yields for ${stats.receivedMessages} messages in turns of $limit",
        )
        assertTrue(otherRuns >= stats.receiveYields / 2, "other coroutine ran $otherRuns times, receive loop yielded ${stats.receiveYields}")
        server.shutdown()
    }

    /** A bulk transfer never sends more than 20 datagrams per drive or 10 segments per transmit. */
    @Test
    fun sendDrivesAreBounded() = quicTest(30.seconds) {
        val endpoint = endpoint()
        val clientD = async { endpoint.connect(endpoint.localAddr(), "localhost").await() }
        val server = assertNotNull(endpoint.accept()).await()
        val client = clientD.await()
        val data = genData(4 * 1024 * 1024, 1)
        val reader = async { server.acceptUni().readToEnd() }
        val started = kotlin.time.TimeSource.Monotonic.markNow()
        val send = client.openUni()
        send.writeAll(data)
        send.finish()
        assertContentEquals(data, reader.await())
        val elapsed = started.elapsedNow()
        // What limits the rate (a Windows run moved about 4 MiB/s, Linux about 15): loss, congestion window, RTT.
        val cs = client.stats()
        println(
            "transfer: 4 MiB in $elapsed; client path: rtt ${cs.path.rtt}, min ${cs.path.minRtt}, cwnd ${cs.path.cwnd}, " +
                "sent ${cs.path.sentPackets}, lost ${cs.path.lostPackets}, congestion events ${cs.path.congestionEvents}; " +
                "client udp tx ${cs.udpTx.datagrams} datagrams in ${cs.udpTx.ios} sends; server udp rx ${server.stats().udpRx.datagrams}; " +
                "socket buffers send ${endpoint.socket.sendBufferSize()} / receive ${endpoint.socket.receiveBufferSize()}",
        )

        val stats = endpoint.driverStats
        println(
            "send budget: max ${stats.maxDatagramsInDrive} datagrams per drive, max ${stats.maxSegmentsInTransmit} " +
                "segments per transmit, ${stats.transmitYields} yields",
        )
        assertTrue(stats.maxDatagramsInDrive <= 20, "a drive sent ${stats.maxDatagramsInDrive} datagrams")
        assertTrue(stats.maxSegmentsInTransmit <= 10, "a transmit had ${stats.maxSegmentsInTransmit} segments")
        assertTrue(stats.transmitYields > 0, "a 4 MiB transfer never used a full send budget")
        endpoint.shutdown()
    }

    @Test
    fun concurrentReadIsRefused() = quicTest {
        val (client, server, endpoint) = connectedPair()
        val send = client.openUni()
        send.writeAll("x".encodeToByteArray())
        val recv = server.acceptUni()
        recv.readExact(ByteArray(1))
        val first = launch(start = CoroutineStart.UNDISPATCHED) { recv.read(ByteArray(8)) }
        assertFailsWith<IllegalStateException> { recv.read(ByteArray(8)) }
        assertFailsWith<IllegalStateException> { recv.receivedReset() }
        send.writeAll("yz".encodeToByteArray())
        first.join()
        endpoint.shutdown()
    }

    @Test
    fun concurrentWriteIsRefused() = quicTest {
        val (client, _, endpoint) = connectedPair(TransportConfig().streamReceiveWindow(VarInt(1000)))
        val send = client.openUni()
        // The peer never reads: the first write parks on flow control
        val first = launch(start = CoroutineStart.UNDISPATCHED) { runCatching { send.writeAll(ByteArray(10_000)) } }
        assertTrue(first.isActive, "the first write should be parked")
        assertFailsWith<IllegalStateException> { send.write(ByteArray(1)) }
        first.cancel()
        endpoint.shutdown()
    }

    /** Closing a stream while another coroutine waits on it resumes that coroutine instead of leaving it parked. */
    @Test
    fun closeResumesParkedRead() = quicTest {
        val (client, server, endpoint) = connectedPair()
        val send = client.openUni()
        send.writeAll("x".encodeToByteArray())
        val recv = server.acceptUni()
        recv.readExact(ByteArray(1))
        val read = async(start = CoroutineStart.UNDISPATCHED) { recv.read(ByteArray(8)) }
        assertTrue(read.isActive)
        recv.close()
        assertEquals(-1, read.await(), "a read parked on a closed stream ends like a read after stop")
        assertEquals(VarInt(0), send.stopped())
        endpoint.shutdown()
    }

    @Test
    fun closeResumesParkedWrite() = quicTest {
        val (client, _, endpoint) = connectedPair(TransportConfig().streamReceiveWindow(VarInt(1000)))
        val send = client.openUni()
        val write = async(start = CoroutineStart.UNDISPATCHED) { runCatching { send.writeAll(ByteArray(10_000)) } }
        assertTrue(write.isActive, "the write should be parked")
        send.close()
        val e = write.await().exceptionOrNull()
        assertEquals(WriteError.ClosedStream(), e, "a write parked on a closed stream fails with ClosedStream")
        endpoint.shutdown()
    }
}
