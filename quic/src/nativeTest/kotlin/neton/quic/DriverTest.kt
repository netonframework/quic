package neton.quic

import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import kotlinx.coroutines.yield
import neton.io.bytes.Bytes
import neton.io.core.monotonicNanos
import neton.io.net.bindUdp
import neton.quic.proto.ConnectionError
import neton.quic.proto.EndpointConfig
import neton.quic.proto.default
import neton.quic.proto.IdleTimeout
import neton.quic.proto.RandomConnectionIdGenerator
import neton.quic.proto.TestTls
import neton.quic.proto.TransportConfig
import neton.quic.proto.VarInt
import kotlin.test.Ignore
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds

/**
 * quinn `src/tests.rs`, test for test, over real loopback UDP with the mock TLS session. quinn's `tokio::spawn`ed
 * tasks are coroutines launched in the test's scope; a failure in one of them fails the test (tokio only logs a
 * panicking task), so where quinn tolerates a task failing late the port says so.
 */
class DriverTest {

    @Test
    fun handshakeTimeout() {
        val idleTimeout = 500.milliseconds
        var elapsed = 0L
        quicTest {
            val client = Endpoint.client(V4_LOCALHOST)
            val transportConfig = TransportConfig()
                .maxIdleTimeout(IdleTimeout.of(idleTimeout))
                .initialRtt(10.milliseconds)
            val clientConfig = mockClientConfig().transportConfig(transportConfig)

            val start = monotonicNanos()
            val e = assertFailsWith<ConnectionError> { client.connectWith(clientConfig, localhostV4(1), "localhost").await() }
            assertEquals(ConnectionError.TimedOut, e, "unexpected error: $e")
            elapsed = monotonicNanos() - start
            client.shutdown()
        }
        val dt = elapsed.nanoseconds
        assertTrue(dt > idleTimeout && dt < idleTimeout * 2, "handshake timed out after $dt")
    }

    @Test
    fun closeEndpoint() = quicTest {
        val endpoint = Endpoint.client(V4_LOCALHOST)
        endpoint.setDefaultClientConfig(mockClientConfig())

        val conn1 = endpoint.connect(localhostV4(1234), "localhost")
        launch { runCatching { conn1.await() } }

        val conn = endpoint.connect(localhostV4(1234), "localhost")
        endpoint.close(VarInt(0), ByteArray(0))
        val e = assertFailsWith<ConnectionError> { conn.await() }
        assertEquals(ConnectionError.LocallyClosed, e, "unexpected error: $e")
        endpoint.close()
    }

    @Test
    fun localAddr() = quicTest {
        val socket = bindUdp(V6_LOCALHOST)
        val addr = socket.localAddress
        val ep = Endpoint.create(EndpointConfig.default(), null, socket)
        assertEquals(addr, ep.localAddr())
        ep.close()
    }

    @Test
    fun readAfterClose() = quicTest {
        val endpoint = endpoint()
        val msg = "goodbye!".encodeToByteArray()
        val server = launch {
            val newConn = assertNotNull(endpoint.accept(), "endpoint").await()
            val s = newConn.openUni()
            s.writeAll(msg)
            s.finish()
            // Wait for the stream to be closed, one way or another.
            runCatching { s.stopped() }
        }
        val newConn = endpoint.connect(endpoint.localAddr(), "localhost").await()
        delay(100.milliseconds)
        val stream = newConn.acceptUni()
        val got = stream.readToEnd()
        assertContentEquals(msg, got)
        server.join()
        endpoint.shutdown()
    }

    @Test
    fun exportKeyingMaterial() = quicTest {
        val endpoint = endpoint()
        val outgoing = async { endpoint.connect(endpoint.localAddr(), "localhost").await() }
        val incoming = async { assertNotNull(endpoint.accept(), "endpoint").await() }
        val outgoingConn = outgoing.await()
        val incomingConn = incoming.await()
        val iBuf = ByteArray(64)
        incomingConn.exportKeyingMaterial(iBuf, "asdf".encodeToByteArray(), "qwer".encodeToByteArray())
        val oBuf = ByteArray(64)
        outgoingConn.exportKeyingMaterial(oBuf, "asdf".encodeToByteArray(), "qwer".encodeToByteArray())
        assertContentEquals(iBuf, oBuf)
        endpoint.shutdown()
    }

    @Test
    fun ipBlocking() = quicTest {
        val factory = EndpointFactory()
        val client1 = factory.endpoint()
        val client1Addr = client1.localAddr()
        val client2 = factory.endpoint()
        val server = factory.endpoint()
        val serverAddr = server.localAddr()
        val serverTask = launch {
            while (true) {
                val accepting = server.accept() ?: break
                if (accepting.remoteAddress() == client1Addr) {
                    accepting.refuse()
                } else if (accepting.remoteAddressValidated()) {
                    accepting.await()
                } else {
                    accepting.retry()
                }
            }
        }
        val a = async {
            val e = assertFailsWith<ConnectionError>("server should have blocked this") {
                client1.connect(serverAddr, "localhost").await()
            }
            assertTrue(e is ConnectionError.ConnectionClosed, "wrong error: $e")
        }
        val b = async { client2.connect(serverAddr, "localhost").await() }
        a.await()
        b.await()
        serverTask.cancel()
        client1.shutdown()
        client2.shutdown()
        server.shutdown()
    }

    @Test
    fun zeroRtt() {
        if (TestTls.skipOnReal("DriverTest.zeroRtt", TestTls.NO_ZERO_RTT)) return
        zeroRttOnTheTestDouble()
    }

    private fun zeroRttOnTheTestDouble() = quicTest {
        val endpoint = endpoint()
        val msg0 = "zero".encodeToByteArray()
        val msg1 = "one".encodeToByteArray()
        val serverTask = launch {
            repeat(2) { round ->
                val incoming = assertNotNull(endpoint.accept()).accept()
                val (connection, established) = assertNotNull(incoming.into0Rtt())
                launch {
                    while (true) {
                        val x = try {
                            connection.acceptUni()
                        } catch (e: ConnectionError) {
                            break
                        }
                        assertContentEquals(msg0, x.readToEnd())
                    }
                }
                // sending 0.5-RTT
                val s = connection.openUni()
                s.writeAll(msg0)
                s.finish()
                established.await()
                // sending 1-RTT. ⚖️ In the second round the client may have closed the connection by now; quinn's
                // spawned task would panic unnoticed there, so a lost connection is tolerated.
                try {
                    val s1 = connection.openUni()
                    s1.writeAll(msg1)
                    // The peer might close the connection before ACKing
                    runCatching { s1.finish() }
                } catch (e: Exception) {
                    if (round == 0 || (e !is ConnectionError && e !is WriteError)) throw e
                }
            }
        }

        val connecting = endpoint.connect(endpoint.localAddr(), "localhost")
        assertNull(connecting.into0Rtt(), "0-RTT succeeded without keys")
        val connection = connecting.await()
        run {
            val stream = connection.acceptUni()
            assertContentEquals(msg0, stream.readToEnd())
            // Read a 1-RTT message to ensure the handshake completes fully, allowing the server's NewSessionTicket
            // frame to be received.
            val stream1 = connection.acceptUni()
            assertContentEquals(msg1, stream1.readToEnd())
            connection.close()
        }

        // initial connection complete
        val (connection2, zeroRtt) = assertNotNull(
            endpoint.connect(endpoint.localAddr(), "localhost").into0Rtt(),
            "missing 0-RTT keys",
        )
        // Send something ASAP to use 0-RTT
        launch {
            val s = connection2.openUni()
            // sending 0-RTT
            s.writeAll(msg0)
            s.finish()
        }
        val stream = connection2.acceptUni()
        assertContentEquals(msg0, stream.readToEnd())
        assertTrue(zeroRtt.await())

        stream.close()
        connection2.close()
        serverTask.join()
        endpoint.waitIdle()
        endpoint.close()
    }

    @Test
    fun echoV6() = runEcho(EchoArgs(clientAddr = V6_UNSPECIFIED, serverAddr = V6_LOCALHOST, nrStreams = 1, streamSize = 10 * 1024))

    @Test
    fun echoV4() = runEcho(EchoArgs(clientAddr = V4_UNSPECIFIED, serverAddr = V4_LOCALHOST, nrStreams = 1, streamSize = 10 * 1024))

    @Test
    fun echoDualstack() = runEcho(EchoArgs(clientAddr = V6_UNSPECIFIED, serverAddr = V4_LOCALHOST, nrStreams = 1, streamSize = 10 * 1024))

    @Test
    @Ignore // As in quinn (#[ignore]): a stress test
    fun stressReceiveWindow() = runEcho(
        EchoArgs(V4_UNSPECIFIED, V4_LOCALHOST, nrStreams = 50, streamSize = 25 * 1024 + 11, receiveWindow = 37, streamReceiveWindow = 100L * 1024 * 1024),
    )

    @Test
    @Ignore // As in quinn (#[ignore]): a stress test
    fun stressStreamReceiveWindow() = runEcho(
        // Note that there is no point in running this with too many streams, since the window is only active within
        // a stream.
        EchoArgs(V4_UNSPECIFIED, V4_LOCALHOST, nrStreams = 2, streamSize = 250 * 1024 + 11, receiveWindow = 100L * 1024 * 1024, streamReceiveWindow = 37),
    )

    @Test
    @Ignore // As in quinn (#[ignore]): a stress test
    fun stressBothWindows() = runEcho(
        EchoArgs(V4_UNSPECIFIED, V4_LOCALHOST, nrStreams = 50, streamSize = 25 * 1024 + 11, receiveWindow = 37, streamReceiveWindow = 37),
    )

    @Test
    fun rebindRecv() = quicTest {
        val client = Endpoint.client(V4_LOCALHOST)
        client.setDefaultClientConfig(mockClientConfig().transportConfig(TransportConfig().maxConcurrentUniStreams(VarInt(1))))
        val server = Endpoint.server(mockServerConfig(), V4_LOCALHOST)
        val serverAddr = server.localAddr()

        val msg = "hello".encodeToByteArray()
        val writeSignal = CompletableDeferred<Unit>()
        val connectedSignal = CompletableDeferred<Unit>()
        val serverTask = launch {
            val connection = assertNotNull(server.accept()).await()
            connectedSignal.complete(Unit)
            writeSignal.await()
            val stream = connection.openUni()
            stream.writeAll(msg)
            stream.finish()
            // Wait for the stream to be closed, one way or another.
            runCatching { stream.stopped() }
        }

        val connection = client.connect(serverAddr, "localhost").await()
        connectedSignal.await()
        client.rebind(bindUdp(V4_LOCALHOST))
        writeSignal.complete(Unit)
        val stream = connection.acceptUni()
        assertContentEquals(msg, stream.readToEnd(msg.size))
        serverTask.join()
        client.shutdown()
        server.shutdown()
    }

    @Test
    fun streamIdFlowControl() = quicTest {
        val endpoint = endpointWithConfig(TransportConfig().maxConcurrentUniStreams(VarInt(1)))
        val clientD = async { endpoint.connect(endpoint.localAddr(), "localhost").await() }
        val serverD = async { assertNotNull(endpoint.accept()).await() }
        val client = clientD.await()
        val server = serverD.await()

        // If `openUni` doesn't get unblocked when the previous stream is closed, this will time out. ⚖️ quinn drops
        // each stream right away (finishing the send streams and stopping the receive streams); here `close` does.
        listOf(
            async { client.openUni().close() },
            async { client.openUni().close() },
            async { client.openUni().close() },
            async {
                server.acceptUni().close()
                server.acceptUni().close()
            },
        ).awaitAll()
        endpoint.shutdown()
    }

    @Test
    fun twoDatagramReaders() = quicTest {
        val endpoint = endpoint()
        val clientD = async { endpoint.connect(endpoint.localAddr(), "localhost").await() }
        val serverD = async { assertNotNull(endpoint.accept()).await() }
        val client = clientD.await()
        val server = serverD.await()

        val done = CompletableDeferred<Unit>()
        val a = async {
            val x = client.readDatagram()
            done.complete(Unit)
            x
        }
        val b = async {
            val x = client.readDatagram()
            done.complete(Unit)
            x
        }
        val c = async {
            server.sendDatagram(Bytes.wrap("one".encodeToByteArray()))
            done.await()
            server.sendDatagramWait(Bytes.wrap("two".encodeToByteArray()))
        }
        val x = a.await().decodeToString()
        val y = b.await().decodeToString()
        c.await()
        assertTrue(x == "one" || y == "one")
        assertTrue(x == "two" || y == "two")
        endpoint.shutdown()
    }

    @Test
    fun multipleConnsWithZeroLengthCids() = quicTest {
        val factory = EndpointFactory()
        factory.endpointConfig.cidGenerator { RandomConnectionIdGenerator(0) }
        val server = factory.endpoint()
        val serverAddr = server.localAddr()
        val client1 = factory.endpoint()
        val client2 = factory.endpoint()

        val c1 = launch {
            val conn = client1.connect(serverAddr, "localhost").await()
            conn.closed()
        }
        val c2 = launch {
            val conn = client2.connect(serverAddr, "localhost").await()
            conn.closed()
        }
        val s = launch {
            val conn1 = assertNotNull(server.accept()).await()
            val conn2 = assertNotNull(server.accept()).await()
            // Both connections are now concurrently live.
            conn1.close(VarInt(42), ByteArray(0))
            conn2.close(VarInt(42), ByteArray(0))
        }
        c1.join()
        c2.join()
        s.join()
        server.shutdown()
        client1.shutdown()
        client2.shutdown()
    }

    @Test
    fun streamStopped() = quicTest {
        val factory = EndpointFactory()
        val server = factory.endpoint()
        val serverAddr = server.localAddr()
        val client = factory.endpoint()

        val serverConn = async {
            val conn = assertNotNull(server.accept()).await()
            val stream = conn.acceptUni()
            val buf = ByteArray(2)
            stream.readExact(buf)
            stream.stop(VarInt(42))
            conn
        }
        withTimeout(100.milliseconds) {
            val conn = client.connect(serverAddr, "localhost").await()
            val stream = conn.openUni()
            val stopped1 = async(start = CoroutineStart.LAZY) { stream.stopped() }
            val stopped2 = async(start = CoroutineStart.LAZY) { stream.stopped() }
            val stopped3 = async(start = CoroutineStart.LAZY) { stream.stopped() }

            stream.writeAll("hi".encodeToByteArray())
            // verify that both waiters resolved
            assertEquals(VarInt(42), stopped1.await())
            assertEquals(VarInt(42), stopped2.await())
            // close the stream
            stream.close()
            // verify that a waiter also resolves after closing the stream
            assertEquals(VarInt(42), stopped3.await())
        }
        serverConn.await()
        server.shutdown()
        client.shutdown()
    }

    @Test
    fun streamStopped2() = quicTest {
        val endpoint = endpoint()
        val connD = async { endpoint.connect(endpoint.localAddr(), "localhost").await() }
        val serverD = async { assertNotNull(endpoint.accept()).await() }
        val conn = connD.await()
        serverD.await()

        val sendStream = conn.openUni()
        val stopped = async { withTimeout(100.milliseconds) { sendStream.stopped() } }
        // run the waiter once so that it is registered
        yield()
        // close the send stream
        sendStream.close()
        // make sure the waiter still resolves
        assertNull(stopped.await())
        endpoint.shutdown()
    }

    @Test
    fun streamDropRemovesBlockedReader() {
        for (dropStream in listOf(false, true)) quicTest {
            val factory = EndpointFactory()
            val server = factory.endpoint()
            val serverAddress = server.localAddr()
            val client = factory.endpoint()

            val serverTask = launch {
                val conn = assertNotNull(server.accept()).await()
                val stream = conn.acceptUni()

                // read "hello"
                val buf = ByteArray(5)
                stream.readExact(buf)

                // do a blocking read which will add the stream in conn.blocked_readers. ⚖️ quinn polls the read
                // future once with a counting waker; here the read starts, suspends, and is cancelled, and the
                // blocked-reader table is inspected directly.
                val read = launch(start = CoroutineStart.UNDISPATCHED) { stream.read(ByteArray(64)) }
                read.cancel()
                val blocked = { conn.state.blockedReaders.containsKey(stream.id.value) }

                if (!dropStream) {
                    // We have a blocked reader; closing the connection should wake it.
                    assertTrue(blocked())
                    conn.close(VarInt(0), "done".encodeToByteArray())
                    assertFalse(blocked(), "closing the connection wakes the blocked reader")
                } else {
                    // closing the stream should remove it from blocked_readers, so no wake-up remains
                    stream.close()
                    assertFalse(blocked(), "no wakeups should have occurred")
                    conn.close(VarInt(0), "done".encodeToByteArray())
                    assertFalse(blocked(), "no wakeups should have occurred")
                }
            }

            val conn = client.connect(serverAddress, "localhost").await()
            val stream = conn.openUni()
            // need to send some data to actually start the stream
            stream.writeAll("hello".encodeToByteArray())

            serverTask.join()
            server.shutdown()
            client.shutdown()
        }
    }

    /** Test that closing a `RecvStream` after cancelling a read and then explicitly `stop`ing it doesn't fail. */
    @Test
    fun recvStreamCancelStopDrop() = quicTest {
        val factory = EndpointFactory()
        val server = factory.endpoint()
        val serverAddr = server.localAddr()
        val client = factory.endpoint()
        val recvDropped = CompletableDeferred<Unit>()
        val a = launch {
            val conn = assertNotNull(server.accept()).await()
            val recv = conn.acceptUni()
            // Start a read of the stream, let it suspend, then immediately cancel it
            val read = launch(start = CoroutineStart.UNDISPATCHED) { recv.readToEnd() }
            assertTrue(read.isActive)
            read.cancel()
            recvDropped.complete(Unit)
            recv.stop(VarInt(0))
            recv.close()
        }
        val b = launch {
            val conn = client.connect(serverAddr, "localhost").await()
            val send = conn.openUni()
            runCatching { send.writeAll("hello".encodeToByteArray()) }
            // Don't close (finish) the send stream until the read has been cancelled by the server, ensuring that
            // readToEnd can't complete immediately.
            recvDropped.await()
            send.close()
        }
        a.join()
        b.join()
        server.shutdown()
        client.shutdown()
    }

    private class EchoArgs(
        val clientAddr: neton.io.net.SocketAddress,
        val serverAddr: neton.io.net.SocketAddress,
        val nrStreams: Int,
        val streamSize: Int,
        val receiveWindow: Long? = null,
        val streamReceiveWindow: Long? = null,
    )

    private fun runEcho(args: EchoArgs) = quicTest(60_000.milliseconds) {
        // Use small receive windows
        val transportConfig = TransportConfig()
        args.receiveWindow?.let { transportConfig.receiveWindow(VarInt(it)) }
        args.streamReceiveWindow?.let { transportConfig.streamReceiveWindow(VarInt(it)) }
        transportConfig.maxConcurrentBidiStreams(VarInt(1))
        transportConfig.maxConcurrentUniStreams(VarInt(1))

        // We don't use the `endpoint` helper here because we want two different endpoints with different addresses.
        val serverConfig = mockServerConfig().transportConfig(transportConfig)
        val serverSock = bindUdp(args.serverAddr)
        val serverAddr = serverSock.localAddress
        val server = Endpoint.create(EndpointConfig.default(), serverConfig, serverSock)

        val client = Endpoint.client(args.clientAddr)
        client.setDefaultClientConfig(mockClientConfig().transportConfig(transportConfig))

        val serverTask = launch {
            val incoming = assertNotNull(server.accept())
            // quinn: the local IP is reported on Linux, Android, the BSDs, macOS and Windows
            val localIp = assertNotNull(incoming.localIp(), "Local IP must be available")
            assertTrue(isLoopback(localIp), "local IP $localIp is not loopback")

            val newConn = incoming.await()
            launch {
                while (true) {
                    val stream = try {
                        newConn.acceptBi()
                    } catch (e: ConnectionError) {
                        break
                    }
                    launch { echo(stream) }
                }
            }
            server.waitIdle()
        }

        val newConn = client.connect(serverAddr, "localhost").await()

        /** This is just an arbitrary number to generate deterministic test data. */
        val seed = 0x12345678L

        for (i in 0 until args.nrStreams) {
            val (send, recv) = newConn.openBi()
            val msg = genData(args.streamSize, seed)

            val sendTask = async {
                send.writeAll(msg)
                send.finish()
            }
            val recvTask = async { recv.readToEnd() }
            sendTask.await()
            val data = recvTask.await()
            assertContentEquals(msg, data, "Data mismatch")
        }
        newConn.close(VarInt(0), "done".encodeToByteArray())
        client.waitIdle()
        serverTask.join()
        client.close()
        server.close()
    }

    private suspend fun echo(stream: Pair<SendStream, RecvStream>) {
        val (send, recv) = stream
        while (true) {
            // These are 32 buffers, for reading approximately 32kB at once
            val bufs = Array(32) { Bytes.EMPTY }
            val n = recv.readChunks(bufs)
            if (n < 0) break
            send.writeAllChunks(bufs.copyOf(n).requireNoNulls())
        }
        runCatching { send.finish() }
    }

    private fun isLoopback(ip: neton.io.net.SocketAddress): Boolean {
        val a = ip.toCanonical()
        val b = a.ipBytes()
        return if (a.isIpv4) b[0] == 127.toByte() else (0 until 15).all { b[it] == 0.toByte() } && b[15] == 1.toByte()
    }
}
