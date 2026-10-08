package neton.quic

import kotlin.native.runtime.GC
import kotlin.native.runtime.NativeRuntimeApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import neton.io.bytes.Bytes
import neton.io.net.bindUdp
import neton.quic.proto.ClientAuth
import neton.quic.proto.ClientConfig
import neton.quic.proto.ConnectionError
import neton.quic.proto.EndpointConfig
import neton.quic.proto.NativeKeys
import neton.quic.proto.NativeTls
import neton.quic.proto.ServerConfig
import neton.quic.proto.TestTls
import neton.quic.proto.TlsHandshakeData
import neton.quic.proto.TransportConfig
import neton.quic.proto.TransportErrorCode
import neton.quic.proto.VarInt
import neton.quic.proto.default
import neton.quic.proto.withCrypto
import neton.quic.testkit.TestCa

/**
 * End to end over the `neton.quic` driver on loopback UDP with the real TLS session: echo on many streams with key
 * updates in the middle, application close, certificate / ALPN failures, and native sessions back to baseline.
 */
class RealTlsDriverTest {
    private val h3 = listOf("echo/1".encodeToByteArray())

    private suspend fun server(clientAuth: ClientAuth = ClientAuth.None): Endpoint {
        val cfg = ServerConfig.withCrypto(TestTls.serverCrypto(h3, clientAuth))
            .transportConfig(TransportConfig().maxConcurrentBidiStreams(VarInt(64)))
        return Endpoint.create(EndpointConfig.default(), cfg, bindUdp(V4_LOCALHOST))
    }

    private suspend fun client(config: ClientConfig = ClientConfig(TestTls.clientCrypto(h3))): Endpoint =
        Endpoint.client(V4_UNSPECIFIED).also { it.setDefaultClientConfig(config) }

    @OptIn(NativeRuntimeApi::class)
    private fun settle() {
        var last = -1L
        var stable = 0
        while (stable < 3) {
            GC.collect()
            kotlin.native.concurrent.Worker.current.park(20_000)
            val now = NativeTls.liveSessions + NativeKeys.live
            if (now == last) stable++ else stable = 0
            last = now
        }
    }

    @Test
    fun echoManyStreamsWithKeyUpdatesAndClose() {
        settle()
        val sessions = NativeTls.liveSessions
        val keys = NativeKeys.live
        quicTest(60.seconds) {
            val server = server()
            val serverAddr = server.localAddr()
            val client = client()
            val serverTask = launch {
                val conn = assertNotNull(server.accept()).await()
                val hd = conn.handshakeData() as TlsHandshakeData
                assertContentEquals(h3[0], hd.protocol)
                assertEquals("localhost", hd.serverName)
                launch {
                    while (true) {
                        val (send, recv) = try { conn.acceptBi() } catch (e: ConnectionError) { break }
                        launch {
                            send.writeAll(recv.readToEnd())
                            send.finish()
                        }
                    }
                }
                val reason = conn.closed()
                assertIs<ConnectionError.ApplicationClosed>(reason)
                assertEquals(VarInt(7), reason.reason.errorCode)
            }
            val conn = client.connect(serverAddr, "localhost").await()
            assertContentEquals(TestTls.server.certDer, (conn.peerIdentity() as List<*>).first() as ByteArray)
            val streams = (0 until 32).map { i ->
                async {
                    val (send, recv) = conn.openBi()
                    val msg = genData(48 * 1024 + i, i.toLong())
                    val w = async { send.writeAll(msg); send.finish() }
                    val echoed = recv.readToEnd()
                    w.await()
                    assertContentEquals(msg, echoed, "stream $i")
                }
            }
            // Key updates while the streams run
            repeat(4) {
                kotlinx.coroutines.delay(5)
                conn.forceKeyUpdate()
            }
            streams.awaitAll()
            // and data after the last update
            val (send, recv) = conn.openBi()
            send.writeAll("after the updates".encodeToByteArray())
            send.finish()
            assertEquals("after the updates", recv.readToEnd().decodeToString())
            conn.close(VarInt(7), "bye".encodeToByteArray())
            serverTask.join()
            client.waitIdle()
            server.waitIdle()
            client.close()
            server.close()
        }
        settle()
        assertEquals(sessions, NativeTls.liveSessions, "TLS sessions left after the endpoints closed")
        assertEquals(keys, NativeKeys.live, "keys left after the endpoints closed")
    }

    /**
     * 0-RTT through the driver on real TLS (SPEC §11.14; quinn's `zero_rtt`): the first connection leaves the client
     * with tickets; the second sends its request in 0-RTT (`into0Rtt`), the server accepts it, and the echo comes back.
     * The first connection waits for its tickets before it closes: they arrive after the handshake, and a client that
     * closes at once may close before they come (quinn and rustls alike).
     */
    @Test
    fun zeroRttThroughTheDriver() = quicTest {
        val server = server()
        val crypto = TestTls.clientCrypto(h3)
        val client = client(ClientConfig(crypto))
        val serverTask = launch {
            repeat(2) {
                val (conn, _) = assertNotNull(assertNotNull(server.accept()).accept().into0Rtt())
                launch {
                    val (send, recv) = conn.acceptBi()
                    send.writeAll(recv.readToEnd())
                    send.finish()
                    conn.closed()
                }
            }
        }
        repeat(2) { round ->
            val connecting = client.connect(server.localAddr(), "localhost")
            val early = connecting.into0Rtt()
            if (round == 0) assertNull(early, "no ticket yet") else assertNotNull(early, "round 1 resumes with 0-RTT")
            val conn = early?.first ?: connecting.await()
            val (send, recv) = conn.openBi()
            val msg = "round $round".encodeToByteArray()
            send.writeAll(msg)
            send.finish()
            assertContentEquals(msg, recv.readToEnd())
            if (early != null) assertTrue(early.second.await(), "the server accepted the 0-RTT data")
            while (round == 0 && crypto.tickets.size == 0) delay(5)
            conn.close(VarInt(0), ByteArray(0))
        }
        serverTask.join()
        client.waitIdle()
        client.close()
        server.shutdown()
    }

    /**
     * A server that awaits the handshake before accepting streams still learns which ones the client opened in 0-RTT
     * (`isEarlyData`, SPEC §11.18); quinn's `is0rtt` says only whether the stream was accepted while handshaking.
     * A stream the client opens after the handshake is not early data.
     */
    @Test
    fun earlyDataIsVisibleToAServerThatAwaitsTheHandshake() = quicTest {
        val server = server()
        val crypto = TestTls.clientCrypto(h3)
        val client = client(ClientConfig(crypto))
        val seen = ArrayList<Pair<Boolean, Boolean>>() // (is0rtt, isEarlyData) per accepted stream
        val serverTask = launch {
            repeat(2) { round ->
                val incoming = assertNotNull(server.accept())
                // Accepted later, so that the client's 0-RTT stream is sent before the handshake can complete
                delay(100)
                val conn = incoming.await()
                launch {
                    repeat(if (round == 0) 1 else 2) {
                        val (send, recv) = conn.acceptBi()
                        seen += recv.is0rtt() to recv.isEarlyData()
                        send.writeAll(recv.readToEnd())
                        send.finish()
                    }
                    conn.closed()
                }
            }
        }
        suspend fun echo(conn: Connection, text: String) {
            val (send, recv) = conn.openBi()
            send.writeAll(text.encodeToByteArray())
            send.finish()
            assertContentEquals(text.encodeToByteArray(), recv.readToEnd())
        }
        val first = client.connect(server.localAddr(), "localhost").await()
        echo(first, "1-RTT")
        while (crypto.tickets.size == 0) delay(5)
        first.close(VarInt(0), ByteArray(0))
        val (conn, accepted) = assertNotNull(client.connect(server.localAddr(), "localhost").into0Rtt())
        echo(conn, "0-RTT")
        assertTrue(accepted.await())
        echo(conn, "after the handshake")
        conn.close(VarInt(0), ByteArray(0))
        serverTask.join()
        assertEquals(listOf(false to false, false to true, false to false), seen)
        client.waitIdle()
        client.close()
        server.shutdown()
    }

    @Test
    fun connectByIpAddress() = quicTest {
        val server = server()
        val client = client()
        val accept = async { assertNotNull(server.accept()).await() }
        val conn = client.connect(localhostV4(server.localAddr().port), "127.0.0.1").await()
        accept.await()
        conn.close(VarInt(0), ByteArray(0))
        client.waitIdle()
        client.close()
        server.shutdown()
    }

    @Test
    fun untrustedServerFailsTheConnection() = quicTest {
        val server = server()
        val client = client(ClientConfig(TestTls.clientCrypto(h3, trust = TestCa.create("elsewhere").trustAnchors)))
        launch { server.accept()?.let { runCatching { it.await() } } }
        val e = assertFailsWith<ConnectionError> { client.connect(server.localAddr(), "localhost").await() }
        assertIs<ConnectionError.Transport>(e, "$e")
        assertEquals(TransportErrorCode.crypto(48), e.error.code)
        client.shutdown()
        server.shutdown()
    }

    @Test
    fun alpnMismatchFailsTheConnection() = quicTest {
        val server = server()
        val client = client(ClientConfig(TestTls.clientCrypto(listOf("other".encodeToByteArray()))))
        launch { server.accept()?.let { runCatching { it.await() } } }
        val e = assertFailsWith<ConnectionError> { client.connect(server.localAddr(), "localhost").await() }
        assertIs<ConnectionError.ConnectionClosed>(e, "$e")
        assertEquals(TransportErrorCode.crypto(120), e.reason.errorCode)
        client.shutdown()
        server.shutdown()
    }

    @Test
    fun clientAuthentication() = quicTest {
        val server = server(ClientAuth.Require(TestTls.ca.trustAnchors))
        val client = client(ClientConfig(TestTls.clientCrypto(h3, identity = TestTls.client)))
        val accept = async { assertNotNull(server.accept()).await() }
        client.connect(server.localAddr(), "localhost").await()
        val serverConn = accept.await()
        assertContentEquals(TestTls.client.certDer, (serverConn.peerIdentity() as List<*>).first() as ByteArray)
        client.shutdown()
        server.shutdown()
    }

    @Test
    fun manyConnectCloseCyclesReturnToBaseline() {
        settle()
        val sessions = NativeTls.liveSessions
        val refs = NativeTls.liveStableRefs
        quicTest(60.seconds) {
            val server = server()
            val serverAddr = server.localAddr()
            val client = client()
            val serverTask = launch {
                while (true) {
                    val incoming = server.accept() ?: break
                    launch { runCatching { incoming.await().closed() } }
                }
            }
            repeat(40) { i ->
                val conn = client.connect(serverAddr, "localhost").await()
                val (send, recv) = conn.openBi()
                send.writeAll("ping $i".encodeToByteArray())
                send.finish()
                conn.close(VarInt(0), ByteArray(0))
                runCatching { recv.readToEnd() }
            }
            client.waitIdle()
            client.close()
            server.close(VarInt(0), ByteArray(0))
            server.waitIdle()
            serverTask.cancel()
            server.close()
        }
        settle()
        assertEquals(sessions, NativeTls.liveSessions)
        assertEquals(refs, NativeTls.liveStableRefs)
        assertTrue(NativeTls.liveSessions >= 0)
    }
}
