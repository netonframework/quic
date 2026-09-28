package neton.quic

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.CoroutineStart
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import neton.quic.proto.ConnectionError
import neton.quic.proto.TransportConfig
import neton.quic.proto.TransportErrorCode
import neton.quic.proto.VarInt
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds

/**
 * SPEC §3 "生命周期": quinn's drop rules, carried by explicit `close()` (and `use { }`, so that cancellation runs them
 * too). One test per rule, plus the counter-case where a rule must not fire.
 */
class LifecycleTest {

    // ---- SendStream: close = finish, or reset with the peer's code if it was stopped ----

    @Test
    fun sendStreamCloseFinishes() = quicTest {
        val (client, server, endpoint) = connectedPair()
        val send = client.openUni()
        send.writeAll("abc".encodeToByteArray())
        send.close()
        // The peer sees the data and then the end of the stream: close finished it
        assertContentEquals("abc".encodeToByteArray(), server.acceptUni().readToEnd())
        assertNull(send.stopped(), "a finished stream reports no stop code")
        assertEquals(0L, client.stats().frameTx.resetStream)
        endpoint.shutdown()
    }

    @Test
    fun sendStreamCloseAfterStopResets() = quicTest {
        val (client, server, endpoint) = connectedPair()
        val send = client.openUni()
        send.writeAll("hi".encodeToByteArray())
        val recv = server.acceptUni()
        recv.readExact(ByteArray(2))
        recv.stop(VarInt(7))
        assertEquals(VarInt(7), send.stopped())
        send.close()
        // quinn: `finish` fails with `Stopped(7)`, so the stream is reset with that code
        awaitUntil { client.stats().frameTx.resetStream > 0 }
        assertFailsWith<neton.quic.proto.ClosedStream> { send.reset(VarInt(1)) }
        endpoint.shutdown()
    }

    @Test
    fun sendStreamUseFinishesOnCancellation() = quicTest {
        val (client, server, endpoint) = connectedPair()
        val written = kotlinx.coroutines.CompletableDeferred<Unit>()
        val writer = launch {
            client.openUni().use { send ->
                send.writeAll("partial".encodeToByteArray())
                written.complete(Unit)
                awaitCancellation()
            }
        }
        written.await()
        writer.cancel()
        assertContentEquals("partial".encodeToByteArray(), server.acceptUni().readToEnd())
        endpoint.shutdown()
    }

    // ---- RecvStream: close before the end = stop(0) ----

    @Test
    fun recvStreamCloseBeforeEndStops() = quicTest {
        val (client, server, endpoint) = connectedPair()
        val send = client.openUni()
        send.writeAll("hello".encodeToByteArray())
        val recv = server.acceptUni()
        recv.readExact(ByteArray(1))
        recv.close()
        assertEquals(VarInt(0), send.stopped(), "closing an unfinished RecvStream stops it with code 0")
        endpoint.shutdown()
    }

    @Test
    fun recvStreamCloseAfterEndDoesNotStop() = quicTest {
        val (client, server, endpoint) = connectedPair()
        val send = client.openUni()
        send.writeAll("hello".encodeToByteArray())
        send.finish()
        val recv = server.acceptUni()
        assertContentEquals("hello".encodeToByteArray(), recv.readToEnd())
        recv.close()
        assertNull(send.stopped(), "a stream read to its end is not stopped by close")
        assertEquals(0L, server.stats().frameTx.stopSending)
        endpoint.shutdown()
    }

    // ---- Connection: close() = close with code 0 ----

    @Test
    fun connectionCloseUsesCode0() = quicTest {
        val (client, server, endpoint) = connectedPair()
        client.close()
        assertApplicationClosedWith0(server.closed())
        assertEquals(ConnectionError.LocallyClosed, client.closeReason())
        endpoint.shutdown()
    }

    @Test
    fun connectionUseClosesOnCancellation() = quicTest {
        val (client, server, endpoint) = connectedPair()
        val user = launch { client.use { awaitCancellation() } }
        delay(10.milliseconds)
        user.cancel()
        assertApplicationClosedWith0(server.closed())
        endpoint.shutdown()
    }

    @Test
    fun connectionCloseKeepsAnEarlierReason() = quicTest {
        val (client, server, endpoint) = connectedPair()
        client.close(VarInt(42), "bye".encodeToByteArray())
        client.close() // already closed: no second close
        val reason = assertIs<ConnectionError.ApplicationClosed>(server.closed())
        assertEquals(VarInt(42), reason.reason.errorCode)
        endpoint.shutdown()
    }

    @Test
    fun connectingCloseClosesConnection() = quicTest {
        val factory = EndpointFactory()
        val server = factory.endpoint()
        val client = factory.endpoint()
        val connecting = client.connect(server.localAddr(), "localhost")
        // The server has the client's Initial and answers it
        val serverConnecting = assertNotNull(server.accept()).accept()
        connecting.close()
        assertFailsWith<IllegalStateException> { connecting.await() }
        // The peer is told: an application close during the handshake is sent as APPLICATION_ERROR (RFC 9000 §10.2.3)
        val e = assertIs<ConnectionError.ConnectionClosed>(assertFailsWith<ConnectionError> { serverConnecting.await() })
        assertEquals(TransportErrorCode.APPLICATION_ERROR, e.reason.errorCode)
        // The attempt drains, and the client endpoint becomes idle
        client.waitIdle()
        assertEquals(0, client.openConnections())
        server.shutdown()
        client.shutdown()
    }

    // ---- Incoming: refused when closed, or when the endpoint is closed while it is still held ----

    @Test
    fun incomingCloseRefuses() = quicTest {
        val factory = EndpointFactory()
        val server = factory.endpoint()
        val client = factory.endpoint()
        val connecting = client.connect(server.localAddr(), "localhost")
        assertNotNull(server.accept()).close()
        assertRefused(assertFailsWith<ConnectionError> { connecting.await() })
        assertEquals(1L, server.stats().refusedHandshakes)
        server.shutdown()
        client.shutdown()
    }

    @Test
    fun incomingHeldIsRefusedWhenEndpointCloses() = quicTest {
        val factory = EndpointFactory()
        val server = factory.endpoint()
        val client = factory.endpoint()
        val connecting = client.connect(server.localAddr(), "localhost")
        val incoming = assertNotNull(server.accept())
        server.close() // quinn: dropping the endpoint while the Incoming is never used
        assertRefused(assertFailsWith<ConnectionError> { connecting.await() })
        assertEquals(1L, server.stats().refusedHandshakes)
        assertFailsWith<IllegalStateException>("a refused Incoming cannot be accepted") { incoming.accept() }
        assertNull(server.accept(), "a closed endpoint hands out no more connection attempts")
        client.shutdown()
    }

    /** The endpoint outlives its release while it has connections; a held Incoming is refused at the release. */
    @Test
    fun incomingHeldIsRefusedWhenEndpointClosesWithLiveConnections() = quicTest {
        val factory = EndpointFactory()
        val server = factory.endpoint()
        val client = factory.endpoint()
        val first = async(start = CoroutineStart.UNDISPATCHED) { client.connect(server.localAddr(), "localhost").await() }
        val serverConn = assertNotNull(server.accept()).await()
        first.await()
        val connecting = client.connect(server.localAddr(), "localhost")
        val incoming = assertNotNull(server.accept())
        server.close()
        assertRefused(assertFailsWith<ConnectionError> { connecting.await() })
        assertFailsWith<IllegalStateException> { incoming.accept() }
        assertEquals(1, server.openConnections(), "the live connection is not affected")
        serverConn.close()
        server.waitIdle()
        client.shutdown()
    }

    @Test
    fun endpointRefusesNewAttemptsOnceClosed() = quicTest {
        val factory = EndpointFactory()
        val server = factory.endpoint()
        val client = factory.endpoint()
        // Keep the server endpoint alive with one connection, then release it
        val first = async(start = CoroutineStart.UNDISPATCHED) { client.connect(server.localAddr(), "localhost").await() }
        val serverConn = assertNotNull(server.accept()).await()
        first.await()
        server.close()
        assertRefused(assertFailsWith<ConnectionError> { client.connect(server.localAddr(), "localhost").await() })
        serverConn.close()
        server.waitIdle()
        client.shutdown()
    }

    // ---- helpers ----

    private fun assertApplicationClosedWith0(e: ConnectionError) {
        val closed = assertIs<ConnectionError.ApplicationClosed>(e, "expected the peer's application close, got $e")
        assertEquals(VarInt(0), closed.reason.errorCode)
        assertEquals(0, closed.reason.reason.size)
    }

    private fun assertRefused(e: ConnectionError) {
        val closed = assertIs<ConnectionError.ConnectionClosed>(e, "expected a refusal, got $e")
        assertEquals(TransportErrorCode.CONNECTION_REFUSED, closed.reason.errorCode)
    }

    private suspend fun awaitUntil(condition: () -> Boolean) {
        while (!condition()) delay(1.milliseconds)
    }
}
