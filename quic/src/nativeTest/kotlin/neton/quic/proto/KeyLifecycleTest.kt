package neton.quic.proto

import neton.io.bytes.Bytes
import kotlin.native.runtime.GC
import kotlin.native.runtime.NativeRuntimeApi
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

/**
 * Native cipher contexts are released when their keys are retired, not when the GC gets to them: after connections
 * close and drain, attempts are refused or retried, and keys are updated, the number of live contexts is back where it
 * started (quinn frees them on drop). The baseline is taken once the cleaners of garbage left by earlier tests (for
 * example connections a test abandoned without closing) have run, so that they do not release keys in the middle of
 * a count; which tests ran before depends on the filter and the order.
 */
class KeyLifecycleTest {
    private fun bytes(s: String) = Bytes.wrap(s.encodeToByteArray())

    @Test
    fun manyConnectionsWithKeyUpdatesReleaseEveryKey() {
        val baseline = settledNativeKeys()
        repeat(20) { round ->
            val pair = ConnPair.default()
            val (clientCh, serverCh) = pair.connect()
            assertTrue(NativeKeys.live > baseline, "an open connection holds keys")
            val s = pair.clientStreams(clientCh).open(Dir.Bi)!!
            repeat(3) { i ->
                pair.clientSend(clientCh, s).writeOk("round $round update $i".encodeToByteArray())
                pair.drive()
                if (i % 2 == 0) pair.clientConn(clientCh).forceKeyUpdate() else pair.serverConn(serverCh).forceKeyUpdate()
                pair.drive()
            }
            pair.clientConn(clientCh).close(pair.time, VarInt(0), bytes("done"))
            pair.drive()
            assertNull(pair.clientConn(clientCh).poll())
            assertEquals(0, pair.client.endpoint.knownConnections())
            assertEquals(0, pair.server.endpoint.knownConnections())
        }
        assertEquals(baseline, NativeKeys.live, "native key contexts left after the connections drained")
    }

    @Test
    fun refusedAndRetriedAttemptsReleaseTheirInitialKeys() {
        val baseline = settledNativeKeys()
        repeat(10) {
            val pair = ConnPair.default()
            var validated = 0
            pair.server.handleIncoming = { incoming ->
                if (incoming.remoteAddressValidated()) { validated++; IncomingConnectionBehavior.Reject } else IncomingConnectionBehavior.Retry
            }
            // One `Incoming` per ClientHello datagram: the count assumes a one-datagram ClientHello (the two-datagram
            // case, with TLS sessions counted too, is `RealTlsConnectionTest.refusedAndRetriedAttemptsWithATwoDatagramClientHello`).
            val clientCh = pair.beginConnect(oneDatagramHelloClientConfig())
            pair.drive()
            assertTrue(pair.clientConn(clientCh).isClosed)
            pair.drive()
            assertEquals(1, validated)
            assertEquals(0, pair.client.endpoint.knownConnections())
        }
        assertEquals(baseline, NativeKeys.live, "native key contexts left after refused / retried attempts")
    }

    @Test
    fun closeAndTheCleanerReleaseExactlyOnce() {
        val baseline = settledNativeKeys()
        val keys = initialKeys(1, ConnectionId.of(ByteArray(8) { it.toByte() }), Side.Client)
        assertEquals(baseline + 4, NativeKeys.live)
        keys.close()
        assertEquals(baseline, NativeKeys.live)
        keys.close()                                         // idempotent
        assertEquals(baseline, NativeKeys.live)
    }

    @OptIn(NativeRuntimeApi::class)
    @Test
    fun theCleanerIsOnlyABackstop() {
        val baseline = settledNativeKeys()
        fun leak() { initialKeys(1, ConnectionId.of(ByteArray(8) { it.toByte() }), Side.Server) }   // never closed
        leak()
        assertEquals(baseline + 4, NativeKeys.live)
        var tries = 0
        while (NativeKeys.live != baseline && tries++ < 200) { GC.collect(); kotlin.native.concurrent.Worker.current.park(10_000) }
        assertEquals(baseline, NativeKeys.live, "the cleaner did not release an unreachable key")
    }
}
