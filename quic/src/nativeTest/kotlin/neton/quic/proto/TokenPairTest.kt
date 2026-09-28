package neton.quic.proto

import neton.io.bytes.Bytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

// quinn-proto `tests/token.rs`: Retry tokens and address validation tokens (NEW_TOKEN) end to end.

/** A settable wall clock (token.rs:317). */
internal class FakeTimeSource : TimeSource {
    private var now: Duration = StdSystemTime.now()

    fun advance(dur: Duration) {
        now += dur
    }

    override fun now(): Duration = now
}

class TokenPairTest {

    private fun ConnPair.assertNothingKnown() {
        assertEquals(0, client.endpoint.knownConnections())
        assertEquals(0, client.endpoint.knownCids())
        assertEquals(0, server.endpoint.knownConnections())
        assertEquals(0, server.endpoint.knownCids())
    }

    /** Connect with [config], close from the client and drive until both sides forgot the connection. */
    private fun ConnPair.connectAndClose(config: ClientConfig) {
        val (clientCh, _) = connectWith(config)
        clientConn(clientCh).close(time, VarInt(42), Bytes.EMPTY)
        drive()
        assertNothingKnown()
    }

    // token.rs:8
    @Test
    fun statelessRetry() {
        val pair = ConnPair.default()
        pair.server.handleIncoming = ::validateIncoming
        val (clientCh, _) = pair.connect()
        pair.clientConn(clientCh).close(pair.time, VarInt(42), Bytes.EMPTY)
        pair.drive()
        pair.assertNothingKnown()
    }

    // token.rs:26
    @Test
    fun retryTokenExpired() {
        val fakeTime = FakeTimeSource()
        val retryTokenLifetime = 1.seconds

        val pair = ConnPair.default()
        pair.server.handleIncoming = ::validateIncoming

        val config = serverConfig().timeSource(fakeTime).retryTokenLifetime(retryTokenLifetime)
        pair.server.endpoint.setServerConfig(config)

        val clientCh = pair.beginConnect(clientConfig())
        pair.driveClient()
        pair.driveServer()
        pair.driveClient()

        // to expire retry token
        fakeTime.advance(retryTokenLifetime + 1.milliseconds)

        pair.drive()
        val lost = pair.clientConn(clientCh).poll() as? Event.ConnectionLost ?: fail("expected the connection to be lost")
        val closed = lost.reason as? ConnectionError.ConnectionClosed ?: fail("expected a close, got ${lost.reason}")
        assertEquals(TransportErrorCode.INVALID_TOKEN, closed.reason.errorCode)

        pair.assertNothingKnown()
    }

    // token.rs:63
    @Test
    fun useToken() {
        val pair = ConnPair.default()
        val clientConfig = clientConfig()
        pair.connectAndClose(clientConfig.copy())

        pair.server.handleIncoming = { incoming ->
            assertTrue(incoming.remoteAddressValidated())
            assertTrue(incoming.mayRetry())
            IncomingConnectionBehavior.Accept
        }
        pair.connectAndClose(clientConfig)
    }

    // token.rs:98
    @Test
    fun retryThenUseToken() {
        val pair = ConnPair.default()
        val clientConfig = clientConfig()
        pair.server.handleIncoming = ::validateIncoming
        pair.connectAndClose(clientConfig.copy())

        pair.server.handleIncoming = { incoming ->
            assertTrue(incoming.remoteAddressValidated())
            assertTrue(incoming.mayRetry())
            IncomingConnectionBehavior.Accept
        }
        pair.connectAndClose(clientConfig)
    }

    // token.rs:134
    @Test
    fun useTokenThenRetry() {
        val pair = ConnPair.default()
        val clientConfig = clientConfig()
        pair.connectAndClose(clientConfig.copy())

        var i = 0
        pair.server.handleIncoming = { incoming ->
            when (i) {
                0 -> {
                    assertTrue(incoming.remoteAddressValidated())
                    assertTrue(incoming.mayRetry())
                    i += 1
                    IncomingConnectionBehavior.Retry
                }
                1 -> {
                    assertTrue(incoming.remoteAddressValidated())
                    assertFalse(incoming.mayRetry())
                    i += 1
                    IncomingConnectionBehavior.Accept
                }
                else -> fail("too many handle_incoming iterations")
            }
        }
        pair.connectAndClose(clientConfig)
    }

    // token.rs:182
    @Test
    fun useSameTokenTwice() {
        /** Hands out the first token it was given, every time. */
        class EvilTokenStore : TokenStore {
            private var token: Bytes = Bytes.EMPTY

            override fun insert(serverName: String, token: Bytes) {
                if (this.token.isEmpty) this.token = token
            }

            override fun take(serverName: String): Bytes? = if (token.isEmpty) null else token
        }

        val pair = ConnPair.default()
        val clientConfig = clientConfig().tokenStore(EvilTokenStore())
        pair.connectAndClose(clientConfig.copy())

        pair.server.handleIncoming = { incoming ->
            assertTrue(incoming.remoteAddressValidated())
            assertTrue(incoming.mayRetry())
            IncomingConnectionBehavior.Accept
        }
        pair.connectAndClose(clientConfig.copy())

        pair.server.handleIncoming = { incoming ->
            assertFalse(incoming.remoteAddressValidated())
            assertTrue(incoming.mayRetry())
            IncomingConnectionBehavior.Accept
        }
        pair.connectAndClose(clientConfig)
    }

    // token.rs:256
    @Test
    fun useTokenExpired() {
        val fakeTime = FakeTimeSource()
        val lifetime = 10000.seconds
        val serverConfig = serverConfig().timeSource(fakeTime)
        serverConfig.validationToken.lifetime(lifetime)
        val pair = ConnPair.new(EndpointConfig.default(), serverConfig)
        val clientConfig = clientConfig()
        pair.connectAndClose(clientConfig.copy())

        pair.server.handleIncoming = { incoming ->
            assertTrue(incoming.remoteAddressValidated())
            assertTrue(incoming.mayRetry())
            IncomingConnectionBehavior.Accept
        }
        pair.connectAndClose(clientConfig.copy())

        fakeTime.advance(lifetime + 1.seconds)

        pair.server.handleIncoming = { incoming ->
            assertFalse(incoming.remoteAddressValidated())
            assertTrue(incoming.mayRetry())
            IncomingConnectionBehavior.Accept
        }
        pair.connectAndClose(clientConfig)
    }
}
