package neton.quic

import neton.quic.testkit.*

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.coroutineScope
import kotlinx.coroutines.withTimeout
import neton.io.net.SocketAddress
import neton.io.net.UdpSocket
import neton.io.net.bindUdp
import neton.io.net.runReactor
import neton.quic.proto.ClientConfig
import neton.quic.proto.CryptoClientConfig
import neton.quic.proto.CryptoServerConfig
import neton.quic.proto.TestTls
import neton.quic.proto.TestTlsKind
import neton.quic.proto.EndpointConfig
import neton.quic.testkit.MockClientCrypto
import neton.quic.testkit.MockServerCrypto
import neton.quic.proto.ServerConfig
import neton.quic.proto.TransportConfig
import neton.quic.proto.VarInt
import neton.quic.proto.default
import neton.quic.proto.withCrypto
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

// Helpers of quinn's `tests.rs`, over real loopback UDP with the test-only mock TLS session (SPEC §4): where quinn
// generates a self-signed certificate and trusts it, the endpoints here share a `MockServerCrypto` /
// `MockClientCrypto` pair.

/**
 * Run a test on a fresh reactor, failing it after [timeout] (quinn's tests rely on tokio's; a hung Kotlin test would
 * never end). Endpoints created inside are children of the test's scope.
 */
internal fun quicTest(timeout: Duration = 20.seconds, block: suspend CoroutineScope.() -> Unit) = runReactor {
    withTimeout(timeout) { coroutineScope { block() } }
}

/** Close an endpoint's connections and release it, so that the test's scope can complete. */
internal fun Endpoint.shutdown() {
    close(VarInt(0), ByteArray(0))
    close()
}

internal val V4_LOCALHOST: SocketAddress = SocketAddress.IPV4_LOCALHOST_ANY_PORT
internal val V6_LOCALHOST: SocketAddress = SocketAddress.IPV6_LOCALHOST_ANY_PORT
internal val V4_UNSPECIFIED: SocketAddress = SocketAddress.IPV4_UNSPECIFIED_ANY_PORT
internal val V6_UNSPECIFIED: SocketAddress = SocketAddress.IPV6_UNSPECIFIED_ANY_PORT

/** `127.0.0.1:port`. */
internal fun localhostV4(port: Int): SocketAddress = SocketAddress.ipv4(127, 0, 0, 1, port)

/**
 * quinn's `EndpointFactory`: endpoints suitable for connecting to themselves and each other, on [tls] (the harness
 * default: the test double unless `NETON_QUIC_TEST_TLS=real`). With real TLS the server presents the test CA's
 * certificate for `localhost` / 127.0.0.1 / ::1 and the client trusts the CA.
 */
internal class EndpointFactory(tls: TestTlsKind = TestTls.kind, alpn: List<String> = emptyList()) {
    val serverCrypto: CryptoServerConfig = if (tls == TestTlsKind.Real) TestTls.serverCrypto(alpn.map { it.encodeToByteArray() }) else MockServerCrypto(alpn = alpn.map { it.encodeToByteArray() })
    val clientCrypto: CryptoClientConfig = if (tls == TestTlsKind.Real) TestTls.clientCrypto(alpn.map { it.encodeToByteArray() }) else MockClientCrypto(alpn = alpn.map { it.encodeToByteArray() })
    var endpointConfig: EndpointConfig = EndpointConfig.default()

    suspend fun endpoint(): Endpoint = endpointWithConfig(TransportConfig())

    suspend fun endpointWithConfig(transportConfig: TransportConfig): Endpoint {
        val serverConfig = ServerConfig.withCrypto(serverCrypto).transportConfig(transportConfig)
        val endpoint = Endpoint.create(endpointConfig, serverConfig, bindUdp(V4_LOCALHOST))
        endpoint.setDefaultClientConfig(ClientConfig(clientCrypto).transportConfig(transportConfig))
        return endpoint
    }
}

/** Construct an endpoint suitable for connecting to itself. */
internal suspend fun endpoint(): Endpoint = EndpointFactory().endpoint()

internal suspend fun endpointWithConfig(transportConfig: TransportConfig): Endpoint =
    EndpointFactory().endpointWithConfig(transportConfig)

/** A client configuration on a fresh client of the harness's TLS layer (the test double by default). */
internal fun mockClientConfig(): ClientConfig = ClientConfig(TestTls.defaultClientCrypto())

/** A server configuration on a fresh server of the harness's TLS layer (the test double by default). */
internal fun mockServerConfig(): ServerConfig = ServerConfig.withCrypto(TestTls.defaultServerCrypto())

internal suspend fun bindLocalV4(): UdpSocket = bindUdp(V4_LOCALHOST)

/** Deterministic test data (quinn's `gen_data` uses a seeded `StdRng`; ⚖️ this is Kotlin's seeded generator). */
internal fun genData(size: Int, seed: Long): ByteArray = kotlin.random.Random(seed).nextBytes(size)

/** A client and a server connection on one endpoint connected to itself. */
internal data class ConnectedPair(val client: Connection, val server: Connection, val endpoint: Endpoint)

internal suspend fun CoroutineScope.connectedPair(transport: TransportConfig = TransportConfig()): ConnectedPair {
    val endpoint = endpointWithConfig(transport)
    val clientD = async { endpoint.connect(endpoint.localAddr(), "localhost").await() }
    val server = checkNotNull(endpoint.accept()).await()
    return ConnectedPair(clientD.await(), server, endpoint)
}
