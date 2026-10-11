package neton.quic

import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitAll
import kotlinx.coroutines.launch
import kotlinx.coroutines.withTimeout
import neton.io.net.SocketAddress
import neton.io.net.bindUdp
import neton.io.net.runReactor
import neton.quic.proto.Certificates
import neton.quic.proto.ClientConfig
import neton.quic.proto.ConnectionError
import neton.quic.proto.EndpointConfig
import neton.quic.proto.PrivateKey
import neton.quic.proto.ServerConfig
import neton.quic.proto.TlsClientConfig
import neton.quic.proto.TlsHandshakeData
import neton.quic.proto.TlsServerConfig
import neton.quic.proto.TransportConfig
import neton.quic.proto.VarInt
import neton.quic.proto.default
import neton.quic.proto.withCrypto
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * QUIC on the JVM, end to end: real TLS 1.3 through openssl-kotlin's JNI library and loopback UDP through neton-io's
 * NIO reactor (no test doubles). Echo on many streams with key updates, an application close, resumption with 0-RTT,
 * and a client that does not trust the server.
 */
class JvmEndToEndTest {
    private val alpn = listOf("echo/1".encodeToByteArray())
    private val certificate = Certificates.pem(JvmTestIdentity.CERTIFICATE_PEM)

    private fun serverCrypto() = TlsServerConfig(certificate, PrivateKey.pem(JvmTestIdentity.PRIVATE_KEY_PEM), alpn)

    private fun test(block: suspend CoroutineScope.() -> Unit) = runReactor { withTimeout(60.seconds) { block() } }

    private suspend fun server(): Endpoint {
        val cfg = ServerConfig.withCrypto(serverCrypto()).transportConfig(TransportConfig().maxConcurrentBidiStreams(VarInt(64)))
        return Endpoint.create(EndpointConfig.default(), cfg, bindUdp(SocketAddress.IPV4_LOCALHOST_ANY_PORT))
    }

    /** Echoes every bidirectional stream of every connection until the connection ends. */
    private fun CoroutineScope.echo(server: Endpoint) = launch {
        while (true) {
            val incoming = server.accept() ?: break
            launch {
                val conn = try { incoming.await() } catch (_: ConnectionError) { return@launch }
                while (true) {
                    val (send, recv) = try { conn.acceptBi() } catch (_: ConnectionError) { break }
                    launch {
                        send.writeAll(recv.readToEnd())
                        send.finish()
                    }
                }
            }
        }
    }

    @Test
    fun echoOnManyStreamsWithKeyUpdates() = test {
        val server = server()
        val serving = echo(server)
        val client = Endpoint.client(SocketAddress.IPV4_UNSPECIFIED_ANY_PORT)
        client.setDefaultClientConfig(ClientConfig(TlsClientConfig(certificate, alpn)))
        val conn = client.connect(server.localAddr(), "localhost").await()
        assertContentEquals(alpn[0], (conn.handshakeData() as TlsHandshakeData).protocol)
        assertContentEquals(certificate.toDer()[0], (conn.peerIdentity() as List<*>).first() as ByteArray)
        val streams = (0 until 16).map { i ->
            async {
                val (send, recv) = conn.openBi()
                val message = Random(i).nextBytes(64 * 1024 + i)
                val w = async { send.writeAll(message); send.finish() }
                val echoed = recv.readToEnd()
                w.await()
                assertContentEquals(message, echoed, "stream $i")
            }
        }
        repeat(3) {
            kotlinx.coroutines.delay(5)
            conn.forceKeyUpdate()
        }
        streams.awaitAll()
        conn.close(VarInt(7), "bye".encodeToByteArray())
        client.waitIdle()
        client.close()
        serving.cancel()
        server.close()
    }

    @Test
    fun aResumedConnectionSendsZeroRttData() = test {
        val server = server()
        val serving = echo(server)
        val client = Endpoint.client(SocketAddress.IPV4_UNSPECIFIED_ANY_PORT)
        client.setDefaultClientConfig(ClientConfig(TlsClientConfig(certificate, alpn)))
        // A first connection leaves a session ticket in the client configuration.
        val first = client.connect(server.localAddr(), "localhost").await()
        val (s1, r1) = first.openBi()
        s1.writeAll(byteArrayOf(1)); s1.finish()
        assertContentEquals(byteArrayOf(1), r1.readToEnd())
        first.close(VarInt(0), ByteArray(0))
        // The second sends its request in 0-RTT.
        val connecting = client.connect(server.localAddr(), "localhost")
        val (conn, accepted) = assertNotNull(connecting.into0Rtt(), "no 0-RTT: the ticket did not resume")
        val (send, recv) = conn.openBi()
        send.writeAll("early".encodeToByteArray()); send.finish()
        assertEquals("early", recv.readToEnd().decodeToString())
        assertTrue(accepted.await(), "the server rejected the 0-RTT data")
        conn.close(VarInt(0), ByteArray(0))
        client.waitIdle()
        client.close()
        serving.cancel()
        server.close()
    }

    @Test
    fun aClientThatDoesNotTrustTheServerFails() = test {
        val server = server()
        val serving = echo(server)
        val stranger = Certificates.pem(strangerCertificate())
        val client = Endpoint.client(SocketAddress.IPV4_UNSPECIFIED_ANY_PORT)
        client.setDefaultClientConfig(ClientConfig(TlsClientConfig(stranger, alpn)))
        val e = runCatching { client.connect(server.localAddr(), "localhost").await() }.exceptionOrNull()
        assertIs<ConnectionError>(e, "got $e")
        client.close()
        serving.cancel()
        server.close()
    }

    /** Some other valid certificate (not the server's). */
    private fun strangerCertificate(): String = STRANGER

    private companion object {
        // A self-signed certificate for localhost from another key (openssl req -x509, P-256, 2026-10-11).
        const val STRANGER = """
-----BEGIN CERTIFICATE-----
MIIBkjCCATmgAwIBAgIUF3qzyxJ3NuIA3X/DXwUFiZf5wgUwCgYIKoZIzj0EAwIw
EzERMA8GA1UEAwwIc3RyYW5nZXIwIBcNMjYwMTAxMDAwMDAwWhgPMjEyNTEyMzEw
MDAwMDBaMBMxETAPBgNVBAMMCHN0cmFuZ2VyMFkwEwYHKoZIzj0CAQYIKoZIzj0D
AQcDQgAEYmjxKcAd9Wida0a0pmfYpDAr882kihINkQQITE7ZCKjsXS4WVY0JFB4w
D5Ryjo2pJ/n45lmfZcGojK54IMSNQaNpMGcwHQYDVR0OBBYEFNUQ9hdTj+fpjJoA
liWLEQXw1IfSMB8GA1UdIwQYMBaAFNUQ9hdTj+fpjJoAliWLEQXw1IfSMA8GA1Ud
EwEB/wQFMAMBAf8wFAYDVR0RBA0wC4IJbG9jYWxob3N0MAoGCCqGSM49BAMCA0cA
MEQCIBQWfdzYx7Y0g6Nk9O09QYLXAOsoApAWz/NeD/0J6IE4AiBq0Jjfsp0EjSAb
KTzeNlgE/AUS7f0sux6diWopcjk5HA==
-----END CERTIFICATE-----
"""
    }
}
