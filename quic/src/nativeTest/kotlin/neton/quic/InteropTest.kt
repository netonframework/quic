@file:OptIn(ExperimentalForeignApi::class)

package neton.quic

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.toKString
import kotlinx.coroutines.launch
import neton.io.net.SocketAddress
import neton.io.net.bindUdp
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
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread
import platform.posix.getenv
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/**
 * The Kotlin side of the interop runs against quinn 0.11 (SPEC §11.9), as a test that does nothing unless
 * `NETON_QUIC_INTEROP` is set, so it stays out of the production artifact and runs from the test binary:
 *
 * - `NETON_QUIC_INTEROP=server NETON_QUIC_INTEROP_ADDR=127.0.0.1:4433 NETON_QUIC_INTEROP_CERT=server.pem
 *   NETON_QUIC_INTEROP_KEY=server.key NETON_QUIC_INTEROP_CONNS=1 test.kexe --ktest_filter=neton.quic.InteropTest.*`:
 *   accept that many connection attempts (failed handshakes are logged); echo every bidirectional stream, sending each echo in a new key phase (forced 300 ms after the
 *   stream was read); print what was
 *   negotiated and how each connection ended.
 * - `NETON_QUIC_INTEROP=client NETON_QUIC_INTEROP_ADDR=127.0.0.1:4434 NETON_QUIC_INTEROP_NAME=localhost
 *   NETON_QUIC_INTEROP_CA=ca.pem test.kexe --ktest_filter=neton.quic.InteropTest.*`: open streams one after
 *   another, each echoed and compared, each in a new key phase forced 300 ms after the previous echo; close with
 *   code 0x42. The pauses let each update be discarded (3 PTO) before the other side's, so none is skipped as
 *   concurrent and each is carried by data.
 *
 * ALPN is `neton-interop`. Certificates are verified against the given CA (no insecure mode).
 */
class InteropTest {
    private fun env(name: String): String? = getenv(name)?.toKString()?.ifEmpty { null }
    private val alpn = listOf("neton-interop".encodeToByteArray())

    private fun readFile(path: String): ByteArray {
        val f = fopen(path, "rb") ?: error("cannot open $path")
        try {
            val out = ArrayList<Byte>()
            memScoped {
                val buf = allocArray<ByteVar>(4096)
                while (true) {
                    val n = fread(buf, 1u, 4096u, f).toInt()
                    if (n <= 0) break
                    out.addAll(buf.readBytes(n).toList())
                }
            }
            return out.toByteArray()
        } finally {
            fclose(f)
        }
    }

    private fun address(s: String): SocketAddress {
        val host = s.substringBeforeLast(':')
        val port = s.substringAfterLast(':').toInt()
        val parts = host.split('.').map { it.toInt() }
        return SocketAddress.ipv4(parts[0], parts[1], parts[2], parts[3], port)
    }

    private fun log(msg: String) = println("[neton-quic interop] $msg")

    @Test
    fun interop() {
        when (env("NETON_QUIC_INTEROP")) {
            "server" -> server()
            "client" -> client()
            else -> return
        }
    }

    private fun server() = quicTest(120.seconds) {
        val tls = TlsServerConfig(
            Certificates.pem(readFile(env("NETON_QUIC_INTEROP_CERT")!!)),
            PrivateKey.pem(readFile(env("NETON_QUIC_INTEROP_KEY")!!)),
            alpn,
        )
        val cfg = ServerConfig.withCrypto(tls).transportConfig(TransportConfig().maxConcurrentBidiStreams(VarInt(100)))
        val endpoint = Endpoint.create(EndpointConfig.default(), cfg, bindUdp(address(env("NETON_QUIC_INTEROP_ADDR")!!)))
        log("server listening on ${endpoint.localAddr()}")
        val conns = env("NETON_QUIC_INTEROP_CONNS")?.toInt() ?: 1
        var served = 0
        repeat(conns) { n ->
            val conn = try {
                endpoint.accept()!!.await()
            } catch (e: ConnectionError) {
                log("conn $n: handshake failed: $e")
                return@repeat
            }
            served++
            val hd = conn.handshakeData() as TlsHandshakeData
            log("conn $n: connected from ${conn.remoteAddress()}; ALPN ${hd.protocol?.decodeToString()}; SNI ${hd.serverName}")
            var streams = 0
            val echo = launch {
                while (true) {
                    val (send, recv) = try { conn.acceptBi() } catch (e: ConnectionError) { break }
                    val data = recv.readToEnd()
                    // The client's update came with this stream; once it is discarded (3 PTO), update ours and send
                    // the echo in the new key phase
                    kotlinx.coroutines.delay(300)
                    conn.forceKeyUpdate()
                    send.writeAll(data)
                    send.finish()
                    streams++
                }
            }
            val reason = conn.closed()
            echo.join()
            val inner = conn.state.inner
            log("conn $n: closed: $reason; streams echoed $streams; key updates ${inner.keyUpdates} (${inner.peerKeyUpdates} by the peer); lost packets ${conn.stats().path.lostPackets}")
            assertTrue(streams > 0)
            assertTrue(inner.keyUpdates - inner.peerKeyUpdates >= 1, "a key update of ours was accepted")
            assertTrue(inner.peerKeyUpdates >= 1, "a key update of the peer was accepted")
        }
        assertTrue(served > 0, "no connection was served")
        endpoint.waitIdle()
        endpoint.close()
        log("server done")
    }

    private fun client() = quicTest(120.seconds) {
        val tls = TlsClientConfig(Certificates.pem(readFile(env("NETON_QUIC_INTEROP_CA")!!)), alpn)
        val endpoint = Endpoint.client(SocketAddress.IPV4_UNSPECIFIED_ANY_PORT)
        endpoint.setDefaultClientConfig(ClientConfig(tls))
        val name = env("NETON_QUIC_INTEROP_NAME") ?: "localhost"
        val conn = endpoint.connect(address(env("NETON_QUIC_INTEROP_ADDR")!!), name).await()
        val hd = conn.handshakeData() as TlsHandshakeData
        val chain = conn.peerIdentity() as List<*>
        log("client connected to $name; ALPN ${hd.protocol?.decodeToString()}; server chain ${chain.size} certificate(s)")
        assertContentEquals(alpn[0], hd.protocol)
        val streams = env("NETON_QUIC_INTEROP_STREAMS")?.toInt() ?: 8
        var total = 0L
        for (i in 0 until streams) {
            val (send, recv) = conn.openBi()
            val msg = genData(100_000 + i * 997, i.toLong())
            val writer = launch { send.writeAll(msg); send.finish() }
            val back = recv.readToEnd()
            writer.join()
            assertContentEquals(msg, back, "stream $i")
            total += back.size
            // The server's update came with the echo; once it is discarded (3 PTO), update ours and send the next
            // stream in the new key phase
            kotlinx.coroutines.delay(300)
            conn.forceKeyUpdate()
        }
        val inner = conn.state.inner
        log("client echoed $streams streams, $total bytes; key updates ${inner.keyUpdates} (${inner.peerKeyUpdates} by the peer); lost packets ${conn.stats().path.lostPackets}")
        conn.close(VarInt(0x42), "done".encodeToByteArray())
        val reason = conn.closed()
        log("client closed: $reason")
        endpoint.waitIdle()
        endpoint.close()
        assertTrue(inner.keyUpdates - inner.peerKeyUpdates >= 1, "a key update of ours was accepted")
        assertTrue(inner.peerKeyUpdates >= 1, "a key update of the peer was accepted")
        assertTrue(reason is ConnectionError.LocallyClosed, "$reason")
        log("client done")
    }
}
