package neton.quic

import kotlinx.coroutines.launch
import neton.quic.proto.ConnectionError
import neton.quic.proto.IdleTimeout
import neton.quic.proto.TransportConfig
import neton.quic.proto.VarInt
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds

/**
 * quinn `tests/many_connections.rs`: 50 connections to one endpoint (the endpoint connects to itself), each sending
 * 1 MiB with a CRC-32 prefix on a unidirectional stream; the server closes each connection once it has read the stream.
 *
 * ⚖️ quinn marks this test `#[ignore]` (slow under its default test settings); here it runs with the suite, as the
 * driver's many-connection check on one reactor.
 */
class ManyConnectionsTest {
    private val errors = ArrayList<ConnectionError>()

    @Test
    fun connectNNodesTo1AndSend1mbData() = quicTest(120.seconds) {
        val (cfg, clientCfg) = configure()
        val endpoint = Endpoint.server(cfg, V4_LOCALHOST)
        val listenerAddr = endpoint.localAddr()

        val expectedMessages = 50

        launch {
            repeat(expectedMessages) {
                val conn = checkNotNull(endpoint.accept()).await()
                launch {
                    try {
                        while (true) {
                            val stream = try {
                                conn.acceptUni()
                            } catch (e: ConnectionError) {
                                break
                            }
                            readFromPeer(stream)
                            conn.close(VarInt(0), ByteArray(0))
                        }
                    } catch (e: ConnectionError) {
                        errors.add(e)
                    }
                }
            }
        }

        repeat(expectedMessages) {
            val data = randomDataWithHash(1024 * 1024)
            val connecting = endpoint.connectWith(clientCfg, listenerAddr, "localhost")
            launch {
                try {
                    val conn = try {
                        connecting.await()
                    } catch (e: ConnectionError) {
                        throw WriteError.ConnectionLost(e)
                    }
                    writeToPeer(conn, data)
                } catch (e: WriteError) {
                    when {
                        e is WriteError.ConnectionLost &&
                            (e.error is ConnectionError.ApplicationClosed || e.error == ConnectionError.Reset) -> {}
                        e is WriteError.ConnectionLost -> errors.add(e.error)
                        else -> fail("unexpected write error $e")
                    }
                }
            }
        }

        endpoint.waitIdle()
        assertTrue(errors.isEmpty(), "some connections failed: $errors")
        endpoint.close()
    }

    /** The CRC's standard check value, so that a broken checksum cannot pass the transfer test vacuously. */
    @Test
    fun crc32CheckValue() {
        val data = "123456789".encodeToByteArray()
        kotlin.test.assertEquals(0xCBF43926.toInt(), crc32(data, 0, data.size))
    }

    private suspend fun readFromPeer(stream: RecvStream) {
        try {
            val data = stream.readToEnd(1024 * 1024 * 5)
            assertTrue(hashCorrect(data))
        } catch (e: ReadToEndError) {
            when (e) {
                is ReadToEndError.TooLong -> fail("unreachable")
                is ReadToEndError.Read -> when (val r = e.error) {
                    is ReadError.Reset -> fail("unexpected stream reset: ${r.errorCode}")
                    is ReadError.ConnectionLost -> throw r.error
                    else -> fail("unreachable: $r")
                }
            }
        }
    }

    private suspend fun writeToPeer(conn: Connection, data: ByteArray) {
        val s = try {
            conn.openUni()
        } catch (e: ConnectionError) {
            throw WriteError.ConnectionLost(e)
        }
        s.writeAll(data)
        s.finish()
        // Wait for the stream to be fully received
        try {
            s.stopped()
        } catch (e: StoppedError) {
            if (e is StoppedError.ConnectionLost && e.error is ConnectionError.ApplicationClosed) return
            throw e.toWriteError()
        }
    }

    /** Builds the server and client configurations: idle timeout 20 s. */
    private fun configure() = Pair(
        mockServerConfig().transportConfig(TransportConfig().maxIdleTimeout(IdleTimeout.of(20.seconds))),
        mockClientConfig().transportConfig(TransportConfig().maxIdleTimeout(IdleTimeout.of(20.seconds))),
    )

    /** Constructs a buffer with random bytes of given size prefixed with a hash of this data. */
    private fun randomDataWithHash(size: Int): ByteArray {
        val data = Random.nextBytes(size + 4)
        val hash = crc32(data, 4, data.size)
        // write hash in big endian
        data[0] = (hash ushr 24).toByte()
        data[1] = (hash ushr 16).toByte()
        data[2] = (hash ushr 8).toByte()
        data[3] = hash.toByte()
        return data
    }

    /** Checks if given data buffer hash is correct. Hash itself is a 4 byte prefix in the data. */
    private fun hashCorrect(data: ByteArray): Boolean {
        val encoded = ((data[0].toInt() and 0xFF) shl 24) or ((data[1].toInt() and 0xFF) shl 16) or
            ((data[2].toInt() and 0xFF) shl 8) or (data[3].toInt() and 0xFF)
        return encoded == crc32(data, 4, data.size)
    }

    private companion object {
        /** CRC-32/ISO-HDLC (the `crc` crate's `CRC_32_ISO_HDLC`). */
        val TABLE = IntArray(256) { n ->
            var c = n
            repeat(8) { c = if (c and 1 != 0) (c ushr 1) xor 0xEDB88320.toInt() else c ushr 1 }
            c
        }

        fun crc32(data: ByteArray, from: Int, to: Int): Int {
            var c = -1
            for (i in from until to) c = TABLE[(c xor data[i].toInt()) and 0xFF] xor (c ushr 8)
            return c.inv()
        }
    }
}
