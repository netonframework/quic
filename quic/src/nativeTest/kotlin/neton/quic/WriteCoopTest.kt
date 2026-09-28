package neton.quic

import kotlinx.coroutines.async
import neton.quic.proto.VarInt
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNotNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * A writer that keeps finding flow-control credit must still let the connection's driver run (cooperative budget,
 * tokio's coop in quinn). Before: small writes never suspended, so nothing was sent and no packet handled until the
 * whole stream window (about 1.25 MB) was used up — a peer's STOP_SENDING was noticed only then.
 */
class WriteCoopTest {
    @Test
    fun stopSendingReachesAWriterThatNeverRunsOutOfCredit() = quicTest {
        val factory = EndpointFactory()
        val server = factory.endpoint()
        val serverAddr = server.localAddr()
        val client = factory.endpoint()

        val serverSide = async {
            val conn = assertNotNull(server.accept()).await()
            val stream = conn.acceptUni()
            val buf = ByteArray(6)
            stream.readExact(buf)               // the first write arrived: the driver ran while the writer loops
            stream.stop(VarInt(7))
            conn
        }
        val conn = client.connect(serverAddr, "localhost").await()
        val stream = conn.openUni()
        val chunk = ByteArray(6) { it.toByte() }
        var written = 0L
        try {
            while (true) {
                stream.writeAll(chunk)
                written += chunk.size
                if (written > 4L * 1024 * 1024) fail("no STOP_SENDING after $written bytes")
            }
        } catch (e: WriteError.Stopped) {
            assertEquals(VarInt(7), e.errorCode)
        }
        // Far below one stream window: the stop took effect while credit remained.
        assertTrue(written < 256 * 1024, "stopped only after $written bytes")
        serverSide.await()
        server.shutdown()
        client.shutdown()
    }
}
