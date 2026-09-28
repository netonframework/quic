package neton.quic

import kotlinx.coroutines.async
import kotlinx.coroutines.flow.toList
import kotlinx.coroutines.launch
import neton.io.bytes.Buffer
import neton.io.codec.LineCodec
import neton.io.core.Framed
import neton.io.core.Io
import neton.io.core.IoStream
import neton.io.core.StreamCapability
import neton.io.testkit.IoStreamConformance
import neton.io.testkit.StreamPair
import neton.quic.proto.VarInt
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertIs
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

/** SPEC §3: bidirectional streams as neton-io [IoStream]s ([QuicStream]). */
class QuicStreamTest {

    /** neton-io's IoStream conformance suite (neton-io SPEC §28.6), every check on a fresh stream of one connection. */
    @Test
    fun conformance() = quicTest(120.seconds) {
        val (client, server, endpoint) = connectedPair()
        val failures = IoStreamConformance(
            "quic",
            open = { openPair(client, server, resetting = false) },
            openResetting = { openPair(client, server, resetting = true) },
        ).run()
        failures.forEach { println("FAIL $it") }
        assertEquals(emptyList(), failures)
        endpoint.shutdown()
    }

    @Test
    fun declaresItsCapabilities() = quicTest {
        val (client, _, endpoint) = connectedPair()
        val stream = client.openBiStream()
        assertEquals(setOf(StreamCapability.HalfClose, StreamCapability.ResumableAfterCancel), stream.capabilities)
        stream.close()
        endpoint.shutdown()
    }

    /** A line protocol over neton-io's [Framed] + [LineCodec], unchanged, on a QUIC stream. */
    @Test
    fun framedLineEcho() = quicTest {
        val (client, server, endpoint) = connectedPair()
        val lines = List(200) { "line $it " + "x".repeat(it * 7) }
        val echo = launch {
            val stream = server.acceptBiStream()
            val framed = Framed(Io(stream), LineCodec, LineCodec)
            framed.incoming().collect { framed.send(it.uppercase()) }
            stream.shutdownOutput()
            stream.close()
        }
        val stream = client.openBiStream()
        val framed = Framed(Io(stream), LineCodec, LineCodec)
        val replies = async { framed.incoming().toList() }
        for (line in lines) framed.feed(line)
        framed.flush()
        stream.shutdownOutput()
        assertEquals(lines.map { it.uppercase() }, replies.await())
        stream.close()
        echo.join()
        endpoint.shutdown()
    }

    /** A peer's reset is an [IoException][neton.io.core.IoException] carrying [ReadError.Reset], not EOF. */
    @Test
    fun peerResetIsAnError() = quicTest {
        val (client, server, endpoint) = connectedPair()
        val (a, b) = openPair(client, server, resetting = false).let { it.a as QuicStream to it.b as QuicStream }
        b.send.reset(VarInt(9))
        val e = assertIs<QuicStreamException>(runCatching { a.read(Buffer()) }.exceptionOrNull())
        assertEquals(ReadError.Reset(VarInt(9)), e.error)
        a.close()
        b.close()
        endpoint.shutdown()
    }

    /** Closing the IoStream stops the peer's sending with code 0 and finishes ours (the lifecycle rules). */
    @Test
    fun closeFollowsTheLifecycleRules() = quicTest {
        val (client, server, endpoint) = connectedPair()
        val (a, b) = openPair(client, server, resetting = false).let { it.a as QuicStream to it.b as QuicStream }
        a.write(Buffer().also { it.writeBytes("bye".encodeToByteArray()) })
        a.close()
        assertEquals(VarInt(0), b.send.stopped(), "a's unread receive half was stopped with 0")
        val got = Buffer()
        while (b.read(got) >= 0) Unit
        assertEquals("bye", got.readAll().decodeToString(), "a's send half was finished after its data")
        assertTrue(client.closeReason() == null, "closing a stream leaves the connection open")
        b.close()
        endpoint.shutdown()
    }

    /**
     * A fresh connected pair on [client] → [server]. The stream only reaches the peer once something is written, so
     * one byte is sent and consumed before the pair is handed out. With [resetting], closing `b` resets its sending
     * half and stops its receiving half (the suite's "peer reset" hook).
     */
    private suspend fun openPair(client: Connection, server: Connection, resetting: Boolean): StreamPair {
        val (send, recv) = client.openBi()
        send.writeAll(byteArrayOf(0))
        val (peerSend, peerRecv) = server.acceptBi()
        peerRecv.readExact(ByteArray(1))
        val a = QuicStream(send, recv)
        val b = QuicStream(peerSend, peerRecv)
        return StreamPair(a, if (resetting) Resetting(b) else b)
    }

    private class Resetting(private val inner: QuicStream) : IoStream by inner {
        override fun close() {
            runCatching { inner.send.reset(VarInt(1)) }
            runCatching { inner.recv.stop(VarInt(1)) }
            inner.close()
        }
    }
}
