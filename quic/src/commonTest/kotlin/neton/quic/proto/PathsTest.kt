package neton.quic.proto

import neton.io.net.SocketAddress
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds

// connection/paths.rs test (1), then RTT estimation and path bookkeeping not tested in quinn.
class PathsTest {
    private val now0 = Instant(1_000_000_000_000L)

    @Test
    fun resetRefreshesPacerBudget() {
        val now = now0
        val config = TransportConfig()
        val remote = SocketAddress.ipv4(203, 0, 113, 1, 4433)
        val path = PathData.new(remote, true, null, 0, now, config)
        val mtu = path.currentMtu()
        val window = path.congestion.window()

        for (i in 0 until 1000) {
            if (path.pacing.delay(path.rtt.get(), mtu.toLong(), mtu, window, now).isSome) break
            path.pacing.onTransmit(mtu)
        }
        assertTrue(path.pacing.delay(path.rtt.get(), mtu.toLong(), mtu, window, now).isSome)

        path.reset(now, config)

        assertEquals(
            Instant.NONE,
            path.pacing.delay(path.rtt.get(), path.currentMtu().toLong(), path.currentMtu(), path.congestion.window(), now),
        )
    }

    @Test
    fun rttEstimator() {
        val rtt = RttEstimator(333.milliseconds)
        assertEquals(333.milliseconds, rtt.get())
        assertEquals(166_500_000.nanoseconds, rtt.variance())
        assertEquals(333.milliseconds + 666.milliseconds, rtt.ptoBase())

        // First sample: smoothed = latest, var = latest / 2, min = latest
        rtt.update(10.milliseconds, 100.milliseconds)
        assertEquals(100.milliseconds, rtt.get())
        assertEquals(50.milliseconds, rtt.variance())
        assertEquals(100.milliseconds, rtt.min())

        // min + ack delay <= latest: the ack delay is subtracted
        rtt.update(10.milliseconds, 120.milliseconds)
        // adjusted 110: var = (3 * 50 + 10) / 4 = 40, smoothed = (7 * 100 + 110) / 8 = 101.25
        assertEquals(40.milliseconds, rtt.variance())
        assertEquals(101_250.microseconds, rtt.get())
        assertEquals(120.milliseconds, rtt.conservative())

        // min + ack delay > latest: the ack delay is not subtracted, min falls
        rtt.update(50.milliseconds, 90.milliseconds)
        assertEquals(90.milliseconds, rtt.min())
        assertEquals(90.milliseconds, rtt.latest())
        assertEquals((7 * 101_250_000L + 90_000_000L) / 8, rtt.get().inWholeNanoseconds)
        assertEquals(rtt.get(), rtt.conservative())

        val copy = rtt.copy()
        rtt.update(0.milliseconds, 500.milliseconds)
        assertEquals(90.milliseconds, copy.latest())

        // PTO base uses the timer granularity as the floor of 4 * var
        val tiny = RttEstimator(0.milliseconds)
        tiny.update(0.milliseconds, 100.microseconds)
        assertEquals(100.microseconds + 1.milliseconds, tiny.ptoBase())
    }

    @Test
    fun pathDataBookkeeping() {
        val config = TransportConfig()
        val remote = SocketAddress.ipv4(203, 0, 113, 1, 4433)
        val path = PathData.new(remote, true, 1400, 7, now0, config)
        assertEquals(1200, path.currentMtu())
        assertEquals(1400, path.mtud.state!!.peerMaxUdpPayloadSize)
        assertTrue(path.sendingEcn)
        assertFalse(path.validated)

        // Anti-amplification: three times what was received
        path.totalRecvd = 1200
        assertFalse(path.antiAmplificationBlocked(3600))
        assertTrue(path.antiAmplificationBlocked(3601))
        path.validated = true
        assertFalse(path.antiAmplificationBlocked(1_000_000))

        val space = PacketSpace(now0)
        val p = SentPacket()
        p.pathGeneration = 7; p.size = 1000; p.ackEliciting = true; p.timeSent = now0
        path.sent(space.getTxNumber(), p, space)
        p.size = 0; p.ackEliciting = false
        path.sent(space.getTxNumber(), p, space)
        assertEquals(1000L, path.inFlight.bytes)
        assertEquals(1L, path.inFlight.ackEliciting)
        assertTrue(path.removeInFlight(space.take(0)!!))
        assertEquals(0L, path.inFlight.bytes)
        assertEquals(0L, path.inFlight.ackEliciting)

        // A packet from another path generation is not counted
        val other = SentPacket()
        other.pathGeneration = 6
        assertFalse(path.removeInFlight(other))

        // Persistent congestion start: strictly after the first packet sent after an RTT sample
        assertFalse(path.firstPacketAfterRttSampleBefore(SpaceId.Data, 5))
        path.setFirstPacketAfterRttSample(SpaceId.Handshake, 10)
        assertTrue(path.firstPacketAfterRttSampleBefore(SpaceId.Data, 0))
        assertTrue(path.firstPacketAfterRttSampleBefore(SpaceId.Handshake, 11))
        assertFalse(path.firstPacketAfterRttSampleBefore(SpaceId.Handshake, 10))
        assertFalse(path.firstPacketAfterRttSampleBefore(SpaceId.Initial, 100))

        val next = PathData.fromPrevious(SocketAddress.ipv4(203, 0, 113, 2, 4433), path, 8, now0)
        assertEquals(8L, next.generation())
        assertEquals(path.congestion.window(), next.congestion.window())
        assertEquals(SpaceId.Handshake, next.firstPacketAfterRttSampleSpace)
        assertFalse(next.validated)
        assertEquals(0L, next.inFlight.bytes)

        // MTU discovery disabled by configuration or by the caller
        val noMtud = PathData.new(remote, false, null, 0, now0, config)
        assertNull(noMtud.mtud.state)
        val noMtudConfig = PathData.new(remote, true, null, 0, now0, TransportConfig().mtuDiscoveryConfig(null))
        assertNull(noMtudConfig.mtud.state)
    }

    @Test
    fun pathResponses() {
        val a = SocketAddress.ipv4(10, 0, 0, 1, 1)
        val b = SocketAddress.ipv4(10, 0, 0, 2, 1)
        val r = PathResponses()
        assertTrue(r.isEmpty())
        r.push(5, 100, a)
        r.push(4, 101, a) // older challenge for a queued remote: ignored
        r.push(6, 102, a) // newer: replaces
        r.push(7, 200, b)
        assertNull(r.popOnPath(a)) // the last one is for b
        assertEquals(OffPathResponse(200, b), r.popOffPath(a))
        assertNull(r.popOffPath(a))
        assertEquals(102L, r.popOnPath(a))
        assertTrue(r.isEmpty())

        // At most 16 queued responses
        for (i in 0 until 20) r.push(i.toLong(), i.toLong(), SocketAddress.ipv4(10, 0, 1, i, 1))
        var n = 0
        while (true) {
            val x = r.popOffPath(a) ?: break
            assertEquals(15L - n, x.token)
            n++
        }
        assertEquals(16, n)
    }
}
