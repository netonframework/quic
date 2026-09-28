package neton.quic.proto

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds

// congestion/cubic.rs tests (2)
class CubicTest {
    private val now0 = Instant(1_000_000_000_000L)

    @Test
    fun fastConvergenceReducesWMaxWithoutDoubleReducingWindow() {
        val now = now0
        val config = CubicConfig()
        val cubic = Cubic(config, now, BASE_DATAGRAM_SIZE.toInt())
        val window = 8 * BASE_DATAGRAM_SIZE

        cubic.window = window
        cubic.ssthresh = window
        cubic.cubicState.wMax = 12.0 * BASE_DATAGRAM_SIZE.toDouble()

        cubic.onCongestionEvent(now, now + 1.milliseconds, false, 0)

        assertEquals(window.toDouble() * (1.0 + BETA_CUBIC) / 2.0, cubic.cubicState.wMax)
        assertEquals((window.toDouble() * BETA_CUBIC).toLong(), cubic.ssthresh)
        assertEquals(cubic.ssthresh, cubic.window)
    }

    @Test
    fun congestionAvoidanceDoesNotOverflowAfterLongLosslessPeriod() {
        val now = now0
        val rtt = RttEstimator(100.milliseconds)
        val config = CubicConfig()
        val cubic = Cubic(config, now, BASE_DATAGRAM_SIZE.toInt())

        // Put CUBIC directly into congestion avoidance.
        cubic.ssthresh = cubic.window
        cubic.recoveryStartTime = now
        val window = cubic.window

        // After ten days without a congestion event, w_cubic exceeds u64::MAX. Before this fix, computing the window
        // increment overflowed.
        val later = now + (10 * 24 * 60 * 60).seconds
        cubic.onAck(later, later, BASE_DATAGRAM_SIZE, false, rtt)

        assertEquals(window + BASE_DATAGRAM_SIZE, cubic.window)
    }

    // Not in quinn: slow start, loss reduction, persistent congestion and the controller copy.
    @Test
    fun slowStartLossAndPersistentCongestion() {
        val rtt = RttEstimator(100.milliseconds)
        val cubic = CubicConfig().build(now0, 1200) as Cubic
        assertEquals(12000L, cubic.initialWindow())
        cubic.onAck(now0, now0, 1200, false, rtt)
        assertEquals(13200L, cubic.window())
        cubic.onAck(now0, now0, 1200, true, rtt) // app-limited: no growth
        assertEquals(13200L, cubic.window())

        cubic.onCongestionEvent(now0 + 1.seconds, now0 + 500.milliseconds, false, 1200)
        assertEquals((13200 * BETA_CUBIC).toLong(), cubic.window())
        // Packets sent before the recovery start neither grow nor shrink the window
        val w = cubic.window()
        cubic.onAck(now0 + 2.seconds, now0 + 1.seconds, 1200, false, rtt)
        cubic.onCongestionEvent(now0 + 2.seconds, now0 + 1.seconds, false, 1200)
        assertEquals(w, cubic.window())

        val copy = cubic.cloneBox()
        cubic.onCongestionEvent(now0 + 3.seconds, now0 + 3.seconds, true, 1200)
        assertEquals(2400L, cubic.window())
        assertEquals(w, copy.window())
        assertEquals(Instant.NONE, cubic.recoveryStartTime)

        cubic.onMtuUpdate(1500)
        assertEquals(3000L, cubic.window())
        assertEquals(cubic.window(), cubic.metrics().congestionWindow)
    }
}

// Not in quinn (new_reno.rs has no tests): NewReno's slow start, ABC congestion avoidance and loss reduction.
class NewRenoTest {
    private val now0 = Instant(1_000_000_000_000L)
    private val rtt = RttEstimator(100.milliseconds)

    @Test
    fun slowStartAvoidanceAndLoss() {
        val reno = NewRenoConfig().build(now0, 1200) as NewReno
        assertEquals(12000L, reno.window())
        // Packets sent at the recovery start (construction time) do not count
        reno.onAck(now0, now0, 1200, false, rtt)
        assertEquals(12000L, reno.window())
        reno.onAck(now0, now0 + 1.milliseconds, 1200, false, rtt)
        assertEquals(13200L, reno.window())

        reno.onCongestionEvent(now0 + 1.seconds, now0 + 2.milliseconds, false, 1200)
        assertEquals(6600L, reno.window())
        assertEquals(6600L, reno.metrics().ssthresh)

        // Congestion avoidance: one MTU per window acknowledged
        for (i in 0 until 5) reno.onAck(now0 + 2.seconds, now0 + 2.seconds, 1200, false, rtt)
        assertEquals(6600L, reno.window())
        reno.onAck(now0 + 2.seconds, now0 + 2.seconds, 1200, false, rtt)
        assertEquals(7800L, reno.window())

        reno.onCongestionEvent(now0 + 3.seconds, now0 + 3.seconds, true, 1200)
        assertEquals(2400L, reno.window())
        reno.onMtuUpdate(1400)
        assertEquals(2800L, reno.window())
    }

    @Test
    fun configDefaults() {
        assertEquals(12000L, NewRenoConfig().initialWindow)
        assertEquals(0.5f, NewRenoConfig().lossReductionFactor)
        assertEquals(12000L, CubicConfig().initialWindow)
        assertEquals(240_000L, BbrConfig().initialWindow)
        assertEquals(20000L, NewRenoConfig().initialWindow(20000).build(now0, 1200).initialWindow())
    }
}

// congestion/bbr/min_max.rs test (1), plus BBR checks not in quinn.
class BbrTest {
    @Test
    fun test() {
        val round = 25L
        val minMax = MinMax()
        minMax.updateMax(round + 1, 100)
        assertEquals(100L, minMax.get())
        minMax.updateMax(round + 3, 120)
        assertEquals(120L, minMax.get())
        minMax.updateMax(round + 5, 160)
        assertEquals(160L, minMax.get())
        minMax.updateMax(round + 7, 100)
        assertEquals(160L, minMax.get())
        minMax.updateMax(round + 10, 100)
        assertEquals(160L, minMax.get())
        minMax.updateMax(round + 14, 100)
        assertEquals(160L, minMax.get())
        minMax.updateMax(round + 16, 100)
        assertEquals(100L, minMax.get())
        minMax.updateMax(round + 18, 130)
        assertEquals(130L, minMax.get())
    }

    @Test
    fun bandwidthFromDelta() {
        assertEquals(-1L, BandwidthEstimation.bwFromDelta(1000, 0))
        assertEquals(1_000_000L, BandwidthEstimation.bwFromDelta(1000, 1_000_000))
        val bw = BandwidthEstimation()
        assertEquals("0.000 MB/s", bw.toString())
    }

    /**
     * A window-limited sender over a bottleneck link (one 1200-byte packet per 100 µs, i.e. 12 MB/s, 50 ms RTT):
     * BBR leaves startup and drain, estimates the bottleneck bandwidth and paces near it.
     */
    @Test
    fun steadyFlowReachesProbeBandwidth() {
        val bbr = Bbr(BbrConfig(), 1200, Random(1))
        assertEquals(240_000L, bbr.window())
        assertEquals(BbrMode.Startup, bbr.mode)
        val rtt = RttEstimator(50.milliseconds)
        val serviceNanos = 100_000L
        val propagationNanos = 50_000_000L
        var t = 1_000_000_000L
        var nextPn = 0L
        var inFlight = 0L
        var linkFreeAt = t
        // (packet number, sent time, ACK arrival time), in ACK order
        val pending = ArrayDeque<LongArray>()
        repeat(40_000) {
            // Send while the window allows; the bottleneck queues packets
            while (inFlight + 1200 <= bbr.window()) {
                bbr.onSent(Instant(t), 1200, nextPn)
                val departs = maxOf(linkFreeAt, t) + serviceNanos
                linkFreeAt = departs
                pending.addLast(longArrayOf(nextPn, t, departs + propagationNanos))
                nextPn++
                inFlight += 1200
            }
            // Deliver the ACKs due by now as one batch
            var largest = -1L
            while (pending.isNotEmpty() && pending.first()[2] <= t) {
                val (pn, sent, _) = pending.removeFirst()
                rtt.update(0.milliseconds, (t - sent).nanoseconds)
                inFlight -= 1200
                bbr.onAck(Instant(t), Instant(sent), 1200, false, rtt)
                largest = pn
            }
            if (largest >= 0) bbr.onEndAcks(Instant(t), inFlight, false, largest)
            t += serviceNanos
        }
        assertTrue(bbr.mode == BbrMode.ProbeBw || bbr.mode == BbrMode.ProbeRtt, "mode ${bbr.mode}")
        val estimate = bbr.maxBandwidth.getEstimate()
        assertTrue(estimate in 11_000_000L..13_000_000L, "bandwidth estimate $estimate")
        assertTrue(bbr.pacingRate > 0)
        assertEquals(bbr.pacingRate * 8, bbr.metrics().pacingRate)
        assertNull(bbr.metrics().ssthresh)
        val copy = bbr.cloneBox() as Bbr
        assertEquals(bbr.window(), copy.window())
        assertEquals(bbr.mode, copy.mode)
    }

    @Test
    fun lossEntersRecovery() {
        val bbr = Bbr(BbrConfig(), 1200, Random(1))
        val rtt = RttEstimator(50.milliseconds)
        bbr.onSent(Instant(0), 1200, 10)
        bbr.onCongestionEvent(Instant(1), Instant(0), false, 1200)
        bbr.onAck(Instant(2), Instant(0), 1200, false, rtt)
        bbr.onEndAcks(Instant(2), 0, false, 5)
        assertEquals(BbrRecoveryState.Conservation, bbr.recoveryState)
        bbr.onMtuUpdate(1500)
        assertTrue(bbr.window() >= 4 * 1500)
    }
}
