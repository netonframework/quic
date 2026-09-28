package neton.quic.proto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds

// connection/mtud.rs tests (28), with virtual time. quinn's `None` probe sizes / packet numbers are -1 here.
class MtudTest {

    /** A virtual `Instant::now()`. */
    private val now0 = Instant(5_000_000_000_000L)

    private fun defaultMtud(): MtuDiscovery = MtuDiscovery.new(1_200, 1_200, null, MtuDiscoveryConfig())

    private fun completed(mtud: MtuDiscovery): Boolean = mtud.state!!.phase == MtudPhase.Complete

    /** Drives mtud until it reaches the Complete phase. */
    private fun driveToCompletion(mtud: MtuDiscovery, now: Instant, linkPayloadSizeLimit: Int): List<Int> {
        val probedSizes = ArrayList<Int>()
        for (probePn in 1L until 100L) {
            val result = mtud.pollTransmit(now, probePn)

            if (completed(mtud)) break

            // "Send" next probe
            assertTrue(result >= 0)
            val probeSize = result
            probedSizes.add(probeSize)

            if (probeSize <= linkPayloadSizeLimit) {
                mtud.onAcked(SpaceId.Data, probePn, probeSize)
            } else {
                mtud.onProbeLost()
            }
        }
        return probedSizes
    }

    @Test
    fun blackHoleDetectorIgnoresBurstContainingNonSuspiciousPacket() {
        val mtud = defaultMtud()
        mtud.onNonProbeLost(2, 1300)
        mtud.onNonProbeLost(3, 1300)
        assertEquals(3L, mtud.blackHoleDetector.largestNonProbeLost())
        assertEquals(0, mtud.blackHoleDetector.suspiciousLossBurstCount())

        mtud.onNonProbeLost(4, 800)
        assertFalse(mtud.blackHoleDetected(now0))
        assertEquals(-1L, mtud.blackHoleDetector.largestNonProbeLost())
        assertEquals(0, mtud.blackHoleDetector.suspiciousLossBurstCount())
    }

    @Test
    fun blackHoleDetectorCountsBurstContainingOnlySuspiciousPackets() {
        val mtud = defaultMtud()
        mtud.onNonProbeLost(2, 1300)
        mtud.onNonProbeLost(3, 1300)
        assertEquals(3L, mtud.blackHoleDetector.largestNonProbeLost())
        assertEquals(0, mtud.blackHoleDetector.suspiciousLossBurstCount())

        assertFalse(mtud.blackHoleDetected(now0))
        assertEquals(-1L, mtud.blackHoleDetector.largestNonProbeLost())
        assertEquals(1, mtud.blackHoleDetector.suspiciousLossBurstCount())
    }

    @Test
    fun blackHoleDetectorIgnoresEmptyBurst() {
        val mtud = defaultMtud()
        assertFalse(mtud.blackHoleDetected(now0))
        assertEquals(0, mtud.blackHoleDetector.suspiciousLossBurstCount())
    }

    @Test
    fun mtuDiscoveryDisabledDoesNothing() {
        val mtud = MtuDiscovery.disabled(1_200, 1_200)
        val probeSize = mtud.pollTransmit(now0, 0)
        assertEquals(-1, probeSize)
    }

    @Test
    fun mtuDiscoveryDisabledLostFourPacketBurstsTriggersBlackHoleDetection() {
        val mtud = MtuDiscovery.disabled(1_400, 1_250)
        val now = now0

        for (i in 0L until 4L) {
            // The packets are never contiguous, so each one has its own burst
            mtud.onNonProbeLost(i * 2, 1300)
        }

        assertTrue(mtud.blackHoleDetected(now))
        assertEquals(1250, mtud.currentMtu())
        assertNull(mtud.state)
    }

    @Test
    fun mtuDiscoveryLostTwoPacketBurstsDoesNotTriggerBlackHoleDetection() {
        val mtud = defaultMtud()
        val now = now0

        for (i in 0L until 2L) {
            mtud.onNonProbeLost(i, 1300)
            assertFalse(mtud.blackHoleDetected(now))
        }
    }

    @Test
    fun mtuDiscoveryLostFourPacketBurstsTriggersBlackHoleDetectionAndResetsTimer() {
        val mtud = defaultMtud()
        val now = now0

        for (i in 0L until 4L) {
            // The packets are never contiguous, so each one has its own burst
            mtud.onNonProbeLost(i * 2, 1300)
        }

        assertTrue(mtud.blackHoleDetected(now))
        assertEquals(1200, mtud.currentMtu())
        val state = mtud.state!!
        if (state.phase == MtudPhase.Complete) {
            assertEquals(now + 60.seconds, state.nextActivation)
        } else {
            fail("Unexpected MTUD phase!")
        }
    }

    @Test
    fun mtuDiscoveryAfterCompleteReactivatesWhenIntervalElapsed() {
        val config = MtuDiscoveryConfig().upperBound(9_000)
        val mtud = MtuDiscovery.new(1_200, 1_200, null, config)
        val now = now0
        driveToCompletion(mtud, now, 1_500)

        // Polling right after completion does not cause new packets to be sent
        assertEquals(-1, mtud.pollTransmit(now, 42))
        assertTrue(completed(mtud))
        assertEquals(1_471, mtud.currentMtu())

        // Polling after the interval has passed does (taking the current mtu as lower bound)
        assertEquals(5235, mtud.pollTransmit(now + 600.seconds, 43))

        val state = mtud.state!!
        if (state.phase == MtudPhase.Searching) {
            assertEquals(1_471, state.search.lowerBound)
            assertEquals(9_000, state.search.upperBound)
        } else {
            fail("Unexpected MTUD phase!")
        }
    }

    @Test
    fun mtuDiscoveryLostThreeProbesLowersProbeSize() {
        val mtud = defaultMtud()

        val probeSizes = (0L until 4L).map { i ->
            val probeSize = mtud.pollTransmit(now0, i)
            assertTrue(probeSize >= 0, "no probe returned for packet $i")

            mtud.onProbeLost()
            probeSize
        }.iterator()

        // After the first probe is lost, it gets retransmitted twice
        val firstProbeSize = probeSizes.next()
        repeat(2) { assertEquals(firstProbeSize, probeSizes.next()) }

        // After the third probe is lost, we decrement our probe size
        val fourthProbeSize = probeSizes.next()
        assertTrue(fourthProbeSize < firstProbeSize)
        assertEquals(firstProbeSize - (firstProbeSize - 1_200) / 2 - 1, fourthProbeSize)
    }

    @Test
    fun mtuDiscoveryWithPeerMaxUdpPayloadSizeClampsUpperBound() {
        val mtud = defaultMtud()

        mtud.onPeerMaxUdpPayloadSizeReceived(1300)
        val probedSizes = driveToCompletion(mtud, now0, 1500)

        assertEquals(1300, mtud.state!!.peerMaxUdpPayloadSize)
        assertEquals(1300, mtud.currentMtu())
        assertEquals(listOf(1250, 1275, 1300), probedSizes)
        assertTrue(completed(mtud))
    }

    @Test
    fun mtuDiscoveryWithPreviousPeerMaxUdpPayloadSizeClampsUpperBound() {
        val mtud = MtuDiscovery.new(1500, 1_200, 1400, MtuDiscoveryConfig())

        assertEquals(1400, mtud.currentMtu())
        assertEquals(1400, mtud.state!!.peerMaxUdpPayloadSize)

        val probedSizes = driveToCompletion(mtud, now0, 1500)

        assertEquals(1400, mtud.currentMtu())
        assertTrue(probedSizes.isEmpty())
        assertTrue(completed(mtud))
    }

    /** quinn: `#[cfg(debug_assertions)] #[should_panic(expected = ...)]`; test binaries are debug binaries. */
    @Test
    fun mtuDiscoveryWithPeerMaxUdpPayloadSizeDuringSearchPanics() {
        val mtud = defaultMtud()
        assertTrue(mtud.pollTransmit(now0, 0) >= 0)
        assertEquals(MtudPhase.Searching, mtud.state!!.phase)
        val e = assertFailsWith<AssertionError> { mtud.onPeerMaxUdpPayloadSizeReceived(1300) }
        assertTrue(e.message!!.contains("Transport parameters received after MTU probing started"))
    }

    @Test
    fun mtuDiscoveryWith1500Limit() {
        val mtud = defaultMtud()

        val probedSizes = driveToCompletion(mtud, now0, 1500)

        assertEquals(listOf(1326, 1389, 1420, 1452), probedSizes)
        assertEquals(1452, mtud.currentMtu())
        assertTrue(completed(mtud))
    }

    @Test
    fun mtuDiscoveryWith1500LimitAnd10000UpperBound() {
        val config = MtuDiscoveryConfig().upperBound(10_000)
        val mtud = MtuDiscovery.new(1_200, 1_200, null, config)

        val probedSizes = driveToCompletion(mtud, now0, 1500)

        val expectedProbedSizes = listOf(
            5600, 5600, 5600, 3399, 3399, 3399, 2299, 2299, 2299, 1749, 1749, 1749, 1474, 1611,
            1611, 1611, 1542, 1542, 1542, 1507, 1507, 1507,
        )
        assertEquals(expectedProbedSizes, probedSizes)
        assertEquals(1474, mtud.currentMtu())
        assertTrue(completed(mtud))
    }

    @Test
    fun mtuDiscoveryNoLostProbesFindsMaximumUdpPayload() {
        val config = MtuDiscoveryConfig().upperBound(MAX_UDP_PAYLOAD)
        val mtud = MtuDiscovery.new(1200, 1200, null, config)

        driveToCompletion(mtud, now0, 0xFFFF)

        assertEquals(65527, mtud.currentMtu())
        assertTrue(completed(mtud))
    }

    @Test
    fun mtuDiscoveryLostHalfOfProbesFindsMaximumUdpPayload() {
        val config = MtuDiscoveryConfig().upperBound(MAX_UDP_PAYLOAD)
        val mtud = MtuDiscovery.new(1200, 1200, null, config)

        val now = now0
        var iterations = 0
        for (i in 1L until 100L) {
            iterations += 1

            val probePn = i * 2 - 1
            val otherPn = i * 2

            val result = mtud.pollTransmit(now0, probePn)

            if (completed(mtud)) break

            // "Send" next probe
            assertTrue(result >= 0)
            assertTrue(mtud.inFlightMtuProbe() >= 0)

            // Nothing else to send while the probe is in-flight
            assertEquals(-1, mtud.pollTransmit(now, otherPn))

            if (i % 2 == 0L) {
                // ACK probe and ensure it results in an increase of current_mtu
                mtud.onAcked(SpaceId.Data, probePn, result)
            } else {
                mtud.onProbeLost()
            }
        }

        assertEquals(25, iterations)
        assertEquals(65527, mtud.currentMtu())
        assertTrue(completed(mtud))
    }

    @Test
    fun searchStateLowerBoundHigherThanUpperBoundClampsUpperBound() {
        val config = MtuDiscoveryConfig().upperBound(1400)

        val state = SearchState(1500, 0xFFFF, config)
        assertEquals(1500, state.lowerBound)
        assertEquals(1500, state.upperBound)
    }

    @Test
    fun searchStateLowerBoundHigherThanPeerMaxUdpPayloadSizeClampsLowerBound() {
        val config = MtuDiscoveryConfig().upperBound(9000)

        val state = SearchState(1500, 1300, config)
        assertEquals(1300, state.lowerBound)
        assertEquals(1300, state.upperBound)
    }

    @Test
    fun searchStateUpperBoundHigherThanPeerMaxUdpPayloadSizeClampsUpperBound() {
        val config = MtuDiscoveryConfig().upperBound(9000)

        val state = SearchState(1200, 1450, config)
        assertEquals(1200, state.lowerBound)
        assertEquals(1450, state.upperBound)
    }

    // Loss of packets larger than have been acknowledged should indicate a black hole
    @Test
    fun simpleBlackHoleDetection() {
        val bhd = BlackHoleDetector(1200)
        bhd.onNonProbeAcked((BLACK_HOLE_THRESHOLD + 1).toLong() * 2, 1300)
        for (i in 0 until BLACK_HOLE_THRESHOLD) bhd.onNonProbeLost(i.toLong() * 2, 1400)
        // But not before `BLACK_HOLE_THRESHOLD + 1` bursts
        assertFalse(bhd.blackHoleDetected())
        bhd.onNonProbeLost(BLACK_HOLE_THRESHOLD.toLong() * 2, 1400)
        assertTrue(bhd.blackHoleDetected())
    }

    // Loss of packets followed in transmission order by confirmation of a larger packet should not indicate a black
    // hole
    @Test
    fun nonSuspiciousBursts() {
        val bhd = BlackHoleDetector(1200)
        bhd.onNonProbeAcked((BLACK_HOLE_THRESHOLD + 1).toLong() * 2, 1500)
        for (i in 0..BLACK_HOLE_THRESHOLD) bhd.onNonProbeLost(i.toLong() * 2, 1400)
        assertFalse(bhd.blackHoleDetected())
    }

    // Loss of packets smaller than have been acknowledged previously should still indicate a black hole
    @Test
    fun dynamicMtuReduction() {
        val bhd = BlackHoleDetector(1200)
        bhd.onNonProbeAcked(0, 1500)
        for (i in 0..BLACK_HOLE_THRESHOLD) bhd.onNonProbeLost(i.toLong() * 2, 1400)
        assertTrue(bhd.blackHoleDetected())
    }

    // Bursts containing heterogeneous packets are judged based on the smallest
    @Test
    fun mixedNonSuspiciousBursts() {
        val bhd = BlackHoleDetector(1200)
        bhd.onNonProbeAcked((BLACK_HOLE_THRESHOLD + 1).toLong() * 3, 1400)
        for (i in 0..BLACK_HOLE_THRESHOLD) {
            bhd.onNonProbeLost(i.toLong() * 3, 1500)
            bhd.onNonProbeLost(i.toLong() * 3 + 1, 1300)
        }
        assertFalse(bhd.blackHoleDetected())
    }

    // Multi-packet bursts are only counted once
    @Test
    fun burstsCountOnce() {
        val bhd = BlackHoleDetector(1200)
        bhd.onNonProbeAcked((BLACK_HOLE_THRESHOLD + 1).toLong() * 3, 1400)
        for (i in 0 until BLACK_HOLE_THRESHOLD) {
            bhd.onNonProbeLost(i.toLong() * 3, 1500)
            bhd.onNonProbeLost(i.toLong() * 3 + 1, 1500)
        }
        assertFalse(bhd.blackHoleDetected())
        bhd.onNonProbeLost(BLACK_HOLE_THRESHOLD.toLong() * 3, 1500)
        assertTrue(bhd.blackHoleDetected())
    }

    // Non-suspicious bursts don't interfere with detection of suspicious bursts
    @Test
    fun interleavedBursts() {
        val bhd = BlackHoleDetector(1200)
        bhd.onNonProbeAcked((BLACK_HOLE_THRESHOLD + 1).toLong() * 4, 1400)
        for (i in 0..BLACK_HOLE_THRESHOLD) {
            bhd.onNonProbeLost(i.toLong() * 4, 1500)
            bhd.onNonProbeLost(i.toLong() * 4 + 2, 1300)
        }
        assertTrue(bhd.blackHoleDetected())
    }

    // Bursts that are non-suspicious before a delivered packet become suspicious past it
    @Test
    fun suspiciousAfterAcked() {
        val bhd = BlackHoleDetector(1200)
        bhd.onNonProbeAcked((BLACK_HOLE_THRESHOLD + 1).toLong() * 2, 1400)
        for (i in 0..BLACK_HOLE_THRESHOLD) bhd.onNonProbeLost(i.toLong() * 2, 1300)
        assertFalse(bhd.blackHoleDetected(), "1300 byte losses preceding a 1400 byte delivery are not suspicious")
        for (i in 0..BLACK_HOLE_THRESHOLD) {
            bhd.onNonProbeLost((BLACK_HOLE_THRESHOLD.toLong() + 1 + i) * 2, 1300)
        }
        assertTrue(bhd.blackHoleDetected(), "1300 byte losses following a 1400 byte delivery are suspicious")
    }

    // Loss bursts that precede the delivery of another packet of the largest size seen so far are not suspicious:
    // that delivery proves the path still carries packets of that size, even though it does not raise `acked_mtu`.
    // This is the steady state of a bulk transfer, where every packet is full-size and one ACK typically both
    // confirms new packets and reveals older losses.
    @Test
    fun equalSizeDeliveryClearsPrecedingBursts() {
        val bhd = BlackHoleDetector(1200)
        // A full-size packet was delivered long ago...
        bhd.onNonProbeAcked(0, 1400)
        // ...and a newer full-size packet is delivered now, before loss detection runs
        bhd.onNonProbeAcked((BLACK_HOLE_THRESHOLD + 1).toLong() * 2, 1400)
        // Loss detection then reveals bursts that were transmitted before that delivery
        for (i in 0..BLACK_HOLE_THRESHOLD) bhd.onNonProbeLost(i.toLong() * 2 + 1, 1400)
        assertFalse(bhd.blackHoleDetected(), "full-size losses preceding a full-size delivery are not suspicious")
        // Full-size losses transmitted after the last delivery are still suspicious
        for (i in 0..BLACK_HOLE_THRESHOLD) {
            bhd.onNonProbeLost((BLACK_HOLE_THRESHOLD.toLong() + 1 + i) * 2 + 1, 1400)
        }
        assertTrue(bhd.blackHoleDetected(), "full-size losses following the last full-size delivery are suspicious")
    }

    // Acknowledgment of a packet marks prior loss bursts with the same packet size as non-suspicious
    @Test
    fun retroactivelyNonSuspicious() {
        val bhd = BlackHoleDetector(1200)
        for (i in 0 until BLACK_HOLE_THRESHOLD) bhd.onNonProbeLost(i.toLong() * 2, 1400)
        bhd.onNonProbeAcked(BLACK_HOLE_THRESHOLD.toLong() * 2, 1400)
        bhd.onNonProbeLost(BLACK_HOLE_THRESHOLD.toLong() * 2 + 1, 1400)
        assertFalse(bhd.blackHoleDetected())
    }

    // Not in quinn: the fixed-array burst list against quinn's `Vec<LossBurst>` algorithm, on random event sequences.
    @Test
    fun blackHoleDetectorMatchesVecModel() {
        val rnd = kotlin.random.Random(17)
        repeat(300) {
            val minMtu = 1200
            val bhd = BlackHoleDetector(minMtu)
            val model = VecBlackHoleDetector(minMtu)
            var pn = 0L
            repeat(200) {
                pn += 1 + rnd.nextInt(3)
                val len = 1100 + rnd.nextInt(8) * 50
                when (rnd.nextInt(10)) {
                    in 0..3 -> { bhd.onNonProbeLost(pn, len); model.onNonProbeLost(pn, len) }
                    in 4..6 -> { bhd.onNonProbeAcked(pn, len); model.onNonProbeAcked(pn, len) }
                    7 -> { bhd.onProbeAcked(pn, len); model.onProbeAcked(pn, len) }
                    else -> assertEquals(model.blackHoleDetected(), bhd.blackHoleDetected())
                }
                assertEquals(model.bursts.size, bhd.suspiciousLossBurstCount())
                assertEquals(model.currentLatest, bhd.largestNonProbeLost())
            }
        }
    }

    /** quinn's `BlackHoleDetector`, transcribed with a list, as the model for [blackHoleDetectorMatchesVecModel]. */
    private class VecBlackHoleDetector(val minMtu: Int) {
        val bursts = ArrayList<Int>()
        var currentSmallest = 0
        var currentLatest = -1L
        var largestPostLossPacket = 0L
        var ackedMtu = minMtu

        fun onProbeAcked(pn: Long, len: Int) { bursts.clear(); ackedMtu = len; largestPostLossPacket = pn }

        fun onNonProbeAcked(pn: Long, len: Int) {
            if (len < ackedMtu) return
            if (len == ackedMtu) { largestPostLossPacket = maxOf(largestPostLossPacket, pn); return }
            ackedMtu = len
            largestPostLossPacket = pn
            bursts.retainAll { it > len }
        }

        fun onNonProbeLost(pn: Long, len: Int) {
            if (currentLatest >= 0 && pn - currentLatest != 1L) finish()
            currentSmallest = if (currentLatest >= 0) minOf(currentSmallest, len) else len
            currentLatest = pn
        }

        fun blackHoleDetected(): Boolean {
            finish()
            if (bursts.size <= BLACK_HOLE_THRESHOLD) return false
            bursts.clear()
            return true
        }

        private fun finish() {
            if (currentLatest < 0) return
            val smallest = currentSmallest
            val latest = currentLatest
            currentLatest = -1
            if (smallest <= minMtu || (latest < largestPostLossPacket && smallest <= ackedMtu)) return
            if (latest > largestPostLossPacket) ackedMtu = minMtu
            if (bursts.size <= BLACK_HOLE_THRESHOLD) { bursts.add(smallest); return }
            val idx = bursts.indices.minByOrNull { bursts[it] }!!
            if (bursts[idx] < smallest) bursts[idx] = smallest
        }
    }
}
