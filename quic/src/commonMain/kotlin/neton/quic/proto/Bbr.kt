package neton.quic.proto

import kotlin.math.abs
import kotlin.random.Random

// BBR congestion control (quinn-proto `congestion/bbr/{mod.rs, bw_estimation.rs, min_max.rs}`).
//
// ⚖️ quinn's `Option<Instant>` fields are nanosecond `Long`s with [NO_TIME] for `None` (the ACK path assigns them
// per acknowledged packet; an `Instant?` would box each time).

private const val NO_TIME: Long = Long.MIN_VALUE
private const val NANOS_10_SECS: Long = 10 * NANOS_PER_SEC
private const val K_PROBE_RTT_TIME_NANOS: Long = 200 * NANOS_PER_MILLI

/**
 * Experimental! Use at your own risk.
 *
 * Aims for reduced buffer bloat and improved performance over high bandwidth-delay product networks. Based on
 * google's quiche implementation
 * <https://source.chromium.org/chromium/chromium/src/+/master:net/third_party/quiche/src/quic/core/congestion_control/bbr_sender.cc>
 * of BBR <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control>. More discussion and
 * links at <https://groups.google.com/g/bbr-dev>.
 *
 * [random] picks the gain-cycle offset; quinn seeds a `Pcg32` from the thread RNG, so this defaults to
 * [Random.Default] (not seeded from the endpoint either).
 */
class Bbr(private val config: BbrConfig, currentMtu: Int, private val random: Random = Random.Default) : Controller {
    private var currentMtu: Long = currentMtu.toLong()
    internal var maxBandwidth = BandwidthEstimation()
        private set
    private var ackedBytes: Long = 0
    internal var mode: BbrMode = BbrMode.Startup
        private set
    private var lossState = 0L // LossState.lost_bytes
    internal var recoveryState: BbrRecoveryState = BbrRecoveryState.NotInRecovery
        private set
    private var recoveryWindow: Long = 0
    private var isAtFullBandwidth = false
    private var pacingGain: Float = K_DEFAULT_HIGH_GAIN
    private var highGain: Float = K_DEFAULT_HIGH_GAIN
    private var drainGain: Float = 1.0f / K_DEFAULT_HIGH_GAIN
    private var cwndGain: Float = K_DEFAULT_HIGH_GAIN
    private var highCwndGain: Float = K_DEFAULT_HIGH_GAIN
    private var lastCycleStart: Long = NO_TIME
    private var currentCycleOffset: Int = 0
    private var initCwnd: Long = config.initialWindow
    private var minCwnd: Long = calculateMinWindow(currentMtu.toLong())
    private var prevInFlightCount: Long = 0
    private var exitProbeRttAt: Long = NO_TIME
    private var probeRttLastStartedAt: Long = NO_TIME
    private var minRtt: Long = 0 // nanoseconds
    private var exitingQuiescence = false
    internal var pacingRate: Long = 0
        private set
    private var maxAckedPacketNumber: Long = 0
    private var maxSentPacketNumber: Long = 0
    private var endRecoveryAtPacketNumber: Long = 0
    internal var cwnd: Long = config.initialWindow
        private set
    private var currentRoundTripEndPacketNumber: Long = 0
    private var roundCount: Long = 0
    private var bwAtLastRound: Long = 0
    private var roundWoBwGain: Long = 0
    private var ackAggregation = AckAggregationState()

    private fun hasLosses(): Boolean = lossState != 0L

    private fun enterStartupMode() {
        mode = BbrMode.Startup
        pacingGain = highGain
        cwndGain = highCwndGain
    }

    private fun enterProbeBandwidthMode(now: Instant) {
        mode = BbrMode.ProbeBw
        cwndGain = K_DERIVED_HIGH_CWNDGAIN
        lastCycleStart = now.nanos
        // Pick a random offset for the gain cycle out of {0, 2..7} range. 1 is excluded because in that case
        // increased gain and decreased gain would not follow each other.
        var randIndex = random.nextInt(0, K_PACING_GAIN.size - 1)
        if (randIndex >= 1) randIndex += 1
        currentCycleOffset = randIndex
        pacingGain = K_PACING_GAIN[randIndex]
    }

    private fun updateRecoveryState(isRoundStart: Boolean) {
        // Exit recovery when there are no losses for a round.
        if (hasLosses()) endRecoveryAtPacketNumber = maxSentPacketNumber
        when (recoveryState) {
            // Enter conservation on the first loss.
            BbrRecoveryState.NotInRecovery -> if (hasLosses()) {
                recoveryState = BbrRecoveryState.Conservation
                // This will cause the |recovery_window| to be set to the correct value in
                // CalculateRecoveryWindow().
                recoveryWindow = 0
                // Since the conservation phase is meant to be lasting for a whole round, extend the current round
                // as if it were started right now.
                currentRoundTripEndPacketNumber = maxSentPacketNumber
            }
            BbrRecoveryState.Growth, BbrRecoveryState.Conservation -> {
                if (recoveryState == BbrRecoveryState.Conservation && isRoundStart) {
                    recoveryState = BbrRecoveryState.Growth
                }
                // Exit recovery if appropriate.
                if (!hasLosses() && maxAckedPacketNumber > endRecoveryAtPacketNumber) {
                    recoveryState = BbrRecoveryState.NotInRecovery
                }
            }
        }
    }

    private fun updateGainCyclePhase(now: Instant, inFlight: Long) {
        // In most cases, the cycle is advanced after an RTT passes.
        var shouldAdvanceGainCycling = lastCycleStart != NO_TIME && saturatingSubU(now.nanos, lastCycleStart) > minRtt
        // If the pacing gain is above 1.0, the connection is trying to probe the bandwidth by increasing the number
        // of bytes in flight to at least pacing_gain * BDP. Make sure that it actually reaches the target, as long
        // as there are no losses suggesting that the buffers are not able to hold that much.
        if (pacingGain > 1.0f && !hasLosses() && prevInFlightCount < getTargetCwnd(pacingGain)) {
            shouldAdvanceGainCycling = false
        }

        // If pacing gain is below 1.0, the connection is trying to drain the extra queue which could have been
        // incurred by probing prior to it. If the number of bytes in flight falls down to the estimated BDP value
        // earlier, conclude that the queue has been successfully drained and exit this cycle early.
        if (pacingGain < 1.0f && inFlight <= getTargetCwnd(1.0f)) shouldAdvanceGainCycling = true

        if (shouldAdvanceGainCycling) {
            currentCycleOffset = (currentCycleOffset + 1) % K_PACING_GAIN.size
            lastCycleStart = now.nanos
            // Stay in low gain mode until the target BDP is hit. Low gain mode will be exited immediately when the
            // target BDP is achieved.
            if (DRAIN_TO_TARGET && pacingGain < 1.0f &&
                abs(K_PACING_GAIN[currentCycleOffset] - 1.0f) < FLOAT_EPSILON &&
                inFlight > getTargetCwnd(1.0f)
            ) {
                return
            }
            pacingGain = K_PACING_GAIN[currentCycleOffset]
        }
    }

    private fun maybeExitStartupOrDrain(now: Instant, inFlight: Long) {
        if (mode == BbrMode.Startup && isAtFullBandwidth) {
            mode = BbrMode.Drain
            pacingGain = drainGain
            cwndGain = highCwndGain
        }
        if (mode == BbrMode.Drain && inFlight <= getTargetCwnd(1.0f)) enterProbeBandwidthMode(now)
    }

    private fun isMinRttExpired(now: Instant, appLimited: Boolean): Boolean =
        !appLimited && (probeRttLastStartedAt == NO_TIME || saturatingSubU(now.nanos, probeRttLastStartedAt) > NANOS_10_SECS)

    private fun maybeEnterOrExitProbeRtt(now: Instant, isRoundStart: Boolean, bytesInFlight: Long, appLimited: Boolean) {
        val minRttExpired = isMinRttExpired(now, appLimited)
        if (minRttExpired && !exitingQuiescence && mode != BbrMode.ProbeRtt) {
            mode = BbrMode.ProbeRtt
            pacingGain = 1.0f
            // Do not decide on the time to exit ProbeRtt until the |bytes_in_flight| is at the target small value.
            exitProbeRttAt = NO_TIME
            probeRttLastStartedAt = now.nanos
        }

        if (mode == BbrMode.ProbeRtt) {
            if (exitProbeRttAt == NO_TIME) {
                // If the window has reached the appropriate size, schedule exiting ProbeRtt. The CWND during
                // ProbeRtt is kMinimumCongestionWindow, but we allow an extra packet since QUIC checks CWND before
                // sending a packet.
                if (bytesInFlight < getProbeRttCwnd() + currentMtu) {
                    exitProbeRttAt = addNanos(now.nanos, K_PROBE_RTT_TIME_NANOS)
                }
            } else if (isRoundStart && now.nanos >= exitProbeRttAt) {
                if (!isAtFullBandwidth) enterStartupMode() else enterProbeBandwidthMode(now)
            }
        }

        exitingQuiescence = false
    }

    private fun getTargetCwnd(gain: Float): Long {
        val bw = maxBandwidth.getEstimate()
        val bdp = (minRtt / NANOS_PER_MICRO) * bw
        val bdpf = bdp.toDouble()
        val cwnd = f64ToU64((gain.toDouble() * bdpf) / 1_000_000.0)
        // BDP estimate will be zero if no bandwidth samples are available yet.
        if (cwnd == 0L) return initCwnd
        return maxOf(cwnd, minCwnd)
    }

    private fun getProbeRttCwnd(): Long {
        if (PROBE_RTT_BASED_ON_BDP) return getTargetCwnd(K_MODERATE_PROBE_RTT_MULTIPLIER)
        return minCwnd
    }

    private fun calculatePacingRate() {
        val bw = maxBandwidth.getEstimate()
        if (bw == 0L) return
        val targetRate = f64ToU64(bw.toDouble() * pacingGain.toDouble())
        if (isAtFullBandwidth) {
            pacingRate = targetRate
            return
        }

        // Pace at the rate of initial_window / RTT as soon as RTT measurements are available.
        if (pacingRate == 0L && minRtt != 0L) {
            pacingRate = BandwidthEstimation.bwFromDelta(initCwnd, minRtt)
            return
        }

        // Do not decrease the pacing rate during startup.
        if (pacingRate < targetRate) pacingRate = targetRate
    }

    private fun calculateCwnd(bytesAcked: Long, excessAcked: Long) {
        if (mode == BbrMode.ProbeRtt) return
        var targetWindow = getTargetCwnd(cwndGain)
        if (isAtFullBandwidth) {
            // Add the max recently measured ack aggregation to CWND.
            targetWindow += ackAggregation.maxAckHeight.get()
        } else {
            // Add the most recent excess acked. Because CWND never decreases in STARTUP, this will automatically
            // create a very localized max filter.
            targetWindow += excessAcked
        }
        // Instead of immediately setting the target CWND as the new one, BBR grows the CWND towards
        // |target_window| by only increasing it |bytes_acked| at a time.
        if (isAtFullBandwidth) {
            cwnd = minOf(targetWindow, cwnd + bytesAcked)
        } else if (cwndGain < targetWindow.toFloat() || ackedBytes < initCwnd) {
            // If the connection is not yet out of startup phase, do not decrease the window.
            cwnd += bytesAcked
        }

        // Enforce the limits on the congestion window.
        if (cwnd < minCwnd) cwnd = minCwnd
    }

    private fun calculateRecoveryWindow(bytesAcked: Long, bytesLost: Long, inFlight: Long) {
        if (!recoveryState.inRecovery) return
        // Set up the initial recovery window.
        if (recoveryWindow == 0L) {
            recoveryWindow = maxOf(minCwnd, inFlight + bytesAcked)
            return
        }

        // Remove losses from the recovery window, while accounting for a potential integer underflow.
        if (recoveryWindow >= bytesLost) {
            recoveryWindow -= bytesLost
        } else {
            // k_max_segment_size = current_mtu
            recoveryWindow = currentMtu
        }
        // In CONSERVATION mode, just subtracting losses is sufficient. In GROWTH, release additional |bytes_acked|
        // to achieve a slow-start-like behavior.
        if (recoveryState == BbrRecoveryState.Growth) recoveryWindow += bytesAcked

        // Sanity checks. Ensure that we always allow to send at least an MSS or |bytes_acked| in response,
        // whichever is larger.
        recoveryWindow = maxOf(maxOf(recoveryWindow, inFlight + bytesAcked), minCwnd)
    }

    /** <https://datatracker.ietf.org/doc/html/draft-cardwell-iccrg-bbr-congestion-control#section-4.3.2.2> */
    private fun checkIfFullBwReached(appLimited: Boolean) {
        if (appLimited) return
        val target = f64ToU64(bwAtLastRound.toDouble() * K_STARTUP_GROWTH_TARGET.toDouble())
        val bw = maxBandwidth.getEstimate()
        if (bw >= target) {
            bwAtLastRound = bw
            roundWoBwGain = 0
            ackAggregation.maxAckHeight.reset()
            return
        }

        roundWoBwGain += 1
        if (roundWoBwGain >= K_ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP || recoveryState.inRecovery) {
            isAtFullBandwidth = true
        }
    }

    override fun onSent(now: Instant, bytes: Long, lastPacketNumber: Long) {
        maxSentPacketNumber = lastPacketNumber
        maxBandwidth.onSent(now, bytes)
    }

    override fun onAck(now: Instant, sent: Instant, bytes: Long, appLimited: Boolean, rtt: RttEstimator) {
        maxBandwidth.onAck(now, sent, bytes, roundCount, appLimited)
        ackedBytes += bytes
        if (isMinRttExpired(now, appLimited) || minRtt > rtt.minNanos()) minRtt = rtt.minNanos()
    }

    override fun onEndAcks(now: Instant, inFlight: Long, appLimited: Boolean, largestPacketNumAcked: Long) {
        val bytesAcked = maxBandwidth.bytesAckedThisWindow()
        val excessAcked = ackAggregation.updateAckAggregationBytes(bytesAcked, now, roundCount, maxBandwidth.getEstimate())
        maxBandwidth.endAcks(roundCount, appLimited)
        if (largestPacketNumAcked >= 0) maxAckedPacketNumber = largestPacketNumAcked

        var isRoundStart = false
        if (bytesAcked > 0) {
            isRoundStart = maxAckedPacketNumber > currentRoundTripEndPacketNumber
            if (isRoundStart) {
                currentRoundTripEndPacketNumber = maxSentPacketNumber
                roundCount += 1
            }
        }

        updateRecoveryState(isRoundStart)

        if (mode == BbrMode.ProbeBw) updateGainCyclePhase(now, inFlight)

        if (isRoundStart && !isAtFullBandwidth) checkIfFullBwReached(appLimited)

        maybeExitStartupOrDrain(now, inFlight)

        maybeEnterOrExitProbeRtt(now, isRoundStart, inFlight, appLimited)

        // After the model is updated, recalculate the pacing rate and congestion window.
        calculatePacingRate()
        calculateCwnd(bytesAcked, excessAcked)
        calculateRecoveryWindow(bytesAcked, lossState, inFlight)

        prevInFlightCount = inFlight
        lossState = 0
    }

    override fun onCongestionEvent(now: Instant, sent: Instant, isPersistentCongestion: Boolean, lostBytes: Long) {
        lossState += lostBytes
    }

    override fun onMtuUpdate(newMtu: Int) {
        currentMtu = newMtu.toLong()
        minCwnd = calculateMinWindow(currentMtu)
        initCwnd = maxOf(config.initialWindow, minCwnd)
        cwnd = maxOf(cwnd, minCwnd)
    }

    override fun window(): Long {
        if (mode == BbrMode.ProbeRtt) {
            return getProbeRttCwnd()
        } else if (recoveryState.inRecovery && mode != BbrMode.Startup) {
            return minOf(cwnd, recoveryWindow)
        }
        return cwnd
    }

    override fun metrics(): ControllerMetrics = ControllerMetrics(window(), null, pacingRate * 8)

    override fun cloneBox(): Controller {
        val c = Bbr(config, currentMtu.toInt(), random)
        c.maxBandwidth = maxBandwidth.copy()
        c.ackedBytes = ackedBytes
        c.mode = mode
        c.lossState = lossState
        c.recoveryState = recoveryState
        c.recoveryWindow = recoveryWindow
        c.isAtFullBandwidth = isAtFullBandwidth
        c.pacingGain = pacingGain
        c.highGain = highGain
        c.drainGain = drainGain
        c.cwndGain = cwndGain
        c.highCwndGain = highCwndGain
        c.lastCycleStart = lastCycleStart
        c.currentCycleOffset = currentCycleOffset
        c.initCwnd = initCwnd
        c.minCwnd = minCwnd
        c.prevInFlightCount = prevInFlightCount
        c.exitProbeRttAt = exitProbeRttAt
        c.probeRttLastStartedAt = probeRttLastStartedAt
        c.minRtt = minRtt
        c.exitingQuiescence = exitingQuiescence
        c.pacingRate = pacingRate
        c.maxAckedPacketNumber = maxAckedPacketNumber
        c.maxSentPacketNumber = maxSentPacketNumber
        c.endRecoveryAtPacketNumber = endRecoveryAtPacketNumber
        c.cwnd = cwnd
        c.currentRoundTripEndPacketNumber = currentRoundTripEndPacketNumber
        c.roundCount = roundCount
        c.bwAtLastRound = bwAtLastRound
        c.roundWoBwGain = roundWoBwGain
        c.ackAggregation = ackAggregation.copy()
        return c
    }

    override fun initialWindow(): Long = config.initialWindow

    override fun toString(): String =
        "Bbr(mode=$mode, recoveryState=$recoveryState, cwnd=$cwnd, pacingRate=$pacingRate, maxBandwidth=$maxBandwidth)"
}

/** Configuration for the [Bbr] congestion controller (bbr/mod.rs:517). */
class BbrConfig : ControllerFactory {
    internal var initialWindow: Long = K_MAX_INITIAL_CONGESTION_WINDOW * BASE_DATAGRAM_SIZE
        private set

    /**
     * Default limit on the amount of outstanding data in bytes.
     *
     * Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
     */
    fun initialWindow(value: Long): BbrConfig { initialWindow = value; return this }

    override fun build(now: Instant, currentMtu: Int): Controller = Bbr(this, currentMtu)

    override fun toString(): String = "BbrConfig(initialWindow=$initialWindow)"
}

/** bbr/mod.rs:546 */
internal class AckAggregationState {
    val maxAckHeight = MinMax()
    private var aggregationEpochStartTime: Long = NO_TIME
    private var aggregationEpochBytes: Long = 0

    fun updateAckAggregationBytes(newlyAckedBytes: Long, now: Instant, round: Long, maxBandwidth: Long): Long {
        // Compute how many bytes are expected to be delivered, assuming max bandwidth is correct.
        val start = if (aggregationEpochStartTime == NO_TIME) now.nanos else aggregationEpochStartTime
        val expectedBytesAcked = maxBandwidth * (saturatingSubU(now.nanos, start) / NANOS_PER_MICRO) / 1_000_000

        // Reset the current aggregation epoch as soon as the ack arrival rate is less than or equal to the max
        // bandwidth.
        if (aggregationEpochBytes <= expectedBytesAcked) {
            // Reset to start measuring a new aggregation epoch.
            aggregationEpochBytes = newlyAckedBytes
            aggregationEpochStartTime = now.nanos
            return 0
        }

        // Compute how many extra bytes were delivered vs max bandwidth. Include the bytes most recently
        // acknowledged to account for stretch acks.
        aggregationEpochBytes += newlyAckedBytes
        val diff = aggregationEpochBytes - expectedBytesAcked
        maxAckHeight.updateMax(round, diff)
        return diff
    }

    fun copy(): AckAggregationState = AckAggregationState().also {
        it.maxAckHeight.copyFrom(maxAckHeight)
        it.aggregationEpochStartTime = aggregationEpochStartTime
        it.aggregationEpochBytes = aggregationEpochBytes
    }
}

/** bbr/mod.rs:587 */
internal enum class BbrMode {
    /** Startup phase of the connection. */
    Startup,

    /** After achieving the highest possible bandwidth during the startup, lower the pacing rate to drain the queue. */
    Drain,

    /** Cruising mode. */
    ProbeBw,

    /** Temporarily slow down sending in order to empty the buffer and measure the real minimum RTT. */
    ProbeRtt,
}

/** Indicates how the congestion control limits the amount of bytes in flight (bbr/mod.rs:602). */
internal enum class BbrRecoveryState {
    /** Do not limit. */
    NotInRecovery,

    /** Allow an extra outstanding byte for each byte acknowledged. */
    Conservation,

    /** Allow two extra outstanding bytes for each byte acknowledged (slow start). */
    Growth;

    val inRecovery: Boolean get() = this != NotInRecovery
}

private fun calculateMinWindow(currentMtu: Long): Long = 4 * currentMtu

/** The gain used for the STARTUP, equal to 2/ln(2). */
private const val K_DEFAULT_HIGH_GAIN: Float = 2.885f

/** The newly derived CWND gain for STARTUP, 2. */
private const val K_DERIVED_HIGH_CWNDGAIN: Float = 2.0f

/** The cycle of gains used during the ProbeBw stage. */
private val K_PACING_GAIN = floatArrayOf(1.25f, 0.75f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f, 1.0f)

private const val K_STARTUP_GROWTH_TARGET: Float = 1.25f
private const val K_ROUND_TRIPS_WITHOUT_GROWTH_BEFORE_EXITING_STARTUP: Long = 3

/** Do not allow initial congestion window to be greater than 200 packets. */
private const val K_MAX_INITIAL_CONGESTION_WINDOW: Long = 200

private const val PROBE_RTT_BASED_ON_BDP: Boolean = true
private const val DRAIN_TO_TARGET: Boolean = true
private const val K_MODERATE_PROBE_RTT_MULTIPLIER: Float = 0.75f

/** Rust `f32::EPSILON`. */
private const val FLOAT_EPSILON: Float = 1.1920929E-7f

/** bbr/bw_estimation.rs:6 */
internal class BandwidthEstimation {
    private var totalAcked: Long = 0
    private var prevTotalAcked: Long = 0
    private var ackedTime: Long = NO_TIME
    private var prevAckedTime: Long = NO_TIME
    private var totalSent: Long = 0
    private var prevTotalSent: Long = 0
    private var sentTime: Long = NO_TIME
    private var prevSentTime: Long = NO_TIME
    private val maxFilter = MinMax()
    private var ackedAtLastWindow: Long = 0

    fun onSent(now: Instant, bytes: Long) {
        prevTotalSent = totalSent
        totalSent += bytes
        prevSentTime = sentTime
        sentTime = now.nanos
    }

    fun onAck(now: Instant, @Suppress("UNUSED_PARAMETER") sent: Instant, bytes: Long, round: Long, appLimited: Boolean) {
        prevTotalAcked = totalAcked
        totalAcked += bytes
        prevAckedTime = ackedTime
        ackedTime = now.nanos

        val prevSentTime = prevSentTime
        if (prevSentTime == NO_TIME) return

        val sendRate = if (sentTime != NO_TIME && sentTime > prevSentTime) {
            bwFromDelta(totalSent - prevTotalSent, sentTime - prevSentTime).let { if (it < 0) 0 else it }
        } else {
            Long.MAX_VALUE // will take the min of send and ack, so this is just a skip (quinn `u64::MAX`)
        }

        val ackRate = if (prevAckedTime != NO_TIME) {
            bwFromDelta(totalAcked - prevTotalAcked, saturatingSubU(now.nanos, prevAckedTime)).let { if (it < 0) 0 else it }
        } else {
            0
        }

        val bandwidth = minOf(sendRate, ackRate)
        if (!appLimited && maxFilter.get() < bandwidth) maxFilter.updateMax(round, bandwidth)
    }

    fun bytesAckedThisWindow(): Long = totalAcked - ackedAtLastWindow

    fun endAcks(@Suppress("UNUSED_PARAMETER") currentRound: Long, @Suppress("UNUSED_PARAMETER") appLimited: Boolean) {
        ackedAtLastWindow = totalAcked
    }

    fun getEstimate(): Long = maxFilter.get()

    fun copy(): BandwidthEstimation = BandwidthEstimation().also {
        it.totalAcked = totalAcked; it.prevTotalAcked = prevTotalAcked
        it.ackedTime = ackedTime; it.prevAckedTime = prevAckedTime
        it.totalSent = totalSent; it.prevTotalSent = prevTotalSent
        it.sentTime = sentTime; it.prevSentTime = prevSentTime
        it.maxFilter.copyFrom(maxFilter)
        it.ackedAtLastWindow = ackedAtLastWindow
    }

    /** quinn's `Display`: the estimate in MB/s with three decimals. */
    override fun toString(): String {
        val mbps = getEstimate().toFloat() / (1024 * 1024).toFloat()
        val thousandths = kotlin.math.round(mbps.toDouble() * 1000.0).toLong()
        return "${thousandths / 1000}.${(thousandths % 1000).toString().padStart(3, '0')} MB/s"
    }

    companion object {
        /** Bytes per second over [deltaNanos]; -1 when the delta is zero (quinn `None`). */
        fun bwFromDelta(bytes: Long, deltaNanos: Long): Long {
            if (deltaNanos == 0L) return -1
            val bNs = bytes * 1_000_000_000L
            return bNs / deltaNanos
        }
    }
}

/**
 * Kathleen Nichols' algorithm for tracking the minimum (or maximum) value of a data stream over some fixed time
 * interval (bbr/min_max.rs). It uses constant space and constant time per update yet almost always delivers the same
 * minimum as an implementation that has to keep all the data in the window.
 *
 * The algorithm keeps track of the best, 2nd best & 3rd best min values, maintaining an invariant that the
 * measurement time of the n'th best >= n-1'th best. It also makes sure that the three values are widely separated in
 * the time window since that bounds the worse case error when that data is monotonically increasing over the window.
 *
 * Upon getting a new min, we can forget everything earlier because it has no value - the new min is <= everything
 * else in the window by definition and it samples the most recent. So we restart fresh on every new min and
 * overwrites 2nd & 3rd choices. The same property holds for 2nd & 3rd best.
 *
 * Samples are three (round, value) pairs in parallel arrays; `time` is a round count, not a timestamp.
 */
internal class MinMax {
    /** Round count, not a timestamp. */
    private val window: Long = 10
    private val times = LongArray(3)
    private val values = LongArray(3)

    fun get(): Long = values[0]

    private fun fill(time: Long, value: Long) {
        times.fill(time)
        values.fill(value)
    }

    fun reset() = fill(0, 0)

    /** update_min is also defined in the original source, but removed here since it is not used. */
    fun updateMax(currentRound: Long, measurement: Long) {
        val time = currentRound
        val value = measurement

        if (values[0] == 0L /* uninitialised */ ||
            /* found new max? */ value >= values[0] ||
            /* nothing left in window? */ time - times[2] > window
        ) {
            fill(time, value) /* forget earlier samples */
            return
        }

        if (value >= values[1]) {
            times[2] = time; values[2] = value
            times[1] = time; values[1] = value
        } else if (value >= values[2]) {
            times[2] = time; values[2] = value
        }

        subwinUpdate(time, value)
    }

    /* As time advances, update the 1st, 2nd, and 3rd choices. */
    private fun subwinUpdate(time: Long, value: Long) {
        val dt = time - times[0]
        if (dt > window) {
            // Passed entire window without a new sample so make 2nd choice the new sample & 3rd choice the new 2nd
            // choice. We may have to iterate this since our 2nd choice may also be outside the window (we checked
            // on entry that the third choice was in the window).
            shiftIn(time, value)
            if (time - times[0] > window) shiftIn(time, value)
        } else if (times[1] == times[0] && dt > window / 4) {
            // We've passed a quarter of the window without a new sample so take a 2nd choice from the 2nd quarter
            // of the window.
            times[2] = time; values[2] = value
            times[1] = time; values[1] = value
        } else if (times[2] == times[1] && dt > window / 2) {
            // We've passed half the window without finding a new sample so take a 3rd choice from the last half of
            // the window.
            times[2] = time; values[2] = value
        }
    }

    private fun shiftIn(time: Long, value: Long) {
        times[0] = times[1]; values[0] = values[1]
        times[1] = times[2]; values[1] = values[2]
        times[2] = time; values[2] = value
    }

    fun copyFrom(other: MinMax) {
        other.times.copyInto(times)
        other.values.copyInto(values)
    }
}
