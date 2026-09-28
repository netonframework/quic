package neton.quic.proto

import kotlin.math.cbrt

// The RFC 8312 congestion controller (quinn-proto `congestion/cubic.rs`).

/** CUBIC constants, the values recommended in RFC 8312. */
internal const val BETA_CUBIC: Double = 0.7
private const val C: Double = 0.4

/**
 * CUBIC state variables, kept across the connection (cubic.rs:21). [k] and [wMax] are described in the RFC.
 * The calculations are based on a count of cwnd as bytes, not packets; time and RTT are seconds (`f64`).
 */
internal class CubicState {
    var k: Double = 0.0
    var wMax: Double = 0.0

    /** Store cwnd increment during congestion avoidance. */
    var cwndInc: Long = 0

    /** K = cbrt(w_max * (1 - beta_cubic) / C) (Eq. 2) */
    fun cubicK(maxDatagramSize: Long): Double {
        val wMax = this.wMax / maxDatagramSize.toDouble()
        return cbrt(wMax * (1.0 - BETA_CUBIC) / C)
    }

    /** W_cubic(t) = C * (t - K)^3 - w_max (Eq. 1); [tNanos] is a duration. */
    fun wCubic(tNanos: Long, maxDatagramSize: Long): Double {
        val wMax = this.wMax / maxDatagramSize.toDouble()
        val x = secsF64(tNanos) - k
        return (C * (x * x * x) + wMax) * maxDatagramSize.toDouble()
    }

    /** W_est(t) = w_max * beta_cubic + 3 * (1 - beta_cubic) / (1 + beta_cubic) * (t / RTT) (Eq. 4) */
    fun wEst(tNanos: Long, rttNanos: Long, maxDatagramSize: Long): Double {
        val wMax = this.wMax / maxDatagramSize.toDouble()
        return (wMax * BETA_CUBIC + 3.0 * (1.0 - BETA_CUBIC) / (1.0 + BETA_CUBIC) * secsF64(tNanos) / secsF64(rttNanos)) *
            maxDatagramSize.toDouble()
    }

    fun copy(): CubicState = CubicState().also { it.k = k; it.wMax = wMax; it.cwndInc = cwndInc }

    override fun toString(): String = "State(k=$k, wMax=$wMax, cwndInc=$cwndInc)"
}

/** The RFC 8312 congestion controller, as widely used for TCP (cubic.rs:63). */
class Cubic(private val config: CubicConfig, @Suppress("UNUSED_PARAMETER") now: Instant, currentMtu: Int) : Controller {
    /** Maximum number of bytes in flight that may be sent. */
    internal var window: Long = config.initialWindow

    /**
     * Slow start threshold in bytes. When the congestion window is below ssthresh, the mode is slow start and the
     * window grows by the number of bytes acknowledged. (quinn `u64::MAX`: ⚖️ `Long.MAX_VALUE`.)
     */
    internal var ssthresh: Long = Long.MAX_VALUE

    /**
     * The time when QUIC first detects a loss, causing it to enter recovery. When a packet sent after this time is
     * acknowledged, QUIC exits recovery. [Instant.NONE] for quinn's `None`.
     */
    internal var recoveryStartTime: Instant = Instant.NONE
    internal val cubicState = CubicState()
    private var currentMtu: Long = currentMtu.toLong()

    private fun minimumWindow(): Long = 2 * currentMtu

    override fun onAck(now: Instant, sent: Instant, bytes: Long, appLimited: Boolean, rtt: RttEstimator) {
        if (appLimited || (recoveryStartTime.isSome && sent <= recoveryStartTime)) return

        if (window < ssthresh) {
            // Slow start
            window += bytes
        } else {
            // Congestion avoidance.
            val caStartTime: Instant
            if (recoveryStartTime.isSome) {
                caStartTime = recoveryStartTime
            } else {
                // When we come here without congestion_event() triggered, initialize
                // congestion_recovery_start_time, w_max and k.
                caStartTime = now
                recoveryStartTime = now
                cubicState.wMax = window.toDouble()
                cubicState.k = 0.0
            }

            val t = saturatingSubU(now.nanos, caStartTime.nanos)
            val rttNanos = rtt.getNanos()

            // w_cubic(t + rtt)
            val wCubic = cubicState.wCubic(t + rttNanos, currentMtu)

            // w_est(t)
            val wEst = cubicState.wEst(t, rttNanos, currentMtu)

            var cubicCwnd = window

            if (wCubic < wEst) {
                // TCP friendly region.
                cubicCwnd = maxOf(cubicCwnd, f64ToU64(wEst))
            } else if (cubicCwnd < f64ToU64(wCubic)) {
                // Concave region or convex region use same increment.
                val cubicInc = (wCubic - cubicCwnd.toDouble()) / cubicCwnd.toDouble() * currentMtu.toDouble()

                // w_cubic grows cubically with the time since the last congestion event and can exceed `u64::MAX`
                // after a long lossless period.
                cubicCwnd = saturatingAddU(cubicCwnd, f64ToU64(cubicInc))
            }

            // Update the increment and increase cwnd by MSS.
            cubicState.cwndInc += cubicCwnd - window

            // cwnd_inc can be more than 1 MSS in the late stage of max probing. However RFC 9002 §7.3.3
            // (Congestion Avoidance) limits the increase of cwnd to 1 max_datagram_size per cwnd acknowledged.
            if (cubicState.cwndInc >= currentMtu) {
                window += currentMtu
                cubicState.cwndInc = 0
            }
        }
    }

    override fun onCongestionEvent(now: Instant, sent: Instant, isPersistentCongestion: Boolean, lostBytes: Long) {
        if (recoveryStartTime.isSome && sent <= recoveryStartTime) return

        recoveryStartTime = now
        val window = this.window.toDouble()

        // Fast convergence lowers W_max first; the 0.7 loss reduction still applies to the old window, not to that
        // already-reduced W_max.
        // https://www.rfc-editor.org/rfc/rfc9438.html#section-4.7
        // https://www.rfc-editor.org/rfc/rfc9438.html#section-4.6
        if (window < cubicState.wMax) {
            cubicState.wMax = window * (1.0 + BETA_CUBIC) / 2.0
        } else {
            cubicState.wMax = window
        }

        ssthresh = maxOf(f64ToU64(window * BETA_CUBIC), minimumWindow())
        this.window = ssthresh
        cubicState.k = cubicState.cubicK(currentMtu)

        cubicState.cwndInc = f64ToU64(cubicState.cwndInc.toDouble() * BETA_CUBIC)

        if (isPersistentCongestion) {
            recoveryStartTime = Instant.NONE
            cubicState.wMax = this.window.toDouble()

            // 4.7 Timeout - reduce ssthresh based on BETA_CUBIC
            ssthresh = maxOf(f64ToU64(this.window.toDouble() * BETA_CUBIC), minimumWindow())

            cubicState.cwndInc = 0

            this.window = minimumWindow()
        }
    }

    override fun onMtuUpdate(newMtu: Int) {
        currentMtu = newMtu.toLong()
        window = maxOf(window, minimumWindow())
    }

    override fun window(): Long = window

    override fun metrics(): ControllerMetrics = ControllerMetrics(window(), ssthresh, null)

    override fun cloneBox(): Controller = Cubic(config, Instant.NONE, currentMtu.toInt()).also {
        it.window = window
        it.ssthresh = ssthresh
        it.recoveryStartTime = recoveryStartTime
        val s = cubicState
        it.cubicState.k = s.k; it.cubicState.wMax = s.wMax; it.cubicState.cwndInc = s.cwndInc
    }

    override fun initialWindow(): Long = config.initialWindow

    override fun toString(): String =
        "Cubic(window=$window, ssthresh=$ssthresh, recoveryStartTime=$recoveryStartTime, cubicState=$cubicState, currentMtu=$currentMtu)"
}

/** Configuration for the [Cubic] congestion controller (cubic.rs:264). */
class CubicConfig : ControllerFactory {
    internal var initialWindow: Long = 14720L.coerceIn(2 * BASE_DATAGRAM_SIZE, 10 * BASE_DATAGRAM_SIZE)
        private set

    /**
     * Default limit on the amount of outstanding data in bytes.
     *
     * Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
     */
    fun initialWindow(value: Long): CubicConfig { initialWindow = value; return this }

    override fun build(now: Instant, currentMtu: Int): Controller = Cubic(this, now, currentMtu)

    override fun toString(): String = "CubicConfig(initialWindow=$initialWindow)"
}
