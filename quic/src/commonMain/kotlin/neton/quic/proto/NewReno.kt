package neton.quic.proto

// A simple, standard congestion controller (quinn-proto `congestion/new_reno.rs`).

/** RFC 9002 NewReno. */
class NewReno(private val config: NewRenoConfig, now: Instant, currentMtu: Int) : Controller {
    private var currentMtu: Long = currentMtu.toLong()

    /** Maximum number of bytes in flight that may be sent. */
    internal var window: Long = config.initialWindow

    /**
     * Slow start threshold in bytes. When the congestion window is below ssthresh, the mode is slow start and the
     * window grows by the number of bytes acknowledged. (quinn `u64::MAX`: ⚖️ `Long.MAX_VALUE`.)
     */
    internal var ssthresh: Long = Long.MAX_VALUE

    /**
     * The time when QUIC first detects a loss, causing it to enter recovery. When a packet sent after this time is
     * acknowledged, QUIC exits recovery.
     */
    private var recoveryStartTime: Instant = now

    /** Bytes which had been acked by the peer since leaving slow start. */
    private var bytesAcked: Long = 0

    private fun minimumWindow(): Long = 2 * currentMtu

    override fun onAck(now: Instant, sent: Instant, bytes: Long, appLimited: Boolean, rtt: RttEstimator) {
        if (appLimited || sent <= recoveryStartTime) return

        if (window < ssthresh) {
            // Slow start
            window += bytes

            if (window >= ssthresh) {
                // Exiting slow start. Initialize `bytesAcked` for congestion avoidance: any bytes over `ssthresh`
                // already count towards the congestion avoidance phase, independent of how close to `ssthresh`
                // the window was when switching states, and independent of datagram sizes.
                bytesAcked = window - ssthresh
            }
        } else {
            // Congestion avoidance. This uses the method which does not require floating point math, which also
            // increases the window by 1 datagram for every round trip: Appropriate Byte Counting,
            // https://tools.ietf.org/html/rfc3465
            bytesAcked += bytes

            if (bytesAcked >= window) {
                bytesAcked -= window
                window += currentMtu
            }
        }
    }

    override fun onCongestionEvent(now: Instant, sent: Instant, isPersistentCongestion: Boolean, lostBytes: Long) {
        if (sent <= recoveryStartTime) return

        recoveryStartTime = now
        window = (window.toFloat() * config.lossReductionFactor).toLong()
        window = maxOf(window, minimumWindow())
        ssthresh = window

        if (isPersistentCongestion) window = minimumWindow()
    }

    override fun onMtuUpdate(newMtu: Int) {
        currentMtu = newMtu.toLong()
        window = maxOf(window, minimumWindow())
    }

    override fun window(): Long = window

    override fun metrics(): ControllerMetrics = ControllerMetrics(window(), ssthresh, null)

    override fun cloneBox(): Controller = NewReno(config, recoveryStartTime, currentMtu.toInt()).also {
        it.window = window
        it.ssthresh = ssthresh
        it.bytesAcked = bytesAcked
    }

    override fun initialWindow(): Long = config.initialWindow

    override fun toString(): String =
        "NewReno(currentMtu=$currentMtu, window=$window, ssthresh=$ssthresh, recoveryStartTime=$recoveryStartTime, bytesAcked=$bytesAcked)"
}

/** Configuration for the [NewReno] congestion controller (new_reno.rs:132). */
class NewRenoConfig : ControllerFactory {
    internal var initialWindow: Long = 14720L.coerceIn(2 * BASE_DATAGRAM_SIZE, 10 * BASE_DATAGRAM_SIZE)
        private set
    internal var lossReductionFactor: Float = 0.5f
        private set

    /**
     * Default limit on the amount of outstanding data in bytes.
     *
     * Recommended value: `min(10 * max_datagram_size, max(2 * max_datagram_size, 14720))`
     */
    fun initialWindow(value: Long): NewRenoConfig { initialWindow = value; return this }

    /** Reduction in congestion window when a new loss event is detected. */
    fun lossReductionFactor(value: Float): NewRenoConfig { lossReductionFactor = value; return this }

    override fun build(now: Instant, currentMtu: Int): Controller = NewReno(this, now, currentMtu)

    override fun toString(): String = "NewRenoConfig(initialWindow=$initialWindow, lossReductionFactor=$lossReductionFactor)"
}
