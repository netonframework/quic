package neton.quic.proto

// Logic for controlling the rate at which data is sent (quinn-proto `congestion.rs`).
//
// ⚖️ Types: byte counts and packet numbers are `Long` (quinn `u64`; no value can reach 2^63), MTUs are `Int`
// (`u16`). `Option<u64>` packet numbers are `Long` with -1 for `None`, so the per-ACK calls do not box.

/** Common interface for different congestion controllers (congestion.rs:17). */
interface Controller {
    /** One or more packets were just sent. */
    fun onSent(now: Instant, bytes: Long, lastPacketNumber: Long) {}

    /**
     * Packet deliveries were confirmed.
     *
     * [appLimited] indicates whether the connection was blocked on outgoing application data prior to receiving
     * these acknowledgements.
     */
    fun onAck(now: Instant, sent: Instant, bytes: Long, appLimited: Boolean, rtt: RttEstimator) {}

    /**
     * Packets are acked in batches, all with the same `now` argument. This indicates one of those batches has
     * completed. [largestPacketNumAcked] is -1 when there is none (quinn `None`).
     */
    fun onEndAcks(now: Instant, inFlight: Long, appLimited: Boolean, largestPacketNumAcked: Long) {}

    /**
     * Packets were deemed lost or marked congested.
     *
     * [isPersistentCongestion] indicates whether all packets sent within the persistent congestion threshold
     * period ending when the most recent packet in this batch was sent were lost. [lostBytes] indicates how many
     * bytes were lost; it is 0 for ECN triggers.
     */
    fun onCongestionEvent(now: Instant, sent: Instant, isPersistentCongestion: Boolean, lostBytes: Long)

    /** The known MTU for the current network path has been updated. */
    fun onMtuUpdate(newMtu: Int)

    /** Number of ack-eliciting bytes that may be in flight. */
    fun window(): Long

    /** Implementation-specific metrics used to populate `qlog` traces when they are enabled. */
    fun metrics(): ControllerMetrics = ControllerMetrics(congestionWindow = window())

    /** Duplicate the controller's state (quinn `clone_box`). */
    fun cloneBox(): Controller

    /** Initial congestion window. */
    fun initialWindow(): Long

    // ⛔ quinn's `into_any` (down-casting a `Box<dyn Controller>`): Kotlin casts with `as`.
}

/** Common congestion controller metrics (congestion.rs:88). */
class ControllerMetrics(
    /** Congestion window (bytes). */
    val congestionWindow: Long = 0,
    /** Slow start threshold (bytes). */
    val ssthresh: Long? = null,
    /** Pacing rate (bits/s). */
    val pacingRate: Long? = null,
) {
    override fun toString(): String =
        "ControllerMetrics(congestionWindow=$congestionWindow, ssthresh=$ssthresh, pacingRate=$pacingRate)"
}

/** Constructs controllers on demand (congestion.rs:99). */
fun interface ControllerFactory {
    /** Construct a fresh [Controller]. */
    fun build(now: Instant, currentMtu: Int): Controller
}

internal const val BASE_DATAGRAM_SIZE: Long = 1200
