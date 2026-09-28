package neton.quic.proto

import kotlin.math.abs
import kotlin.time.Duration
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.Duration.Companion.milliseconds

// ACK frequency extension state (quinn-proto `connection/ack_frequency.rs`, draft-ietf-quic-ack-frequency-04).

/** State associated to ACK frequency (ack_frequency.rs:8). */
internal class AckFrequencyState(defaultMaxAckDelay: Duration) {
    //
    // Sending ACK_FREQUENCY frames
    //

    /** Packet number of the in-flight ACK_FREQUENCY frame (-1 for none) and the max ACK delay it requested. */
    private var inFlightAckFrequencyPn: Long = -1
    private var inFlightAckFrequencyMaxAckDelay: Duration = Duration.ZERO
    private var nextOutgoingSequenceNumber: VarInt = VarInt(0)
    var peerMaxAckDelay: Duration = defaultMaxAckDelay

    //
    // Receiving ACK_FREQUENCY frames
    //

    /** Sequence number of the last ACK_FREQUENCY frame processed; -1 for none. */
    private var lastAckFrequencyFrame: Long = -1
    var maxAckDelay: Duration = defaultMaxAckDelay

    /**
     * Returns the `max_ack_delay` that should be requested of the peer when sending an ACK_FREQUENCY frame.
     */
    fun candidateMaxAckDelay(rtt: Duration, config: AckFrequencyConfig, peerParams: TransportParameters): Duration {
        val minAckDelay = (peerParams.minAckDelay?.value ?: 0L).microseconds

        // Use the peer's max_ack_delay if no custom max_ack_delay was provided in the config
        val candidate = config.maxAckDelay ?: peerMaxAckDelay

        // Must be no smaller than the `min_ack_delay` advertised by the peer
        return maxOf(
            // Should be less than the RTT (itself at least `MIN_AUTOMATIC_ACK_DELAY`)
            minOf(candidate, maxOf(rtt, MIN_AUTOMATIC_ACK_DELAY)),
            minAckDelay,
        )
    }

    /**
     * Returns the `max_ack_delay` for the purposes of calculating the PTO.
     *
     * This `max_ack_delay` is defined as the maximum of the peer's current `max_ack_delay` and all in-flight
     * `max_ack_delay`s (i.e. proposed values that haven't been acknowledged yet, but might be already in use by the
     * peer).
     */
    fun maxAckDelayForPto(): Duration {
        // Note: we have at most one in-flight ACK_FREQUENCY frame
        return if (inFlightAckFrequencyPn >= 0) maxOf(peerMaxAckDelay, inFlightAckFrequencyMaxAckDelay) else peerMaxAckDelay
    }

    /** Returns the next sequence number for an ACK_FREQUENCY frame. */
    fun nextSequenceNumber(): VarInt {
        check(nextOutgoingSequenceNumber <= VarInt.MAX)

        val seq = nextOutgoingSequenceNumber
        nextOutgoingSequenceNumber = VarInt(nextOutgoingSequenceNumber.value + 1)
        return seq
    }

    /** Returns true if we should send an ACK_FREQUENCY frame. */
    fun shouldSendAckFrequency(rtt: Duration, config: AckFrequencyConfig, peerParams: TransportParameters): Boolean {
        if (nextOutgoingSequenceNumber.value == 0L) {
            // Always send at startup
            return true
        }
        val current = if (inFlightAckFrequencyPn >= 0) inFlightAckFrequencyMaxAckDelay else peerMaxAckDelay
        val desired = candidateMaxAckDelay(rtt, config, peerParams)
        val error = (secsF32(desired.inWholeNanoseconds) / secsF32(current.inWholeNanoseconds)) - 1.0f
        return abs(error) > MAX_RTT_ERROR
    }

    /** Notifies the [AckFrequencyState] that a packet containing an ACK_FREQUENCY frame was sent. */
    fun ackFrequencySent(pn: Long, requestedMaxAckDelay: Duration) {
        inFlightAckFrequencyPn = pn
        inFlightAckFrequencyMaxAckDelay = requestedMaxAckDelay
    }

    /** Notifies the [AckFrequencyState] that a packet has been ACKed. */
    fun onAcked(pn: Long) {
        if (inFlightAckFrequencyPn >= 0 && inFlightAckFrequencyPn == pn) {
            inFlightAckFrequencyPn = -1
            peerMaxAckDelay = inFlightAckFrequencyMaxAckDelay
        }
    }

    /**
     * Notifies the [AckFrequencyState] that an ACK_FREQUENCY frame was received.
     *
     * Updates the endpoint's params according to the payload of the ACK_FREQUENCY frame, or throws a
     * PROTOCOL_VIOLATION [TransportError] in case the requested `max_ack_delay` is invalid.
     *
     * Returns `true` if the frame was processed and `false` if it was ignored because of being stale.
     */
    fun ackFrequencyReceived(frame: Frame.AckFrequency, pendingAcks: PendingAcks): Boolean {
        if (lastAckFrequencyFrame >= 0 && frame.sequence.value <= lastAckFrequencyFrame) return false

        lastAckFrequencyFrame = frame.sequence.value

        // Update max_ack_delay
        val maxAckDelay = frame.requestMaxAckDelay.value.microseconds
        if (maxAckDelay < TIMER_GRANULARITY) {
            throw TransportError.PROTOCOL_VIOLATION(
                "Requested Max Ack Delay in ACK_FREQUENCY frame is less than min_ack_delay",
            )
        }
        this.maxAckDelay = maxAckDelay

        // Update the rest of the params
        pendingAcks.setAckFrequencyParams(frame)

        return true
    }

    private companion object {
        /**
         * Maximum proportion difference between the most recently requested max ACK delay and the currently desired
         * one before a new request is sent, when the peer supports the ACK frequency extension and an explicit max
         * ACK delay is not configured.
         */
        const val MAX_RTT_ERROR: Float = 0.2f

        /**
         * Minimum value to request the peer set max ACK delay to when the peer supports the ACK frequency extension
         * and an explicit max ACK delay is not configured. Keep in sync with [AckFrequencyConfig.maxAckDelay]
         * documentation.
         */
        val MIN_AUTOMATIC_ACK_DELAY: Duration = 25.milliseconds
    }
}
