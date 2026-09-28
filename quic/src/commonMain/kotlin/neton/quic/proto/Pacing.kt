package neton.quic.proto

import kotlin.time.Duration

// Pacing of packet transmissions (quinn-proto `connection/pacing.rs`).

/**
 * A simple token-bucket pacer (pacing.rs:15).
 *
 * The pacer's capacity is derived on a fraction of the congestion window which can be sent in regular intervals.
 * Once the bucket is empty, further transmission is blocked. The bucket refills at a rate slightly faster than one
 * congestion window per RTT, as recommended in <https://tools.ietf.org/html/draft-ietf-quic-recovery-34#section-7.7>.
 */
internal class Pacer(smoothedRtt: Duration, window: Long, mtu: Int, now: Instant) {
    internal var capacity: Long = optimalCapacity(smoothedRtt.inWholeNanoseconds, window, mtu)
        private set
    private var lastWindow: Long = window
    private var lastMtu: Int = mtu
    internal var tokens: Long = capacity
        private set
    private var prev: Instant = now

    /** Record that a packet has been transmitted. */
    fun onTransmit(packetLength: Int) {
        tokens = saturatingSubU(tokens, packetLength.toLong())
    }

    /**
     * Return how long we need to wait before sending [bytesToSend].
     *
     * If we can send a packet right away, this returns [Instant.NONE] (⚖️ quinn `None`; not boxed on this
     * per-packet path). Otherwise, returns the time at which this function should be called again.
     *
     * The 5/4 ratio used here comes from the suggestion that N = 1.25 in the draft IETF RFC for QUIC.
     */
    fun delay(smoothedRtt: Duration, bytesToSend: Long, mtu: Int, window: Long, now: Instant): Instant {
        debugAssert(window != 0L) { "zero-sized congestion control window is nonsense" }
        val rttNanos = smoothedRtt.inWholeNanoseconds

        if (window != lastWindow || mtu != lastMtu) {
            capacity = optimalCapacity(rttNanos, window, mtu)

            // Clamp the tokens
            tokens = minOf(capacity, tokens)
            lastWindow = window
            lastMtu = mtu
        }

        // if we can already send a packet, there is no need for delay
        if (tokens >= bytesToSend) return Instant.NONE

        // we disable pacing for extremely large windows
        if (window > 0xFFFF_FFFFL) return Instant.NONE

        // A timestamp earlier than a previously recorded time is ignored (quinn warns and uses zero).
        val timeElapsed = if (now.nanos >= prev.nanos) now.nanos - prev.nanos else 0L

        if (rttNanos == 0L) return Instant.NONE

        val elapsedRtts = secsF64(timeElapsed) / secsF64(rttNanos)
        val newTokens = window.toDouble() * 1.25 * elapsedRtts
        tokens = minOf(saturatingAddU(tokens, f64ToU64(newTokens)), capacity)

        prev = now

        // if we can already send a packet, there is no need for delay
        if (tokens >= bytesToSend) return Instant.NONE

        // quinn: `smoothed_rtt.checked_mul((max(bytes_to_send, capacity) - tokens) as u32) / window`, then
        // `/ 5 * 4`: divisions come before multiplications to prevent overflow; this is the time at which the
        // pacing window becomes empty. floor(floor(x / w) / 5) == floor(x / (5 w)).
        val factor = (maxOf(bytesToSend, capacity) - tokens) and 0xFFFF_FFFFL
        val delay = mulDivU128(rttNanos, factor, window * 5) * 4
        return Instant(addNanos(prev.nanos, delay))
    }

    override fun toString(): String = "Pacer(capacity=$capacity, lastWindow=$lastWindow, lastMtu=$lastMtu, tokens=$tokens, prev=$prev)"

    internal companion object {
        /**
         * The burst interval. The capacity will be refilled in 4/5 of that time. 2ms is chosen here since framework
         * timers might have 1ms precision. If kernel-level pacing is supported later a higher time here might be
         * more applicable.
         */
        const val BURST_INTERVAL_NANOS: Long = 2_000_000 // 2ms

        /** Allows some usage of GSO, and doesn't slow down the handshake. */
        const val MIN_BURST_SIZE: Long = 10

        /** Creating 256 packets took 1ms in a benchmark, so larger bursts don't make sense. */
        const val MAX_BURST_SIZE: Long = 256

        /**
         * Calculates a pacer capacity for a certain window and RTT (pacing.rs:126).
         *
         * The goal is to emit a burst (of size `capacity`) in timer intervals which compromise between ideally
         * distributing datagrams over time and constantly waking up the connection to produce additional
         * datagrams. Too short burst intervals means we will never meet them since the timer accuracy in user-space
         * is not high enough. If we miss the interval by more than 25%, we will lose that part of the congestion
         * window since no additional tokens for the extra-elapsed time can be stored. Too long burst intervals make
         * pacing less effective.
         */
        fun optimalCapacity(smoothedRttNanos: Long, window: Long, mtu: Int): Long {
            val rtt = maxOf(smoothedRttNanos, 1L)

            val capacity = mulDivU128(window, BURST_INTERVAL_NANOS, rtt)

            // Small bursts are less efficient (no GSO), could increase latency and don't effectively use the
            // channel's buffer capacity. Large bursts might block the connection on sending.
            // (Rust `u64::clamp`: the truncated `u128` quotient is unsigned.)
            val lo = MIN_BURST_SIZE * mtu
            val hi = MAX_BURST_SIZE * mtu
            return when {
                capacity.toULong() < lo.toULong() -> lo
                capacity.toULong() > hi.toULong() -> hi
                else -> capacity
            }
        }
    }
}
