package neton.quic.proto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds

// connection/pacing.rs tests (4). quinn's `None` delay is `Instant.NONE`.
class PacingTest {
    private val burstIntervalNanos = Pacer.BURST_INTERVAL_NANOS
    private val now0 = Instant(1_000_000_000_000L)

    @Test
    fun doesNotPanicOnBadInstant() {
        val oldInstant = now0
        val newInstant = oldInstant + 15.microseconds
        val rtt = 400.microseconds

        assertTrue(Pacer(rtt, 30000, 1500, newInstant).delay(0.microseconds, 0, 1500, 1, oldInstant).isNone)
        assertTrue(Pacer(rtt, 30000, 1500, newInstant).delay(0.microseconds, 1600, 1500, 1, oldInstant).isNone)
        assertTrue(Pacer(rtt, 30000, 1500, newInstant).delay(0.microseconds, 1500, 1500, 3000, oldInstant).isNone)
    }

    @Test
    fun derivesInitialCapacity() {
        val window = 2_000_000L
        val mtu = 1500
        val rtt = 50.milliseconds
        val now = now0

        var pacer = Pacer(rtt, window, mtu, now)
        assertEquals(window * burstIntervalNanos / rtt.inWholeNanoseconds, pacer.capacity)
        assertEquals(pacer.capacity, pacer.tokens)

        pacer = Pacer(0.milliseconds, window, mtu, now)
        assertEquals(Pacer.MAX_BURST_SIZE * mtu, pacer.capacity)
        assertEquals(pacer.capacity, pacer.tokens)

        pacer = Pacer(rtt, 1, mtu, now)
        assertEquals(Pacer.MIN_BURST_SIZE * mtu, pacer.capacity)
        assertEquals(pacer.capacity, pacer.tokens)
    }

    @Test
    fun adjustsCapacity() {
        val window = 2_000_000L
        val mtu = 1500
        val rtt = 50.milliseconds
        val now = now0

        val pacer = Pacer(rtt, window, mtu, now)
        assertEquals(window * burstIntervalNanos / rtt.inWholeNanoseconds, pacer.capacity)
        assertEquals(pacer.capacity, pacer.tokens)
        val initialTokens = pacer.tokens

        pacer.delay(rtt, mtu.toLong(), mtu, window * 2, now)
        assertEquals(2 * window * burstIntervalNanos / rtt.inWholeNanoseconds, pacer.capacity)
        assertEquals(initialTokens, pacer.tokens)

        pacer.delay(rtt, mtu.toLong(), mtu, window / 2, now)
        assertEquals(window / 2 * burstIntervalNanos / rtt.inWholeNanoseconds, pacer.capacity)
        assertEquals(initialTokens / 2, pacer.tokens)

        pacer.delay(rtt, mtu.toLong(), mtu * 2, window, now)
        assertEquals(window * burstIntervalNanos / rtt.inWholeNanoseconds, pacer.capacity)

        pacer.delay(rtt, mtu.toLong(), 20_000, window, now)
        assertEquals(20_000L * Pacer.MIN_BURST_SIZE, pacer.capacity)
    }

    @Test
    fun computesPauseCorrectly() {
        val window = 2_000_000L
        val mtu = 1000
        val rtt = 50.milliseconds
        val oldInstant = now0

        val pacer = Pacer(rtt, window, mtu, oldInstant)
        val packetCapacity = pacer.capacity / mtu

        for (i in 0 until packetCapacity) {
            assertEquals(
                Instant.NONE,
                pacer.delay(rtt, mtu.toLong(), mtu, window, oldInstant),
                "When capacity is available packets should be sent immediately",
            )

            pacer.onTransmit(mtu)
        }

        val paceDuration = (burstIntervalNanos * 4 / 5).nanoseconds

        val delayed = pacer.delay(rtt, mtu.toLong(), mtu, window, oldInstant)
        assertTrue(delayed.isSome, "Send must be delayed")
        assertEquals(paceDuration, delayed - oldInstant)

        // Refill half of the tokens
        assertEquals(Instant.NONE, pacer.delay(rtt, mtu.toLong(), mtu, window, oldInstant + paceDuration / 2))
        assertEquals(pacer.capacity / 2, pacer.tokens)

        for (i in 0 until packetCapacity / 2) {
            assertEquals(
                Instant.NONE,
                pacer.delay(rtt, mtu.toLong(), mtu, window, oldInstant),
                "When capacity is available packets should be sent immediately",
            )

            pacer.onTransmit(mtu)
        }

        // Refill all capacity by waiting more than the expected duration
        assertEquals(Instant.NONE, pacer.delay(rtt, mtu.toLong(), mtu, window, oldInstant + paceDuration * 3 / 2))
        assertEquals(pacer.capacity, pacer.tokens)
    }

    // Not in quinn: the `u128` capacity arithmetic for windows whose product with the burst interval overflows a Long,
    // and the disabled pacing for windows above u32::MAX.
    @Test
    fun hugeWindows() {
        val mtu = 1200
        // window * 2e6 overflows 2^63; the u128 quotient is then clamped
        assertEquals(Pacer.MAX_BURST_SIZE * mtu, Pacer.optimalCapacity(1, Long.MAX_VALUE / 2, mtu))
        assertEquals(Pacer.MAX_BURST_SIZE * mtu, Pacer.optimalCapacity(1_000_000_000_000L, 1L shl 50, mtu))
        val pacer = Pacer(50.milliseconds, 1L shl 40, mtu, now0)
        repeat(1000) { pacer.onTransmit(mtu) }
        assertEquals(Instant.NONE, pacer.delay(50.milliseconds, 100_000, mtu, 1L shl 40, now0))
    }

    @Test
    fun mulDivU128() {
        assertEquals(7L, mulDivU128(3, 5, 2))
        val big = mulDivU128(Long.MAX_VALUE, 4, 2) // 2^64 - 2: truncated to 64 bits as in Rust's `as u64`
        assertEquals(-2L, big)
        assertEquals(Long.MAX_VALUE, mulDivU128(Long.MAX_VALUE, Long.MAX_VALUE, Long.MAX_VALUE))
        assertEquals(Duration.ZERO, 0L.nanosDuration())
    }
}
