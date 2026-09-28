package neton.quic.proto

import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds

/**
 * A point on a monotonic timeline, in nanoseconds from an arbitrary origin (quinn's `std::time::Instant`).
 *
 * The protocol layer never reads a clock: the caller passes `now` in (SPEC §1), from the reactor's monotonic clock
 * in production or from a virtual clock in simulations. ⚖️ A value class over `Long` nanoseconds rather than
 * `kotlin.time.TimeMark`, whose values cannot be constructed freely for virtual time.
 */
value class Instant(val nanos: Long) : Comparable<Instant> {

    override fun compareTo(other: Instant): Int = nanos.compareTo(other.nanos)

    /** quinn `Instant::checked_add`: `null` if the result is not representable. */
    fun checkedAdd(d: Duration): Instant? {
        if (d.isInfinite()) return null
        val dn = d.inWholeNanoseconds
        val r = nanos + dn
        if ((dn > 0 && r < nanos) || (dn < 0 && r > nanos)) return null
        return Instant(r)
    }

    operator fun plus(d: Duration): Instant {
        // Not via checkedAdd: a nullable Instant result would be boxed on this hot path.
        if (d.isInfinite()) throw ArithmeticException("overflow when adding duration to instant")
        return Instant(addNanos(nanos, d.inWholeNanoseconds))
    }

    operator fun minus(other: Instant): Duration = (nanos - other.nanos).nanoseconds

    /**
     * quinn `Instant::saturating_duration_since`, which is also what `Instant - Instant` does in Rust: zero when
     * [earlier] is later than this instant.
     */
    fun saturatingDurationSince(earlier: Instant): Duration =
        if (nanos <= earlier.nanos) Duration.ZERO else (nanos - earlier.nanos).nanoseconds

    /** Whether this is the [NONE] sentinel. */
    val isNone: Boolean get() = nanos == Long.MIN_VALUE

    /** Whether this is a real instant (not [NONE]). */
    val isSome: Boolean get() = nanos != Long.MIN_VALUE

    override fun toString(): String = if (isNone) "Instant(None)" else "Instant(${nanos}ns)"

    companion object {
        /**
         * ⚖️ quinn's `Option<Instant>::None` on allocation-free paths: an `Instant?` holding a value is boxed on
         * Kotlin/Native, so per-packet state (timers, loss times, pacing deadlines) keeps this sentinel instead.
         * It compares below every real instant.
         */
        val NONE: Instant = Instant(Long.MIN_VALUE)
    }
}

/** `a + d` for nanosecond values, throwing like Rust's `Instant + Duration` on overflow. */
internal fun addNanos(a: Long, d: Long): Long {
    val r = a + d
    if ((d > 0 && r < a) || (d < 0 && r > a)) throw ArithmeticException("overflow when adding duration to instant")
    return r
}
