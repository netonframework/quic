package neton.quic.proto

import kotlin.jvm.JvmInline
import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds

/**
 * A point on a monotonic timeline, in nanoseconds from an arbitrary origin (quinn's `std::time::Instant`).
 *
 * The protocol layer never reads a clock: the caller passes `now` in (SPEC §1), from the reactor's monotonic clock
 * in production or from a virtual clock in simulations. ⚖️ A value class over `Long` nanoseconds rather than
 * `kotlin.time.TimeMark`, whose values cannot be constructed freely for virtual time.
 */
@JvmInline
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

    operator fun plus(d: Duration): Instant = checkedAdd(d) ?: throw ArithmeticException("overflow when adding duration to instant")

    operator fun minus(other: Instant): Duration = (nanos - other.nanos).nanoseconds

    override fun toString(): String = "Instant(${nanos}ns)"
}
