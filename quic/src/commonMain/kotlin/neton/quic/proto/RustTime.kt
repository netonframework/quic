package neton.quic.proto

import kotlin.time.Duration
import kotlin.time.Duration.Companion.nanoseconds

// Arithmetic that reproduces Rust's `core::time::Duration` exactly where quinn's results depend on it
// (floating-point conversions, `u128` intermediates), on durations kept as `Long` nanoseconds. Durations in the
// recovery code are non-negative nanosecond counts below 2^63 (about 292 years); Rust's range is larger, which only
// matters for values no connection can reach.

internal const val NANOS_PER_SEC: Long = 1_000_000_000L
internal const val NANOS_PER_MILLI: Long = 1_000_000L
internal const val NANOS_PER_MICRO: Long = 1_000L

/** Rust `Duration::as_secs_f64`: whole seconds plus the sub-second nanoseconds divided by 1e9. */
internal fun secsF64(nanos: Long): Double =
    (nanos / NANOS_PER_SEC).toDouble() + (nanos % NANOS_PER_SEC).toDouble() / NANOS_PER_SEC.toDouble()

/** Rust `Duration::as_secs_f32`. */
internal fun secsF32(nanos: Long): Float =
    (nanos / NANOS_PER_SEC).toFloat() + (nanos % NANOS_PER_SEC).toFloat() / NANOS_PER_SEC.toFloat()

/** Rust `f64 as u64` (saturating; NaN is 0), capped at `Long.MAX_VALUE` (⚖️ no `u64` in Kotlin). */
internal fun f64ToU64(x: Double): Long = when {
    x.isNaN() || x <= 0.0 -> 0L
    x >= 9.223372036854775807E18 -> Long.MAX_VALUE
    else -> x.toLong()
}

/** Rust `u64::saturating_add` on non-negative values, capped at `Long.MAX_VALUE`. */
internal fun saturatingAddU(a: Long, b: Long): Long {
    val r = a + b
    return if (r < 0) Long.MAX_VALUE else r
}

/** Rust `u64::saturating_sub`. */
internal fun saturatingSubU(a: Long, b: Long): Long = if (a > b) a - b else 0L

/** The high 64 bits of the unsigned 128-bit product of [x] and [y]. */
internal fun unsignedMulHigh(x: Long, y: Long): Long {
    val x0 = x and 0xFFFF_FFFFL; val x1 = x ushr 32
    val y0 = y and 0xFFFF_FFFFL; val y1 = y ushr 32
    val p00 = x0 * y0
    val p01 = x0 * y1
    val p10 = x1 * y0
    val p11 = x1 * y1
    val middle = (p00 ushr 32) + (p01 and 0xFFFF_FFFFL) + (p10 and 0xFFFF_FFFFL)
    return p11 + (p01 ushr 32) + (p10 ushr 32) + (middle ushr 32)
}

/**
 * Rust `(a as u128 * b as u128 / c as u128) as u64` for non-negative [a], [b] and positive [c]: the floor of the
 * exact quotient, truncated to its low 64 bits. The common case (the product fits a `Long`) is one division.
 */
internal fun mulDivU128(a: Long, b: Long, c: Long): Long {
    val hi = unsignedMulHigh(a, b)
    val lo = a * b
    if (hi == 0L && lo >= 0L) return lo / c
    // Restoring long division of hi:lo by c; the remainder stays below c < 2^63, so shifting it left fits 64 bits.
    var q = 0L
    var r = 0L
    for (i in 127 downTo 0) {
        val bit = if (i >= 64) (hi ushr (i - 64)) and 1L else (lo ushr i) and 1L
        r = (r shl 1) or bit
        if (r.toULong() >= c.toULong()) {
            r -= c
            if (i < 64) q = q or (1L shl i)
        }
    }
    return q
}

/** A nanosecond count as a Kotlin [Duration]. */
internal fun Long.nanosDuration(): Duration = this.nanoseconds
