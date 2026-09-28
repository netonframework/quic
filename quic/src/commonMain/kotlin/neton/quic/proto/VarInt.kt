package neton.quic.proto

import kotlin.jvm.JvmInline

/**
 * An integer less than 2^62, suitable for encoding as a QUIC variable-length integer
 * (quinn-proto `varint.rs`, RFC 9000 §16).
 *
 * A value class over [Long]: it is unboxed wherever it is used as a non-null type, so frames and
 * transport parameters that carry `VarInt` fields cost nothing extra over a plain `Long`.
 * The primary constructor does not check the bound (quinn's `from_u64_unchecked`); use [fromLong]
 * or [fromLongOrNull] for untrusted values.
 */
@JvmInline
value class VarInt(val value: Long) : Comparable<VarInt> {

    /** Number of bytes needed to encode this value (quinn `VarInt::size`, varint.rs:55). */
    val size: Int get() = varIntSize(value)

    /** quinn `into_inner`. */
    fun toLong(): Long = value

    override fun compareTo(other: VarInt): Int = value.compareTo(other.value)

    override fun toString(): String = value.toString()

    companion object {
        /** The largest representable value. */
        val MAX: VarInt = VarInt((1L shl 62) - 1)

        /** The largest encoded value length. */
        const val MAX_SIZE: Int = 8

        val ZERO: VarInt = VarInt(0)

        /** Infallible construction from a 32-bit unsigned value (quinn `from_u32`). */
        fun fromU32(x: Int): VarInt = VarInt(x.toLong() and 0xFFFF_FFFFL)

        /** Succeeds iff `0 <= x < 2^62` (quinn `from_u64`); throws [VarIntBoundsExceeded] otherwise. */
        fun fromLong(x: Long): VarInt {
            if (x < 0 || x >= (1L shl 62)) throw VarIntBoundsExceeded()
            return VarInt(x)
        }

        /** Like [fromLong] but returns `null` when out of range. */
        fun fromLongOrNull(x: Long): VarInt? = if (x < 0 || x >= (1L shl 62)) null else VarInt(x)
    }
}

/** Error returned when constructing a [VarInt] from a value >= 2^62 (quinn `VarIntBoundsExceeded`). */
class VarIntBoundsExceeded : IllegalArgumentException("value too large for varint encoding")

/** Encoded size of [x] as a QUIC varint; [x] must be in `[0, 2^62)`. */
fun varIntSize(x: Long): Int = when {
    x < 0 -> throw IllegalStateException("malformed VarInt")
    x < (1L shl 6) -> 1
    x < (1L shl 14) -> 2
    x < (1L shl 30) -> 4
    x < (1L shl 62) -> 8
    else -> throw IllegalStateException("malformed VarInt")
}
