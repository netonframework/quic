package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes

// Coding helpers (quinn-proto `coding.rs`, `varint.rs` Codec impl).
//
// Buffer choice: decoding runs over a plain `ByteArray` + cursor ([Reader]) because `neton.io.bytes.Bytes`
// hides its backing array (every `get(i)` is a bounds-checked call) and received packets are decrypted in
// place anyway, so the connection layer holds a mutable array, like quinn's `BytesMut`. Payload slices handed
// out by the frame iterator are zero-copy `Bytes` views over that array (`Bytes.wrap(array).slice(..)`).
// Encoding appends to a `neton.io.bytes.Buffer` (quinn's `BufMut` / `Vec<u8>`), which already has
// one-bounds-check big-endian writers; code that must patch bytes in place (packet length, header
// protection) works on `Buffer.backingArray()`.

/**
 * The provided buffer was too small (quinn `coding::UnexpectedEnd`).
 *
 * A single preallocated instance: decoding errors are ordinary on the receive path (garbage datagrams), so
 * throwing must not allocate or capture a stack trace each time.
 */
object UnexpectedEnd : Exception("unexpected end of buffer")

/**
 * A read cursor over `array[pos, end)` (quinn's `Buf` over `&[u8]` / `io::Cursor`). All getters throw
 * [UnexpectedEnd] when not enough bytes remain and leave the cursor unchanged in that case.
 */
class Reader(val array: ByteArray, pos: Int = 0, end: Int = array.size) {
    /** Current read position (absolute index into [array]). */
    var pos: Int = pos
        internal set

    /** Exclusive end of the readable region (absolute index into [array]). */
    var end: Int = end
        internal set

    init {
        require(pos in 0..end && end <= array.size) { "bad range [$pos, $end) of ${array.size}" }
    }

    val remaining: Int get() = end - pos

    fun hasRemaining(): Boolean = pos < end

    fun getU8(): Int {
        if (pos >= end) throw UnexpectedEnd
        return array[pos++].toInt() and 0xFF
    }

    fun getU16(): Int {
        if (end - pos < 2) throw UnexpectedEnd
        val a = array; val p = pos
        pos = p + 2
        return ((a[p].toInt() and 0xFF) shl 8) or (a[p + 1].toInt() and 0xFF)
    }

    /** Big-endian 32-bit value as the raw bits of an [Int] (use for QUIC versions). */
    fun getI32(): Int {
        if (end - pos < 4) throw UnexpectedEnd
        val a = array; val p = pos
        pos = p + 4
        return ((a[p].toInt() and 0xFF) shl 24) or ((a[p + 1].toInt() and 0xFF) shl 16) or
            ((a[p + 2].toInt() and 0xFF) shl 8) or (a[p + 3].toInt() and 0xFF)
    }

    /** Big-endian unsigned 32-bit value. */
    fun getU32(): Long = getI32().toLong() and 0xFFFF_FFFFL

    /** Big-endian unsigned `n`-byte value, `1 <= n <= 8` (bytes' `get_uint`). */
    fun getUInt(n: Int): Long {
        if (end - pos < n) throw UnexpectedEnd
        var v = 0L
        for (i in 0 until n) v = (v shl 8) or (array[pos + i].toLong() and 0xFF)
        pos += n
        return v
    }

    /** Big-endian 64-bit value (raw bits). */
    fun getU64(): Long = getUInt(8)

    /** A QUIC varint (quinn `VarInt::decode`, varint.rs:144). */
    fun getVar(): Long {
        val p = pos
        if (p >= end) throw UnexpectedEnd
        val a = array
        val first = a[p].toInt() and 0xFF
        val len = 1 shl (first ushr 6)
        if (end - p < len) throw UnexpectedEnd
        var v = (first and 0x3F).toLong()
        for (i in 1 until len) v = (v shl 8) or (a[p + i].toLong() and 0xFF)
        pos = p + len
        return v
    }

    fun getVarInt(): VarInt = VarInt(getVar())

    fun skip(n: Int) {
        if (n < 0 || end - pos < n) throw UnexpectedEnd
        pos += n
    }

    /** Copy [n] bytes into [dst] at [dstOffset] and advance. */
    fun copyTo(dst: ByteArray, dstOffset: Int, n: Int) {
        if (end - pos < n) throw UnexpectedEnd
        array.copyInto(dst, dstOffset, pos, pos + n)
        pos += n
    }

    /** Read [n] bytes into a fresh array. */
    fun getBytes(n: Int): ByteArray {
        if (n < 0 || end - pos < n) throw UnexpectedEnd
        val out = array.copyOfRange(pos, pos + n)
        pos += n
        return out
    }

    /** Consume everything that remains. */
    fun clear() { pos = end }
}

/** Append a QUIC varint; [x] must be in `[0, 2^62)` (quinn `BufMutExt::write_var`, coding.rs:125). */
fun Buffer.writeVar(x: Long) {
    when {
        x < 0 -> throw VarIntBoundsExceeded()
        x < (1L shl 6) -> writeByte(x.toByte())
        x < (1L shl 14) -> writeShort((0x4000L or x).toInt())
        x < (1L shl 30) -> writeInt((0x8000_0000L or x).toInt())
        x < (1L shl 62) -> writeLong((3L shl 62) or x)
        else -> throw VarIntBoundsExceeded()
    }
}

fun Buffer.writeVar(x: VarInt) = writeVar(x.value)

/** Number of bytes written so far (quinn `Vec::len` on an output buffer). */
internal val Buffer.len: Int get() = readableBytes

/** Append the low [n] bytes of [v], big-endian (bytes' `put_uint`). */
internal fun Buffer.writeUInt(v: Long, n: Int) {
    for (i in n - 1 downTo 0) writeByte((v ushr (8 * i)).toByte())
}

/** Write a varint into [dst] at [pos]; returns the position after it. */
fun encodeVarInto(x: Long, dst: ByteArray, pos: Int): Int {
    val n = varIntSize(x)
    val tag = when (n) { 1 -> 0L; 2 -> 1L; 4 -> 2L; else -> 3L }
    val v = x or (tag shl (8 * n - 2))
    for (i in 0 until n) dst[pos + i] = (v ushr (8 * (n - 1 - i))).toByte()
    return pos + n
}

/** A zero-copy slice of `array[from, to)`. The caller must not modify that region afterwards. */
internal fun sliceOf(array: ByteArray, from: Int, to: Int): Bytes =
    if (from == to) Bytes.EMPTY else Bytes.wrap(array).slice(from, to)

internal fun ByteArray.toHex(from: Int = 0, to: Int = size): String {
    val digits = "0123456789abcdef"
    val sb = StringBuilder((to - from) * 2)
    for (i in from until to) {
        val b = this[i].toInt() and 0xFF
        sb.append(digits[b ushr 4]).append(digits[b and 0xF])
    }
    return sb.toString()
}
