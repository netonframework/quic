package neton.quic.proto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertNull
import kotlin.test.assertSame

// varint.rs / coding.rs have no tests of their own; these cover the codec, its bounds and RFC 9000 Appendix A.1.
class VarIntTest {

    private fun roundTrip(v: Long, expected: ByteArray) {
        val out = encoded { it.writeVar(v) }
        assertContentEquals(expected, out, "encode $v")
        assertEquals(expected.size, varIntSize(v))
        val r = Reader(out)
        assertEquals(v, r.getVar())
        assertEquals(0, r.remaining)
        val into = ByteArray(8)
        assertEquals(expected.size, encodeVarInto(v, into, 0))
        assertContentEquals(expected, into.copyOf(expected.size))
    }

    @Test
    fun rfc9000AppendixA1Examples() {
        roundTrip(151_288_809_941_952_652L, hex("c2197c5eff14e88c"))
        roundTrip(494_878_333L, hex("9d7f3e7d"))
        roundTrip(15_293L, hex("7bbd"))
        roundTrip(37L, hex("25"))
        // "the two-byte sequence 0x40 0x25 also decodes to 37"
        assertEquals(37L, Reader(hex("4025")).getVar())
    }

    @Test
    fun sizeBoundaries() {
        roundTrip(0, hex("00"))
        roundTrip(63, hex("3f"))
        roundTrip(64, hex("4040"))
        roundTrip(16383, hex("7fff"))
        roundTrip(16384, hex("80004000"))
        roundTrip((1L shl 30) - 1, hex("bfffffff"))
        roundTrip(1L shl 30, hex("c000000040000000"))
        roundTrip(VarInt.MAX.value, hex("ffffffffffffffff"))
    }

    @Test
    fun bounds() {
        assertEquals((1L shl 62) - 1, VarInt.MAX.value)
        assertEquals(VarInt(5), VarInt.fromLong(5))
        assertFailsWith<VarIntBoundsExceeded> { VarInt.fromLong(1L shl 62) }
        assertFailsWith<VarIntBoundsExceeded> { VarInt.fromLong(-1) }
        assertNull(VarInt.fromLongOrNull(1L shl 62))
        assertEquals(0xFFFF_FFFFL, VarInt.fromU32(-1).value)
        assertFailsWith<VarIntBoundsExceeded> { encoded { it.writeVar(1L shl 62) } }
    }

    @Test
    fun truncatedInputIsUnexpectedEnd() {
        for (enc in listOf("", "40", "80ffff", "c0ffffffffffff")) {
            val r = Reader(hex(enc))
            assertSame(UnexpectedEnd, assertFailsWith<UnexpectedEnd> { r.getVar() })
            assertEquals(0, r.pos, "cursor unchanged on failure")
        }
    }

    @Test
    fun fixedWidthCodec() {
        val bytes = encoded { it.writeByte(0xab.toByte()); it.writeShort(0xcdef); it.writeInt(0x01234567); it.writeLong(-2) }
        val r = Reader(bytes)
        assertEquals(0xab, r.getU8())
        assertEquals(0xcdef, r.getU16())
        assertEquals(0x01234567L, r.getU32())
        assertEquals(-2L, r.getU64())
        assertFailsWith<UnexpectedEnd> { r.getU8() }
    }
}
