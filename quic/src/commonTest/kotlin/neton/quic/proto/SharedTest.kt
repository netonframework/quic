package neton.quic.proto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertTrue

// shared.rs and transport_error.rs have no tests of their own.
class SharedTest {

    @Test
    fun connectionIdBasics() {
        val a = ConnectionId.of(hex("0a0b0c"))
        assertEquals("0a0b0c", a.toString())
        assertEquals(a, ConnectionId.of(hex("0a0b0c")))
        assertTrue(ConnectionId.of(hex("ff")) < a, "shorter IDs sort first, like quinn's derived Ord")
        assertTrue(ConnectionId.of(hex("0a0b0b")) < a)
        assertFailsWith<IllegalArgumentException> { ConnectionId.of(ByteArray(21)) }
        assertEquals(ConnectionId.EMPTY, ConnectionId.of(ByteArray(0)))

        val long = encoded { a.encodeLong(it) }
        assertEquals(listOf<Byte>(3, 0x0a, 0x0b, 0x0c), long.toList())
        assertEquals(a, ConnectionId.decodeLong(Reader(long)))
        assertNull(ConnectionId.decodeLong(Reader(hex("15" + "00".repeat(21)))), "longer than 20 bytes")
        assertNull(ConnectionId.decodeLong(Reader(hex("0301"))), "truncated")
    }

    @Test
    fun resetTokenEquality() {
        val t = ResetToken(ByteArray(16) { it.toByte() })
        assertEquals(t, ResetToken(ByteArray(16) { it.toByte() }))
        assertNotEquals(t, ResetToken(ByteArray(16)))
        val buf = ByteArray(20).also { t.copyInto(it, 4) }
        assertTrue(t.matches(buf, 4))
        assertFalse(t.matches(buf, 3))
        assertEquals("000102030405060708090a0b0c0d0e0f", t.toString())
    }

    @Test
    fun streamIds() {
        val id = StreamId.of(Side.Server, Dir.Uni, 5)
        assertEquals(23L, id.value)
        assertEquals(Side.Server, id.initiator)
        assertEquals(Dir.Uni, id.dir)
        assertEquals(5L, id.index)
        assertEquals("server unidirectional stream 5", id.toString())
        assertEquals(Side.Client, !Side.Server)
    }

    @Test
    fun transportErrorFormatting() {
        val e = TransportError.PROTOCOL_VIOLATION("bad").also { it.frame = FrameType.CRYPTO }
        assertEquals(
            "detected an error with protocol compliance that was not covered by more specific error codes in CRYPTO: bad",
            e.message,
        )
        assertEquals("PROTOCOL_VIOLATION", TransportErrorCode.PROTOCOL_VIOLATION.toString())
        assertEquals(0x12aL, TransportErrorCode.crypto(0x2a).value)
        assertEquals("Code::crypto(2a)", TransportErrorCode.crypto(0x2a).toString())
        assertEquals("the cryptographic handshake failed: error 42", TransportErrorCode.crypto(0x2a).description)
        assertEquals("Code(1234)", TransportErrorCode(0x1234).toString())
        assertEquals("unknown error", TransportErrorCode(0x1234).description)
        assertEquals(TransportError.of(TransportErrorCode.NO_ERROR), TransportError.NO_ERROR(""))
    }
}
