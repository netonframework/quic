package neton.quic

import neton.io.bytes.Bytes
import neton.quic.proto.Chunk
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** quinn `recv_stream.rs` tests. */
class ReadToEndBufferTest {
    private fun chunk(offset: Long, s: String) = Chunk(offset, Bytes.wrap(s.encodeToByteArray()))

    @Test
    fun readToEndReorderedLimit() {
        val buffer = ReadToEndBuffer(4)
        buffer.push(chunk(4, "efgh"))
        assertFailsWith<ReadToEndError.TooLong> { buffer.push(chunk(0, "abcd")) }
        assertEquals(1, buffer.read.size)
    }

    @Test
    fun readToEndReorderedExactLimitAfterPrefix() {
        val buffer = ReadToEndBuffer(8)
        // A previously consumed prefix must not count against the remaining-data limit.
        buffer.push(chunk(104, "efgh"))
        buffer.push(chunk(100, "abcd"))
        assertContentEquals("abcdefgh".encodeToByteArray(), buffer.finish())
    }

    @Test
    fun readToEndGapsAndEmpty() {
        assertTrue(ReadToEndBuffer(0).finish().isEmpty())
        val buffer = ReadToEndBuffer(5)
        buffer.push(chunk(14, "e"))
        buffer.push(chunk(10, "a"))
        assertContentEquals("a\u0000\u0000\u0000e".encodeToByteArray(), buffer.finish())
        val buffer2 = ReadToEndBuffer(4)
        buffer2.push(chunk(10, "a"))
        assertFailsWith<ReadToEndError.TooLong> { buffer2.push(chunk(14, "e")) }
    }
}
