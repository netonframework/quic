package neton.quic.proto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

class CidGeneratorTest {

    // ---- cid_generator.rs test ----

    @Test
    fun validateKeyedCid() {
        val generator = HashedConnectionIdGenerator()
        val cid = generator.generateCid()
        assertTrue(generator.validate(cid))
    }

    // ---- beyond the reference test ----

    @Test
    fun fxHashMatchesRustcHash() {
        // Vectors from rustc-hash 2.1.3 (`FxHasher::default()`, `write_u64(key)`, `write(nonce)`, `finish()`).
        fun h(key: Long, nonce: ByteArray): Long = FxHasher().apply { writeU64(key); write(nonce, 0, nonce.size) }.finish()
        assertEquals(0x148f95e1fb77650aL, h(0, byteArrayOf(1, 2, 3)))
        assertEquals(0xf6d25056ddc5ac0bUL.toLong(), h(0x0123456789abcdefL, byteArrayOf(-1, 0, 0x7f)))
        assertEquals(0x3b6e9b001fd95b70L, h(-1L, byteArrayOf(9, 8, 7)))
        // Byte-string hashing paths: >16, 8..16 and 4..8 bytes.
        val bytes = ByteArray(40) { it.toByte() }
        fun w(n: Int): Long = FxHasher().apply { write(bytes, 0, n) }.finish()
        assertEquals(0x1cf6c75d0a8fecdcL, w(40))
        assertEquals(0x51006a0c404227a1L, w(12))
        assertEquals(0x911c5ecde51477daUL.toLong(), w(5))
    }

    @Test
    fun hashedCidRejectsOthers() {
        val a = HashedConnectionIdGenerator(key = 1)
        val b = HashedConnectionIdGenerator(key = 2)
        assertEquals(8, a.cidLen)
        var rejected = 0
        repeat(100) {
            val cid = a.generateCid()
            assertEquals(8, cid.size)
            assertTrue(a.validate(cid))
            if (!b.validate(cid)) rejected++
        }
        assertTrue(rejected > 95, "a different key rejects almost every CID")
        assertFalse(a.validate(ConnectionId.of(ByteArray(4))))
        // Deterministic given the nonce: the same key recognises IDs across instances ("restarts").
        val fixed = HashedConnectionIdGenerator(key = 1, random = { d, o, l -> for (i in o until o + l) d[i] = 0x11 })
        assertEquals(fixed.generateCid(), fixed.generateCid())
        assertTrue(a.validate(fixed.generateCid()))
        assertEquals(null, a.cidLifetime)
        assertEquals(5.seconds, a.setLifetime(5.seconds).cidLifetime)
    }

    @Test
    fun randomCidLengths() {
        for (len in listOf(0, 1, 8, MAX_CID_SIZE)) {
            val g = RandomConnectionIdGenerator(len)
            assertEquals(len, g.cidLen)
            assertEquals(len, g.generateCid().size)
            assertTrue(g.validate(g.generateCid()))
        }
        val g = RandomConnectionIdGenerator(MAX_CID_SIZE)
        assertNotEquals(g.generateCid(), g.generateCid())
    }
}
