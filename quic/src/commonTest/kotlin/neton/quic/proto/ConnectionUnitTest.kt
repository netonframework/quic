package neton.quic.proto

import neton.io.bytes.Buffer
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.time.Duration.Companion.milliseconds

/**
 * Unit tests for pieces of the connection and endpoint layers: quinn's one module test in `connection/mod.rs`, and
 * checks of the deviations that stand in for Rust behaviour (float duration arithmetic, the allocation-free ACK range
 * walk, the ACK size computed instead of truncating, the slab's key reuse).
 */
class ConnectionUnitTest {

    // connection/mod.rs:4121
    @Test
    fun negotiateMaxIdleTimeoutCommutative() {
        val testParams = listOf(
            Triple(null, null, null),
            Triple(null, VarInt(0), null),
            Triple(null, VarInt(2), 2.milliseconds),
            Triple(VarInt(0), VarInt(0), null),
            Triple(VarInt(2), VarInt(0), 2.milliseconds),
            Triple(VarInt(1), VarInt(4), 1.milliseconds),
        )
        for ((left, right, result) in testParams) {
            assertEquals(result, negotiateMaxIdleTimeout(left, right))
            assertEquals(result, negotiateMaxIdleTimeout(right, left))
        }
    }

    /** `Duration::from_secs_f64(f64::from_bits(bits)).as_nanos()`, printed by rustc 1.98. */
    private val fromSecsF64Vectors = listOf(
        "0000000000000000" to 0L,
        "3ddb7cdfd9d7bdbb" to 0L,
        "3dfb7cdfd9d7bdbb" to 0L,
        "3e012e0be826d695" to 1L,
        "3e1129a601c68b1a" to 1L,
        "3e112e0be826d695" to 1L,
        "3e19c511dc3a41df" to 1L,
        "3e25798ee2308c3a" to 3L,
        "3fefffffffbb47d0" to 999999999L,
        "3fefffffffb9e7f8" to 999999999L,
        "3ff0000000000000" to 1000000000L,
        "3ff0000000225c18" to 1000000001L,
        "400599999999999a" to 2700000000L,
        "3e977cf44765195f" to 350L,
        "3f50000000000000" to 976562L,
        "41cdcd6500000000" to 1000000000000000000L,
        "420122e6e0000000" to 9200000000000000000L,
        "40934a4584fd0ee6" to 1234567890123L,
        "3abec4665b00eda4" to 0L,
        "3f0a6e1de29d0e56" to 50411L,
        "3f30dd1c5066dd2f" to 257320L,
        "3c1f66f15ad057c4" to 0L,
        "3dbab04c890c3805" to 0L,
        "3c249abd631e9efd" to 0L,
        "3b02db7443103508" to 0L,
        "4157b17474b70f8b" to 6211025823673139L,
        "3ff3a23ba13ace00" to 1227107649L,
        "404ac0c162e549e0" to 53505901682L,
        "3d048f0a1bb54069" to 0L,
        "407439d820971eb8" to 323615265456L,
        "3e1a172dcf398e97" to 2L,
        "3fa321fc02d4299a" to 37368656L,
        "41c128f75da00a9d" to 575794875250323892L,
        "3b85f5879c5e0c33" to 0L,
        "3a521329aa393db3" to 0L,
        "3f16421a619b1412" to 84908L,
        "3b864287e9734b88" to 0L,
        "39b4f97c5e54ccd3" to 0L,
    )

    @Test
    fun fromSecsF64MatchesRust() {
        for ((bits, nanos) in fromSecsF64Vectors) {
            val x = Double.fromBits(bits.toULong(16).toLong())
            assertEquals(nanos, fromSecsF64(x), "from_secs_f64($x)")
        }
    }

    /** `Duration::from_nanos(n).mul_f32(f).as_nanos()`, printed by rustc 1.98. */
    private val mulF32Vectors = listOf(
        Triple(0L, 1.125f, 0L),
        Triple(0L, 0.7f, 0L),
        Triple(0L, 1.125f, 0L),
        Triple(1L, 1.125f, 1L),
        Triple(1L, 0.7f, 1L),
        Triple(1L, 1.125f, 1L),
        Triple(999L, 1.125f, 1124L),
        Triple(999L, 0.7f, 699L),
        Triple(999L, 1.125f, 1124L),
        Triple(1000000L, 1.125f, 1125000L),
        Triple(1000000L, 0.7f, 700000L),
        Triple(1000000L, 1.125f, 1125000L),
        Triple(333000000L, 1.125f, 374625000L),
        Triple(333000000L, 0.7f, 233099996L),
        Triple(333000000L, 1.125f, 374625000L),
        Triple(1234567891L, 1.125f, 1388888877L),
        Triple(1234567891L, 0.7f, 864197509L),
        Triple(1234567891L, 1.125f, 1388888877L),
        Triple(25000000000L, 1.125f, 28125000000L),
        Triple(25000000000L, 0.7f, 17499999702L),
        Triple(25000000000L, 1.125f, 28125000000L),
        Triple(3600000000123L, 1.125f, 4050000000138L),
        Triple(3600000000123L, 0.7f, 2519999957171L),
        Triple(3600000000123L, 1.125f, 4050000000138L),
    )

    @Test
    fun mulF32MatchesRust() {
        for ((nanos, f, expected) in mulF32Vectors) assertEquals(expected, mulF32(nanos, f), "$nanos * $f")
    }

    @Test
    fun ackForEachRangeMatchesIteratorAndEncodedSize() {
        val rng = Random(7)
        repeat(500) {
            val set = ArrayRangeSet()
            var pn = rng.nextLong(0, 1L shl 40)
            repeat(rng.nextInt(1, MAX_ACK_BLOCKS)) {
                val len = rng.nextLong(1, 100)
                set.insert(pn, pn + len)
                pn += len + rng.nextLong(1, 1000)
            }
            val delay = rng.nextLong(0, 1L shl 30)
            val ecn = if (rng.nextBoolean()) EcnCounts(rng.nextLong(0, 1000), rng.nextLong(0, 10), rng.nextLong(0, 1L shl 20)) else null
            val buf = Buffer(64)
            Frame.Ack.encode(delay, set, ecn, buf)
            val encoded = buf.readAll()
            assertEquals(encoded.size, Frame.Ack.encodedSize(delay, set, ecn))

            val ack = FrameIter(encoded).next() as Frame.Ack
            val walked = ArrayList<LongRange>()
            ack.forEachRange { first, last -> walked.add(first..last) }
            assertEquals(ack.ranges(), walked)
            assertEquals(set.ranges().reversed(), walked)
        }
    }

    @Test
    fun slabReusesMostRecentlyFreedKey() {
        val slab = Slab<String>()
        assertEquals(0, slab.insert("a"))
        assertEquals(1, slab.insert("b"))
        assertEquals(2, slab.insert("c"))
        slab.remove(0)
        slab.remove(2)
        assertEquals(2, slab.vacantKey())
        assertEquals(2, slab.insert("d"))
        assertEquals(0, slab.insert("e"))
        assertEquals(3, slab.insert("f"))
        assertEquals(4, slab.len)
        assertEquals(null, slab.tryRemove(7))
    }
}
