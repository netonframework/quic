package neton.quic.proto

import neton.io.bytes.Bytes
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertNull

// token_memory_cache.rs tests (3). quinn's Pcg32 is a Kotlin `Random` with a fixed seed.
class TokenMemoryCacheTest {

    private fun newRng(): Random = Random(0x5eadbeef)

    private fun token(i: Int): Bytes = Bytes.wrap(byteArrayOf(i.toByte()))

    @Test
    fun cacheTest() {
        val rng = newRng()
        val n = 2

        repeat(10) {
            val cache1 = ArrayList<Pair<Int, ArrayDeque<Bytes>>>() // keep it sorted oldest to newest
            val cache2 = TokenMemoryCache(20, 2)

            for (i in 0 until 200) {
                val serverName = (rng.nextInt().toUInt() % 10u).toInt()
                if (rng.nextDouble() < 0.666) {
                    // store
                    val token = token(i)
                    val j = cache1.indexOfFirst { it.first == serverName }
                    if (j >= 0) {
                        val (_, queue) = cache1.removeAt(j)
                        queue.addLast(token)
                        if (queue.size > n) queue.removeFirst()
                        cache1.add(serverName to queue)
                    } else {
                        val queue = ArrayDeque<Bytes>()
                        queue.addLast(token)
                        cache1.add(serverName to queue)
                        if (cache1.size > 20) cache1.removeAt(0)
                    }
                    cache2.insert(serverName.toString(), token)
                } else {
                    // take
                    val j = cache1.indexOfFirst { it.first == serverName }
                    val expecting = if (j < 0) {
                        null
                    } else {
                        val (_, queue) = cache1.removeAt(j)
                        val t = queue.removeFirst()
                        if (queue.isNotEmpty()) cache1.add(serverName to queue)
                        t
                    }
                    assertEquals(expecting, cache2.take(serverName.toString()))
                }
            }
        }
    }

    @Test
    fun zeroMaxServerNames() {
        // test that this edge case doesn't panic
        val cache = TokenMemoryCache(0, 2)
        for (i in 0 until 10) {
            cache.insert(i.toString(), token(i))
            for (j in 0 until 10) assertNull(cache.take(j.toString()))
        }
    }

    @Test
    fun zeroQueueLength() {
        // test that this edge case doesn't panic
        val cache = TokenMemoryCache(256, 0)
        for (i in 0 until 10) {
            cache.insert(i.toString(), token(i))
            for (j in 0 until 10) assertNull(cache.take(j.toString()))
        }
    }
}
