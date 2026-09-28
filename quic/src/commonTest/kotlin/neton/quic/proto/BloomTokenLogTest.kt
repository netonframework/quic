package neton.quic.proto

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.seconds

// bloom_token_log.rs tests (7). quinn's Pcg32 streams are Kotlin `Random`s with fixed seeds; `SystemTime::now()` is a
// fixed wall-clock time.
class BloomTokenLogTest {

    private fun newRng(): Random = Random(0xdeadbeef)

    private val now = (55 * 365).days

    private fun BloomTokenLog.tryInsert(token: U128, issued: Duration, lifetime: Duration): Boolean =
        try {
            checkAndInsert(token, issued, lifetime)
            true
        } catch (_: TokenReuseError) {
            false
        }

    /** quinn: the identity hasher returns the `u64` it hashes. The Kotlin set stores fingerprints directly. */
    @Test
    fun identityHashTest() {
        val rng = newRng()
        repeat(100) {
            val n = rng.nextLong()
            val set = TokenFilter.Set()
            set.checkAndInsert(n, FilterConfig(1 shl 20, 1))
            assertTrue(n in set.items)
        }
    }

    @Test
    fun optimalKNumTest() {
        assertEquals(58, optimalKNum(10L shl 20, 1_000_000))
        assertEquals(1, optimalKNum(10L shl 20, 1_000_000_000_000_000))
        // assert that these don't panic:
        optimalKNum(10L shl 20, 0)
        optimalKNum(Long.MAX_VALUE, 1_000_000)
    }

    @Test
    fun bloomTokenLogConversion() {
        val rng = newRng()
        val log = BloomTokenLog.newExpectedItems(800, 200)

        val issued = now
        val lifetime = 1_000_000.seconds

        for (i in 0 until 200) {
            val token = U128.random(rng)
            val result = log.tryInsert(token, issued, lifetime)
            val filter = log.filter1
            if (filter is TokenFilter.Set) {
                assertTrue(filter.capacity * 8 <= 800)
                assertEquals(i + 1, filter.items.size)
                assertTrue(result)
            } else {
                assertTrue(i > 10, "definitely bloomed too early")
            }
            assertFailsWith<TokenReuseError> { log.checkAndInsert(token, issued, lifetime) }
        }

        assertTrue(log.filter1 is TokenFilter.Bloom, "didn't bloom")
    }

    @Test
    fun turnOver() {
        val rng = newRng()
        val log = BloomTokenLog.newExpectedItems(800, 200)
        val lifetime = 1_000.seconds
        val old = ArrayList<Pair<U128, Duration>>()
        var accepted = 0

        for (i in 0 until 200) {
            val token = U128.random(rng)
            val now = lifetime * 10 + lifetime * i / 10
            val issued = now - lifetime * rng.nextDouble(0.0, 3.0)
            if (log.tryInsert(token, issued, lifetime)) accepted += 1
            old.add(token to issued)
            val (oldToken, oldIssued) = old[rng.nextInt(old.size)]
            assertFailsWith<TokenReuseError> { log.checkAndInsert(oldToken, oldIssued, lifetime) }
        }
        assertTrue(accepted > 0)
    }

    private fun testDoesntPanic(log: BloomTokenLog) {
        val rng = newRng()

        val issued = now
        val lifetime = 1_000_000.seconds

        repeat(200) { log.tryInsert(U128.random(rng), issued, lifetime) }
    }

    @Test
    fun maxBytesZero() {
        // "max bytes" is documented to be approximate. but make sure it doesn't panic.
        testDoesntPanic(BloomTokenLog.newExpectedItems(0, 200))
    }

    @Test
    fun expectedHitsZero() {
        testDoesntPanic(BloomTokenLog.newExpectedItems(100, 0))
    }

    @Test
    fun kNumZero() {
        testDoesntPanic(BloomTokenLog(100, 0))
    }

    // Not in quinn: the set's capacity follows hashbrown (3, 7, 14, 28, 56, 112, ... after 1, 4, 8, 15, 29, 57
    // insertions), so the default filter converts at the same size as in quinn.
    @Test
    fun hashSetCapacityFollowsHashbrown() {
        val set = TokenFilter.Set()
        val config = FilterConfig(Long.MAX_VALUE, 1)
        val capacities = ArrayList<Long>()
        for (i in 1L..120L) {
            set.checkAndInsert(i, config)
            if (capacities.lastOrNull() != set.capacity) capacities.add(set.capacity)
        }
        assertEquals(listOf(3L, 7L, 14L, 28L, 56L, 112L, 224L), capacities)
    }

    // Not in quinn: the bloom filter against vectors from fastbloom 0.17 + rustc-hash 2.1.3 (the words of the bit
    // vector folded with FNV-1a-style multiply, and the number of `insert` calls reporting a previous presence plus
    // 1000 per repeated insert).
    @Test
    fun bloomMatchesFastbloom() {
        val vectors = listOf(
            listOf(64L, 1L, 5L, 5000L, 0xb062bfb5edb3032cUL.toLong()),
            listOf(1000L, 3L, 50L, 50000L, 0x25b0fbed105e7afaUL.toLong()),
            listOf(3200L, 5L, 200L, 200001L, 0x85b279a9e6ce2359UL.toLong()),
            listOf(6400L, 58L, 100L, 100000L, 0x9c986d98b683e90eUL.toLong()),
        )
        for ((bits, k, n, expectedRes, expectedHash) in vectors) {
            val b = TokenFilter.Bloom(bits, k.toInt())
            var res = 0L
            for (i in 0L until n) {
                val x = i * -0x61c8864680b583ebL // 0x9E3779B97F4A7C15
                if (b.insert(x)) res += 1
                if (b.insert(x)) res += 1000
            }
            var h = -0x340d631b7bdddcdbL // 0xcbf29ce484222325
            for (w in b.words()) { h = h xor w; h *= 0x100000001b3L }
            assertEquals(expectedRes, res, "inserts for $bits bits, k=$k")
            assertEquals(expectedHash, h, "bits for $bits bits, k=$k")
        }
    }

    @Test
    fun rejectsZeroLifetimeAndPastTokens() {
        val log = BloomTokenLog()
        assertFailsWith<TokenReuseError> { log.checkAndInsert(U128(1, 2), now, Duration.ZERO) }
        log.checkAndInsert(U128(1, 2), now, 14.days)
        // A token expiring before the current first period is rejected
        assertFailsWith<TokenReuseError> { log.checkAndInsert(U128(3, 4), Duration.ZERO, 1.days) }
        assertEquals(58, log.config.kNum)
        assertEquals(5L shl 20, log.config.filterMaxBytes)
    }
}
