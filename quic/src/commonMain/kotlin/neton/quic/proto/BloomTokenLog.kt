package neton.quic.proto

import kotlin.math.ln
import kotlin.math.roundToLong
import kotlin.time.Duration

// Bloom filter-based token log (quinn-proto `bloom_token_log.rs`).

/**
 * Bloom filter-based [TokenLog] (bloom_token_log.rs:25).
 *
 * Parameterizable over an approximate maximum number of bytes to allocate. Starts out by storing used tokens in a
 * hash set. Once the hash set becomes too large, converts it to a bloom filter. This achieves a memory profile of
 * linear growth with an upper bound.
 *
 * Divides time into periods based on `lifetime` and stores two filters at any given moment, for each of the two
 * periods currently non-expired tokens could expire in. As such, turns over filters as time goes on to avoid bloom
 * filter false positive rate increasing infinitely over time.
 *
 * The primary constructor takes an approximate maximum memory usage and a
 * [bloom filter k number](https://en.wikipedia.org/wiki/Bloom_filter). If choosing a custom k number, note that
 * `BloomTokenLog` always maintains two filters between them and divides the allocation budget of `maxBytes` evenly
 * between them. As such, each bloom filter will contain `maxBytes * 4` bits.
 *
 * The bloom filter is fastbloom 0.17's with rustc-hash's `FxBuildHasher`, reproduced bit for bit (same bit layout,
 * same double hashing; `BloomTokenLogTest.bloomMatchesFastbloom` checks vectors from the Rust crates), so a given set
 * of tokens sets the same bits as in quinn.
 */
class BloomTokenLog(maxBytes: Long, kNum: Int) : TokenLog {
    private val lock = SpinLock()
    internal val config = FilterConfig(filterMaxBytes = maxBytes / 2, kNum = kNum)

    // filter1 covers tokens that expire in the period starting at period1Start and extending lifetime after.
    // filter2 covers tokens for the next lifetime after that.
    private var period1Start: Duration = Duration.ZERO // UNIX_EPOCH
    internal var filter1: TokenFilter = TokenFilter.Set()
        private set
    internal var filter2: TokenFilter = TokenFilter.Set()
        private set

    /**
     * Default to 20 MiB max memory consumption and expected one million hits (bloom_token_log.rs:132).
     *
     * With the default validation token lifetime of 2 weeks, this corresponds to one token usage per 1.21 seconds.
     */
    constructor() : this(DEFAULT_MAX_BYTES, optimalKNum(DEFAULT_MAX_BYTES, DEFAULT_EXPECTED_HITS))

    override fun checkAndInsert(nonce: U128, issued: Duration, lifetime: Duration) {
        if (lifetime == Duration.ZERO) {
            // avoid divide-by-zero if lifetime is zero
            throw TokenReuseError()
        }

        lock.withLock {
            // calculate how many periods past period 1 the token expires
            val expiresAt = issued + lifetime
            if (expiresAt < period1Start) {
                // shouldn't happen unless time travels backwards or lifetime changes or the current system time is
                // before the Unix epoch (quinn warns "BloomTokenLog presented with token too far in past")
                throw TokenReuseError()
            }
            val periodsForward = (expiresAt - period1Start).inWholeNanoseconds / lifetime.inWholeNanoseconds

            // get relevant filter
            val filter = when (periodsForward) {
                0L -> filter1
                1L -> filter2
                2L -> {
                    // turn over filter 1
                    filter1 = filter2
                    filter2 = TokenFilter.Set()
                    period1Start += lifetime
                    filter2
                }
                else -> {
                    // turn over both filters
                    filter1 = TokenFilter.Set()
                    filter2 = TokenFilter.Set()
                    period1Start = expiresAt
                    filter1
                }
            }

            // Insert into the filter.
            //
            // The token's nonce needs to guarantee uniqueness because of the role it plays in the encryption of the
            // tokens, so it is 128 bits. But since the token log can tolerate false positives, we trim it down to
            // 64 bits, which would still only have a small collision rate even at significant amounts of usage,
            // while allowing us to store twice as many in the hash set variant.
            //
            // Token nonce values are uniformly randomly generated server-side and cryptographically
            // integrity-checked, so we don't need to employ secure hashing to trim it down to 64 bits, we can simply
            // truncate (quinn `nonce as u64`: the low half).
            val converted = filter.checkAndInsert(nonce.lo, config)
            if (converted != null) {
                if (filter === filter1) filter1 = converted else filter2 = converted
            }
        }
    }

    companion object {
        /**
         * Construct with an approximate maximum memory usage and expected number of validation token usages per
         * expiration period. Calculates the optimal bloom filter k number automatically.
         */
        fun newExpectedItems(maxBytes: Long, expectedHits: Long): BloomTokenLog =
            BloomTokenLog(maxBytes, optimalKNum(maxBytes, expectedHits))

        // remember to change the doc comment for the default constructor if these ever change
        internal const val DEFAULT_MAX_BYTES: Long = 10L shl 20
        internal const val DEFAULT_EXPECTED_HITS: Long = 1_000_000
    }
}

/** Unchanging parameters governing [TokenFilter] behavior (bloom_token_log.rs:151). */
internal class FilterConfig(val filterMaxBytes: Long, val kNum: Int)

/** Period filter within [BloomTokenLog] (bloom_token_log.rs:157). */
internal sealed class TokenFilter {
    /**
     * Record [fingerprint]; throws [TokenReuseError] if it may have been recorded before. Returns the filter that
     * replaces this one (the set turning into a bloom filter), or `null`.
     */
    abstract fun checkAndInsert(fingerprint: Long, config: FilterConfig): TokenFilter?

    /**
     * quinn's `HashSet<u64, IdentityBuildHasher>` (fingerprints are uniformly random, so they are their own hash).
     * ⚖️ A Kotlin set; [capacity] replays hashbrown's growth policy so that the set turns into a bloom filter at the
     * same size as in quinn.
     */
    class Set : TokenFilter() {
        val items = HashSet<Long>()

        /** hashbrown's `capacity()` for the same insertions. */
        var capacity: Long = 0
            private set

        override fun checkAndInsert(fingerprint: Long, config: FilterConfig): TokenFilter? {
            if (!items.add(fingerprint)) throw TokenReuseError()
            if (items.size.toLong() > capacity) {
                // hashbrown `reserve_rehash(1)` on a full table: resize to fit max(items, capacity + 1).
                capacity = bucketMaskToCapacity(capacityToBuckets(maxOf(items.size.toLong(), capacity + 1)) - 1)
            }

            if (capacity * 8 <= config.filterMaxBytes) return null

            // convert to bloom
            // avoid panicking if user passed in filter_max_bytes of 0. we document that this limit is approximate, so
            // just fudge it up to 1.
            val bloom = Bloom(maxOf(config.filterMaxBytes * 8, 1L), config.kNum)
            for (item in items) bloom.insert(item)
            return bloom
        }

        private companion object {
            /** hashbrown `capacity_to_buckets`. */
            fun capacityToBuckets(cap: Long): Long {
                if (cap < 8) return if (cap < 4) 4 else 8
                val adjusted = cap * 8 / 7
                var buckets = 1L
                while (buckets < adjusted) buckets = buckets shl 1 // next_power_of_two
                return buckets
            }

            /** hashbrown `bucket_mask_to_capacity`. */
            fun bucketMaskToCapacity(bucketMask: Long): Long =
                if (bucketMask < 8) bucketMask else ((bucketMask + 1) / 8) * 7
        }
    }

    /**
     * fastbloom 0.17 `BloomFilter<FxBuildHasher>` with `num_bits` rounded up to whole 64-bit words and `max(1, k)`
     * hashes per item.
     */
    class Bloom(numBits: Long, hashes: Int) : TokenFilter() {
        private val bits = LongArray(((numBits + 63) / 64).toInt())
        private val numBits: Long = bits.size.toLong() * 64
        private val numHashesMinusOne: Int = maxOf(1, hashes) - 1

        /** Insert [x]; returns whether it may have been present before (fastbloom `insert`). */
        fun insert(x: Long): Boolean {
            // rustc-hash `FxHasher`: `write_u64(x)` then `finish()`
            val hash = (x * FX_K).rotateLeft(26)
            var previouslyContained = set(index(hash))
            // fastbloom `DoubleHasher`
            var h1 = hash
            val h2 = hash * DOUBLE_HASH_MUL
            for (i in 0 until numHashesMinusOne) {
                h1 = h1.rotateLeft(5) + h2
                previouslyContained = set(index(h1)) and previouslyContained
            }
            return previouslyContained
        }

        /** The bit vector's words (fastbloom `as_slice`), for tests. */
        internal fun words(): LongArray = bits.copyOf()

        /** fastbloom `index`: `(hash as u128 * num_bits as u128) >> 64`. */
        private fun index(hash: Long): Long = unsignedMulHigh(hash, numBits)

        private fun set(index: Long): Boolean {
            val w = (index ushr 6).toInt()
            val bit = 1L shl (index and 63).toInt()
            val previouslyContained = bits[w] and bit != 0L
            bits[w] = bits[w] or bit
            return previouslyContained
        }

        override fun checkAndInsert(fingerprint: Long, config: FilterConfig): TokenFilter? {
            if (insert(fingerprint)) throw TokenReuseError()
            return null
        }

        private companion object {
            const val FX_K: Long = -0x0eca8515d19d563bL // 0xf1357aea2e62a9c5
            const val DOUBLE_HASH_MUL: Long = 0x517c_c1b7_2722_0a95L
        }
    }
}

/**
 * The bloom filter k number minimizing false positives for [numBytes] of filter and [expectedHits] items
 * (bloom_token_log.rs:241): `round(m ln 2 / n)`, at least 1.
 */
internal fun optimalKNum(numBytes: Long, expectedHits: Long): Int {
    // be more forgiving rather than panickey here. excessively high num_bits may occur if the user wishes it to be
    // unbounded, so just saturate. expected_hits of 0 would cause divide-by-zero, so just fudge it up to 1 in that
    // case.
    val numBits = if (numBytes > Long.MAX_VALUE / 8) Long.MAX_VALUE else numBytes * 8
    val hits = maxOf(expectedHits, 1L)
    // reference for this formula: https://programming.guide/bloom-filter-calculator.html
    // optimal k = (m ln 2) / n
    // wherein m is the number of bits, and n is the number of elements in the set.
    //
    // we also impose a minimum return value of 1, to avoid making the bloom filter entirely useless in the case that
    // the user provided an absurdly high ratio of hits / bytes.
    // Rust `as u32` saturates at u32::MAX; ⚖️ the `Int` result saturates at Int.MAX_VALUE (a k no filter can use).
    val k = ((numBits.toDouble() / hits.toDouble()) * ln(2.0)).roundToLong()
    return maxOf(k.coerceIn(0L, Int.MAX_VALUE.toLong()).toInt(), 1)
}
