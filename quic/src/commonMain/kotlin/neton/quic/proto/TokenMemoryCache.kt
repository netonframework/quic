package neton.quic.proto

import neton.io.bytes.Bytes

// Storing tokens sent from servers in NEW_TOKEN frames and using them in subsequent connections
// (quinn-proto `token_memory_cache.rs`).

/**
 * [TokenStore] implementation that stores up to `N` tokens per server name for up to a limited number of server
 * names, in-memory (token_memory_cache.rs:17). Defaults to a maximum of 256 servers and 2 tokens per server.
 *
 * ⚖️ quinn's `HashMap<Arc<str>, u32>` into an `LruSlab` is one [LinkedHashMap] kept in least-recently-used-first
 * order: using an entry (the slab's `get_mut`) moves it to the end, and the first entry is evicted.
 */
class TokenMemoryCache(private val maxServerNames: Int = 256, private val maxTokensPerServer: Int = 2) : TokenStore {
    private val lock = SpinLock()

    /** Server name to its tokens, oldest first; invariant: the token queues are never empty. */
    private val entries = LinkedHashMap<String, ArrayDeque<Bytes>>()

    init {
        require(maxServerNames >= 0 && maxTokensPerServer >= 0)
    }

    override fun insert(serverName: String, token: Bytes) = lock.withLock { store(serverName, token) }

    override fun take(serverName: String): Bytes? = lock.withLock { takeLocked(serverName) }

    private fun store(serverName: String, token: Bytes) {
        if (maxServerNames == 0) {
            // the rest of this method assumes that we can always insert a new entry so long as we're willing to
            // evict a pre-existing entry. thus, an entry limit of 0 is an edge case we must short-circuit on now.
            return
        }
        if (maxTokensPerServer == 0) {
            // similarly to above, the rest of this method assumes that we can always push a new token to a queue so
            // long as we're willing to evict a pre-existing token, so we short-circuit on the edge case of a token
            // limit of 0.
            return
        }

        val tokens = entries.remove(serverName)
        if (tokens != null) {
            // key already exists, push the new token to its token queue (and mark the entry most recently used)
            if (tokens.size >= maxTokensPerServer) {
                debugAssert(tokens.size == maxTokensPerServer) { "assertion failed: tokens.len() == self.max_tokens_per_server" }
                tokens.removeFirst()
            }
            tokens.addLast(token)
            entries[serverName] = tokens
        } else {
            // key does not yet exist, create a new one, evicting the oldest if necessary
            if (entries.size >= maxServerNames) {
                val lru = entries.keys.first()
                entries.remove(lru)
            }
            entries[serverName] = ArrayDeque<Bytes>().also { it.addLast(token) }
        }
    }

    private fun takeLocked(serverName: String): Bytes? {
        val tokens = entries.remove(serverName) ?: return null

        // pop from entry's token queue; we never leave tokens empty
        val token = tokens.removeFirst()

        // token stack emptied: the entry is removed; otherwise it becomes the most recently used
        if (tokens.isNotEmpty()) entries[serverName] = tokens

        return token
    }
}
