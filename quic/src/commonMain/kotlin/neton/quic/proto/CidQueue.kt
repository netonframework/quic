package neton.quic.proto

/**
 * Sliding window of active remote connection IDs (quinn-proto `cid_queue.rs`). May contain gaps due to packet loss
 * or reordering.
 *
 * ⚖️ quinn's ring buffer of `Option<(ConnectionId, Option<ResetToken>)>` is two parallel arrays; an entry is present
 * iff its [cids] slot is non-null. Results are small data classes ([Retired], [Next]) instead of tuples, and
 * `InsertError` is thrown (both variants are preallocated) instead of returned.
 */
internal class CidQueue(cid: ConnectionId) {
    /** Ring buffer indexed by [cursor]. */
    private val cids = arrayOfNulls<ConnectionId>(LEN)
    private val tokens = arrayOfNulls<ResetToken>(LEN)

    /** Index at which circular buffer addressing is based. */
    private var cursor = 0

    /** Sequence number of `buffer[cursor]`: the active CID's, which must be the smallest among CIDs in the buffer. */
    private var offset = 0L

    init {
        cids[0] = cid
    }

    /** CIDs retired by [insert]: sequence numbers `[start, end)`, and the reset token of the new active CID. */
    data class Retired(val start: Long, val end: Long, val resetToken: ResetToken)

    /** The result of [next]: the new active CID's reset token, and the sequence numbers `[start, end)` to retire. */
    data class Next(val resetToken: ResetToken, val start: Long, val end: Long)

    /**
     * Handle a `NEW_CONNECTION_ID` frame (cid_queue.rs:37). Returns a non-empty range of retired sequence numbers
     * and the reset token of the new active CID iff any CIDs were retired, else `null`. Throws [InsertError].
     */
    fun insert(cid: Frame.NewConnectionId): Retired? {
        // Position of new CID wrt. the current active CID
        if (cid.sequence < offset) throw InsertError.Retired
        val index = cid.sequence - offset

        val retiredCount = maxOf(cid.retirePriorTo - offset, 0L)
        if (index >= LEN + retiredCount) throw InsertError.ExceedsLimit

        // Discard retired CIDs, if any
        for (i in 0 until minOf(retiredCount, LEN.toLong()).toInt()) {
            val k = (cursor + i) % LEN
            cids[k] = null
            tokens[k] = null
        }

        // Record the new CID
        val slot = ((cursor + index) % LEN).toInt()
        cids[slot] = cid.id
        tokens[slot] = cid.resetToken

        if (retiredCount == 0L) return null

        // The active CID was retired. Find the first known CID with sequence number of at least retire_prior_to, and
        // inform the caller that all prior CIDs have been retired, and of the new CID's reset token.
        cursor = ((cursor + retiredCount) % LEN).toInt()
        val i = firstPresentStep(0)
        check(i >= 0) { "it is impossible to retire a CID without supplying a new one" }
        val token = tokens[(cursor + i) % LEN] ?: error("non-initial CID missing reset token")
        cursor = (cursor + i) % LEN
        val origOffset = offset
        offset = cid.retirePriorTo + i
        // We don't immediately retire CIDs in the range (orig_offset + LEN)..offset. These are CIDs that we haven't
        // yet received from a NEW_CONNECTION_ID frame, since having previously received them would violate the
        // connection ID limit we specified based on LEN. If we do receive a such a frame in the future, e.g. due to
        // reordering, we'll retire it then. This ensures we can't be made to buffer an arbitrarily large number of
        // RETIRE_CONNECTION_ID frames.
        return Retired(origOffset, minOf(offset, origOffset + LEN), token)
    }

    /**
     * Switch to next active CID if possible, returning its reset token and a non-empty range preceding it to retire
     * (cid_queue.rs:89).
     */
    fun next(): Next? {
        val i = firstPresentStep(1)
        if (i < 0) return null
        val token = tokens[(cursor + i) % LEN]!!
        cids[cursor] = null
        tokens[cursor] = null

        val origOffset = offset
        offset += i
        cursor = (cursor + i) % LEN
        return Next(token, origOffset, offset)
    }

    /** The first step `>= from` whose slot holds a CID (quinn's `iter()` skipping [from] entries), or -1. */
    private fun firstPresentStep(from: Int): Int {
        var seen = 0
        for (step in 0 until LEN) {
            if (cids[(cursor + step) % LEN] != null) {
                if (seen == from) return step
                seen++
            }
        }
        return -1
    }

    /** Replace the initial CID (cid_queue.rs:111). */
    fun updateInitialCid(cid: ConnectionId) {
        // quinn: debug_assert_eq!(self.offset, 0)
        cids[cursor] = cid
        tokens[cursor] = null
    }

    /** Return active remote CID itself. */
    fun active(): ConnectionId = cids[cursor]!!

    /** Return the sequence number of active remote CID. */
    fun activeSeq(): Long = offset

    /** cid_queue.rs:130 */
    sealed class InsertError(message: String) : Exception(message) {
        /** CID was already retired. */
        object Retired : InsertError("CID was already retired")

        /** Sequence number violates the leading edge of the window. */
        object ExceedsLimit : InsertError("sequence number violates the leading edge of the window")
    }

    companion object {
        const val LEN: Int = 5
    }
}
