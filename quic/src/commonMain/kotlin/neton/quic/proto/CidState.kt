package neton.quic.proto

import kotlin.time.Duration

/** Local connection ID management (quinn-proto `connection/cid_state.rs`). */
internal class CidState(
    /** Length of local connection IDs, used to decode short packets. */
    val cidLen: Int,
    /** CID lifetime, or `null` for none. */
    private val cidLifetime: Duration?,
    now: Instant,
    /** Number of local connection IDs that have been issued in NEW_CONNECTION_ID frames. */
    private var issued: Long,
) {
    /** Timestamp when issued CIDs should be retired. */
    private val retireTimestamp = ArrayDeque<CidTimestamp>()

    /** Sequence numbers of local connection IDs not yet retired by the peer. */
    private val activeSeq = LongHashSet()

    /** Sequence number the peer has already retired all CIDs below at our request via `retire_prior_to`. */
    private var prevRetireSeq = 0L

    /** Sequence number to set in retire_prior_to field in NEW_CONNECTION_ID frame. */
    private var retireSeq = 0L

    init {
        // Add sequence number of CIDs used in handshaking into tracking set
        for (seq in 0 until issued) activeSeq.add(seq)
        // Track lifetime of CIDs used in handshaking
        for (seq in 0 until issued) trackLifetime(seq, now)
    }

    /** Find the next timestamp when previously issued CID should be retired (cid_state.rs:56). */
    fun nextTimeout(): Instant? = retireTimestamp.firstOrNull()?.timestamp

    /** Track the lifetime of issued CIDs in [retireTimestamp] (cid_state.rs:64). */
    private fun trackLifetime(newCidSeq: Long, now: Instant) {
        val lifetime = cidLifetime ?: return
        val expireAt = now.checkedAdd(lifetime) ?: return

        val last = retireTimestamp.lastOrNull()
        if (last != null) {
            // Compare the timestamp with the last inserted record. Combine into a single batch if timestamp of
            // current cid is same as the last record
            if (expireAt == last.timestamp) {
                // quinn: debug_assert!(new_cid_seq > last.sequence)
                last.sequence = newCidSeq
                return
            }
        }

        retireTimestamp.addLast(CidTimestamp(newCidSeq, expireAt))
    }

    /**
     * Update local CID state when previously issued CID is retired (cid_state.rs:96). Returns whether a new CID
     * needs to be pushed that notifies remote peer to respond `RETIRE_CONNECTION_ID`.
     */
    fun onCidTimeout(): Boolean {
        // Whether the peer hasn't retired all the CIDs we asked it to yet
        val unretiredIdsFound = anyActiveIn(prevRetireSeq, retireSeq)

        val currentRetirePriorTo = retireSeq
        val next = retireTimestamp.removeFirstOrNull()

        // According to RFC: Endpoints SHOULD NOT issue updates of the Retire Prior To field before receiving
        // RETIRE_CONNECTION_ID frames that retire all connection IDs indicated by the previous Retire Prior To value.
        // https://tools.ietf.org/html/draft-ietf-quic-transport-29#section-5.1.2
        if (!unretiredIdsFound) {
            // All Cids are retired, `prev_retire_cid_seq` can be assigned to `retire_cid_seq`
            prevRetireSeq = retireSeq
            // Advance `retire_seq` if next cid that needs to be retired exists
            if (next != null) retireSeq = next.sequence + 1
        }

        // Check if retirement of all CIDs that reach their lifetime is still needed. According to RFC: An endpoint
        // MUST NOT provide more connection IDs than the peer's limit. An endpoint MAY send connection IDs that
        // temporarily exceed a peer's limit if the NEW_CONNECTION_ID frame also requires the retirement of any
        // excess, by including a sufficiently large value in the Retire Prior To field.
        //
        // If yes (return true), a new CID must be pushed with updated `retire_prior_to` field to remote peer. If no
        // (return false), it means CIDs that reach the end of lifetime have been retired already. Do not push a new
        // CID in order to avoid violating above RFC.
        return anyActiveIn(currentRetirePriorTo, retireSeq)
    }

    private fun anyActiveIn(start: Long, end: Long): Boolean {
        for (seq in start until end) if (seq in activeSeq) return true
        return false
    }

    /** Update CID state when `NewIdentifiers` event is received (cid_state.rs:141). */
    fun newCids(ids: List<IssuedCid>, now: Instant) {
        // `ids` could be empty once active_connection_id_limit is set to 1 by peer
        val lastCid = ids.lastOrNull() ?: return
        issued += ids.size
        // Record the timestamp of CID with the largest seq number
        val sequence = lastCid.sequence
        for (frame in ids) activeSeq.add(frame.sequence)
        trackLifetime(sequence, now)
    }

    /**
     * Update CidState for receipt of a `RETIRE_CONNECTION_ID` frame (cid_state.rs:159). Returns whether a new CID
     * can be issued; throws [TransportError] if the frame was illegal.
     */
    fun onCidRetirement(sequence: Long, limit: Long): Boolean {
        if (cidLen == 0) throw TransportError.PROTOCOL_VIOLATION("RETIRE_CONNECTION_ID when CIDs aren't in use")
        if (sequence > issued) {
            throw TransportError.PROTOCOL_VIOLATION("RETIRE_CONNECTION_ID for unissued sequence number")
        }
        activeSeq.remove(sequence)
        // Consider a scenario where peer A has active remote cid 0,1,2. Peer B first send a NEW_CONNECTION_ID with
        // cid 3 and retire_prior_to set to 1. Peer A processes this NEW_CONNECTION_ID frame; update remote cid to
        // 1,2,3 and meanwhile send a RETIRE_CONNECTION_ID to retire cid 0 to peer B. If peer B doesn't check the cid
        // limit here and send a new cid again, peer A will then face CONNECTION_ID_LIMIT_ERROR
        return limit > activeSeq.size
    }

    /** The value for `retire_prior_to` field in `NEW_CONNECTION_ID` frame. */
    fun retirePriorTo(): Long = retireSeq

    /** Lowest and highest active sequence numbers (quinn's test helper `active_seq`, cid_state.rs:199). */
    internal fun activeSeqBounds(): Pair<Long, Long> {
        var min = -1L // u64::MAX, compared unsigned
        var max = 0L
        activeSeq.forEach { n ->
            if (n.toULong() < min.toULong()) min = n
            if (n > max) max = n
        }
        return min to max
    }

    /** quinn's test helper `assign_retire_seq` (cid_state.rs:214): returns how many CIDs this newly retires. */
    internal fun assignRetireSeq(v: Long): Long {
        // Cannot retire more CIDs than what have been issued
        // quinn: debug_assert!(v <= *self.active_seq.iter().max().unwrap() + 1)
        val n = v - retireSeq
        check(n >= 0)
        retireSeq = v
        return n
    }

    /** Data structure that records when issued CIDs should be retired (cid_state.rs:227). */
    private class CidTimestamp(
        /** Highest cid sequence number created in a batch. */
        var sequence: Long,
        /** Timestamp when cid needs to be retired. */
        val timestamp: Instant,
    )
}
