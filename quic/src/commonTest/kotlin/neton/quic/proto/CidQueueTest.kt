package neton.quic.proto

import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.seconds

// cid_queue.rs tests
class CidQueueTest {

    private fun cid(sequence: Long, retirePriorTo: Long) = Frame.NewConnectionId(
        sequence,
        retirePriorTo,
        ConnectionId.of(ByteArray(8) { 0xAB.toByte() }),
        ResetToken(ByteArray(RESET_TOKEN_SIZE) { 0xCD.toByte() }),
    )

    private fun initialCid(): ConnectionId = ConnectionId.of(ByteArray(8) { 0xFF.toByte() })

    private val len = CidQueue.LEN.toLong()

    @Test
    fun nextDense() {
        val q = CidQueue(initialCid())
        assertNull(q.next())
        assertNull(q.next())

        for (i in 1 until len) q.insert(cid(i, 0))
        for (i in 1 until len) {
            val retire = q.next()!!
            assertEquals(i, q.activeSeq())
            assertEquals(1L, retire.end - retire.start)
        }
        assertNull(q.next())
    }

    @Test
    fun nextSparse() {
        val q = CidQueue(initialCid())
        val seqs = (1 until len).filter { it % 2 == 0L }
        for (i in seqs) q.insert(cid(i, 0))
        for (i in seqs) {
            val retire = q.next()!!
            assertEquals(i, q.activeSeq())
            assertEquals(maxOf(q.activeSeq() - 2, 0L) to q.activeSeq(), retire.start to retire.end)
        }
        assertNull(q.next())
    }

    @Test
    fun wrap() {
        val q = CidQueue(initialCid())

        for (i in 1 until len) q.insert(cid(i, 0))
        for (i in 1 until len - 1) q.next()!!
        for (i in len until len + 3) q.insert(cid(i, 0))
        for (i in (len - 1) until (len + 3)) {
            q.next()!!
            assertEquals(i, q.activeSeq())
        }
        assertNull(q.next())
    }

    @Test
    fun retireDense() {
        val q = CidQueue(initialCid())

        for (i in 1 until len) q.insert(cid(i, 0))
        assertEquals(0L, q.activeSeq())

        assertEquals(0L to 2L, q.insert(cid(4, 2))!!.let { it.start to it.end })
        assertEquals(2L, q.activeSeq())
        assertNull(q.insert(cid(4, 2)))

        for (i in 2 until len - 1) {
            q.next()!!
            assertEquals(i + 1, q.activeSeq())
            assertNull(q.insert(cid(i + 1, i + 1)))
        }

        assertNull(q.next())
    }

    @Test
    fun retireSparse() {
        // Retiring CID 0 when CID 1 is not known should retire CID 1 as we move to CID 2
        val q = CidQueue(initialCid())
        q.insert(cid(2, 0))
        assertEquals(0L to 2L, q.insert(cid(3, 1))!!.let { it.start to it.end })
        assertEquals(2L, q.activeSeq())
    }

    @Test
    fun retireMany() {
        val q = CidQueue(initialCid())
        q.insert(cid(2, 0))
        assertEquals(0L to len, q.insert(cid(1_000_000, 1_000_000))!!.let { it.start to it.end })
        assertEquals(1_000_000L, q.activeSeq())
    }

    @Test
    fun insertLimit() {
        val q = CidQueue(initialCid())
        assertNull(q.insert(cid(len - 1, 0)))
        assertSame(CidQueue.InsertError.ExceedsLimit, assertFailsWith<CidQueue.InsertError> { q.insert(cid(len, 0)) })
    }

    @Test
    fun insertDuplicate() {
        val q = CidQueue(initialCid())
        q.insert(cid(0, 0))
        q.insert(cid(0, 0))
    }

    @Test
    fun insertRetired() {
        val q = CidQueue(initialCid())
        assertNull(q.insert(cid(0, 0)), "reinserting active CID succeeds")
        assertNull(q.next(), "active CID isn't requeued")
        q.insert(cid(1, 0))
        q.next()!!
        assertSame(
            CidQueue.InsertError.Retired,
            assertFailsWith<CidQueue.InsertError>("previous active CID is already retired") { q.insert(cid(0, 0)) },
        )
    }

    @Test
    fun retireThenInsertNext() {
        val q = CidQueue(initialCid())
        for (i in 1 until len) q.insert(cid(i, 0))
        q.next()!!
        q.insert(cid(len, 0))
        assertSame(CidQueue.InsertError.ExceedsLimit, assertFailsWith<CidQueue.InsertError> { q.insert(cid(len + 1, 0)) })
    }

    @Test
    fun alwaysValid() {
        val q = CidQueue(initialCid())
        assertNull(q.next())
        assertEquals(initialCid(), q.active())
        assertEquals(0L, q.activeSeq())
    }
}

// cid_state.rs has no tests of its own (the connection tests use its `active_seq` / `assign_retire_seq` helpers);
// these check the behaviour those tests rely on.
class CidStateTest {

    private val t0 = Instant(1_000_000_000)

    private fun issued(seq: Long) = IssuedCid(seq, ConnectionId.of(ByteArray(8) { seq.toByte() }), ResetToken(ByteArray(16)))

    @Test
    fun handshakeCidsAreActiveAndTracked() {
        val s = CidState(8, 10.seconds, t0, 2)
        assertEquals(0L to 1L, s.activeSeqBounds())
        // both handshake CIDs share one expiry batch
        assertEquals(t0 + 10.seconds, s.nextTimeout())
        assertEquals(0L, s.retirePriorTo())
    }

    @Test
    fun noLifetimeMeansNoTimeout() {
        val s = CidState(8, null, t0, 1)
        assertNull(s.nextTimeout())
        s.newCids(listOf(issued(1), issued(2)), t0)
        assertNull(s.nextTimeout())
        assertEquals(0L to 2L, s.activeSeqBounds())
    }

    @Test
    fun cidTimeoutAdvancesRetirePriorTo() {
        val s = CidState(8, 10.seconds, t0, 1)
        s.newCids(listOf(issued(1), issued(2)), t0 + 1.seconds)
        assertEquals(t0 + 10.seconds, s.nextTimeout())
        // CID 0 expires: ask the peer to retire everything below 1
        assertTrue(s.onCidTimeout())
        assertEquals(1L, s.retirePriorTo())
        assertEquals(t0 + 11.seconds, s.nextTimeout())
        // CIDs 1 and 2 expire, but 0 has not been retired yet: retire_prior_to must not move, and no new CID is
        // needed for the (unchanged) retire_prior_to
        assertFalse(s.onCidTimeout())
        assertEquals(1L, s.retirePriorTo())
        assertNull(s.nextTimeout())
        // the peer retires 0; a later timeout could advance again
        assertTrue(s.onCidRetirement(0, 4))
        assertEquals(1L to 2L, s.activeSeqBounds())
    }

    @Test
    fun cidRetirementErrors() {
        assertEquals(
            TransportErrorCode.PROTOCOL_VIOLATION,
            assertFailsWith<TransportError> { CidState(0, null, t0, 1).onCidRetirement(0, 2) }.code,
        )
        val s = CidState(8, null, t0, 2)
        assertEquals(
            TransportErrorCode.PROTOCOL_VIOLATION,
            assertFailsWith<TransportError> { s.onCidRetirement(3, 2) }.code,
        )
        assertFalse(s.onCidRetirement(0, 1), "one CID still active, limit 1")
        assertTrue(s.onCidRetirement(1, 1))
    }

    @Test
    fun assignRetireSeqCountsNewlyRetired() {
        val s = CidState(8, null, t0, 4)
        assertEquals(2L, s.assignRetireSeq(2))
        assertEquals(1L, s.assignRetireSeq(3))
        assertEquals(3L, s.retirePriorTo())
    }
}
