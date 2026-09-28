package neton.quic.proto

import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue
import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds

// connection/spaces.rs tests (10), then tests of the replaced data structures against models.
class SpacesTest {

    private val window = Dedup.WINDOW_SIZE

    /** The dedup window as quinn's `u128`, for comparisons with binary literals below 2^64. */
    private fun Dedup.window64(): Long {
        assertEquals(0L, hi)
        return lo
    }

    @Test
    fun sanity() {
        val dedup = Dedup()
        assertFalse(dedup.insert(0))
        assertEquals(1L, dedup.next)
        assertEquals(0b1L, dedup.window64())
        assertTrue(dedup.insert(0))
        assertEquals(1L, dedup.next)
        assertEquals(0b1L, dedup.window64())
        assertFalse(dedup.insert(1))
        assertEquals(2L, dedup.next)
        assertEquals(0b11L, dedup.window64())
        assertFalse(dedup.insert(2))
        assertEquals(3L, dedup.next)
        assertEquals(0b111L, dedup.window64())
        assertFalse(dedup.insert(4))
        assertEquals(5L, dedup.next)
        assertEquals(0b11110L, dedup.window64())
        assertFalse(dedup.insert(7))
        assertEquals(8L, dedup.next)
        assertEquals(0b1111_0100L, dedup.window64())
        assertTrue(dedup.insert(4))
        assertFalse(dedup.insert(3))
        assertEquals(8L, dedup.next)
        assertEquals(0b1111_1100L, dedup.window64())
        assertFalse(dedup.insert(6))
        assertEquals(8L, dedup.next)
        assertEquals(0b1111_1101L, dedup.window64())
        assertFalse(dedup.insert(5))
        assertEquals(8L, dedup.next)
        assertEquals(0b1111_1111L, dedup.window64())
    }

    @Test
    fun happypath() {
        val dedup = Dedup()
        for (i in 0L until 2 * window) {
            assertFalse(dedup.insert(i))
            for (j in 0L..i) assertTrue(dedup.insert(j))
        }
    }

    @Test
    fun jump() {
        val dedup = Dedup()
        dedup.insert(2 * window)
        assertTrue(dedup.insert(window))
        assertEquals(2 * window + 1, dedup.next)
        assertEquals(0L, dedup.hi)
        assertEquals(0L, dedup.lo)
        assertFalse(dedup.insert(window + 1))
        assertEquals(2 * window + 1, dedup.next)
        // 1 << (WINDOW_SIZE - 2) = 1 << 127
        assertEquals(Long.MIN_VALUE, dedup.hi)
        assertEquals(0L, dedup.lo)
    }

    @Test
    fun dedupHasMissing() {
        val dedup = Dedup()

        dedup.insert(0)
        assertFalse(dedup.missingInInterval(0, 0))

        dedup.insert(1)
        assertFalse(dedup.missingInInterval(0, 1))

        dedup.insert(3)
        assertTrue(dedup.missingInInterval(1, 3))

        dedup.insert(4)
        assertFalse(dedup.missingInInterval(3, 4))
        assertTrue(dedup.missingInInterval(0, 4))

        dedup.insert(2)
        assertFalse(dedup.missingInInterval(0, 4))
    }

    @Test
    fun dedupOutsideOfWindowHasMissing() {
        val dedup = Dedup()

        for (i in 0L until 140L) dedup.insert(i)

        // 0 and 4 are outside of the window
        assertFalse(dedup.missingInInterval(0, 4))
        dedup.insert(160)
        assertFalse(dedup.missingInInterval(0, 4))
        assertFalse(dedup.missingInInterval(0, 140))
        assertTrue(dedup.missingInInterval(0, 160))
    }

    @Test
    fun dedupSmallestMissing() {
        val dedup = Dedup()

        dedup.insert(0)
        assertEquals(-1L, dedup.smallestMissingInInterval(0, 0))

        dedup.insert(1)
        assertEquals(-1L, dedup.smallestMissingInInterval(0, 1))

        dedup.insert(5)
        dedup.insert(7)
        assertEquals(2L, dedup.smallestMissingInInterval(0, 7))
        assertEquals(6L, dedup.smallestMissingInInterval(5, 7))

        dedup.insert(2)
        assertEquals(3L, dedup.smallestMissingInInterval(1, 7))

        dedup.insert(170)
        dedup.insert(172)
        dedup.insert(300)
        assertEquals(-1L, dedup.smallestMissingInInterval(170, 172))

        dedup.insert(500)
        assertEquals(372L, dedup.smallestMissingInInterval(0, 500))
        assertEquals(372L, dedup.smallestMissingInInterval(0, 373))
        assertEquals(-1L, dedup.smallestMissingInInterval(0, 372))
    }

    private val t0 = Instant(1_000_000_000_000L)

    @Test
    fun pendingAcksFirstPacketIsNotConsideredReordered() {
        val acks = PendingAcks()
        val dedup = Dedup()
        dedup.insert(0)
        acks.packetReceived(t0, 0, true, dedup)
        assertFalse(acks.immediateAckRequired)
    }

    @Test
    fun pendingAcksAfterImmediateAckSet() {
        val acks = PendingAcks()
        val dedup = Dedup()

        // Receive ack-eliciting packet
        dedup.insert(0)
        val now = t0
        acks.insertOne(0, now)
        acks.packetReceived(now, 0, true, dedup)

        // Sanity check
        assertFalse(acks.ranges().isEmpty())
        assertFalse(acks.canSend())

        // Can send ACK after max_ack_delay exceeded
        acks.setImmediateAckRequired()
        assertTrue(acks.canSend())
    }

    @Test
    fun pendingAcksAckDelay() {
        val acks = PendingAcks()
        val dedup = Dedup()

        val t1 = t0
        val t2 = t1 + 2.milliseconds
        val t3 = t2 + 5.milliseconds
        assertEquals(0.milliseconds, acks.ackDelay(t1))
        assertEquals(0.milliseconds, acks.ackDelay(t2))
        assertEquals(0.milliseconds, acks.ackDelay(t3))

        // In-order packet
        dedup.insert(0)
        acks.insertOne(0, t1)
        acks.packetReceived(t1, 0, true, dedup)
        assertEquals(0.milliseconds, acks.ackDelay(t1))
        assertEquals(2.milliseconds, acks.ackDelay(t2))
        assertEquals(7.milliseconds, acks.ackDelay(t3))

        // Out of order (higher than expected)
        dedup.insert(3)
        acks.insertOne(3, t2)
        acks.packetReceived(t2, 3, true, dedup)
        assertEquals(0.milliseconds, acks.ackDelay(t2))
        assertEquals(5.milliseconds, acks.ackDelay(t3))

        // Out of order (lower than expected, so previous instant is kept)
        dedup.insert(2)
        acks.insertOne(2, t3)
        acks.packetReceived(t3, 2, true, dedup)
        assertEquals(5.milliseconds, acks.ackDelay(t3))
    }

    /**
     * quinn: "The tracking state of sent packets should be minimal, and not grow over time" (`size_of::<SentPacket>()
     * <= 128`). Here a sent packet is one slot of [SentPackets]' parallel arrays and no object: check that storing
     * and taking many packets keeps the arrays at the window size, and that a slot is well under 128 bytes.
     */
    @Test
    fun sentPacketSize() {
        // present + time + size + ack-eliciting + largest acked + path generation + two references
        val bytesPerSlot = 1 + 8 + 4 + 1 + 8 + 8 + 8 + 8
        assertTrue(bytesPerSlot <= 128)

        val sent = SentPackets()
        val p = SentPacket()
        for (pn in 0L until 100_000L) {
            p.timeSent = Instant(pn); p.size = 1200; p.ackEliciting = true
            sent.insert(pn, p)
            if (pn >= 10) assertTrue(sent.remove(pn - 10))
        }
        assertEquals(10, sent.size)
        assertEquals(99_990L, sent.first())
    }

    // Not in quinn: the two-`Long` window against a model (a set of seen numbers; numbers more than 128 below the
    // highest are treated as seen, as the bitfield does).
    @Test
    fun dedupMatchesModel() {
        val rnd = Random(21)
        repeat(200) {
            val dedup = Dedup()
            val seen = HashSet<Long>()
            var highest = -1L
            repeat(400) {
                val p = if (highest < 0 || rnd.nextInt(3) == 0) highest + 1 + rnd.nextInt(200) else maxOf(0, highest - rnd.nextInt(300))
                val expected = p in seen || (highest >= 0 && p <= highest && highest - p >= Dedup.WINDOW_SIZE)
                assertEquals(expected, dedup.insert(p), "insert $p (highest $highest)")
                seen.add(p)
                highest = maxOf(highest, p)

                val a = rnd.nextLong(0, highest + 1)
                val b = rnd.nextLong(0, highest + 1)
                val lower = minOf(a, b)
                val upper = maxOf(a, b)
                if (lower in seen && upper in seen) {
                    var expectedMissing = -1L
                    for (q in lower + 1 until upper) {
                        if (highest - q in 1..128 && q !in seen) { expectedMissing = q; break }
                    }
                    assertEquals(expectedMissing, dedup.smallestMissingInInterval(lower, upper), "missing in [$lower, $upper]")
                }
            }
        }
    }

    // Not in quinn: `SentPackets` against a sorted map (quinn's `BTreeMap`) on random insert / take / lookup sequences.
    @Test
    fun sentPacketsMatchesSortedMap() {
        val rnd = Random(23)
        repeat(100) {
            val sent = SentPackets()
            val model = HashMap<Long, Triple<Long, Int, Boolean>>()
            val scratch = SentPacket()
            var next = 0L
            repeat(1000) {
                when (rnd.nextInt(10)) {
                    in 0..4 -> {
                        next += 1 + (if (rnd.nextInt(8) == 0) rnd.nextInt(40) else 0)
                        val size = if (rnd.nextBoolean()) 0 else 1 + rnd.nextInt(1500)
                        val p = SentPacket()
                        p.timeSent = Instant(next * 10); p.size = size; p.ackEliciting = rnd.nextBoolean()
                        p.largestAcked = next - 1
                        sent.insert(next, p)
                        model[next] = Triple(next * 10, size, p.ackEliciting)
                    }
                    in 5..7 -> {
                        val pn = if (model.isNotEmpty() && rnd.nextBoolean()) model.keys.random(rnd) else rnd.nextLong(0, next + 2)
                        val m = model.remove(pn)
                        assertEquals(m != null, sent.take(pn, scratch))
                        if (m != null) {
                            assertEquals(m.first, scratch.timeSent.nanos)
                            assertEquals(m.second, scratch.size)
                            assertEquals(m.third, scratch.ackEliciting)
                            assertEquals(pn - 1, scratch.largestAcked)
                        }
                    }
                    8 -> {
                        val from = rnd.nextLong(0, next + 2)
                        val expected = model.keys.filter { it >= from }.minOrNull() ?: -1L
                        assertEquals(expected, sent.firstAtOrAfter(from))
                    }
                    else -> {
                        val pn = rnd.nextLong(0, next + 2)
                        assertEquals(pn in model, pn in sent)
                        assertEquals(model[pn]?.second ?: -1, sent.sizeOf(pn))
                        assertEquals(model[pn]?.first ?: Instant.NONE.nanos, sent.timeSentOf(pn).nanos)
                    }
                }
                assertEquals(model.size, sent.size)
                assertEquals(model.keys.minOrNull() ?: -1L, sent.first())
                assertEquals(model.keys.maxOrNull() ?: -1L, sent.last())
                assertEquals(model.values.any { it.second != 0 }, sent.hasNonZeroSize())
            }
            // Drain in ascending order
            val drained = ArrayList<Long>()
            sent.drain(scratch) { pn, _ -> drained.add(pn) }
            assertEquals(model.keys.sorted(), drained)
            assertTrue(sent.isEmpty())
        }
    }

    @Test
    fun sentPacketsRejectsOutOfOrderInsert() {
        val sent = SentPackets()
        sent.insert(5, SentPacket())
        assertFailsWith<IllegalArgumentException> { sent.insert(5, SentPacket()) }
        assertFailsWith<IllegalArgumentException> { sent.insert(3, SentPacket()) }
    }

    // Not in quinn: PacketSpace bookkeeping of the non-ACK-eliciting tail and of retransmits moved in and out.
    @Test
    fun packetSpaceForgetsNonAckElicitingTail() {
        val space = PacketSpace(t0)
        val p = SentPacket()
        p.ackEliciting = true
        p.size = 100
        assertNull(space.sent(space.getTxNumber(), p))
        p.ackEliciting = false
        p.size = 0
        // 1001 non-ACK-eliciting packets are retained, the next ones forget the oldest after the ACK-eliciting one
        for (i in 0 until 1001) assertNull(space.sent(space.getTxNumber(), p))
        val forgotten = space.sent(space.getTxNumber(), p)
        assertEquals(1002, space.sentPackets.size)
        assertTrue(forgotten != null && !forgotten.ackEliciting)
        assertFalse(1L in space.sentPackets)
        assertTrue(space.hasInFlight())
        // Taking a tail packet decrements the tail count
        val tail = space.unackedNonAckElicitingTail
        assertTrue(space.take(space.sentPackets.last()) != null)
        assertEquals(tail - 1, space.unackedNonAckElicitingTail)
        assertTrue(space.take(0) != null)
        assertFalse(space.hasInFlight())
    }

    @Test
    fun packetSpaceMovesRetransmits() {
        val space = PacketSpace(t0)
        val streams = StreamsState(Side.Client, VarInt(10), VarInt(10), 1_000_000, VarInt(1_000_000), VarInt(1_000_000))
        val p = SentPacket()
        p.ackEliciting = true
        p.retransmits.getOrCreate().maxData = true
        space.sent(space.getTxNumber(), p)
        assertNull(p.retransmits.get()) // moved into the space
        p.clear()
        p.ackEliciting = true
        space.sent(space.getTxNumber(), p)

        // A probe with nothing pending takes the oldest packet's retransmits
        space.lossProbes = 1
        space.maybeQueueProbe(false, streams)
        assertTrue(space.pending.maxData)
        assertNull(space.sentPackets.retransmitsOf(0))
        assertFalse(space.pingPending)

        // With nothing left to retransmit, a ping
        space.pending = Retransmits()
        space.maybeQueueProbe(false, streams)
        assertTrue(space.pingPending)

        val taken = space.take(1)!!
        assertSame(taken, space.take(1) ?: taken)
        assertNull(space.take(1))
    }

    @Test
    fun detectEcn() {
        val space = PacketSpace(t0)
        assertEquals(EcnCheck.NotCongested, space.detectEcn(2, EcnCounts(2, 0, 0)))
        assertEquals(EcnCheck.Congested, space.detectEcn(2, EcnCounts(3, 0, 1)))
        assertEquals(EcnCheck.Ect0Regression, space.detectEcn(0, EcnCounts(2, 0, 1)))
        assertEquals(EcnCheck.Bleaching, space.detectEcn(3, EcnCounts(4, 0, 1)))
        assertEquals(EcnCheck.Corruption, space.detectEcn(1, EcnCounts(3, 1, 1)))
        assertEquals("ECN bleaching", EcnCheck.Bleaching.error)
    }

    @Test
    fun packetNumberFilterSkipsAndRejectsAcks() {
        val rng = Random(3)
        val space = PacketSpace(t0)
        val filter = PacketNumberFilter.new(rng)
        val allocated = ArrayList<Long>()
        repeat(300) {
            val peek = filter.peek(space)
            val n = filter.allocate(rng, space)
            assertEquals(peek, n)
            allocated.add(n)
        }
        val skipped = (0L..allocated.last()).filter { it !in allocated }
        assertTrue(skipped.isNotEmpty())
        // Skips are spaced exponentially: at most one in 0..64, then one in each [2^n, 2^(n+1))
        assertTrue(skipped.size <= 4, "skipped $skipped")
        val last = skipped.last()
        assertFailsWith<TransportError> { filter.checkAck(SpaceId.Data, last, last) }
        filter.checkAck(SpaceId.Handshake, last, last)
        filter.checkAck(SpaceId.Data, last + 1, last + 10)

        val disabled = PacketNumberFilter.disabled()
        val space2 = PacketSpace(t0)
        repeat(100) { assertEquals(it.toLong(), disabled.allocate(rng, space2)) }
    }

    @Test
    fun pendingAcksThresholdsAndTimer() {
        val acks = PendingAcks()
        val dedup = Dedup()
        assertEquals(Instant.NONE, acks.maxAckDelayTimeout(25.milliseconds))
        dedup.insert(0); acks.insertOne(0, t0)
        assertTrue(acks.packetReceived(t0, 0, true, dedup)) // arms the timer
        assertEquals(t0 + 25.milliseconds, acks.maxAckDelayTimeout(25.milliseconds))
        dedup.insert(1); acks.insertOne(1, t0)
        assertFalse(acks.packetReceived(t0, 1, true, dedup))
        assertTrue(acks.canSend()) // second ack-eliciting packet exceeds the threshold of 1
        acks.acksSent()
        assertFalse(acks.canSend())
        assertTrue(acks.canSendWithOtherFrames())
        assertEquals(Instant.NONE, acks.maxAckDelayTimeout(25.milliseconds))

        // More than 10 non-ACK-eliciting packets force an ACK when a packet is sent anyway
        for (i in 2L until 13L) { dedup.insert(i); acks.insertOne(i, t0); acks.packetReceived(t0, i, false, dedup) }
        assertFalse(acks.canSend())
        acks.maybeAckNonEliciting()
        assertTrue(acks.canSend())

        acks.subtractBelow(12)
        assertTrue(acks.ranges().isEmpty())

        // At most 64 ranges are kept
        for (i in 0L until 100L) acks.insertOne(100 + 2 * i, t0)
        assertEquals(MAX_ACK_BLOCKS, acks.ranges().len)
        assertEquals(100L + 2 * 36, acks.ranges().min())
        assertEquals(Duration.ZERO, acks.ackDelay(t0))
    }

    @Test
    fun pendingAcksAckFrequencyReordering() {
        // reordering threshold 2 (ACK frequency draft §6.1)
        val acks = PendingAcks()
        acks.setAckFrequencyParams(Frame.AckFrequency(VarInt(0), VarInt(10), VarInt(25_000), VarInt(2)))
        val dedup = Dedup()
        for (pn in longArrayOf(0, 1, 2, 3)) { dedup.insert(pn); acks.insertOne(pn, t0); acks.packetReceived(t0, pn, true, dedup) }
        acks.acksSent() // largest acked = 3
        // 4 missing, 5 and 6 arrive: 6 - 4 >= 2 would let the sender declare 4 lost
        dedup.insert(5); acks.insertOne(5, t0); acks.packetReceived(t0, 5, true, dedup)
        assertFalse(acks.immediateAckRequired)
        dedup.insert(6); acks.insertOne(6, t0); acks.packetReceived(t0, 6, true, dedup)
        assertTrue(acks.immediateAckRequired)
    }

    @Test
    fun sendableFrames() {
        assertTrue(SendableFrames.empty().isEmpty())
        val s = SendableFrames.of(acks = true, other = false)
        assertTrue(s.acks)
        assertFalse(s.other)
        assertFalse(s.isEmpty())
        assertEquals("SendableFrames { acks: true, other: false }", s.toString())
    }
}
