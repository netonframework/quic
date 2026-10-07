package neton.quic.proto

import kotlin.random.Random
import kotlin.time.Duration

// Packet number spaces and acknowledgement tracking (quinn-proto `connection/spaces.rs`; `Retransmits` and
// `ThinRetransmits` are in Retransmits.kt).
//
// ⚖️ quinn's `Option<u64>` packet numbers are `Long` with -1 for `None` (packet numbers are below 2^62) and its
// `Option<Instant>` fields are [Instant.NONE]: the ACK and loss-detection paths update them per packet.

/** Per packet number space state (spaces.rs:19). */
internal class PacketSpace(now: Instant) {
    var crypto: Keys? = null
    val dedup = Dedup()

    /** Highest received packet number. */
    var rxPacket: Long = 0

    /** Data to send. */
    var pending = Retransmits()

    /** Packet numbers to acknowledge. */
    val pendingAcks = PendingAcks()

    /**
     * The packet number of the next packet that will be sent, if any. In the Data space, the packet number stored
     * here is sometimes skipped by [PacketNumberFilter] logic.
     */
    var nextPacketNumber: Long = 0

    /** The largest packet number the remote peer acknowledged in an ACK frame; -1 for none. */
    var largestAckedPacket: Long = -1
    var largestAckedPacketSent: Instant = now

    /** The highest-numbered ACK-eliciting packet we've sent. */
    var largestAckElicitingSent: Long = 0

    /** Number of packets in [sentPackets] with numbers above [largestAckElicitingSent]. */
    var unackedNonAckElicitingTail: Long = 0

    /** Transmitted but not acked. */
    val sentPackets = SentPackets()

    /** Number of explicit congestion notification codepoints seen on incoming packets. */
    var ecnCounters: EcnCounts = EcnCounts()

    /**
     * Recent ECN counters sent by the peer in ACK frames.
     *
     * Updated (and inspected) whenever we receive an ACK with a new highest acked packet number. Stored per-space to
     * simplify verification, which would otherwise have difficulty distinguishing between ECN bleaching and counts
     * having been updated by a near-simultaneous ACK already processed in another space.
     */
    var ecnFeedback: EcnCounts = EcnCounts()

    /** Incoming cryptographic handshake stream. */
    val cryptoStream = Assembler()

    /** Current offset of outgoing cryptographic handshake stream. */
    var cryptoOffset: Long = 0

    /** The time the most recently sent retransmittable packet was sent; [Instant.NONE] for none. */
    var timeOfLastAckElicitingPacket: Instant = Instant.NONE

    /**
     * The time at which the earliest sent packet in this space will be considered lost based on exceeding the
     * reordering window in time. Only set for packets numbered prior to a packet that has been acknowledged.
     * [Instant.NONE] for none.
     */
    var lossTime: Instant = Instant.NONE

    /** Number of tail loss probes to send. */
    var lossProbes: Int = 0
    var pingPending: Boolean = false
    var immediateAckPending: Boolean = false

    /** Number of packets sent in the current key phase. */
    var sentWithKeys: Long = 0

    /** Record returned by [take]; valid until the next [take] on this space. */
    private val taken = SentPacket()

    /** Record returned by [sent]; valid until the next [sent] on this space. */
    private val forgotten = SentPacket()

    /**
     * Queue data for a tail loss probe (or anti-amplification deadlock prevention) packet (spaces.rs:118).
     *
     * Probes are sent similarly to normal packets when an expected ACK has not arrived. We never deem a packet lost
     * until we receive an ACK that should have included it, but if a trailing run of packets (or their ACKs) are
     * lost, this might not happen in a timely fashion. We send probe packets to force an ACK, and exempt them from
     * congestion control to prevent a deadlock when the congestion window is filled with lost tail packets.
     *
     * We prefer to send new data, to make the most efficient use of bandwidth. If there's no data waiting to be
     * sent, then we retransmit in-flight data to reduce odds of loss. If there's no in-flight data either, we're
     * probably a client guarding against a handshake anti-amplification deadlock and we just make something up.
     */
    fun maybeQueueProbe(requestImmediateAck: Boolean, streams: StreamsState) {
        if (lossProbes == 0) return

        if (requestImmediateAck) {
            // The probe should be ACKed without delay (should only be used in the Data space and when the peer
            // supports the acknowledgement frequency extension)
            immediateAckPending = true
        }

        if (!pending.isEmpty(streams)) {
            // There's real data to send here, no need to make something up
            return
        }

        // Retransmit the data of the oldest in-flight packet
        var pn = sentPackets.firstAtOrAfter(0)
        while (pn >= 0) {
            val r = sentPackets.retransmitsOf(pn)
            if (r != null && !r.isEmpty(streams)) {
                // Remove retransmitted data from the old packet so we don't end up retransmitting it *again* even
                // if the copy we're sending now gets acknowledged.
                pending.orAssign(r)
                sentPackets.clearRetransmits(pn)
                return
            }
            pn = sentPackets.firstAtOrAfter(pn + 1)
        }

        // Nothing new to send and nothing to retransmit, so fall back on a ping. This should only happen in rare
        // cases during the handshake when the server becomes blocked by anti-amplification.
        if (!immediateAckPending) pingPending = true
    }

    /**
     * Get the next outgoing packet number in this space.
     *
     * In the Data space, the connection's [PacketNumberFilter] must be used rather than calling this directly.
     */
    fun getTxNumber(): Long {
        // An invariant: PacketBuilder.new closes the connection before the numbers run out (RFC 9000 §12.3).
        check(nextPacketNumber < MAX_PACKET_NUMBER)
        val x = nextPacketNumber
        nextPacketNumber += 1
        sentWithKeys += 1
        return x
    }

    fun canSend(streams: StreamsState): SendableFrames {
        val acks = pendingAcks.canSend()
        val other = !pending.isEmpty(streams) || pingPending || immediateAckPending
        return SendableFrames.of(acks, other)
    }

    /**
     * Verifies sanity of an ECN block and returns whether congestion was encountered (spaces.rs:167). ⚖️ quinn's
     * `Result<bool, &str>` is an [EcnCheck].
     */
    fun detectEcn(newlyAcked: Long, ecn: EcnCounts): EcnCheck {
        val ect0Increase = ecn.ect0 - ecnFeedback.ect0
        if (ect0Increase < 0) return EcnCheck.Ect0Regression
        val ect1Increase = ecn.ect1 - ecnFeedback.ect1
        if (ect1Increase < 0) return EcnCheck.Ect1Regression
        val ceIncrease = ecn.ce - ecnFeedback.ce
        if (ceIncrease < 0) return EcnCheck.CeRegression
        val totalIncrease = ect0Increase + ect1Increase + ceIncrease
        if (totalIncrease < newlyAcked) return EcnCheck.Bleaching
        if ((ect0Increase + ceIncrease) < newlyAcked || ect1Increase != 0L) return EcnCheck.Corruption
        // If total_increase > newly_acked (which happens when ACKs are lost), this is required by the draft so that
        // long-term drift does not occur. If =, then the only question is whether to count CE packets as CE or ECT0.
        // Recording them as CE is more consistent and keeps the congestion check obvious.
        ecnFeedback.ect0 = ecn.ect0
        ecnFeedback.ect1 = ecn.ect1
        ecnFeedback.ce = ecn.ce
        return if (ceIncrease != 0L) EcnCheck.Congested else EcnCheck.NotCongested
    }

    /**
     * Stop tracking sent packet [number], and return what we knew about it. ⚖️ The record is owned by this space and
     * valid until the next [take]; its retransmits and stream frames now belong to the caller.
     */
    fun take(number: Long): SentPacket? {
        if (!sentPackets.take(number, taken)) return null
        if (!taken.ackEliciting && number > largestAckElicitingSent) {
            check(unackedNonAckElicitingTail > 0)
            unackedNonAckElicitingTail -= 1
        }
        return taken
    }

    /**
     * Record [packet] as sent with [number]; may return a packet that should be forgotten (spaces.rs:216). The
     * packet's fields are copied, and its retransmits moved, into this space. ⚖️ The returned record is owned by this
     * space and valid until the next [sent].
     */
    fun sent(number: Long, packet: SentPacket): SentPacket? {
        var forgottenPacket: SentPacket? = null
        if (packet.ackEliciting) {
            unackedNonAckElicitingTail = 0
            largestAckElicitingSent = number
        } else if (unackedNonAckElicitingTail > MAX_UNACKED_NON_ACK_ELICTING_TAIL) {
            // Retain state for at most this many non-ACK-eliciting packets sent after the most recently sent
            // ACK-eliciting packet. We're never guaranteed to receive an ACK for those, and we can't judge them as
            // lost without an ACK, so to limit memory in applications which receive packets but don't send
            // ACK-eliciting data for long periods use we must eventually start forgetting about them, although it
            // might also be reasonable to just kill the connection due to weird peer behavior.
            val oldestAfterAckEliciting = sentPackets.firstAtOrAfter(largestAckElicitingSent + 1)
            check(oldestAfterAckEliciting >= 0)
            // Per https://www.rfc-editor.org/rfc/rfc9000.html#name-frames-and-frame-types, non-ACK-eliciting packets
            // must only contain PADDING, ACK, and CONNECTION_CLOSE frames, which require no special handling on ACK
            // or loss beyond removal from in-flight counters if padded.
            sentPackets.take(oldestAfterAckEliciting, forgotten)
            debugAssert(!forgotten.ackEliciting) { "assertion failed: !packet.ack_eliciting" }
            forgottenPacket = forgotten
        } else {
            unackedNonAckElicitingTail += 1
        }

        sentPackets.insert(number, packet)
        return forgottenPacket
    }

    /** Whether any congestion-controlled packets in this space are not yet acknowledged or lost. */
    fun hasInFlight(): Boolean = sentPackets.hasNonZeroSize()

    private companion object {
        const val MAX_UNACKED_NON_ACK_ELICTING_TAIL: Long = 1_000
    }
}

/** quinn's `Index<SpaceId> for [PacketSpace; 3]`. */
internal operator fun Array<PacketSpace>.get(space: SpaceId): PacketSpace = this[space.ordinal]

/** quinn's `Result<bool, &'static str>` from [PacketSpace.detectEcn]: [error] is `null` for the `Ok` values. */
internal enum class EcnCheck(val error: String?) {
    NotCongested(null),
    Congested(null),
    Ect0Regression("peer ECT(0) count regression"),
    Ect1Regression("peer ECT(1) count regression"),
    CeRegression("peer CE count regression"),
    Bleaching("ECN bleaching"),
    Corruption("ECN corruption"),
}

/**
 * Represents one or more packets subject to retransmission (spaces.rs:269).
 *
 * ⚖️ A mutable record: the connection fills one while building a packet and [PathData.sent] copies it into the
 * space's [SentPackets] (which stores the fields in parallel arrays, so tracking a sent packet allocates nothing);
 * [PacketSpace.take] copies a stored packet back out into a record owned by the space.
 */
internal class SentPacket {
    /** [PathData.generation] of the path on which this packet was sent. */
    var pathGeneration: Long = 0

    /** The time the packet was sent. */
    var timeSent: Instant = Instant.NONE

    /**
     * The number of bytes sent in the packet, not including UDP or IP overhead, but including QUIC framing
     * overhead. Zero if this packet is not counted towards congestion control, i.e. not an "in flight" packet.
     */
    var size: Int = 0

    /** Whether an acknowledgement is expected directly in response to this packet. */
    var ackEliciting: Boolean = false

    /** The largest packet number acknowledged by this packet; -1 for none. */
    var largestAcked: Long = -1

    /** Data which needs to be retransmitted in case the packet is lost. */
    val retransmits = ThinRetransmits()

    /** Metadata for stream frames in a packet. The actual application data is stored with the stream state. */
    var streamFrames: StreamMetaVec = StreamMetaVec.EMPTY

    /** Reset to the state of a fresh record, for reuse. */
    fun clear() {
        pathGeneration = 0
        timeSent = Instant.NONE
        size = 0
        ackEliciting = false
        largestAcked = -1
        retransmits.set(null)
        streamFrames = StreamMetaVec.EMPTY
    }

    override fun toString(): String =
        "SentPacket(pathGeneration=$pathGeneration, timeSent=$timeSent, size=$size, ackEliciting=$ackEliciting, " +
            "largestAcked=$largestAcked, retransmits=${retransmits.get() != null}, streamFrames=$streamFrames)"
}

/**
 * The sent packets of a space, by packet number (quinn's `BTreeMap<u64, SentPacket>`, spaces.rs:42).
 *
 * ⚖️ Packet numbers are sent in increasing order and leave the map when acknowledged or lost, so the live ones form
 * a window `[base, base + span)`; the records live in parallel arrays used as a ring buffer indexed by
 * `packet number - base`, so inserting, finding and removing a packet allocate nothing and take O(1) (the arrays
 * grow by doubling when the window outgrows them). Ordered traversal scans the window. Inserting a number not above
 * every stored number (which quinn never does) throws. `SentPacketsTest` checks this against a sorted map.
 */
internal class SentPackets {
    private var capacity = INITIAL_CAPACITY
    private var mask = capacity - 1
    private var present = BooleanArray(capacity)
    private var timeSent = LongArray(capacity)
    private var sizes = IntArray(capacity)
    private var ackEliciting = BooleanArray(capacity)
    private var largestAcked = LongArray(capacity)
    private var pathGeneration = LongArray(capacity)
    private var retransmits = arrayOfNulls<Retransmits>(capacity)
    private var streamFrames = arrayOfNulls<StreamMetaVec>(capacity)

    /** Packet number of ring slot [start]; the lowest stored number when not empty. */
    private var base = 0L
    private var start = 0

    /** Width of the window: the highest stored number is `base + span - 1`. */
    private var span = 0

    /** Number of stored packets. */
    var size: Int = 0
        private set

    /** Number of stored packets whose size is not zero. */
    private var nonZeroSize = 0

    fun isEmpty(): Boolean = size == 0

    /** Whether any stored packet has a non-zero size (quinn `values().any(|x| x.size != 0)`). */
    fun hasNonZeroSize(): Boolean = nonZeroSize > 0

    private fun slotOf(pn: Long): Int {
        if (span == 0 || pn < base || pn - base >= span) return -1
        val i = (start + (pn - base).toInt()) and mask
        return if (present[i]) i else -1
    }

    operator fun contains(pn: Long): Boolean = slotOf(pn) >= 0

    /** The time [pn] was sent, or [Instant.NONE] if it is not stored. */
    fun timeSentOf(pn: Long): Instant {
        val i = slotOf(pn)
        return if (i < 0) Instant.NONE else Instant(timeSent[i])
    }

    /** The size of [pn], or -1 if it is not stored. */
    fun sizeOf(pn: Long): Int {
        val i = slotOf(pn)
        return if (i < 0) -1 else sizes[i]
    }

    /** Whether [pn] is ack-eliciting; false when it is not stored. */
    fun ackElicitingOf(pn: Long): Boolean {
        val i = slotOf(pn)
        return i >= 0 && ackEliciting[i]
    }

    /** The retransmits stored with [pn], if any. */
    fun retransmitsOf(pn: Long): Retransmits? {
        val i = slotOf(pn)
        return if (i < 0) null else retransmits[i]
    }

    /** Drop the retransmits stored with [pn] (quinn `mem::take(&mut packet.retransmits)`). */
    fun clearRetransmits(pn: Long) {
        val i = slotOf(pn)
        if (i >= 0) retransmits[i] = null
    }

    /** The lowest stored packet number, or -1 when empty. */
    fun first(): Long = if (span == 0) -1 else base

    /** The highest stored packet number, or -1 when empty. */
    fun last(): Long = if (span == 0) -1 else base + span - 1

    /** The lowest stored packet number at or above [pn], or -1 (quinn `range(pn..).next()`). */
    fun firstAtOrAfter(pn: Long): Long {
        if (span == 0) return -1
        var p = maxOf(pn, base)
        val end = base + span
        while (p < end) {
            if (present[(start + (p - base).toInt()) and mask]) return p
            p++
        }
        return -1
    }

    /** Store [packet] as [pn], moving its retransmits; [pn] must be above every stored number. */
    fun insert(pn: Long, packet: SentPacket) {
        require(pn >= 0)
        if (span == 0) {
            base = pn
            start = 0
            span = 1
        } else {
            require(pn >= base + span) { "packet $pn inserted out of order" }
            val needed = pn - base + 1
            if (needed > capacity) grow(needed)
            span = needed.toInt()
        }
        val i = (start + (pn - base).toInt()) and mask
        present[i] = true
        timeSent[i] = packet.timeSent.nanos
        sizes[i] = packet.size
        ackEliciting[i] = packet.ackEliciting
        largestAcked[i] = packet.largestAcked
        pathGeneration[i] = packet.pathGeneration
        retransmits[i] = packet.retransmits.take()
        streamFrames[i] = packet.streamFrames
        size++
        if (packet.size != 0) nonZeroSize++
    }

    /** Remove [pn], copying its record into [out]; returns false (leaving [out] alone) when it is not stored. */
    fun take(pn: Long, out: SentPacket): Boolean {
        val i = slotOf(pn)
        if (i < 0) return false
        readInto(i, out)
        removeSlot(i, pn)
        return true
    }

    /** Remove [pn] without reading it; returns whether it was stored. */
    fun remove(pn: Long): Boolean {
        val i = slotOf(pn)
        if (i < 0) return false
        removeSlot(i, pn)
        return true
    }

    /**
     * Remove every packet in ascending order, passing each to [action] through [scratch] (quinn
     * `mem::take(&mut space.sent_packets)` followed by iterating the taken map).
     */
    inline fun drain(scratch: SentPacket, action: (pn: Long, packet: SentPacket) -> Unit) {
        while (true) {
            val pn = first()
            if (pn < 0) return
            take(pn, scratch)
            action(pn, scratch)
        }
    }

    private fun readInto(i: Int, out: SentPacket) {
        out.timeSent = Instant(timeSent[i])
        out.size = sizes[i]
        out.ackEliciting = ackEliciting[i]
        out.largestAcked = largestAcked[i]
        out.pathGeneration = pathGeneration[i]
        out.retransmits.set(retransmits[i])
        out.streamFrames = streamFrames[i] ?: StreamMetaVec.EMPTY
    }

    private fun removeSlot(i: Int, pn: Long) {
        present[i] = false
        retransmits[i] = null
        streamFrames[i] = null
        if (sizes[i] != 0) nonZeroSize--
        size--
        if (size == 0) {
            span = 0
            return
        }
        if (pn == base) {
            // Advance the window past the gap; the highest stored packet bounds the scan.
            do {
                base++
                start = (start + 1) and mask
                span--
            } while (!present[start])
        } else if (pn == base + span - 1) {
            do {
                span--
            } while (!present[(start + span - 1) and mask])
        }
    }

    private fun grow(needed: Long) {
        check(needed <= MAX_CAPACITY) { "sent packet window too large: $needed" }
        var cap = capacity
        while (cap < needed) cap = cap shl 1
        val np = BooleanArray(cap)
        val nt = LongArray(cap)
        val ns = IntArray(cap)
        val na = BooleanArray(cap)
        val nl = LongArray(cap)
        val ng = LongArray(cap)
        val nr = arrayOfNulls<Retransmits>(cap)
        val nf = arrayOfNulls<StreamMetaVec>(cap)
        for (k in 0 until span) {
            val i = (start + k) and mask
            np[k] = present[i]; nt[k] = timeSent[i]; ns[k] = sizes[i]; na[k] = ackEliciting[i]
            nl[k] = largestAcked[i]; ng[k] = pathGeneration[i]; nr[k] = retransmits[i]; nf[k] = streamFrames[i]
        }
        present = np; timeSent = nt; sizes = ns; ackEliciting = na
        largestAcked = nl; pathGeneration = ng; retransmits = nr; streamFrames = nf
        capacity = cap
        mask = cap - 1
        start = 0
    }

    private companion object {
        const val INITIAL_CAPACITY = 16
        const val MAX_CAPACITY = 1L shl 30
    }
}

/**
 * RFC4303-style sliding window packet number deduplicator (spaces.rs:470).
 *
 * A contiguous bitfield, where each bit corresponds to a packet number and the rightmost bit is always set. A set
 * bit represents a packet that has been successfully authenticated. Bits left of the window are assumed to be set.
 *
 * ```text
 * ...xxxxxxxxx 1 0
 *     ^        ^ ^
 * window highest next
 * ```
 *
 * ⚖️ quinn's `u128` window is two `Long` halves ([hi], [lo]).
 */
internal class Dedup {
    /** Upper 64 bits of the window. */
    internal var hi: Long = 0
        private set

    /** Lower 64 bits of the window. */
    internal var lo: Long = 0
        private set

    /** Lowest packet number higher than all yet authenticated. */
    internal var next: Long = 0
        private set

    /** Highest packet number authenticated. */
    private fun highest(): Long = next - 1

    /**
     * Record a newly authenticated packet number.
     *
     * Returns whether the packet might be a duplicate.
     */
    fun insert(packet: Long): Boolean {
        val diff = packet - next
        if (diff >= 0) {
            // Right of window: ((window << 1) | 1).checked_shl(diff), 0 when the shift is 128 or more
            val h1 = (hi shl 1) or (lo ushr 63)
            val l1 = (lo shl 1) or 1L
            if (diff >= 128) {
                hi = 0; lo = 0
            } else {
                val n = diff.toInt()
                hi = shl128Hi(h1, l1, n)
                lo = shl128Lo(l1, n)
            }
            next = packet + 1
            return false
        } else if (highest() - packet < WINDOW_SIZE) {
            // Within window
            val d = highest() - packet
            if (d >= 1) {
                // < highest
                val bit = (d - 1).toInt()
                val duplicate: Boolean
                if (bit >= 64) {
                    val mask = 1L shl (bit - 64)
                    duplicate = hi and mask != 0L
                    hi = hi or mask
                } else {
                    val mask = 1L shl bit
                    duplicate = lo and mask != 0L
                    lo = lo or mask
                }
                return duplicate
            } else {
                // == highest
                return true
            }
        } else {
            // Left of window
            return true
        }
    }

    /**
     * Returns the packet number of the smallest packet missing between the provided interval, or -1 if there are no
     * missing packets (quinn `None`).
     */
    internal fun smallestMissingInInterval(lowerBound: Long, upperBound: Long): Long {
        debugAssert(lowerBound <= upperBound) { "assertion failed: lower_bound <= upper_bound" }
        debugAssert(upperBound <= highest()) { "assertion failed: upper_bound <= self.highest()" }

        // Since we already know the packets at the boundaries have been received, we only need to check those in
        // between them (this removes the necessity of extra logic to deal with the highest packet, which is stored
        // outside the bitfield)
        val lower = lowerBound + 1
        val upper = saturatingSubU(upperBound, 1)

        // Note: the offsets are counted from the right. The highest packet is not included in the bitfield, so we
        // subtract 1 to account for that
        val startOffset = maxOf(highest() - upper, 1L) - 1
        if (startOffset >= BITFIELD_SIZE) {
            // The start offset is outside of the window. All packets outside of the window are considered to be
            // received.
            return -1
        }

        val endOffsetExclusive = saturatingSubU(highest(), lower)

        // The range is clamped at the edge of the window, because any earlier packets are considered to be received
        val rangeLen = minOf(saturatingSubU(endOffsetExclusive, startOffset), BITFIELD_SIZE)
        if (rangeLen == 0L) return -1

        // mask = ((1 << range_len) - 1) << start_offset, or all ones for a full-width range
        val maskHi: Long
        val maskLo: Long
        if (rangeLen == BITFIELD_SIZE) {
            maskHi = -1L; maskLo = -1L
        } else {
            val len = rangeLen.toInt()
            val onesHi = if (len > 64) (1L shl (len - 64)) - 1 else 0L
            val onesLo = if (len >= 64) -1L else (1L shl len) - 1
            val s = startOffset.toInt()
            maskHi = shl128Hi(onesHi, onesLo, s)
            maskLo = shl128Lo(onesLo, s)
        }
        val gapsHi = hi.inv() and maskHi
        val gapsLo = lo.inv() and maskLo

        val leadingZeros = if (gapsHi != 0L) gapsHi.countLeadingZeroBits() else 64 + gapsLo.countLeadingZeroBits()
        val smallestMissingOffset = 128L - leadingZeros
        val smallestMissingPacket = highest() - smallestMissingOffset

        return if (smallestMissingPacket <= upper) smallestMissingPacket else -1
    }

    /**
     * Returns true if there are any missing packets between the provided interval.
     *
     * The provided packet numbers must have been received before calling this function.
     */
    internal fun missingInInterval(lowerBound: Long, upperBound: Long): Boolean =
        smallestMissingInInterval(lowerBound, upperBound) >= 0

    internal companion object {
        /** Number of packets tracked by `Dedup`: one plus the window's 128 bits. */
        const val WINDOW_SIZE: Long = 1 + 128
        private const val BITFIELD_SIZE: Long = 128

        /** High half of a 128-bit `hi:lo << n` for `0 <= n < 128`. */
        private fun shl128Hi(hi: Long, lo: Long, n: Int): Long = when {
            n == 0 -> hi
            n < 64 -> (hi shl n) or (lo ushr (64 - n))
            else -> lo shl (n - 64)
        }

        /** Low half of a 128-bit `hi:lo << n` for `0 <= n < 128`. */
        private fun shl128Lo(lo: Long, n: Int): Long = if (n < 64) lo shl n else 0L
    }
}

/**
 * Indicates which data is available for sending (spaces.rs:602). ⚖️ quinn's `Copy` struct of two flags is a value
 * class over their bits, so returning it allocates nothing.
 */
internal value class SendableFrames private constructor(private val bits: Int) {
    val acks: Boolean get() = bits and ACKS != 0
    val other: Boolean get() = bits and OTHER != 0

    /** Whether no data is sendable. */
    fun isEmpty(): Boolean = bits == 0

    override fun toString(): String = "SendableFrames { acks: $acks, other: $other }"

    companion object {
        private const val ACKS = 1
        private const val OTHER = 2

        fun of(acks: Boolean, other: Boolean): SendableFrames =
            SendableFrames((if (acks) ACKS else 0) or (if (other) OTHER else 0))

        /** Returns that no data is available for sending. */
        fun empty(): SendableFrames = SendableFrames(0)
    }
}

/** Acknowledgement state for received packets (spaces.rs:626). */
internal class PendingAcks {
    /**
     * Whether we should send an ACK immediately, even if that means sending an ACK-only packet.
     *
     * When `immediate_ack_required` is false, the normal behavior is to send ACK frames only when there is other data
     * to send, or when the `MaxAckDelay` timer expires.
     */
    internal var immediateAckRequired: Boolean = false
        private set

    /**
     * The number of ack-eliciting packets received since the last ACK frame was sent. Once the count _exceeds_
     * `ack_eliciting_threshold`, an immediate ACK is required.
     */
    private var ackElicitingSinceLastAckSent: Long = 0
    private var nonAckElicitingSinceLastAckSent: Long = 0
    private var ackElicitingThreshold: Long = 1

    /**
     * The reordering threshold, controlling how we respond to out-of-order ack-eliciting packets.
     *
     * Different values enable different behavior:
     *
     * * `0`: no special action is taken
     * * `1`: an ACK is immediately sent if it is out-of-order according to RFC 9000
     * * `>1`: an ACK is immediately sent if it is out-of-order according to the ACK frequency draft
     */
    private var reorderingThreshold: Long = 1

    /**
     * The earliest ack-eliciting packet since the last ACK was sent, used to calculate the moment upon which
     * `max_ack_delay` elapses.
     */
    private var earliestAckElicitingSinceLastAckSent: Instant = Instant.NONE

    /** The packet number ranges of ack-eliciting packets the peer hasn't confirmed receipt of ACKs for. */
    private val ranges = ArrayRangeSet()

    /**
     * The packet with the largest packet number (-1 for none), and the time upon which it was received (used to
     * calculate ACK delay in [ackDelay]).
     */
    private var largestPacket: Long = -1
    private var largestPacketTime: Instant = Instant.NONE

    /** The ack-eliciting packet we have received with the largest packet number; -1 for none. */
    private var largestAckElicitingPacket: Long = -1

    /** The largest acknowledged packet number sent in an ACK frame; -1 for none. */
    private var largestAcked: Long = -1

    fun setAckFrequencyParams(frame: Frame.AckFrequency) {
        ackElicitingThreshold = frame.ackElicitingThreshold.value
        reorderingThreshold = frame.reorderingThreshold.value
    }

    fun setImmediateAckRequired() {
        immediateAckRequired = true
    }

    fun onMaxAckDelayTimeout() {
        immediateAckRequired = ackElicitingSinceLastAckSent > 0
    }

    /** When the max ACK delay elapses, or [Instant.NONE] (quinn `None`). */
    fun maxAckDelayTimeout(maxAckDelay: Duration): Instant =
        if (earliestAckElicitingSinceLastAckSent.isNone) Instant.NONE else earliestAckElicitingSinceLastAckSent + maxAckDelay

    /** Whether any ACK frames can be sent even if doing so requires a dedicated packet. */
    fun canSend(): Boolean = immediateAckRequired && !ranges.isEmpty()

    /** Whether any ACK frames can be sent in data-initiated packets. */
    fun canSendWithOtherFrames(): Boolean = !ranges.isEmpty()

    /** Returns the delay since the packet with the largest packet number was received. */
    fun ackDelay(now: Instant): Duration =
        if (largestPacket < 0) Duration.ZERO else now.saturatingDurationSince(largestPacketTime)

    /**
     * Handle receipt of a new packet.
     *
     * Returns true if the max ack delay timer should be armed.
     */
    fun packetReceived(now: Instant, packetNumber: Long, ackEliciting: Boolean, dedup: Dedup): Boolean {
        if (!ackEliciting) {
            nonAckElicitingSinceLastAckSent += 1
            return false
        }

        val prevLargestAckEliciting = if (largestAckElicitingPacket < 0) 0L else largestAckElicitingPacket

        // Track largest ack-eliciting packet
        largestAckElicitingPacket = maxOf(largestAckElicitingPacket, packetNumber)

        // Handle ack_eliciting_threshold
        ackElicitingSinceLastAckSent += 1
        immediateAckRequired = immediateAckRequired || ackElicitingSinceLastAckSent > ackElicitingThreshold

        // Handle out-of-order packets
        immediateAckRequired = immediateAckRequired || isOutOfOrder(packetNumber, prevLargestAckEliciting, dedup)

        // Arm max_ack_delay timer if necessary
        if (earliestAckElicitingSinceLastAckSent.isNone && !canSend()) {
            earliestAckElicitingSinceLastAckSent = now
            return true
        }

        return false
    }

    private fun isOutOfOrder(packetNumber: Long, prevLargestAckEliciting: Long, dedup: Dedup): Boolean {
        when (reorderingThreshold) {
            0L -> return false
            1L -> {
                // From https://www.rfc-editor.org/rfc/rfc9000#section-13.2.1-7
                return packetNumber < prevLargestAckEliciting ||
                    dedup.missingInInterval(prevLargestAckEliciting, packetNumber)
            }
            else -> {
                // From acknowledgement frequency draft, section 6.1: send an ACK immediately if doing so would cause
                // the sender to detect a new packet loss
                if (largestAcked < 0 || largestAckElicitingPacket < 0) return false
                val largestAcked = largestAcked
                val largestUnacked = largestAckElicitingPacket
                if (reorderingThreshold > largestAcked) return false
                // The largest packet number that could be declared lost without a new ACK being sent
                val largestReported = largestAcked - reorderingThreshold + 1
                val smallestMissingUnreported = dedup.smallestMissingInInterval(largestReported, largestUnacked)
                if (smallestMissingUnreported < 0) return false
                return largestUnacked - smallestMissingUnreported >= reorderingThreshold
            }
        }
    }

    /**
     * Should be called whenever ACKs have been sent.
     *
     * This will suppress sending further ACKs until additional ACK eliciting frames arrive.
     */
    fun acksSent() {
        // It is possible (though unlikely) that the ACKs we just sent do not cover all the ACK-eliciting packets we
        // have received (e.g. if there is not enough room in the packet to fit all the ranges). To keep things
        // simple, however, we assume they do. If there are indeed some ACKs that weren't covered, the packets might
        // be ACKed later anyway, because they are still contained in `self.ranges`. If we somehow fail to send the
        // ACKs at a later moment, the peer will assume the packets got lost and will retransmit their frames in a
        // new packet, which is suboptimal, because we already received them. Our assumption here is that simplicity
        // results in code that is more performant, even in the presence of occasional redundant retransmits.
        immediateAckRequired = false
        ackElicitingSinceLastAckSent = 0
        nonAckElicitingSinceLastAckSent = 0
        earliestAckElicitingSinceLastAckSent = Instant.NONE
        largestAcked = largestAckElicitingPacket
    }

    /** Insert one packet that needs to be acknowledged. */
    fun insertOne(packet: Long, now: Instant) {
        ranges.insertOne(packet)

        if (largestPacket < 0 || packet > largestPacket) {
            largestPacket = packet
            largestPacketTime = now
        }

        if (ranges.len > MAX_ACK_BLOCKS) ranges.removeMin()
    }

    /** Remove ACKs of packets numbered at or below [max] from the set of pending ACKs. */
    fun subtractBelow(max: Long) {
        ranges.remove(0, max + 1)
    }

    /** Returns the set of currently pending ACK ranges. */
    fun ranges(): ArrayRangeSet = ranges

    /**
     * Queue an ACK if a significant number of non-ACK-eliciting packets have not yet been acknowledged.
     *
     * Should be called immediately before a non-probing packet is composed, when we've already committed to sending a
     * packet regardless.
     */
    fun maybeAckNonEliciting() {
        // If we're going to send a packet anyway, and we've received a significant number of non-ACK-eliciting
        // packets, then include an ACK to help the peer perform timely loss detection even if they're not sending
        // any ACK-eliciting packets themselves. Exact threshold chosen somewhat arbitrarily.
        if (nonAckElicitingSinceLastAckSent > LAZY_ACK_THRESHOLD) immediateAckRequired = true
    }

    private companion object {
        const val LAZY_ACK_THRESHOLD: Long = 10
    }
}

/**
 * Helper for mitigating [optimistic ACK attacks](https://www.rfc-editor.org/rfc/rfc9000.html#name-optimistic-ack-attack)
 * (spaces.rs:914).
 *
 * A malicious peer could prompt the local application to begin a large data transfer, and then send ACKs without
 * first waiting for data to be received. This could defeat congestion control, allowing the connection to consume
 * disproportionate resources. We therefore occasionally skip packet numbers, and classify any ACK referencing a
 * skipped packet number as a transport error.
 *
 * Skipped packet numbers occur only in the application data space (where costly transfers might take place) and are
 * distributed exponentially to reflect the reduced likelihood and impact of bad behavior from a peer that has been
 * well-behaved for an extended period.
 *
 * ACKs for packet numbers that have not yet been allocated are also a transport error, but an attacker with knowledge
 * of the congestion control algorithm in use could time falsified ACKs to arrive after the packets they reference
 * are sent.
 */
internal class PacketNumberFilter private constructor(
    /** Next outgoing packet number to skip. */
    private var nextSkippedPacketNumber: Long,
    /** Next packet number to skip is randomly selected from 2^n..2^n+1. */
    private var exponent: Int,
) {
    /** Most recently skipped packet number; -1 for none. */
    private var prevSkippedPacketNumber: Long = -1

    fun peek(space: PacketSpace): Long {
        val n = space.nextPacketNumber
        if (n != nextSkippedPacketNumber) return n
        return n + 1
    }

    fun allocate(rng: Random, space: PacketSpace): Long {
        val n = space.getTxNumber()
        if (n != nextSkippedPacketNumber) return n

        // Skip this packet number, and choose the next one to skip
        prevSkippedPacketNumber = nextSkippedPacketNumber
        val nextExponent = if (exponent == Int.MAX_VALUE) exponent else exponent + 1
        nextSkippedPacketNumber = rng.nextLong(saturatingPow2(exponent), saturatingPow2(nextExponent))
        exponent = nextExponent

        return space.getTxNumber()
    }

    /** Throws PROTOCOL_VIOLATION if the ACK range `[first, last]` in [spaceId] covers a skipped packet number. */
    fun checkAck(spaceId: SpaceId, first: Long, last: Long) {
        if (spaceId == SpaceId.Data && prevSkippedPacketNumber >= 0 && prevSkippedPacketNumber in first..last) {
            throw TransportError.PROTOCOL_VIOLATION("unsent packet acked")
        }
    }

    companion object {
        fun new(rng: Random): PacketNumberFilter {
            // First skipped PN is in 0..64
            val exponent = 6
            return PacketNumberFilter(rng.nextLong(0, saturatingPow2(exponent)), exponent)
        }

        /** A filter that never skips (quinn's `#[cfg(test)] disabled()`). */
        fun disabled(): PacketNumberFilter = PacketNumberFilter(Long.MAX_VALUE, Int.MAX_VALUE)

        /** Rust `2u64.saturating_pow(e)`, saturating at ⚖️ `Long.MAX_VALUE` (no reachable packet number is near). */
        private fun saturatingPow2(e: Int): Long = if (e >= 63) Long.MAX_VALUE else 1L shl e
    }
}

/** Ensures we can always fit all our ACKs in a single minimum-MTU packet with room to spare. */
internal const val MAX_ACK_BLOCKS: Int = 64

/** One past the largest packet number a sender may use (RFC 9000 §12.3: 2^62). */
internal const val MAX_PACKET_NUMBER: Long = 1L shl 62
