package neton.quic.proto

import neton.io.bytes.Bytes

/**
 * Buffer of outgoing retransmittable stream data (quinn-proto `connection/send_buffer.rs`).
 *
 * Application writes are kept as the `Bytes` they were handed in as (zero-copy); STREAM frames copy from them into
 * the packet.
 */
internal class SendBuffer {
    /**
     * Data queued by the application but not yet acknowledged. May or may not have been sent.
     *
     * ⚖️ quinn narrows the first segment with `Bytes::advance` as its prefix is acknowledged; here the segment stays
     * as written and [frontTrimmed] (which quinn tracks as well) is the start of its live part, so a partial
     * acknowledgement allocates nothing. quinn also shrinks the `VecDeque` when it is mostly empty; Kotlin's
     * `ArrayDeque` has no shrink, and it only holds references.
     */
    internal var unackedSegments = ArrayDeque<Bytes>()
        private set

    /** Total size of the live parts of [unackedSegments]. */
    private var unackedLen = 0L

    /** Acknowledged bytes removed from the first segment's view but still held by its allocation. */
    internal var frontTrimmed = 0
        private set

    /** The first offset that hasn't been written by the application, i.e. the offset past the end of `unacked`. */
    var offset = 0L
        private set

    /** The first offset that hasn't been sent. Always lies in `(offset - unacked.len())..offset`. */
    private var unsent = 0L

    /** Acknowledged ranges which couldn't be discarded yet as they don't include the earliest offset in `unacked`. */
    internal var acks = RangeSet()
        private set

    /** Previously transmitted ranges deemed lost. */
    private var retransmits = RangeSet()

    /**
     * Result of the last [pollTransmit]: the range `[polledStart, polledEnd)` to send and whether its length must be
     * encoded. ⚖️ quinn returns `(Range<u64>, bool)`; fields avoid allocating a result per STREAM frame.
     */
    var polledStart = 0L
        private set
    var polledEnd = 0L
        private set
    var polledEncodeLength = false
        private set

    /** Append application data to the end of the stream (send_buffer.rs:37). */
    fun write(data: Bytes) {
        unackedLen += data.size
        offset += data.size
        unackedSegments.addLast(data)
    }

    /** Discard a range `[start, end)` of acknowledged stream data (send_buffer.rs:44). */
    fun ack(start: Long, end: Long) {
        // Clamp the range to data which is still tracked
        val baseOffset = offset - unackedLen
        acks.insert(maxOf(baseOffset, start), maxOf(baseOffset, end))

        while (!acks.isEmpty() && acks.startAt(0) == offset - unackedLen) {
            var toAdvance = acks.endAt(0) - acks.startAt(0)
            acks.removeMin()

            unackedLen -= toAdvance
            while (toAdvance > 0) {
                val front = unackedSegments.firstOrNull() ?: error("Expected buffered data")
                val frontLen = front.size - frontTrimmed
                if (frontLen <= toAdvance) {
                    toAdvance -= frontLen
                    unackedSegments.removeFirst()
                    frontTrimmed = 0
                } else {
                    frontTrimmed += toAdvance.toInt()
                    toAdvance = 0
                }
            }
        }
    }

    /**
     * Compute the next range to transmit on this stream and update state to account for that transmission
     * (send_buffer.rs:88). The result is in [polledStart], [polledEnd] and [polledEncodeLength].
     *
     * [maxLen] here includes the space which is available to transmit the offset and length of the data to send.
     * The caller has to guarantee that there is at least enough space available to write maximum-sized metadata
     * (8 byte offset + 8 byte length). [polledEncodeLength] tells whether the length needs to be encoded in the
     * STREAM frame's metadata, or can be omitted since the selected range will fill the whole packet.
     */
    fun pollTransmit(maxLen: Int) {
        // quinn: debug_assert!(max_len >= 8 + 8)
        var maxLen = maxLen.toLong()
        var encodeLength = false

        if (!retransmits.isEmpty()) {
            // Retransmit sent data
            val start = retransmits.startAt(0)
            val rangeEnd = retransmits.endAt(0)
            retransmits.removeMin()

            // When the offset is known, we know how many bytes are required to encode it. Offset 0 requires no space
            if (start != 0L) maxLen -= varIntSize(start)
            if (rangeEnd - start < maxLen) {
                encodeLength = true
                maxLen -= 8
            }

            val end = minOf(rangeEnd, maxLen + start)
            if (end != rangeEnd) retransmits.insert(end, rangeEnd)
            polledStart = start
            polledEnd = end
            polledEncodeLength = encodeLength
            return
        }

        // Transmit new data

        // When the offset is known, we know how many bytes are required to encode it. Offset 0 requires no space
        if (unsent != 0L) maxLen -= varIntSize(unsent)
        if (offset - unsent < maxLen) {
            encodeLength = true
            maxLen -= 8
        }

        val end = minOf(offset, maxLen + unsent)
        polledStart = unsent
        polledEnd = end
        polledEncodeLength = encodeLength
        unsent = end
    }

    /**
     * Returns data which is associated with a range `[start, end)` (send_buffer.rs:143).
     *
     * This function can return a subset of the range, if the data is stored in noncontiguous fashion in the send
     * buffer. In this case callers should call the function again with an incremented start offset to retrieve more
     * data. The result is a zero-copy slice (the segment itself when the range covers it).
     *
     * ⚖️ quinn returns a borrowed `&[u8]`; a neton-io `Bytes` sub-slice is a small object, allocated when the range
     * is part of a segment (neton-io has no ranged copy out of `Bytes` that would let the caller skip it).
     */
    fun get(start: Long, end: Long): Bytes {
        val baseOffset = offset - unackedLen

        var segmentOffset = baseOffset
        for (i in 0 until unackedSegments.size) {
            val segment = unackedSegments[i]
            val viewStart = if (i == 0) frontTrimmed else 0
            val viewLen = segment.size - viewStart
            if (start >= segmentOffset && start < segmentOffset + viewLen) {
                val s = (start - segmentOffset).toInt()
                val e = minOf(end - segmentOffset, viewLen.toLong()).toInt()
                return segment.slice(viewStart + s, viewStart + e)
            }
            segmentOffset += viewLen
        }

        return Bytes.EMPTY
    }

    /** Release abandoned data while preserving the final offset for RESET_STREAM (send_buffer.rs:163). */
    fun discard() {
        unackedSegments = ArrayDeque()
        unackedLen = 0
        frontTrimmed = 0
        unsent = offset
        acks = RangeSet()
        retransmits = RangeSet()
    }

    /** Queue a range `[start, end)` of sent but unacknowledged data to be retransmitted (send_buffer.rs:172). */
    fun retransmit(start: Long, end: Long) {
        // quinn: debug_assert!(range.end <= self.unsent, "unsent data can't be lost")
        retransmits.insert(start, end)
    }

    fun retransmitAllFor0rtt() {
        // quinn: debug_assert_eq!(self.offset, self.unacked_len)
        unsent = 0
    }

    /** Whether all sent data has been acknowledged. */
    val isFullyAcked: Boolean get() = unackedLen == 0L

    /** Whether there's data to send. There may be sent unacknowledged data even when this is false. */
    val hasUnsentData: Boolean get() = unsent != offset || !retransmits.isEmpty()

    /** Bytes still retained from application writes, including acknowledged data (send_buffer.rs:204). */
    val buffered: Long get() = unackedLen + frontTrimmed
}
