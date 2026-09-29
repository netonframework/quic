package neton.quic.proto

import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.Duration.Companion.milliseconds

// Network impairment for tests: one direction of a link that loses, duplicates, reorders and delays datagrams, driven
// by a seeded generator so that every run of a scenario sees the same fates. Used by the virtual-time pair simulation
// (`ConnPair.clientToServer` / `serverToClient`) and by the loopback relay of the driver tests (`LossyRelay`).

/** The fate of one datagram: the extra delays of the copies to deliver (none: it is lost). */
internal typealias Fate = List<Duration>

internal class LinkImpairment(seed: Long) {
    private val rng = Random(seed)

    /** Probability that a datagram is lost. */
    var loss = 0.0

    /** Probability that a delivered datagram is delivered twice. */
    var duplicate = 0.0

    /** Probability that a delivered datagram is held back by up to [reorderDelay], letting later ones overtake it. */
    var reorder = 0.0

    /** The most a reordered datagram (or a duplicate) is held back. */
    var reorderDelay: Duration = 10.milliseconds

    /**
     * Targeted loss, consulted before the random fates: returns true to drop a datagram. Receives the datagram's
     * bytes (still encrypted) and its index in this direction.
     */
    var drop: ((data: ByteArray, index: Long) -> Boolean)? = null

    /** Sees every datagram and its fate (for tracing a scenario). */
    var observer: ((data: ByteArray, index: Long, fate: Fate) -> Unit)? = null

    /** Drop everything (a link that went down). */
    var blackhole = false

    /** Datagrams offered to this direction. */
    var datagrams = 0L
        private set

    /** Datagrams lost (by any rule). */
    var dropped = 0L
        private set

    /** Datagrams dropped by the [drop] rule. */
    var droppedByRule = 0L
        private set

    /** Extra copies delivered. */
    var duplicated = 0L
        private set

    /** Datagrams held back. */
    var reordered = 0L
        private set

    fun fate(data: ByteArray): Fate {
        val index = datagrams
        val fate = decide(data)
        observer?.invoke(data, index, fate)
        return fate
    }

    private fun decide(data: ByteArray): Fate {
        val index = datagrams++
        val rule = drop
        if (blackhole || (rule != null && rule(data, index))) {
            dropped++
            droppedByRule++
            return emptyList()
        }
        if (loss > 0 && rng.nextDouble() < loss) {
            dropped++
            return emptyList()
        }
        val first = if (reorder > 0 && rng.nextDouble() < reorder) {
            reordered++
            heldBack()
        } else {
            Duration.ZERO
        }
        if (duplicate > 0 && rng.nextDouble() < duplicate) {
            duplicated++
            return listOf(first, heldBack())
        }
        return listOf(first)
    }

    private fun heldBack(): Duration =
        (1 + rng.nextLong(maxOf(1L, reorderDelay.inWholeMicroseconds))).microseconds

    override fun toString(): String =
        "datagrams=$datagrams dropped=$dropped (by rule $droppedByRule) duplicated=$duplicated reordered=$reordered"

    companion object {
        /** A direction with random [loss], and optionally duplication and reordering. */
        fun lossy(seed: Long, loss: Double, duplicate: Double = 0.0, reorder: Double = 0.0): LinkImpairment =
            LinkImpairment(seed).also {
                it.loss = loss
                it.duplicate = duplicate
                it.reorder = reorder
            }
    }
}

// Packet classification of QUIC v1 datagrams (first packet of the datagram), for targeted loss.

/** Whether the datagram starts with a long-header packet. */
internal fun isLongHeader(data: ByteArray): Boolean = data.isNotEmpty() && data[0].toInt() and 0x80 != 0

/** Whether the datagram starts with an Initial packet (long header, type 0). */
internal fun isInitial(data: ByteArray): Boolean = isLongHeader(data) && (data[0].toInt() shr 4) and 3 == 0

/** Whether the datagram starts with a Handshake packet (long header, type 2). */
internal fun isHandshake(data: ByteArray): Boolean = isLongHeader(data) && (data[0].toInt() shr 4) and 3 == 2

/**
 * Whether the datagram holds a Handshake packet, possibly coalesced after an Initial one (a server's first flight is
 * Initial + Handshake in one datagram). Walks the long-header packets by their Length fields.
 */
internal fun hasHandshake(data: ByteArray): Boolean {
    var at = 0
    while (at < data.size && data[at].toInt() and 0x80 != 0) {
        val type = (data[at].toInt() shr 4) and 3
        if (type == 2) return true
        if (type == 3) return false // Retry: no Length, nothing coalesced
        var p = at + 5 // first byte + version
        p += 1 + (data[p].toInt() and 0xff) // DCID
        p += 1 + (data[p].toInt() and 0xff) // SCID
        if (type == 0) {
            val (tokenLen, n) = readVarInt(data, p)
            p += n + tokenLen.toInt()
        }
        val (length, n) = readVarInt(data, p)
        at = p + n + length.toInt()
    }
    return false
}

private fun readVarInt(data: ByteArray, at: Int): Pair<Long, Int> {
    val first = data[at].toInt() and 0xff
    val len = 1 shl (first shr 6)
    var v = (first and 0x3f).toLong()
    for (i in 1 until len) v = (v shl 8) or (data[at + i].toLong() and 0xff)
    return v to len
}

/** Whether the datagram is a short-header (1-RTT) packet. */
internal fun isShortHeader(data: ByteArray): Boolean = data.isNotEmpty() && data[0].toInt() and 0x80 == 0

/**
 * The number of live native key contexts once garbage left by earlier tests has been collected and its cleaners have
 * run (they would otherwise release keys in the middle of a test and skew its count). A test that compares against
 * this baseline while its own connections are still reachable sees exactly the keys it failed to release.
 */
@OptIn(kotlin.native.runtime.NativeRuntimeApi::class)
internal fun settledNativeKeys(): Long {
    var last = -1L
    var stable = 0
    while (stable < 3) {
        kotlin.native.runtime.GC.collect()
        kotlin.native.concurrent.Worker.current.park(2_000)
        val now = NativeKeys.live
        if (now == last) stable++ else stable = 0
        last = now
    }
    return last
}
