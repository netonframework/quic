package neton.quic.proto

import neton.io.net.SocketAddress
import kotlin.time.Duration

// Network path state (quinn-proto `connection/paths.rs`). qlog recovery metrics are not ported (SPEC §8).

/** Description of a particular network path (paths.rs:16). */
internal class PathData private constructor(
    val remote: SocketAddress,
    internal var rtt: RttEstimator,
    internal var congestion: Controller,
    internal var pacing: Pacer,
    internal var mtud: MtuDiscovery,
    private val generation: Long,
) {
    /** Whether we're enabling ECN on outgoing packets. */
    internal var sendingEcn: Boolean = true
    internal var challenge: Long? = null
    internal var challengePending: Boolean = false

    /**
     * Whether we're certain the peer can both send and receive on this address.
     *
     * Initially equal to `use_stateless_retry` for servers, and becomes false again on every migration. Always true
     * for clients.
     */
    internal var validated: Boolean = false

    /** Total size of all UDP datagrams sent on this path. */
    internal var totalSent: Long = 0

    /** Total size of all UDP datagrams received on this path. */
    internal var totalRecvd: Long = 0

    /**
     * Packet number of the first packet sent after an RTT sample was collected on this path, used in persistent
     * congestion determination: quinn's `Option<(SpaceId, u64)>` as a nullable space and a packet number.
     */
    internal var firstPacketAfterRttSampleSpace: SpaceId? = null
    internal var firstPacketAfterRttSamplePn: Long = 0

    internal val inFlight = InFlight()

    /**
     * Number of the first packet sent on this path, -1 for none. Used to determine whether a packet was sent on an
     * earlier path. Insufficient to determine if a packet was sent on a later path.
     */
    private var firstPacket: Long = -1

    /** Set [firstPacketAfterRttSampleSpace] / [firstPacketAfterRttSamplePn] (quinn `= Some((space, pn))`). */
    internal fun setFirstPacketAfterRttSample(space: SpaceId, pn: Long) {
        firstPacketAfterRttSampleSpace = space
        firstPacketAfterRttSamplePn = pn
    }

    /** quinn `first_packet_after_rtt_sample.is_some_and(|x| x < (space, pn))` (tuple order: space, then number). */
    internal fun firstPacketAfterRttSampleBefore(space: SpaceId, pn: Long): Boolean {
        val s = firstPacketAfterRttSampleSpace ?: return false
        return s < space || (s == space && firstPacketAfterRttSamplePn < pn)
    }

    /**
     * Resets RTT, congestion control, pacing and MTU states (paths.rs:143).
     *
     * This is useful when it is known the underlying path has changed.
     */
    internal fun reset(now: Instant, config: TransportConfig) {
        rtt = RttEstimator(config.initialRtt)
        congestion = config.congestionControllerFactory.build(now, config.getInitialMtu())
        mtud.reset(config.getInitialMtu(), config.minMtu)
        pacing = Pacer(rtt.get(), congestion.initialWindow(), currentMtu(), now)
    }

    /**
     * Indicates whether we're a server that hasn't validated the peer's address and hasn't received enough data
     * from the peer to permit sending [bytesToSend] additional bytes.
     */
    internal fun antiAmplificationBlocked(bytesToSend: Long): Boolean =
        !validated && totalRecvd * 3 < totalSent + bytesToSend

    /** Returns the path's current MTU. */
    internal fun currentMtu(): Int = mtud.currentMtu()

    /**
     * Account for transmission of [packet] with number [pn] in [space] (paths.rs:172). The packet's fields are
     * copied into the space; the caller may reuse the [SentPacket] afterwards.
     */
    internal fun sent(pn: Long, packet: SentPacket, space: PacketSpace) {
        inFlight.insert(packet)
        if (firstPacket < 0) firstPacket = pn
        space.sent(pn, packet)?.let { removeInFlight(it) }
    }

    /**
     * Remove [packet] from this path's congestion control counters, or return `false` if it was sent before this
     * path was established.
     */
    internal fun removeInFlight(packet: SentPacket): Boolean {
        if (packet.pathGeneration != generation) return false
        inFlight.remove(packet)
        return true
    }

    internal fun generation(): Long = generation

    companion object {
        /** paths.rs:59 */
        internal fun new(
            remote: SocketAddress,
            allowMtud: Boolean,
            peerMaxUdpPayloadSize: Int?,
            generation: Long,
            now: Instant,
            config: TransportConfig,
        ): PathData {
            val congestion = config.congestionControllerFactory.build(now, config.getInitialMtu())
            val mtudConfig = config.mtuDiscoveryConfig
            val mtud = if (mtudConfig != null && allowMtud) {
                MtuDiscovery.new(config.getInitialMtu(), config.minMtu, peerMaxUdpPayloadSize, mtudConfig)
            } else {
                MtuDiscovery.disabled(config.getInitialMtu(), config.minMtu)
            }
            return PathData(
                remote,
                RttEstimator(config.initialRtt),
                congestion,
                Pacer(config.initialRtt, congestion.initialWindow(), config.getInitialMtu(), now),
                mtud,
                generation,
            )
        }

        /** paths.rs:109 */
        internal fun fromPrevious(remote: SocketAddress, prev: PathData, generation: Long, now: Instant): PathData {
            val congestion = prev.congestion.cloneBox()
            val smoothedRtt = prev.rtt.get()
            return PathData(
                remote,
                prev.rtt.copy(),
                congestion,
                Pacer(smoothedRtt, congestion.window(), prev.currentMtu(), now),
                prev.mtud.copy(),
                generation,
            ).also {
                it.firstPacketAfterRttSampleSpace = prev.firstPacketAfterRttSampleSpace
                it.firstPacketAfterRttSamplePn = prev.firstPacketAfterRttSamplePn
            }
        }
    }
}

/**
 * RTT estimation for a particular network path (paths.rs:299). quinn's is `Copy`; use [copy]. Durations are kept
 * in nanoseconds; Rust `Duration` arithmetic on them is exact (its division floors, like `Long` division).
 */
class RttEstimator(initialRtt: Duration) {
    /** The most recent RTT measurement made when receiving an ack for a previously unacked packet. */
    private var latest: Long = initialRtt.inWholeNanoseconds

    /** The smoothed RTT of the connection, computed as described in RFC6298; -1 for none. */
    private var smoothed: Long = -1

    /** The RTT variance, computed as described in RFC6298. */
    private var variance: Long = latest / 2

    /** The minimum RTT seen in the connection, ignoring ack delay. */
    private var min: Long = latest

    /** The current best RTT estimation. */
    fun get(): Duration = getNanos().nanosDuration()

    internal fun getNanos(): Long = if (smoothed >= 0) smoothed else latest

    /**
     * Conservative estimate of RTT: the maximum of smoothed and latest RTT, as recommended in 6.1.2 of the
     * recovery spec (draft 29).
     */
    fun conservative(): Duration = maxOf(getNanos(), latest).nanosDuration()

    /** Minimum RTT registered so far for this estimator. */
    fun min(): Duration = min.nanosDuration()

    internal fun minNanos(): Long = min

    /** The latest sample. */
    internal fun latest(): Duration = latest.nanosDuration()

    /** The RTT variance. */
    internal fun variance(): Duration = variance.nanosDuration()

    /** PTO computed as described in RFC9002#6.2.1. */
    internal fun ptoBase(): Duration = (getNanos() + maxOf(4 * variance, TIMER_GRANULARITY.inWholeNanoseconds)).nanosDuration()

    internal fun update(ackDelay: Duration, rtt: Duration) {
        val ackDelayNanos = ackDelay.inWholeNanoseconds
        latest = rtt.inWholeNanoseconds
        // min_rtt ignores ack delay.
        min = minOf(min, latest)
        // Based on RFC6298.
        if (smoothed >= 0) {
            val smoothed = smoothed
            val adjustedRtt = if (min + ackDelayNanos <= latest) latest - ackDelayNanos else latest
            val varSample = if (smoothed > adjustedRtt) smoothed - adjustedRtt else adjustedRtt - smoothed
            variance = (3 * variance + varSample) / 4
            this.smoothed = (7 * smoothed + adjustedRtt) / 8
        } else {
            smoothed = latest
            variance = latest / 2
            min = latest
        }
    }

    /** quinn's `Copy`. */
    fun copy(): RttEstimator = RttEstimator(Duration.ZERO).also {
        it.latest = latest; it.smoothed = smoothed; it.variance = variance; it.min = min
    }

    override fun toString(): String = "RttEstimator(latest=${latest()}, smoothed=${if (smoothed >= 0) smoothed.nanosDuration() else null}, var=${variance()}, min=${min()})"
}

/**
 * PATH_CHALLENGE tokens awaiting a PATH_RESPONSE (paths.rs:358). ⚖️ quinn's `Vec<PathResponse>` is three parallel
 * arrays of at most 16 entries (packet number, token, remote), so queuing a response allocates nothing.
 */
internal class PathResponses {
    private val packets = LongArray(MAX_PATH_RESPONSES)
    private val tokens = LongArray(MAX_PATH_RESPONSES)
    private val remotes = arrayOfNulls<SocketAddress>(MAX_PATH_RESPONSES)
    private var len = 0

    fun push(packet: Long, token: Long, remote: SocketAddress) {
        for (i in 0 until len) {
            if (remotes[i] == remote) {
                // Update a queued response
                if (packets[i] <= packet) {
                    packets[i] = packet
                    tokens[i] = token
                    remotes[i] = remote
                }
                return
            }
        }
        if (len < MAX_PATH_RESPONSES) {
            packets[len] = packet
            tokens[len] = token
            remotes[len] = remote
            len++
        }
        // else: we don't expect to ever hit this with well-behaved peers, so we don't bother dropping older
        // challenges (quinn traces "ignoring excessive PATH_CHALLENGE").
    }

    /**
     * The last queued response if it is for a remote other than [remote], removing it (quinn `pop_off_path`,
     * returning `(token, remote)`; off-path responses are rare, so the result is a small object).
     */
    fun popOffPath(remote: SocketAddress): OffPathResponse? {
        if (len == 0) return null
        val i = len - 1
        val r = remotes[i]!!
        if (r == remote) {
            // We don't bother searching further because we expect that the on-path response will get drained in
            // the immediate future by a call to `pop_on_path`.
            return null
        }
        remotes[i] = null
        len--
        return OffPathResponse(tokens[i], r)
    }

    /** The token of the last queued response if it is for [remote], removing it (quinn `pop_on_path`). */
    fun popOnPath(remote: SocketAddress): Long? {
        if (len == 0) return null
        val i = len - 1
        if (remotes[i] != remote) {
            // We don't bother searching further because we expect that the off-path response will get drained in
            // the immediate future by a call to `pop_off_path`.
            return null
        }
        remotes[i] = null
        len--
        return tokens[i]
    }

    fun isEmpty(): Boolean = len == 0

    private companion object {
        /** Arbitrary permissive limit to prevent abuse. */
        const val MAX_PATH_RESPONSES = 16
    }
}

/** A PATH_RESPONSE to send to a remote other than the current path's (quinn `(u64, SocketAddr)`). */
internal data class OffPathResponse(val token: Long, val remote: SocketAddress)

/**
 * Summary statistics of packets that have been sent on a particular path, but which have not yet been acked or
 * deemed lost (paths.rs:448).
 */
internal class InFlight {
    /**
     * Sum of the sizes of all sent packets considered "in flight" by congestion control.
     *
     * The size does not include IP or UDP overhead. Packets only containing ACK frames do not count towards this to
     * ensure congestion control does not impede congestion feedback.
     */
    var bytes: Long = 0

    /**
     * Number of packets in flight containing frames other than ACK and PADDING.
     *
     * This can be 0 even when bytes is not 0 because PADDING frames cause a packet to be considered "in flight" by
     * congestion control. However, if this is nonzero, bytes will always also be nonzero.
     */
    var ackEliciting: Long = 0

    fun insert(packet: SentPacket) {
        bytes += packet.size
        if (packet.ackEliciting) ackEliciting += 1
    }

    /** Update counters to account for a packet becoming acknowledged, lost, or abandoned. */
    fun remove(packet: SentPacket) {
        bytes -= packet.size
        if (packet.ackEliciting) ackEliciting -= 1
    }
}
