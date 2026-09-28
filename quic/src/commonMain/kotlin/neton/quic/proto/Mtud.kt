package neton.quic.proto

// Datagram Packetization Layer Path MTU Discovery (quinn-proto `connection/mtud.rs`).
//
// ⚖️ MTUs are `Int` (quinn `u16`). quinn's `Option<u16>` probe sizes and `Option<u64>` probe packet numbers are
// `Int` / `Long` with -1 for `None`: `pollTransmit` runs for every packet the connection builds.

/**
 * Implements Datagram Packetization Layer Path Maximum Transmission Unit Discovery (mtud.rs:9).
 *
 * See [MtuDiscoveryConfig] for details.
 */
internal class MtuDiscovery private constructor(
    /** Detected MTU for the path. */
    private var currentMtu: Int,
    /** The state of the MTU discovery, if enabled. */
    internal var state: EnabledMtuDiscovery?,
    /** The state of the black hole detector. */
    internal var blackHoleDetector: BlackHoleDetector,
) {
    internal fun reset(currentMtu: Int, minMtu: Int) {
        this.currentMtu = currentMtu
        val state = this.state
        if (state != null) {
            this.state = EnabledMtuDiscovery(state.config)
            onPeerMaxUdpPayloadSizeReceived(state.peerMaxUdpPayloadSize)
        }
        blackHoleDetector = BlackHoleDetector(minMtu)
    }

    /** Returns the current MTU. */
    fun currentMtu(): Int = currentMtu

    /** Returns the amount of bytes that should be sent as an MTU probe, if any; -1 for none. */
    fun pollTransmit(now: Instant, nextPn: Long): Int = state?.pollTransmit(now, currentMtu, nextPn) ?: -1

    /** Notifies the [MtuDiscovery] that the peer's `max_udp_payload_size` transport parameter has been received. */
    fun onPeerMaxUdpPayloadSizeReceived(peerMaxUdpPayloadSize: Int) {
        currentMtu = minOf(currentMtu, peerMaxUdpPayloadSize)

        val state = state ?: return
        // It is possible for black hole detection to trigger before the connection has been fully established, if
        // the initial MTU is greater the minimum MTU. We should never send probes before the connection has been
        // fully established and we have received the peer's transport parameters though.
        debugAssert(state.phase != MtudPhase.Searching) { "Transport parameters received after MTU probing started" }
        state.peerMaxUdpPayloadSize = peerMaxUdpPayloadSize
    }

    /**
     * Notifies the [MtuDiscovery] that a packet has been ACKed.
     *
     * Returns true if the packet was an MTU probe.
     */
    fun onAcked(space: SpaceId, pn: Long, len: Int): Boolean {
        // MTU probes are only sent in application data space
        if (space != SpaceId.Data) return false

        // Update the state of the MTU search
        val newMtu = state?.onProbeAcked(pn) ?: -1
        return if (newMtu >= 0) {
            currentMtu = newMtu
            blackHoleDetector.onProbeAcked(pn, len)
            true
        } else {
            blackHoleDetector.onNonProbeAcked(pn, len)
            false
        }
    }

    /** Returns the packet number of the in-flight MTU probe, if any; -1 for none. */
    fun inFlightMtuProbe(): Long {
        val state = state ?: return -1
        return if (state.phase == MtudPhase.Searching) state.search.inFlightProbe else -1
    }

    /** Notifies the [MtuDiscovery] that the in-flight MTU probe was lost. */
    fun onProbeLost() {
        state?.onProbeLost()
    }

    /**
     * Notifies the [MtuDiscovery] that a non-probe packet was lost.
     *
     * When done notifying of lost packets, [blackHoleDetected] must be called, to ensure the last loss burst is
     * properly processed and to trigger black hole recovery logic if necessary.
     */
    fun onNonProbeLost(pn: Long, len: Int) = blackHoleDetector.onNonProbeLost(pn, len)

    /**
     * Returns true if a black hole was detected.
     *
     * Calling this function will close the previous loss burst. If a black hole is detected, the current MTU will be
     * reset to `min_mtu`.
     */
    fun blackHoleDetected(now: Instant): Boolean {
        if (!blackHoleDetector.blackHoleDetected()) return false

        currentMtu = blackHoleDetector.minMtu

        state?.onBlackHoleDetected(now)

        return true
    }

    /** quinn's `Clone`. */
    fun copy(): MtuDiscovery = MtuDiscovery(currentMtu, state?.copy(), blackHoleDetector.copy())

    companion object {
        fun new(initialPlpmtu: Int, minMtu: Int, peerMaxUdpPayloadSize: Int?, config: MtuDiscoveryConfig): MtuDiscovery {
            debugAssert(initialPlpmtu >= minMtu) { "initial_max_udp_payload_size must be at least $minMtu" }

            val mtud = MtuDiscovery(initialPlpmtu, EnabledMtuDiscovery(config.copy()), BlackHoleDetector(minMtu))

            // We might be migrating an existing connection to a new path, in which case the transport parameters
            // have already been transmitted, and we already know the value of `peer_max_udp_payload_size`.
            if (peerMaxUdpPayloadSize != null) mtud.onPeerMaxUdpPayloadSizeReceived(peerMaxUdpPayloadSize)

            return mtud
        }

        /** MTU discovery will be disabled and the current MTU will be fixed to the provided value. */
        fun disabled(plpmtu: Int, minMtu: Int): MtuDiscovery = MtuDiscovery(plpmtu, null, BlackHoleDetector(minMtu))
    }
}

/** mtud.rs:275: `Complete` carries [EnabledMtuDiscovery.nextActivation], `Searching` [EnabledMtuDiscovery.search]. */
internal enum class MtudPhase {
    /** We haven't started polling yet. */
    Initial,

    /** We are currently searching for a higher PMTU. */
    Searching,

    /** Searching has completed and will be triggered again at the provided instant. */
    Complete,
}

/**
 * Additional state for enabled MTU discovery (mtud.rs:172). ⚖️ quinn's `Phase` enum with data is [phase] plus the
 * fields of the active variant; the [SearchState] is reused across searches.
 */
internal class EnabledMtuDiscovery(internal val config: MtuDiscoveryConfig) {
    var phase: MtudPhase = MtudPhase.Initial
    var peerMaxUdpPayloadSize: Int = MAX_UDP_PAYLOAD
    val search = SearchState()

    /** The instant of `MtudPhase::Complete`. */
    var nextActivation: Instant = Instant.NONE

    /** Returns the amount of bytes that should be sent as an MTU probe, if any; -1 for none. */
    fun pollTransmit(now: Instant, currentMtu: Int, nextPn: Long): Int {
        if (phase == MtudPhase.Initial) {
            // Start the first search
            phase = MtudPhase.Searching
            search.init(currentMtu, peerMaxUdpPayloadSize, config)
        } else if (phase == MtudPhase.Complete) {
            if (now < nextActivation) return -1

            // Start a new search (we have reached the next activation time)
            phase = MtudPhase.Searching
            search.init(currentMtu, peerMaxUdpPayloadSize, config)
        }

        if (phase == MtudPhase.Searching) {
            val state = search
            // Nothing to do while there is a probe in flight
            if (state.inFlightProbe >= 0) return -1

            // Retransmit lost probes, if any
            if (0 < state.lostProbeCount && state.lostProbeCount < MAX_PROBE_RETRANSMITS) {
                state.inFlightProbe = nextPn
                return state.lastProbedMtu
            }

            val lastProbeSucceeded = state.lostProbeCount == 0

            // The probe is definitely lost (we reached the MAX_PROBE_RETRANSMITS threshold)
            if (!lastProbeSucceeded) {
                state.lostProbeCount = 0
                state.inFlightProbe = -1
            }

            val probeUdpPayloadSize = state.nextMtuToProbe(lastProbeSucceeded)
            if (probeUdpPayloadSize >= 0) {
                state.inFlightProbe = nextPn
                state.lastProbedMtu = probeUdpPayloadSize
                return probeUdpPayloadSize
            } else {
                nextActivation = now + config.interval
                phase = MtudPhase.Complete
                return -1
            }
        }

        return -1
    }

    /**
     * Called when a packet is acknowledged in [SpaceId.Data].
     *
     * Returns the new `current_mtu` if the packet number corresponds to the in-flight MTU probe; -1 otherwise.
     */
    fun onProbeAcked(pn: Long): Int {
        if (phase == MtudPhase.Searching && search.inFlightProbe >= 0 && search.inFlightProbe == pn) {
            search.inFlightProbe = -1
            search.lostProbeCount = 0
            return search.lastProbedMtu
        }
        return -1
    }

    /** Called when the in-flight MTU probe was lost. */
    fun onProbeLost() {
        // We might no longer be searching, e.g. if a black hole was detected
        if (phase == MtudPhase.Searching) {
            search.inFlightProbe = -1
            search.lostProbeCount += 1
        }
    }

    /** Called when a black hole is detected. */
    fun onBlackHoleDetected(now: Instant) {
        // Stop searching, if applicable, and reset the timer
        nextActivation = now + config.blackHoleCooldown
        phase = MtudPhase.Complete
    }

    fun copy(): EnabledMtuDiscovery = EnabledMtuDiscovery(config).also {
        it.phase = phase
        it.peerMaxUdpPayloadSize = peerMaxUdpPayloadSize
        it.search.copyFrom(search)
        it.nextActivation = nextActivation
    }
}

/** mtud.rs:285 */
internal class SearchState() {
    /** The lower bound for the current binary search. */
    var lowerBound: Int = 0

    /** The upper bound for the current binary search. */
    var upperBound: Int = 0

    /** The minimum change to stop the current binary search. */
    var minimumChange: Int = 0

    /** The UDP payload size we last sent a probe for. */
    var lastProbedMtu: Int = 0

    /** Packet number of an in-flight probe (if any); -1 for none. */
    var inFlightProbe: Long = -1

    /** Lost probes at the current probe size. */
    var lostProbeCount: Int = 0

    /**
     * Creates a new search state, with the specified lower bound (the upper bound is derived from the config and the
     * peer's `max_udp_payload_size` transport parameter).
     */
    constructor(lowerBound: Int, peerMaxUdpPayloadSize: Int, config: MtuDiscoveryConfig) : this() {
        init(lowerBound, peerMaxUdpPayloadSize, config)
    }

    /** quinn `SearchState::new`, in place. */
    fun init(lowerBound: Int, peerMaxUdpPayloadSize: Int, config: MtuDiscoveryConfig) {
        val lower = minOf(lowerBound, peerMaxUdpPayloadSize)
        // Rust `Ord::clamp` (panics if min > max; `lower` is at most `peerMaxUdpPayloadSize` here).
        val upper = config.upperBound.coerceIn(lower, peerMaxUdpPayloadSize)

        inFlightProbe = -1
        lostProbeCount = 0
        this.lowerBound = lower
        upperBound = upper
        minimumChange = config.minimumChange
        // During initialization, we consider the lower bound to have already been successfully probed
        lastProbedMtu = lower
    }

    /** Determines the next MTU to probe using binary search; -1 when the search is over. */
    fun nextMtuToProbe(lastProbeSucceeded: Boolean): Int {
        debugAssert(inFlightProbe < 0) { "assertion `left == right` failed: in-flight probe" }

        if (lastProbeSucceeded) {
            lowerBound = lastProbedMtu
        } else {
            upperBound = lastProbedMtu - 1
        }

        val nextMtu = (lowerBound + upperBound) / 2

        // Binary search stopping condition
        if (kotlin.math.abs(nextMtu - lastProbedMtu) < minimumChange) {
            // Special case: if the upper bound is far enough, we want to probe it as a last step (otherwise we will
            // never achieve the upper bound)
            if (maxOf(upperBound - lastProbedMtu, 0) >= minimumChange) return upperBound

            return -1
        }

        return nextMtu
    }

    fun copyFrom(o: SearchState) {
        lowerBound = o.lowerBound; upperBound = o.upperBound; minimumChange = o.minimumChange
        lastProbedMtu = o.lastProbedMtu; inFlightProbe = o.inFlightProbe; lostProbeCount = o.lostProbeCount
    }
}

/**
 * Judges whether packet loss might indicate a drop in MTU (mtud.rs:367).
 *
 * Our MTU black hole detection scheme is a heuristic based on the order in which packets were sent (the packet
 * number order), their sizes, and which are deemed lost.
 *
 * First, contiguous groups of lost packets ("loss bursts") are aggregated, because a group of packets all lost
 * together were probably lost for the same reason.
 *
 * A loss burst is deemed "suspicious" if it contains no packets that are (a) smaller than the minimum MTU or (b)
 * smaller than a more recent acknowledged packet, because such a burst could be fully explained by a reduction in
 * MTU.
 *
 * When the number of suspicious loss bursts exceeds [BLACK_HOLE_THRESHOLD], we judge the evidence for an MTU black
 * hole to be sufficient.
 *
 * ⚖️ quinn's `Vec<LossBurst>` (capacity `BLACK_HOLE_THRESHOLD + 1`, never exceeded) is a fixed [IntArray] of the
 * bursts' smallest packet sizes; `Option<CurrentLossBurst>` is two fields and a flag.
 */
internal class BlackHoleDetector(
    /** The UDP payload size guaranteed to be supported by the network. */
    val minMtu: Int,
) {
    /** Packet loss bursts currently considered suspicious: their smallest packet sizes. */
    private val suspiciousLossBursts = IntArray(BLACK_HOLE_THRESHOLD + 1)
    private var suspiciousCount = 0

    /** Loss burst currently being aggregated, if any. */
    private var hasCurrentLossBurst = false
    private var currentSmallestPacketSize = 0
    private var currentLatestNonProbe = 0L

    /**
     * Packet number of the biggest packet larger than `min_mtu` which we've received acknowledgment of more recently
     * than any suspicious loss burst, if any.
     */
    private var largestPostLossPacket: Long = 0

    /**
     * The maximum of `min_mtu` and the size of `largest_post_loss_packet`, or exactly `min_mtu` if no larger packets
     * have been received since the most recent loss burst.
     */
    private var ackedMtu: Int = minMtu

    fun onProbeAcked(pn: Long, len: Int) {
        // MTU probes are always larger than the previous MTU, so no previous loss bursts are suspicious. At most one
        // MTU probe is in flight at a time, so we don't need to worry about reordering between them.
        suspiciousCount = 0
        ackedMtu = len
        // This might go backwards, but that's okay: a successful ACK means we haven't yet judged a more recently
        // sent packet lost, and we just want to track the largest packet that's been successfully delivered more
        // recently than a loss.
        largestPostLossPacket = pn
    }

    fun onNonProbeAcked(pn: Long, len: Int) {
        if (len < ackedMtu) {
            // We've already seen a larger packet since the most recent suspicious loss burst; nothing to do.
            return
        }
        if (len == ackedMtu) {
            // Another delivery of the largest size seen since the most recent suspicious loss burst. It doesn't raise
            // `acked_mtu`, but loss bursts that precede it cannot be explained by an MTU reduction either, so
            // remember it as the newest such delivery.
            largestPostLossPacket = maxOf(largestPostLossPacket, pn)
            return
        }
        ackedMtu = len
        // This might go backwards, but that's okay as described in `on_probe_acked`.
        largestPostLossPacket = pn
        // Loss bursts packets smaller than this are retroactively deemed non-suspicious.
        var w = 0
        for (r in 0 until suspiciousCount) {
            val s = suspiciousLossBursts[r]
            if (s > len) suspiciousLossBursts[w++] = s
        }
        suspiciousCount = w
    }

    fun onNonProbeLost(pn: Long, len: Int) {
        // A loss burst is a group of consecutive packets that are declared lost, so a distance greater than 1
        // indicates a new burst
        val endLastBurst = hasCurrentLossBurst && pn - currentLatestNonProbe != 1L

        if (endLastBurst) finishLossBurst()

        currentSmallestPacketSize = if (hasCurrentLossBurst) minOf(currentSmallestPacketSize, len) else len
        currentLatestNonProbe = pn
        hasCurrentLossBurst = true
    }

    fun blackHoleDetected(): Boolean {
        finishLossBurst()

        if (suspiciousCount <= BLACK_HOLE_THRESHOLD) return false

        suspiciousCount = 0

        return true
    }

    /** Marks the end of the current loss burst, checking whether it was suspicious. */
    private fun finishLossBurst() {
        if (!hasCurrentLossBurst) return
        hasCurrentLossBurst = false
        val smallestPacketSize = currentSmallestPacketSize
        val latestNonProbe = currentLatestNonProbe
        // If a loss burst contains a packet smaller than the minimum MTU or a more recently transmitted packet, it is
        // not suspicious.
        if (smallestPacketSize <= minMtu ||
            (latestNonProbe < largestPostLossPacket && smallestPacketSize <= ackedMtu)
        ) {
            return
        }
        // The loss burst is now deemed suspicious.

        // A suspicious loss burst more recent than `largest_post_loss_packet` invalidates it. This makes `acked_mtu`
        // a conservative approximation. Ideally we'd update `safe_mtu` and `largest_post_loss_packet` to describe the
        // largest acknowledged packet sent later than this burst, but that would require tracking the size of an
        // unpredictable number of recently acknowledged packets, and erring on the side of false positives is safe.
        if (latestNonProbe > largestPostLossPacket) ackedMtu = minMtu

        if (suspiciousCount <= BLACK_HOLE_THRESHOLD) {
            suspiciousLossBursts[suspiciousCount++] = smallestPacketSize
            return
        }

        // To limit memory use, only track the most suspicious loss bursts: replace the first smallest one, if it is
        // smaller than this burst.
        var smallest = 0
        for (i in 1 until suspiciousCount) {
            if (suspiciousLossBursts[i] < suspiciousLossBursts[smallest]) smallest = i
        }
        if (suspiciousLossBursts[smallest] < smallestPacketSize) suspiciousLossBursts[smallest] = smallestPacketSize
    }

    internal fun suspiciousLossBurstCount(): Int = suspiciousCount

    /** The latest packet of the current loss burst, or -1 when there is none (quinn `Option<u64>`). */
    internal fun largestNonProbeLost(): Long = if (hasCurrentLossBurst) currentLatestNonProbe else -1

    fun copy(): BlackHoleDetector = BlackHoleDetector(minMtu).also {
        suspiciousLossBursts.copyInto(it.suspiciousLossBursts)
        it.suspiciousCount = suspiciousCount
        it.hasCurrentLossBurst = hasCurrentLossBurst
        it.currentSmallestPacketSize = currentSmallestPacketSize
        it.currentLatestNonProbe = currentLatestNonProbe
        it.largestPostLossPacket = largestPostLossPacket
        it.ackedMtu = ackedMtu
    }
}

/** Corresponds to the RFC's `MAX_PROBES` constant (see https://www.rfc-editor.org/rfc/rfc8899#section-5.1.2). */
internal const val MAX_PROBE_RETRANSMITS: Int = 3

/** Maximum number of suspicious loss bursts that will not trigger black hole detection. */
internal const val BLACK_HOLE_THRESHOLD: Int = 3
