package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import neton.io.net.EcnCodepoint
import neton.io.net.SocketAddress
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.Duration.Companion.milliseconds

// Protocol state and logic for a single QUIC connection (quinn-proto `connection/mod.rs`).
//
// ⚖️ Deviations from quinn, beyond the representation choices of the components (SPEC §11):
// - Errors: protocol violations are thrown as [TransportError] (quinn's `?`); [ConnectionError] is also an exception
//   so that [AcceptError] can carry it.
// - Allocation: the per-packet records quinn builds on the stack (`SentFrames`, `SentPacket`, the `PacketBuilder`, the
//   newly-acked range set, the lost-packet list) are fields reused across packets; `Option<Instant>` / `Option<u64>`
//   are [Instant.NONE] / -1 on the per-packet paths.
// - Random numbers: quinn's `StdRng` (ChaCha12) seeded from 32 bytes is a `kotlin.random.Random` seeded from a Long
//   the endpoint draws: equally deterministic for a given endpoint seed, but a different stream.
// - [StreamEvent] is a subtype of [Event] instead of being wrapped in `Event::Stream`, saving an object per event.
// - qlog (`config.qlog_sink`) is not ported (SPEC §8).

/**
 * Protocol state and logic for a single QUIC connection (mod.rs:133).
 *
 * Objects of this type receive [ConnectionEvent]s and emit [EndpointEvent]s and application [Event]s to make
 * progress. To handle timeouts, a connection returns timer updates and expects timeouts through various methods.
 *
 * A connection has roughly four kinds of methods: simple getters; handlers for incoming events from the network or
 * system, named `handle*`; state machine mutators for commands from the application (stream reads and writes, but
 * also things like [SendStream.reset]); and polling functions for outgoing events or actions, named `poll*`.
 *
 * The simplest way to use this API correctly is to call the handlers and mutators whenever appropriate, then after
 * each of those calls, as soon as feasible, call the polling methods in this order: [pollTransmit], [pollTimeout],
 * [pollEndpointEvents], [poll]. Input events must represent monotonically increasing time: [handleTimeout] with
 * events of the same [Instant] may be interleaved in any order with [handleEvent] at that same instant, but events or
 * timeouts with different instants must not be interleaved.
 *
 * A connection is driven by one thread at a time (its packet keys keep scratch buffers).
 */
class Connection internal constructor(
    private val endpointConfig: EndpointConfig,
    internal val config: TransportConfig,
    initCid: ConnectionId,
    locCid: ConnectionId,
    remCid: ConnectionId,
    remote: SocketAddress,
    /**
     * The "real" local IP address which was used to receive the initial packet. Only populated for the server case,
     * and if known.
     */
    private val localIp: SocketAddress?,
    private val crypto: CryptoSession,
    cidGen: ConnectionIdGenerator,
    now: Instant,
    /** QUIC version used for the connection. */
    internal val version: Int,
    /** Whether MTU detection is supported in this environment. */
    private val allowMtud: Boolean,
    rngSeed: Long,
    sideArgs: SideArgs,
) {
    internal val rng: Random = Random(rngSeed)

    /** The CID we initially chose, for use during the handshake. */
    internal val handshakeCid: ConnectionId = locCid

    /** The CID the peer initially chose, for use during the handshake. */
    private var remHandshakeCid: ConnectionId = remCid

    internal var path: PathData = PathData.new(remote, allowMtud, null, 0, now, config)
        private set

    /** Incremented every time we see a new path; stored separately from `path.generation` for aborted migrations. */
    private var pathCounter = 0L

    /** The previous path while the new one is validated, and the remote CID we were using on it. */
    private var prevPathCid: ConnectionId? = null
    private var prevPath: PathData? = null

    private var state: State
    private val side: ConnectionSide = when (sideArgs) {
        is SideArgs.Client -> ConnectionSide.Client(sideArgs.tokenStore.take(sideArgs.serverName) ?: Bytes.EMPTY, sideArgs.tokenStore, sideArgs.serverName)
        is SideArgs.Server -> ConnectionSide.Server(sideArgs.serverConfig)
    }

    /** Whether or not 0-RTT was enabled during the handshake. Does not imply acceptance. */
    private var zeroRttEnabled = false

    /** Set if 0-RTT is supported, then cleared when no longer needed. */
    internal var zeroRttCrypto: ZeroRttCrypto? = null
        private set
    internal var keyPhase = false
        private set

    /** How many packets are in the current key phase. Used only for the Data space. */
    internal var keyPhaseSize: Long
        private set

    /** Transport parameters set by the peer. */
    internal var peerParams: TransportParameters = TransportParameters.default()
        private set

    /** Source connection ID of the first packet received from the peer. */
    private var origRemCid: ConnectionId = remCid

    /** Destination connection ID sent by the client on the first Initial. */
    private val initialDstCid: ConnectionId = initCid

    /** The value that the server included in the Source Connection ID field of a Retry packet, if one was received. */
    private var retrySrcCid: ConnectionId? = null
    private val events = ArrayDeque<Event>()
    private val endpointEvents = ArrayDeque<EndpointEvent>()

    /** Whether the spin bit is in use for this connection. */
    internal val spinEnabled: Boolean

    /** Outgoing spin bit state. */
    internal var spin = false
        private set

    /** Packet number spaces: initial, handshake, 1-RTT. */
    internal val spaces: Array<PacketSpace> = arrayOf(PacketSpace(now), PacketSpace(now), PacketSpace(now))

    /** Highest usable packet number space. */
    private var highestSpace = SpaceId.Initial

    /** 1-RTT keys used prior to a key update. */
    private var prevCrypto: PrevCrypto? = null

    /**
     * 1-RTT keys to be used for the next key update. These are generated in advance to prevent timing attacks and/or
     * DoS by third-party attackers spoofing key updates.
     */
    private var nextCrypto: KeyPair<PacketKey>? = null
    private var accepted0rtt = false

    /** Whether the idle timer should be reset the next time an ack-eliciting packet is transmitted. */
    internal var permitIdleReset = true

    /** Negotiated idle timeout. */
    private var idleTimeout: Duration?

    /**
     * The time we send the next bundled ACK ([Instant.NONE] for none). The goal is to wait long enough for the peer to
     * acknowledge our previous bundled ACK (see [nextBundledAckDelay]).
     */
    private var nextBundledAckTime = Instant.NONE
    private val timers = TimerTable()

    /** Number of packets received which could not be authenticated. */
    private var authenticationFailures = 0L

    /** Why the connection was lost, if it has been. */
    private var error: ConnectionError? = null

    /** Identifies Data-space packet numbers to skip. Not used in earlier spaces. */
    internal val packetNumberFilter: PacketNumberFilter

    // Queued non-retransmittable 1-RTT data

    /** Responses to PATH_CHALLENGE frames. */
    private val pathResponses = PathResponses()
    private var close = false

    // ACK frequency
    private val ackFrequency = AckFrequencyState(getMaxAckDelay(TransportParameters.default()))

    // Loss detection

    /** The number of times a PTO has been sent without receiving an ack. */
    private var ptoCount = 0

    // Congestion control

    /** Whether the most recently received packet had an ECN codepoint set. */
    private var receivingEcn = false

    /** Number of packets authenticated. */
    private var totalAuthedPackets = 0L

    /** Whether the last [pollTransmit] call yielded no data because there was no outgoing application data. */
    private var appLimited = false

    internal val streams = StreamsState(
        side.side,
        config.maxConcurrentUniStreams,
        config.maxConcurrentBidiStreams,
        config.sendWindow,
        config.receiveWindow,
        config.streamReceiveWindow,
    )

    /** Surplus remote CIDs for future use on new paths. */
    private val remCids = CidQueue(remCid)

    // Attributes of CIDs generated by local peer
    private val localCidState: CidState

    /** State of the unreliable datagram extension. */
    internal val datagrams = DatagramState()

    /** Connection level statistics. */
    internal val stats = ConnectionStats()

    // Reused per-packet records (quinn builds these on the stack)
    private val builder = PacketBuilder()
    private val sentFrames = SentFrames()
    private val closeAckFrames = SentFrames()
    internal val sentPacketScratch = SentPacket()
    private val drainScratch = SentPacket()
    private val newlyAcked = ArrayRangeSet()
    private val lostPackets = LongList(16)
    private val decryptResult = DecryptPacketResult()
    private val cryptoScratch = Buffer(256)
    private val cidParser = FixedLengthConnectionIdParser(cidGen.cidLen)
    private val ownVersion = intArrayOf(version)
    private var ptoTime = Instant.NONE
    private var ptoSpace = SpaceId.Initial

    init {
        val prefAddrCid = (sideArgs as? SideArgs.Server)?.prefAddrCid
        val pathValidated = when (sideArgs) {
            is SideArgs.Client -> true
            is SideArgs.Server -> sideArgs.pathValidated
        }
        spaces[SpaceId.Initial].crypto = crypto.initialKeys(initCid, side.side)
        state = State.Handshake(remCidSet = side.isServer, expectedToken = Bytes.EMPTY, clientHello = null)
        localCidState = CidState(cidGen.cidLen, cidGen.cidLifetime, now, if (prefAddrCid != null) 2 else 1)
        // A small initial key phase size ensures peers that don't handle key updates correctly fail sooner rather
        // than later. It's okay for both peers to do this, as the first one to perform an update will reset the
        // other's key phase size in `update_keys`, and a simultaneous key update by both is just like a regular key
        // update with a really fast response. Inspired by quic-go's similar behavior of performing the first key
        // update at the 100th short-header packet.
        keyPhaseSize = rng.nextLong(10, 1000)
        spinEnabled = config.allowSpin && rng.nextInt(8) < 7
        idleTimeout = config.maxIdleTimeout?.let { if (it.value == 0L) null else it.value.milliseconds }
        packetNumberFilter = if (config.deterministicPacketNumbers) PacketNumberFilter.disabled() else PacketNumberFilter.new(rng)
        if (pathValidated) onPathValidated()
        if (side.isClient) {
            // Kick off the connection
            writeCrypto()
            init0rtt()
        }
    }

    /**
     * The next time at which [handleTimeout] should be called, or [Instant.NONE] (⚖️ quinn `None`). The value may
     * change after the application performed some I/O on the connection, a call to [handleEvent], a call to
     * [pollTransmit] that returned a transmit, or a call to [handleTimeout].
     */
    fun pollTimeout(): Instant = timers.nextTimeout()

    /** Application-facing events; poll after [handleEvent] or [handleTimeout] (mod.rs:396). */
    fun poll(): Event? {
        events.removeFirstOrNull()?.let { return it }
        streams.poll()?.let { return it }
        val err = error ?: return null
        error = null
        return Event.ConnectionLost(err)
    }

    /** Endpoint-facing events (mod.rs:414). */
    fun pollEndpointEvents(): EndpointEvent? = endpointEvents.removeFirstOrNull()

    /** Control over streams. */
    fun streams(): Streams = Streams(streams, state.isClosed)

    /** Control over the receive half of stream [id]. */
    fun recvStream(id: StreamId): RecvStream {
        require(id.dir == Dir.Bi || id.initiator != side.side) { "not a receive stream" }
        return RecvStream(id, streams, spaces[SpaceId.Data].pending)
    }

    /** Control over the send half of stream [id]. */
    fun sendStream(id: StreamId): SendStream {
        require(id.dir == Dir.Bi || id.initiator == side.side) { "not a send stream" }
        return SendStream(id, streams, spaces[SpaceId.Data].pending, state.isClosed)
    }

    /**
     * Packets to transmit (mod.rs:460): writes up to [maxDatagrams] datagrams (a segmentation offload batch) into
     * [buf], which must have nothing readable. Poll after the application performed some I/O, after [handleEvent]
     * and after [handleTimeout]. [maxDatagrams] must be at least 1.
     */
    fun pollTransmit(now: Instant, maxDatagrams: Int, buf: Buffer): Transmit? {
        require(maxDatagrams != 0) { "max_datagrams must be at least 1" }
        require(buf.isEmpty) { "the transmit buffer must be empty" }
        @Suppress("NAME_SHADOWING")
        val maxDatagrams = if (config.enableSegmentationOffload) maxDatagrams else 1

        var numDatagrams = 0
        // Position in `buf` of the first byte of the current UDP datagram. When coalescing QUIC packets, this can be
        // earlier than the start of the current QUIC packet.
        var datagramStart = 0
        var segmentSize = path.currentMtu()

        sendPathChallenge(now, buf)?.let { return it }

        // If we need to send a probe, make sure we have something to send.
        for (space in SPACE_IDS) {
            val requestImmediateAck = space == SpaceId.Data && peerSupportsAckFrequency()
            spaces[space].maybeQueueProbe(requestImmediateAck, streams)
        }

        // Check whether we need to send a close message
        val close = when (state) {
            State.Drained -> {
                appLimited = true
                return null
            }
            State.Draining, is State.Closed -> {
                // self.close is only reset once the associated packet had been encoded successfully
                if (!this.close) {
                    appLimited = true
                    return null
                }
                true
            }
            else -> false
        }

        // Check whether we need to send an ACK_FREQUENCY frame
        config.ackFrequencyConfig?.let { cfg ->
            spaces[SpaceId.Data].pending.ackFrequency =
                ackFrequency.shouldSendAckFrequency(path.rtt.get(), cfg, peerParams) &&
                highestSpace == SpaceId.Data && peerSupportsAckFrequency()
        }

        // Reserving capacity can provide more capacity than we asked for. However, we are not allowed to write more
        // than `segment_size`. Therefore the maximum capacity is tracked separately.
        var bufCapacity = 0

        var coalesce = true
        var sentFramesPresent = false
        var padDatagram = false
        var padDatagramToMtu = false
        var congestionBlocked = false

        // Iterate over all spaces and find data to send. This loop will potentially spend multiple iterations in the
        // same space.
        var spaceIdx = 0
        while (spaceIdx < SPACE_IDS.size) {
            val spaceId = SPACE_IDS[spaceIdx]
            // Number of bytes available for frames if this is a 1-RTT packet. We're guaranteed to be able to send an
            // individual frame at least this large in the next 1-RTT packet. This could be generalized to support
            // every space, but it's only needed to handle large fixed-size frames, which only exist in 1-RTT
            // (application datagrams). We don't account for coalesced packets potentially occupying space because
            // frames can always spill into the next datagram.
            val pn = packetNumberFilter.peek(spaces[SpaceId.Data])
            val frameSpace1rtt = maxOf(segmentSize - predict1rttOverhead(pn), 0)

            // Is there data or a close message to send in this space?
            val canSend = spaceCanSend(spaceId, frameSpace1rtt)
            if (canSend.isEmpty() && (!close || spaces[spaceId].crypto == null)) {
                spaceIdx += 1
                continue
            }

            var ackEliciting = !spaces[spaceId].pending.isEmpty(streams) ||
                spaces[spaceId].pingPending || spaces[spaceId].immediateAckPending
            if (spaceId == SpaceId.Data) ackEliciting = ackEliciting || canSend1rtt(frameSpace1rtt)

            padDatagramToMtu = padDatagramToMtu || (spaceId == SpaceId.Data && config.padToMtu)

            // Can we append more data into the current buffer? It is not safe to assume that `buf.len()` is the end
            // of the data, since the last packet might not have been finished.
            val bufEnd = if (builder.active) maxOf(buf.len, builder.minSize) + builder.tagLen else buf.len

            val tagLen = spaces[spaceId].crypto?.packet?.local?.tagLen
                ?: if (spaceId == SpaceId.Data) {
                    (zeroRttCrypto ?: error("sending packets in the application data space requires known 0-RTT or 1-RTT keys")).packet.tagLen
                } else {
                    error("tried to send $spaceId packet without keys")
                }
            if (!coalesce || bufCapacity - bufEnd < MIN_PACKET_SPACE + tagLen) {
                // We need to send 1 more datagram and extend the buffer for that.

                // Is 1 more datagram allowed?
                if (numDatagrams >= maxDatagrams) {
                    // No more datagrams allowed
                    break
                }

                // Anti-amplification is only based on `total_sent`, which gets updated at the end of this method.
                // Therefore we pass the amount of bytes for datagrams that are already created, as well as 1 byte
                // for starting another datagram. If there is any anti-amplification budget left, we always allow a
                // full MTU to be sent (see https://github.com/quinn-rs/quinn/issues/1082)
                if (path.antiAmplificationBlocked(segmentSize.toLong() * numDatagrams + 1)) {
                    // blocked by anti-amplification
                    break
                }

                // Congestion control and pacing checks. Tail loss probes must not be blocked by congestion, or a
                // deadlock could arise
                if (ackEliciting && spaces[spaceId].lossProbes == 0) {
                    // Assume the current packet will get padded to fill the segment
                    val untrackedBytes = if (builder.active) (bufCapacity - builder.headerStart).toLong() else 0L
                    debugAssert(untrackedBytes <= segmentSize) { "assertion failed: untracked_bytes <= segment_size" }

                    val bytesToSend = segmentSize + untrackedBytes
                    if (path.inFlight.bytes + bytesToSend >= path.congestion.window()) {
                        spaceIdx += 1
                        congestionBlocked = true
                        // We continue instead of breaking here in order to avoid blocking loss probes queued for
                        // higher spaces.
                        continue
                    }

                    // Check whether the next datagram is blocked by pacing
                    val smoothedRtt = path.rtt.get()
                    val delay = path.pacing.delay(smoothedRtt, bytesToSend, path.currentMtu(), path.congestion.window(), now)
                    if (delay.isSome) {
                        timers.set(Timer.Pacing, delay)
                        congestionBlocked = true
                        // Loss probes should be subject to pacing, even though they are not congestion controlled.
                        break
                    }
                }

                // Finish current packet
                if (builder.active) {
                    if (padDatagram) builder.padTo(MIN_INITIAL_SIZE)

                    if (numDatagrams > 1 || padDatagramToMtu) {
                        // If too many padding bytes would be required to continue the GSO batch after this packet,
                        // end the GSO batch here. Ensures that fixed-size frames with heterogeneous sizes (e.g.
                        // application datagrams) won't inadvertently waste large amounts of bandwidth. The exact
                        // threshold is a bit arbitrary and might benefit from further tuning, though there's no
                        // universally optimal value.
                        //
                        // Additionally, if this datagram is a loss probe and `segment_size` is larger than
                        // `INITIAL_MTU`, then padding it to `segment_size` to continue the GSO batch would risk
                        // failure to recover from a reduction in path MTU. Loss probes are the only packets for which
                        // we might grow `buf_capacity` by less than `segment_size`.
                        val packetLenUnpadded = maxOf(builder.minSize, buf.len) - datagramStart + builder.tagLen
                        if ((packetLenUnpadded + MAX_PADDING < segmentSize && !padDatagramToMtu) ||
                            datagramStart + segmentSize > bufCapacity
                        ) {
                            // GSO truncated by demand for padding bytes or loss probe; the packet stays open
                            break
                        }

                        // Pad the current datagram to GSO segment size so it can be included in the GSO batch.
                        builder.padTo(segmentSize)
                    }

                    builder.finishAndTrack(now, this, if (sentFramesPresent) sentFrames else null, buf)
                    sentFramesPresent = false

                    if (numDatagrams == 1) {
                        // Set the segment size for this GSO batch to the size of the first UDP datagram in the batch.
                        // Larger data that cannot be fragmented (e.g. application datagrams) will be included in a
                        // future batch. When sending large enough volumes of data for GSO to be useful, we expect
                        // packet sizes to usually be consistent, e.g. populated by max-size STREAM frames or
                        // uniformly sized datagrams.
                        segmentSize = buf.len
                        // Clip the unused capacity out of the buffer so future packets don't overrun
                        bufCapacity = buf.len

                        // Check whether the data we planned to send will fit in the reduced segment size. If not,
                        // bail out and leave it for the next GSO batch so we don't end up trying to send an empty
                        // packet. We can't easily compute the right segment size before the original call to
                        // `space_can_send`, because at that time we haven't determined whether we're going to
                        // coalesce with the first datagram or potentially pad it to `MIN_INITIAL_SIZE`.
                        if (spaceId == SpaceId.Data) {
                            val space1rtt = maxOf(segmentSize - predict1rttOverhead(pn), 0)
                            if (spaceCanSend(spaceId, space1rtt).isEmpty()) break
                        }
                    }
                }

                // Allocate space for another datagram
                val nextDatagramSizeLimit = if (spaces[spaceId].lossProbes == 0) {
                    segmentSize
                } else {
                    spaces[spaceId].lossProbes -= 1
                    // Clamp the datagram to at most the minimum MTU to ensure that loss probes can get through and
                    // enable recovery even if the path MTU has shrank unexpectedly.
                    minOf(segmentSize, INITIAL_MTU)
                }
                bufCapacity += nextDatagramSizeLimit
                if (buf.capacity - buf.readerIndex() < bufCapacity) {
                    // We reserve the maximum space for sending `max_datagrams` upfront to avoid any reallocations if
                    // more datagrams have to be appended later on.
                    buf.reserve(maxDatagrams * segmentSize)
                }
                numDatagrams += 1
                coalesce = true
                padDatagram = false
                datagramStart = buf.len

                debugAssert(datagramStart % segmentSize == 0) { "datagrams in a GSO batch must be aligned to the segment size" }
            } else {
                // We can append/coalesce the next packet into the current datagram. Finish current packet without
                // adding extra padding
                if (builder.active) {
                    builder.finishAndTrack(now, this, if (sentFramesPresent) sentFrames else null, buf)
                    sentFramesPresent = false
                }
            }

            debugAssert(bufCapacity - buf.len >= MIN_PACKET_SPACE) { "assertion failed: buf_capacity - buf.len() >= MIN_PACKET_SPACE" }

            //
            // From here on, we've determined that a packet will definitely be sent.
            //

            if (spaces[SpaceId.Initial].crypto != null && spaceId == SpaceId.Handshake && side.isClient) {
                // A client stops both sending and processing Initial packets when it sends its first Handshake packet.
                discardSpace(now, SpaceId.Initial)
            }
            prevCrypto?.updateUnacked = false

            if (!builder.begin(now, spaceId, remCids.active(), buf, bufCapacity, datagramStart, ackEliciting, this)) {
                return null
            }
            coalesce = coalesce && !builder.shortHeader

            // https://tools.ietf.org/html/draft-ietf-quic-transport-34#section-14.1
            padDatagram = padDatagram || (spaceId == SpaceId.Initial && (side.isClient || ackEliciting))

            if (close) {
                // Encode ACKs before the ConnectionClose message, to give the receiver a better approximate on what
                // data has been processed. This is especially important with ack delay, since the peer might not
                // have gotten any other ACK for the data earlier on.
                if (!spaces[spaceId].pendingAcks.ranges().isEmpty()) {
                    closeAckFrames.reset()
                    tryPopulateAcks(now, receivingEcn, closeAckFrames, spaces[spaceId], buf, stats, bufCapacity)
                }

                // Since there only 64 ACK frames there will always be enough space to encode the ConnectionClose
                // frame too. However we still have the check here to prevent crashes if something changes.
                debugAssert(buf.len + Frame.ConnectionClose.SIZE_BOUND < builder.maxSize) { "ACKs should leave space for ConnectionClose" }
                if (buf.len + Frame.ConnectionClose.SIZE_BOUND < builder.maxSize) {
                    val maxFrameSize = builder.maxSize - buf.len
                    when (val s = state) {
                        is State.Closed -> {
                            if (spaceId == SpaceId.Data || s.reason.isTransportLayer) {
                                s.reason.encode(buf, maxFrameSize)
                            } else {
                                Frame.ConnectionClose(TransportErrorCode.APPLICATION_ERROR, null, Bytes.EMPTY).encode(buf, maxFrameSize)
                            }
                        }
                        State.Draining -> Frame.ConnectionClose(TransportErrorCode.NO_ERROR, null, Bytes.EMPTY).encode(buf, maxFrameSize)
                        else -> error("tried to make a close packet when the connection wasn't closed")
                    }
                }
                if (spaceId == highestSpace) {
                    // Don't send another close packet
                    this.close = false
                    // `CONNECTION_CLOSE` is the final packet
                    break
                } else {
                    // Send a close frame in every possible space for robustness, per RFC9000 "Immediate Close during
                    // the Handshake". Don't bother trying to send anything else.
                    spaceIdx += 1
                    continue
                }
            }

            // Send an off-path PATH_RESPONSE. Prioritized over on-path data to ensure that path validation can occur
            // while the link is saturated.
            if (spaceId == SpaceId.Data && numDatagrams == 1) {
                val offPath = pathResponses.popOffPath(path.remote)
                if (offPath != null) {
                    FrameType.PATH_RESPONSE.encode(buf)
                    buf.writeLong(offPath.token)
                    stats.frameTx.pathResponse += 1
                    builder.padTo(MIN_INITIAL_SIZE)
                    sentFrames.reset()
                    sentFrames.nonRetransmits = true
                    builder.finishAndTrack(now, this, sentFrames, buf)
                    stats.udpTx.onSent(1, buf.len)
                    return Transmit(offPath.remote, null, buf.len, null, localIp)
                }
            }

            populatePacket(now, spaceId, buf, builder.maxSize, builder.exactNumber)
            sentFramesPresent = true

            // ACK-only packets should only be sent when explicitly allowed. If we write them due to any other reason,
            // there is a bug which leads to one component announcing write readiness while not writing any data. This
            // degrades performance. The condition is only checked if the full MTU is available and when potentially
            // large fixed-size frames aren't queued, so that lack of space in the datagram isn't the reason for just
            // writing ACKs.
            debugAssert(
                !(sentFrames.isAckOnly(streams) && !canSend.acks && canSend.other &&
                    (bufCapacity - builder.datagramStart) == path.currentMtu() && datagrams.outgoing.isEmpty()),
            ) { "SendableFrames was $canSend, but only ACKs have been written" }
            padDatagram = padDatagram || sentFrames.requiresPadding

            if (sentFrames.largestAcked >= 0) {
                spaces[spaceId].pendingAcks.acksSent()
                timers.stop(Timer.MaxAckDelay)
                nextBundledAckTime = now + nextBundledAckDelay()
            }

            // Don't increment space_idx. We stay in the current space and check if there is more data to send.
        }

        // Finish the last packet
        if (builder.active) {
            if (padDatagram) builder.padTo(MIN_INITIAL_SIZE)

            // If this datagram is a loss probe and `segment_size` is larger than `INITIAL_MTU`, then padding it to
            // `segment_size` would risk failure to recover from a reduction in path MTU. Loss probes are the only
            // packets for which we might grow `buf_capacity` by less than `segment_size`.
            if (padDatagramToMtu && bufCapacity >= datagramStart + segmentSize) builder.padTo(segmentSize)

            val lastPacketNumber = builder.exactNumber
            builder.finishAndTrack(now, this, if (sentFramesPresent) sentFrames else null, buf)
            path.congestion.onSent(now, buf.len.toLong(), lastPacketNumber)
        }

        appLimited = buf.isEmpty && !congestionBlocked

        // Send MTU probe if necessary
        if (buf.isEmpty && state.isEstablished) {
            val spaceId = SpaceId.Data
            val probeSize = path.mtud.pollTransmit(now, packetNumberFilter.peek(spaces[spaceId]))
            if (probeSize < 0) return null

            buf.reserve(probeSize)
            if (!builder.begin(now, spaceId, remCids.active(), buf, probeSize, 0, true, this)) return null

            // We implement MTU probes as ping packets padded up to the probe size
            FrameType.PING.encode(buf)
            stats.frameTx.ping += 1

            // If supported by the peer, we want no delays to the probe's ACK
            if (peerSupportsAckFrequency()) {
                FrameType.IMMEDIATE_ACK.encode(buf)
                stats.frameTx.immediateAck += 1
            }

            builder.padTo(probeSize)
            sentFrames.reset()
            sentFrames.nonRetransmits = true
            builder.finishAndTrack(now, this, sentFrames, buf)

            stats.path.sentPlpmtudProbes += 1
            numDatagrams = 1
        }

        if (buf.isEmpty) return null

        path.totalSent = saturatingAddU(path.totalSent, buf.len.toLong())

        stats.udpTx.onSent(numDatagrams.toLong(), buf.len)

        return Transmit(
            destination = path.remote,
            ecn = if (path.sendingEcn) EcnCodepoint.Ect0 else null,
            size = buf.len,
            segmentSize = if (numDatagrams == 1) null else segmentSize,
            srcIp = localIp,
        )
    }

    /** Send PATH_CHALLENGE for a previous path if necessary (mod.rs:1023). */
    private fun sendPathChallenge(now: Instant, buf: Buffer): Transmit? {
        val prevPath = prevPath ?: return null
        val prevCid = prevPathCid!!
        if (!prevPath.challengePending) return null
        prevPath.challengePending = false
        val token = prevPath.challenge ?: error("previous path challenge pending without token")
        val destination = prevPath.remote
        debugAssert(highestSpace == SpaceId.Data) { "PATH_CHALLENGE queued without 1-RTT keys" }
        buf.reserve(MIN_INITIAL_SIZE)

        val bufCapacity = buf.capacity - buf.readerIndex()

        // Use the previous CID to avoid linking the new path with the previous path. We don't bother accounting for
        // possible retirement of that prev_cid because this is sent once, immediately after migration, when the CID is
        // known to be valid. Even if a post-migration packet caused the CID to be retired, it's fair to pretend this is
        // sent first.
        if (!builder.begin(now, SpaceId.Data, prevCid, buf, bufCapacity, 0, false, this)) return null
        FrameType.PATH_CHALLENGE.encode(buf)
        buf.writeLong(token)
        stats.frameTx.pathChallenge += 1

        // An endpoint MUST expand datagrams that contain a PATH_CHALLENGE frame to at least the smallest allowed
        // maximum datagram size of 1200 bytes, unless the anti-amplification limit for the path does not permit
        // sending a datagram of this size
        builder.padTo(MIN_INITIAL_SIZE)

        builder.finish(this, now, buf)
        stats.udpTx.onSent(1, buf.len)

        return Transmit(destination, null, buf.len, null, localIp)
    }

    /** Indicate what types of frames are ready to send for the given space (mod.rs:1081). */
    private fun spaceCanSend(spaceId: SpaceId, frameSpace1rtt: Int): SendableFrames {
        if (spaces[spaceId].crypto == null &&
            (spaceId != SpaceId.Data || zeroRttCrypto == null || side.isServer)
        ) {
            // No keys available for this space
            return SendableFrames.empty()
        }
        val canSend = spaces[spaceId].canSend(streams)
        if (spaceId == SpaceId.Data && !canSend.other && canSend1rtt(frameSpace1rtt)) {
            return SendableFrames.of(canSend.acks, true)
        }
        return canSend
    }

    /**
     * The delay to wait after sending an ACK before bundling the next one (mod.rs:1112): at least `RTT + peer's
     * max_ack_delay`, since the packet carrying a bundled ACK is itself ack-eliciting and the peer should get the
     * chance to acknowledge it before we bundle another.
     */
    private fun nextBundledAckDelay(): Duration = path.rtt.get() + ackFrequency.peerMaxAckDelay + TIMER_GRANULARITY

    /**
     * Process [ConnectionEvent]s generated by the associated [Endpoint] (mod.rs:1121), in turn preparing signals
     * (application [Event]s, [EndpointEvent]s and outgoing datagrams) to extract through the polling methods.
     */
    fun handleEvent(event: ConnectionEvent) {
        when (event) {
            is ConnectionEvent.Datagram -> {
                val now = event.now
                val remote = event.remote
                val ecn = event.ecn
                val firstDecode = event.firstDecode
                // If this packet could initiate a migration and we're a client or a server that forbids migration,
                // drop the datagram. This could be relaxed to heuristically permit NAT-rebinding-like migration.
                if (remote != path.remote && !side.remoteMayMigrate()) return

                val wasAntiAmplificationBlocked = path.antiAmplificationBlocked(1)

                stats.udpRx.datagrams += 1
                stats.udpRx.bytes += firstDecode.len.toLong()
                val dataLen = firstDecode.len

                handleDecode(now, remote, ecn, firstDecode)
                // The current `path` might have changed inside `handle_decode`, since the packet could have triggered
                // a migration. Make sure the data received is accounted for the most recent path by accessing `path`
                // after `handle_decode`.
                path.totalRecvd = saturatingAddU(path.totalRecvd, dataLen.toLong())

                if (firstDecode.hasRest) {
                    stats.udpRx.bytes += (firstDecode.restEnd - firstDecode.restStart).toLong()
                    handleCoalesced(now, remote, ecn, firstDecode.data, firstDecode.restStart, firstDecode.restEnd)
                }

                if (wasAntiAmplificationBlocked) {
                    // A prior attempt to set the loss detection timer may have failed due to anti-amplification, so
                    // ensure it's set now. Prevents a handshake deadlock if the server's first flight is lost.
                    setLossDetectionTimer(now)
                }
            }
            is ConnectionEvent.NewIdentifiers -> {
                val now = event.now
                localCidState.newCids(event.ids, now)
                for (i in event.ids.indices.reversed()) spaces[SpaceId.Data].pending.newCids.add(event.ids[i])
                // Update Timer::PushNewCid
                val t = timers.get(Timer.PushNewCid)
                if (t.isNone || t <= now) resetCidRetirement()
            }
        }
    }

    /**
     * Process timer expirations (mod.rs:1193). Most efficient right after the clock reaches [pollTimeout]; spurious
     * extra calls are no-ops.
     */
    fun handleTimeout(now: Instant) {
        for (timer in TIMERS) {
            if (!timers.isExpired(timer, now)) continue
            timers.stop(timer)
            when (timer) {
                Timer.Close -> {
                    state = State.Drained
                    releaseKeys()
            endpointEvents.addLast(EndpointEvent.Drained)
                }
                Timer.Idle -> kill(ConnectionError.TimedOut)
                Timer.KeepAlive -> ping()
                Timer.LossDetection -> onLossDetectionTimeout(now)
                Timer.KeyDiscard -> {
                    zeroRttCrypto?.close()
                    zeroRttCrypto = null
                    prevCrypto?.crypto?.close()
                    prevCrypto = null
                }
                Timer.PathValidation -> {
                    // path validation failed
                    val prev = prevPath
                    if (prev != null) {
                        prevPath = null
                        prevPathCid = null
                        path = prev
                    }
                    path.challenge = null
                    path.challengePending = false
                }
                Timer.Pacing -> {} // pacing timer expired
                Timer.PushNewCid -> {
                    // Update `retire_prior_to` field in NEW_CONNECTION_ID frame
                    val numNewCid = if (localCidState.onCidTimeout()) 1L else 0L
                    if (!state.isClosed) endpointEvents.addLast(EndpointEvent.NeedIdentifiers(now, numNewCid))
                }
                Timer.MaxAckDelay -> {
                    // This timer is only armed in the Data space
                    spaces[SpaceId.Data].pendingAcks.onMaxAckDelayTimeout()
                }
            }
        }
    }

    /**
     * Close the connection immediately (mod.rs:1269). This does not ensure delivery of outstanding data: call it only
     * when all important communications have completed, e.g. after [SendStream.finish] and the corresponding
     * [StreamEvent.Finished]. If [Streams.sendStreams] returns 0, all outstanding stream data has been delivered.
     */
    fun close(now: Instant, errorCode: VarInt, reason: Bytes) {
        closeInner(now, Frame.ApplicationClose(errorCode, reason))
    }

    internal fun closeInner(now: Instant, reason: Frame.Close) {
        val wasClosed = state.isClosed
        if (!wasClosed) {
            closeCommon()
            setCloseTimer(now)
            close = true
            state = State.Closed(reason)
        }
    }

    /** Control datagrams. */
    fun datagrams(): Datagrams = Datagrams(this)

    /** Connection statistics (a snapshot). */
    fun stats(): ConnectionStats {
        val s = stats.copy()
        s.path.rtt = path.rtt.get()
        s.path.minRtt = path.rtt.min()
        s.path.cwnd = path.congestion.window()
        s.path.currentMtu = path.mtud.currentMtu()
        return s
    }

    /** Ping the remote endpoint, causing an ACK-eliciting packet to be transmitted. */
    fun ping() {
        spaces[highestSpace].pingPending = true
    }

    /**
     * Update traffic keys spontaneously (mod.rs:1312). This can be useful for testing key updates, as they otherwise
     * only happen infrequently.
     */
    fun forceKeyUpdate() {
        if (!state.isEstablished) return // ignoring forced key update in illegal state
        // We already just updated, or are currently updating, the keys. Concurrent key updates are illegal.
        if (prevCrypto != null) return
        updateKeys(-1, Instant.NONE, false)
    }

    /** The crypto session. */
    fun cryptoSession(): CryptoSession = crypto

    /**
     * Whether the connection is in the process of being established. If this returns `false`, the connection may be
     * either established or closed, signaled by the emission of a `Connected` or `ConnectionLost` event.
     */
    val isHandshaking: Boolean get() = state.isHandshake

    /**
     * Whether the connection is closed. Closed connections cannot transport any further data; a `ConnectionLost` event
     * is emitted with details when the connection becomes closed.
     */
    val isClosed: Boolean get() = state.isClosed

    /** Whether there is no longer any need to keep the connection around. All drained connections have been closed. */
    val isDrained: Boolean get() = state.isDrained

    /** For clients, whether the peer accepted the 0-RTT data packets; meaningless until the handshake completes. */
    fun accepted0rtt(): Boolean = accepted0rtt

    /** Whether 0-RTT is/was possible during the handshake. */
    fun has0rtt(): Boolean = zeroRttEnabled

    /** Whether there are any pending retransmits. */
    fun hasPendingRetransmits(): Boolean = !spaces[SpaceId.Data].pending.isEmpty(streams)

    /** Whether we're the client or server of this connection. */
    fun side(): Side = side.side

    /** The latest socket address for this connection's peer. */
    fun remoteAddress(): SocketAddress = path.remote

    /**
     * The local IP address which was used when the peer established the connection (port 0). `null` for clients, or
     * when no local IP was passed to [Endpoint.handle] for the datagrams establishing this connection.
     */
    fun localIp(): SocketAddress? = localIp

    /** Current best estimate of this connection's latency (round-trip-time). */
    fun rtt(): Duration = path.rtt.get()

    /** Minimum RTT seen on this path, ignoring ack delay. */
    fun minRtt(): Duration = path.rtt.min()

    /** Current state of this connection's congestion controller, for debugging purposes. */
    fun congestionState(): Controller = path.congestion

    /**
     * Resets path-specific settings (mod.rs:1430): the congestion controller, round-trip estimator, pacer and MTU
     * discovery, for when the underlying network path is known to have changed.
     */
    fun pathChanged(now: Instant) {
        path.reset(now, config)
        dropOversizedDatagrams()
    }

    /** Modify the number of remotely initiated streams that may be concurrently open. */
    fun setMaxConcurrentStreams(dir: Dir, count: VarInt) {
        streams.setMaxConcurrent(dir, count)
        // If the limit was reduced, then a flow control update previously deemed insignificant may now be
        // significant.
        streams.queueMaxStreamId(spaces[SpaceId.Data].pending)
    }

    /**
     * Current number of remotely initiated streams that may be concurrently open. A reduced target set with
     * [setMaxConcurrentStreams] takes effect one closed stream at a time.
     */
    fun maxConcurrentStreams(dir: Dir): Long = streams.maxConcurrent(dir)

    /** See [TransportConfig.sendWindow]. */
    fun setSendWindow(sendWindow: Long) {
        streams.setSendWindow(sendWindow)
    }

    /** See [TransportConfig.receiveWindow]. */
    fun setReceiveWindow(receiveWindow: VarInt) {
        if (streams.setReceiveWindow(receiveWindow)) spaces[SpaceId.Data].pending.maxData = true
    }

    /** mod.rs:1468 */
    private fun onAckReceived(now: Instant, space: SpaceId, ack: Frame.Ack) {
        val sp = spaces[space]
        if (ack.largest >= sp.nextPacketNumber) throw TransportError.PROTOCOL_VIOLATION("unsent packet acked")
        val newLargest = if (sp.largestAckedPacket < 0 || ack.largest > sp.largestAckedPacket) {
            sp.largestAckedPacket = ack.largest
            val timeSent = sp.sentPackets.timeSentOf(ack.largest)
            // This should always succeed, but a misbehaving peer might ACK a packet we haven't sent. At worst, that
            // will result in us spuriously reducing the congestion window.
            if (timeSent.isSome) sp.largestAckedPacketSent = timeSent
            true
        } else {
            false
        }

        // Avoid DoS from unreasonably huge ack ranges by filtering out just the new acks.
        val newlyAcked = newlyAcked
        newlyAcked.clear()
        ack.forEachRange { first, last ->
            packetNumberFilter.checkAck(space, first, last)
            var pn = sp.sentPackets.firstAtOrAfter(first)
            while (pn in 0..last) {
                newlyAcked.insertOne(pn)
                pn = sp.sentPackets.firstAtOrAfter(pn + 1)
            }
        }

        if (newlyAcked.isEmpty()) return

        var ackElicitingAcked = false
        newlyAcked.forEachRange { start, end ->
            for (packet in start until end) {
                val info = sp.take(packet) ?: continue
                if (info.largestAcked >= 0) {
                    // Assume ACKs for all packets below the largest acknowledged in `packet` have been received. This
                    // can cause the peer to spuriously retransmit if some of our earlier ACKs were lost, but allows for
                    // simpler state tracking. See discussion at
                    // https://www.rfc-editor.org/rfc/rfc9000.html#name-limiting-ranges-by-tracking
                    sp.pendingAcks.subtractBelow(info.largestAcked)
                }
                ackElicitingAcked = ackElicitingAcked || info.ackEliciting

                // Notify MTU discovery that a packet was acked, because it might be an MTU probe
                val mtuUpdated = path.mtud.onAcked(space, packet, info.size)
                if (mtuUpdated) path.congestion.onMtuUpdate(path.mtud.currentMtu())

                // Notify ack frequency that a packet was acked, because it might contain an ACK_FREQUENCY frame
                ackFrequency.onAcked(packet)

                onPacketAcked(now, info)
            }
        }

        path.congestion.onEndAcks(now, path.inFlight.bytes, appLimited, sp.largestAckedPacket)

        if (newLargest && ackElicitingAcked) {
            val ackDelay = if (space != SpaceId.Data) {
                Duration.ZERO
            } else {
                // quinn shifts a u64: a result past 2^63 is larger than any max ACK delay
                val micros = ack.delay shl peerParams.ackDelayExponent.value.toInt()
                val peerMax = ackFrequency.peerMaxAckDelay
                if (micros < 0 || micros.microseconds > peerMax) peerMax else micros.microseconds
            }
            val rtt = now.saturatingDurationSince(sp.largestAckedPacketSent)
            path.rtt.update(ackDelay, rtt)
            if (path.firstPacketAfterRttSampleSpace == null) path.setFirstPacketAfterRttSample(space, sp.nextPacketNumber)
        }

        // Must be called before crypto/pto_count are clobbered
        detectLostPackets(now, space, true)

        if (peerCompletedAddressValidation()) ptoCount = 0

        // Explicit congestion notification
        if (path.sendingEcn) {
            val ecn = ack.ecn
            if (ecn != null) {
                // We only examine ECN counters from ACKs that we are certain we received in transmit order, allowing
                // us to compute an increase in ECN counts to compare against the number of newly acked packets that
                // remains well-defined in the presence of arbitrary packet reordering.
                if (newLargest) {
                    // quinn passes `newly_acked.len()`: the number of ranges of its `ArrayRangeSet`
                    processEcn(now, space, newlyAcked.len.toLong(), ecn, sp.largestAckedPacketSent)
                }
            } else {
                // We always start out sending ECN, so any ack that doesn't acknowledge it disables it.
                path.sendingEcn = false
            }
        }

        setLossDetectionTimer(now)
    }

    /** Process a new ECN block from an in-order ACK (mod.rs:1588). */
    private fun processEcn(now: Instant, space: SpaceId, newlyAcked: Long, ecn: EcnCounts, largestSentTime: Instant) {
        when (spaces[space].detectEcn(newlyAcked, ecn)) {
            EcnCheck.NotCongested -> {}
            EcnCheck.Congested -> {
                stats.path.congestionEvents += 1
                path.congestion.onCongestionEvent(now, largestSentTime, false, 0)
            }
            else -> {
                // halting ECN due to verification failure
                path.sendingEcn = false
                // Wipe out the existing value because it might be garbage and could interfere with future attempts to
                // use ECN on new paths.
                spaces[space].ecnFeedback = EcnCounts()
            }
        }
    }

    /**
     * mod.rs:1616. Not timing-aware, so it's safe to call this for inferred acks, such as arise from high-latency
     * handshakes.
     */
    private fun onPacketAcked(now: Instant, info: SentPacket) {
        removeInFlight(info)
        if (info.ackEliciting && path.challenge == null) {
            // Only pass ACKs to the congestion controller if we are not validating the current path, so as to ignore
            // any ACKs from older paths still coming in.
            path.congestion.onAck(now, info.timeSent, info.size.toLong(), appLimited, path.rtt)
        }

        // Update state for confirmed delivery of frames
        val retransmits = info.retransmits.get()
        if (retransmits != null) {
            val resets = retransmits.resetStream
            for (i in 0 until resets.size) streams.resetAcked(resets[i].id)
        }

        val frames = info.streamFrames
        for (i in 0 until frames.size) streams.receivedAckOf(frames.id(i), frames.start(i), frames.end(i), frames.fin(i))
    }

    private fun setKeyDiscardTimer(now: Instant, space: SpaceId) {
        val start = if (zeroRttCrypto != null) {
            now
        } else {
            val prev = prevCrypto ?: error("no previous keys")
            check(prev.endPacket >= 0) { "update not acknowledged yet" }
            prev.endPacketTime
        }
        timers.set(Timer.KeyDiscard, start + pto(space) * 3)
    }

    private fun onLossDetectionTimeout(now: Instant) {
        val lossSpace = lossTimeSpace()
        if (lossSpace != null) {
            // Time threshold loss Detection
            detectLostPackets(now, lossSpace, false)
            setLossDetectionTimer(now)
            return
        }

        if (!ptoTimeAndSpace(now)) return // PTO expired while unset
        val space = ptoSpace

        val count = if (path.inFlight.ackEliciting == 0L) {
            // A PTO when we're not expecting any ACKs must be due to handshake anti-amplification deadlock preventions
            debugAssert(!peerCompletedAddressValidation()) { "assertion failed: !self.peer_completed_address_validation()" }
            1
        } else {
            // Conventional loss probe
            2
        }
        spaces[space].lossProbes = saturatingAddU32(spaces[space].lossProbes, count)
        ptoCount = saturatingAddU32(ptoCount, 1)
        setLossDetectionTimer(now)
    }

    /** mod.rs:1695 */
    private fun detectLostPackets(now: Instant, pnSpace: SpaceId, dueToAck: Boolean) {
        val lostPackets = lostPackets
        lostPackets.clear()
        var lostMtuProbe = -1L
        val inFlightMtuProbe = path.mtud.inFlightMtuProbe()
        val rtt = path.rtt.conservative()
        val lossDelay = maxOf(mulF32(rtt.inWholeNanoseconds, config.timeThreshold), TIMER_GRANULARITY.inWholeNanoseconds)

        val sp = spaces[pnSpace]
        val largestAckedPacket = sp.largestAckedPacket
        check(largestAckedPacket >= 0)
        val packetThreshold = config.packetThreshold.toLong()
        var sizeOfLostPackets = 0L

        // InPersistentCongestion: Determine if all packets in the time period before the newest lost packet, including
        // the edges, are marked lost. PTO computation must always include max ACK delay, i.e. operate as if in Data
        // space (see RFC9001 §7.6.1).
        val congestionPeriod = (pto(SpaceId.Data) * config.persistentCongestionThreshold).inWholeNanoseconds
        var persistentCongestionStart = Instant.NONE
        var prevPacket = 0L
        var hasPrevPacket = false
        var inPersistentCongestion = false

        sp.lossTime = Instant.NONE

        var packet = sp.sentPackets.firstAtOrAfter(0)
        while (packet in 0 until largestAckedPacket) {
            if (!hasPrevPacket || prevPacket != packet - 1) {
                // An intervening packet was acknowledged
                persistentCongestionStart = Instant.NONE
            }

            val timeSent = sp.sentPackets.timeSentOf(packet)
            // Packets sent before now - loss_delay are deemed lost. However, we avoid this subtraction as it can panic
            // and there's no saturating equivalent of this subtraction operation with a Duration.
            val packetTooOld = now.saturatingDurationSince(timeSent).inWholeNanoseconds >= lossDelay
            if (packetTooOld || largestAckedPacket >= packet + packetThreshold) {
                if (packet == inFlightMtuProbe) {
                    // Lost MTU probes are not included in `lost_packets`, because they should not trigger a congestion
                    // control response
                    lostMtuProbe = inFlightMtuProbe
                } else {
                    lostPackets.add(packet)
                    sizeOfLostPackets += sp.sentPackets.sizeOf(packet).toLong()
                    if (sp.sentPackets.ackElicitingOf(packet) && dueToAck) {
                        if (persistentCongestionStart.isSome) {
                            // Two ACK-eliciting packets lost more than congestion_period apart, with no ACKed packets in
                            // between
                            if (timeSent.saturatingDurationSince(persistentCongestionStart).inWholeNanoseconds > congestionPeriod) {
                                inPersistentCongestion = true
                            }
                        } else if (path.firstPacketAfterRttSampleBefore(pnSpace, packet)) {
                            // Persistent congestion must start after the first RTT sample
                            persistentCongestionStart = timeSent
                        }
                    }
                }
            } else {
                val nextLossTime = Instant(addNanos(timeSent.nanos, lossDelay))
                if (sp.lossTime.isNone || nextLossTime < sp.lossTime) sp.lossTime = nextLossTime
                persistentCongestionStart = Instant.NONE
            }

            prevPacket = packet
            hasPrevPacket = true
            packet = sp.sentPackets.firstAtOrAfter(packet + 1)
        }

        // OnPacketsLost
        if (!lostPackets.isEmpty()) {
            val largestLost = lostPackets[lostPackets.size - 1]
            val oldBytesInFlight = path.inFlight.bytes
            val largestLostSent = sp.sentPackets.timeSentOf(largestLost)
            stats.path.lostPackets += lostPackets.size.toLong()
            stats.path.lostBytes += sizeOfLostPackets

            for (i in 0 until lostPackets.size) {
                val lost = lostPackets[i]
                val info = sp.take(lost)!! // safe: lost_packets is populated just above
                removeInFlight(info)
                val frames = info.streamFrames
                for (f in 0 until frames.size) streams.retransmit(frames.id(f), frames.start(f), frames.end(f), frames.fin(f))
                sp.pending.orAssign(info.retransmits)
                path.mtud.onNonProbeLost(lost, info.size)
            }

            if (path.mtud.blackHoleDetected(now)) {
                stats.path.blackHolesDetected += 1
                path.congestion.onMtuUpdate(path.mtud.currentMtu())
                dropOversizedDatagrams()
            }

            // Don't apply congestion penalty for lost ack-only packets
            val lostAckEliciting = oldBytesInFlight != path.inFlight.bytes

            if (lostAckEliciting) {
                stats.path.congestionEvents += 1
                path.congestion.onCongestionEvent(now, largestLostSent, inPersistentCongestion, sizeOfLostPackets)
            }
        }

        // Handle a lost MTU probe
        if (lostMtuProbe >= 0) {
            // safe: lost_mtu_probe is omitted from lost_packets, and therefore must not have been removed yet
            val info = spaces[SpaceId.Data].take(lostMtuProbe)!!
            removeInFlight(info)
            path.mtud.onProbeLost()
            stats.path.lostPlpmtudProbes += 1
        }
    }

    /** The space with the earliest loss time, or `null` (quinn `loss_time_and_space`, mod.rs:1828). */
    private fun lossTimeSpace(): SpaceId? {
        var best: SpaceId? = null
        for (id in SPACE_IDS) {
            val t = spaces[id].lossTime
            if (t.isNone) continue
            // `min_by_key` returns the first of equal minima
            if (best == null || t < spaces[best].lossTime) best = id
        }
        return best
    }

    /**
     * quinn `pto_time_and_space` (mod.rs:1834): returns `false` for `None`, otherwise sets [ptoTime] and [ptoSpace].
     */
    private fun ptoTimeAndSpace(now: Instant): Boolean {
        val backoff = 1 shl minOf(ptoCount, MAX_BACKOFF_EXPONENT)
        var duration = path.rtt.ptoBase() * backoff

        if (path.inFlight.ackEliciting == 0L) {
            debugAssert(!peerCompletedAddressValidation()) { "assertion failed: !self.peer_completed_address_validation()" }
            ptoSpace = if (highestSpace == SpaceId.Handshake) SpaceId.Handshake else SpaceId.Initial
            ptoTime = now + duration
            return true
        }

        var found = false
        for (space in SPACE_IDS) {
            if (!spaces[space].hasInFlight()) continue
            if (space == SpaceId.Data) {
                // Skip ApplicationData until handshake completes.
                if (isHandshaking) return found
                // Include max_ack_delay and backoff for ApplicationData.
                duration += ackFrequency.maxAckDelayForPto() * backoff
            }
            val lastAckEliciting = spaces[space].timeOfLastAckElicitingPacket
            if (lastAckEliciting.isNone) continue
            val pto = lastAckEliciting + duration
            if (!found || pto < ptoTime) {
                ptoTime = pto
                ptoSpace = space
                found = true
            }
        }
        return found
    }

    private fun peerCompletedAddressValidation(): Boolean {
        if (side.isServer || state.isClosed) return true
        // The server is guaranteed to have validated our address if any of our handshake or 1-RTT packets are
        // acknowledged or we've seen HANDSHAKE_DONE and discarded handshake keys.
        return spaces[SpaceId.Handshake].largestAckedPacket >= 0 ||
            spaces[SpaceId.Data].largestAckedPacket >= 0 ||
            (spaces[SpaceId.Data].crypto != null && spaces[SpaceId.Handshake].crypto == null)
    }

    internal fun setLossDetectionTimer(now: Instant) {
        if (state.isClosed) {
            // No loss detection takes place on closed connections, and `close_common` already stopped time timer.
            // Ensure we don't restart it inadvertently, e.g. in response to a reordered packet being handled by
            // state-insensitive code.
            return
        }

        val lossSpace = lossTimeSpace()
        if (lossSpace != null) {
            // Time threshold loss detection.
            timers.set(Timer.LossDetection, spaces[lossSpace].lossTime)
            return
        }

        if (path.antiAmplificationBlocked(1)) {
            // We wouldn't be able to send anything, so don't bother.
            timers.stop(Timer.LossDetection)
            return
        }

        if (path.inFlight.ackEliciting == 0L && peerCompletedAddressValidation()) {
            // There is nothing to detect lost, so no timer is set. However, the client needs to arm the timer if the
            // server might be blocked by the anti-amplification limit.
            timers.stop(Timer.LossDetection)
            return
        }

        // Determine which PN space to arm PTO for. Calculate PTO duration
        if (ptoTimeAndSpace(now)) timers.set(Timer.LossDetection, ptoTime) else timers.stop(Timer.LossDetection)
    }

    /** Probe Timeout. */
    private fun pto(space: SpaceId): Duration {
        val maxAckDelay = if (space == SpaceId.Data) ackFrequency.maxAckDelayForPto() else Duration.ZERO
        return path.rtt.ptoBase() + maxAckDelay
    }

    /** mod.rs:1931; [packet] is -1 for packets without a number. */
    private fun onPacketAuthenticated(
        now: Instant,
        spaceId: SpaceId,
        ecn: EcnCodepoint?,
        packet: Long,
        spin: Boolean,
        is1rtt: Boolean,
    ) {
        totalAuthedPackets += 1
        resetKeepAlive(now)
        resetIdleTimeout(now, spaceId)
        permitIdleReset = true
        receivingEcn = receivingEcn || ecn != null
        if (ecn != null) {
            val space = spaces[spaceId]
            space.ecnCounters.add(ecn)
            if (ecn.isCe) space.pendingAcks.setImmediateAckRequired()
        }

        if (packet < 0) return
        if (side.isServer) {
            if (spaces[SpaceId.Initial].crypto != null && spaceId == SpaceId.Handshake) {
                // A server stops sending and processing Initial packets when it receives its first Handshake packet.
                discardSpace(now, SpaceId.Initial)
            }
            if (zeroRttCrypto != null && is1rtt) {
                // Discard 0-RTT keys soon after receiving a 1-RTT packet
                setKeyDiscardTimer(now, spaceId)
            }
        }
        val space = spaces[spaceId]
        space.pendingAcks.insertOne(packet, now)
        if (packet >= space.rxPacket) {
            space.rxPacket = packet
            // Update outgoing spin bit, inverting iff we're the client
            this.spin = side.isClient xor spin
        }
    }

    internal fun resetIdleTimeout(now: Instant, space: SpaceId) {
        val timeout = idleTimeout ?: return
        if (state.isClosed) {
            timers.stop(Timer.Idle)
            return
        }
        val ptos = pto(space) * 3
        timers.set(Timer.Idle, now + if (timeout > ptos) timeout else ptos)
    }

    internal fun resetKeepAlive(now: Instant) {
        val interval = config.keepAliveInterval ?: return
        if (!state.isEstablished) return
        timers.set(Timer.KeepAlive, now + interval)
    }

    private fun resetCidRetirement() {
        localCidState.nextTimeout()?.let { timers.set(Timer.PushNewCid, it) }
    }

    /**
     * Handle the already-decrypted first packet from the client (mod.rs:2016). Decrypting the first packet in the
     * [Endpoint] allows stateless packet handling to be more efficient. Returns the error that failed the connection,
     * or `null`.
     */
    internal fun handleFirstPacket(
        now: Instant,
        remote: SocketAddress,
        ecn: EcnCodepoint?,
        packetNumber: Long,
        packet: Packet,
        rest: PartialDecode,
    ): ConnectionError? {
        debugAssert(side.isServer) { "assertion failed: self.side.is_server()" }
        val len = packet.headerLen + packet.payloadLen
        path.totalRecvd = len.toLong()

        val hs = state as? State.Handshake ?: error("first packet must be delivered in Handshake state")
        hs.expectedToken = (packet.header as InitialHeader).token

        onPacketAuthenticated(now, SpaceId.Initial, ecn, packetNumber, false, false)

        try {
            processDecryptedPacket(now, remote, packetNumber, packet)?.let { return it }
        } catch (e: TransportError) {
            return ConnectionError.Transport(e)
        }
        if (rest.hasRest) handleCoalesced(now, remote, ecn, rest.data, rest.restStart, rest.restEnd)

        return null
    }

    private fun init0rtt() {
        val early = crypto.earlyCrypto() ?: return
        if (side.isClient) {
            val params = try {
                crypto.transportParameters()
            } catch (e: TransportError) {
                // session ticket has malformed transport parameters
                return
            } ?: error("crypto layer didn't supply transport parameters with ticket")
            // Certain values must not be cached
            val cached = params.copy()
            val defaults = TransportParameters.default()
            cached.initialSrcCid = null
            cached.originalDstCid = null
            cached.preferredAddress = null
            cached.retrySrcCid = null
            cached.statelessResetToken = null
            cached.minAckDelay = null
            cached.ackDelayExponent = defaults.ackDelayExponent
            cached.maxAckDelay = defaults.maxAckDelay
            setPeerParams(cached)
        }
        // 0-RTT enabled
        zeroRttEnabled = true
        zeroRttCrypto?.close()
        zeroRttCrypto = ZeroRttCrypto(early.header, early.packet)
    }

    /** mod.rs:2097 */
    private fun readCrypto(space: SpaceId, frame: Frame.Crypto, payloadLen: Int) {
        val expected = if (!state.isHandshake) {
            SpaceId.Data
        } else if (highestSpace == SpaceId.Initial) {
            SpaceId.Initial
        } else {
            // On the server, self.highest_space can be Data after receiving the client's first flight, but we expect
            // Handshake CRYPTO until the handshake is complete.
            SpaceId.Handshake
        }
        // We can't decrypt Handshake packets when highest_space is Initial, CRYPTO frames in 0-RTT packets are
        // illegal, and we don't process 1-RTT packets until the handshake is complete. Therefore, we will never see
        // CRYPTO data from a later-than-expected space.
        debugAssert(space <= expected) { "received out-of-order CRYPTO data" }

        val sp = spaces[space]
        val end = frame.offset + frame.data.size
        if (space < expected && end > sp.cryptoStream.bytesRead) {
            // received new CRYPTO data at an unexpected encryption level
            throw TransportError.PROTOCOL_VIOLATION("new data at unexpected encryption level")
        }

        val max = saturatingSubU(end, sp.cryptoStream.bytesRead)
        if (max > config.cryptoBufferSize) throw TransportError.CRYPTO_BUFFER_EXCEEDED("")

        if (!sp.cryptoStream.insert(frame.offset, frame.data, payloadLen)) {
            throw TransportError.INTERNAL_ERROR("too many gaps in crypto stream buffer")
        }

        while (true) {
            val chunk = sp.cryptoStream.read(Int.MAX_VALUE, true) ?: break
            if (crypto.readHandshake(chunk.bytes)) events.addLast(Event.HandshakeDataReady)
        }
    }

    /** mod.rs:2149 */
    private fun writeCrypto() {
        while (true) {
            val space = highestSpace
            val outgoing = cryptoScratch
            outgoing.clear()
            val keys = crypto.writeHandshake(outgoing)
            if (keys != null) {
                when (space) {
                    SpaceId.Initial -> upgradeCrypto(SpaceId.Handshake, keys)
                    SpaceId.Handshake -> upgradeCrypto(SpaceId.Data, keys)
                    SpaceId.Data -> error("got updated secrets during 1-RTT")
                }
            }
            if (outgoing.isEmpty) {
                if (space == highestSpace) break
                // Keys updated, check for more data to send
                continue
            }
            val offset = spaces[space].cryptoOffset
            val data = Bytes.copyOf(outgoing.backingArray(), outgoing.readerIndex(), outgoing.readerIndex() + outgoing.len)
            outgoing.clear()
            val hs = state
            if (hs is State.Handshake && space == SpaceId.Initial && offset == 0L && side.isClient) hs.clientHello = data
            spaces[space].cryptoOffset += data.size
            spaces[space].pending.crypto.addLast(Frame.Crypto(offset, data))
        }
    }

    /** Switch to stronger cryptography during handshake (mod.rs:2189). */
    private fun upgradeCrypto(space: SpaceId, keys: Keys) {
        debugAssert(spaces[space].crypto == null) { "already reached packet space $space" }
        if (space == SpaceId.Data) {
            // Precompute the first key update
            nextCrypto = crypto.next1rttKeys() ?: error("handshake should be complete")
        }

        spaces[space].crypto = keys
        debugAssert(space > highestSpace) { "assertion failed: space as usize > self.highest_space as usize" }
        highestSpace = space
        if (space == SpaceId.Data && side.isClient) {
            // Discard 0-RTT keys because 1-RTT keys are available.
            zeroRttCrypto?.close()
            zeroRttCrypto = null
        }
    }

    private fun discardSpace(now: Instant, spaceId: SpaceId) {
        debugAssert(spaceId != SpaceId.Data) { "assertion failed: space_id != SpaceId::Data" }
        if (spaceId == SpaceId.Initial) {
            // No longer needed
            (side as? ConnectionSide.Client)?.token = Bytes.EMPTY
        }
        val space = spaces[spaceId]
        space.crypto?.close()                   // ⚖️ quinn drops them; the native contexts are freed now
        space.crypto = null
        space.timeOfLastAckElicitingPacket = Instant.NONE
        space.lossTime = Instant.NONE
        space.sentPackets.drain(drainScratch) { _, packet -> removeInFlight(packet) }
        setLossDetectionTimer(now)
    }

    private fun handleCoalesced(now: Instant, remote: SocketAddress, ecn: EcnCodepoint?, data: ByteArray, start: Int, end: Int) {
        path.totalRecvd = saturatingAddU(path.totalRecvd, (end - start).toLong())
        var from = start
        var to = end
        while (from >= 0) {
            val partialDecode = try {
                PartialDecode.decode(data, from, to, cidParser, ownVersion, endpointConfig.greaseQuicBit)
            } catch (e: PacketDecodeError) {
                // malformed header
                return
            }
            from = partialDecode.restStart
            to = partialDecode.restEnd
            handleDecode(now, remote, ecn, partialDecode)
        }
    }

    /** quinn `handle_decode` with `packet_crypto::unprotect_header` (packet_crypto.rs:12) inline. */
    private fun handleDecode(now: Instant, remote: SocketAddress, ecn: EcnCodepoint?, partialDecode: PartialDecode) {
        val headerCrypto: HeaderKey? = if (partialDecode.is0rtt) {
            // dropping unexpected 0-RTT packet when there are no 0-RTT keys
            zeroRttCrypto?.header ?: return
        } else {
            val space = partialDecode.space
            if (space != null) {
                // discarding unexpected packets of a space without keys
                spaces[space].crypto?.header?.remote ?: return
            } else {
                // Unprotected packet
                null
            }
        }

        val token = peerParams.statelessResetToken
        val end = partialDecode.end
        val statelessReset = partialDecode.len >= RESET_TOKEN_SIZE + 5 && token != null &&
            token.matches(partialDecode.data, end - RESET_TOKEN_SIZE)

        val packet = try {
            partialDecode.finish(headerCrypto)
        } catch (e: PacketDecodeError) {
            // unable to complete packet decoding
            if (!statelessReset) return
            null
        }
        handlePacket(now, remote, ecn, packet, statelessReset)
    }

    /** mod.rs:2278 */
    private fun handlePacket(now: Instant, remote: SocketAddress, ecn: EcnCodepoint?, packet: Packet?, statelessReset: Boolean) {
        stats.udpRx.ios += 1

        if (isHandshaking && remote != path.remote) {
            // discarding packet with unexpected remote during handshake
            return
        }

        val wasClosed = state.isClosed
        val wasDrained = state.isDrained

        var number = DECRYPT_FAILED
        var decryptError: TransportError? = null
        if (packet != null) {
            try {
                number = decryptPacket(now, packet)
            } catch (e: TransportError) {
                decryptError = e
            }
        }

        val result: ConnectionError? = when {
            statelessReset -> ConnectionError.Reset // got stateless reset
            decryptError != null -> ConnectionError.Transport(decryptError) // illegal packet
            number == DECRYPT_FAILED -> {
                // failed to authenticate packet
                authenticationFailures += 1
                val integrityLimit = spaces[highestSpace].crypto!!.packet.local.integrityLimit
                if (authenticationFailures > integrityLimit) {
                    ConnectionError.Transport(TransportError.AEAD_LIMIT_REACHED("integrity limit violated"))
                } else {
                    return
                }
            }
            else -> {
                val decrypted = packet!!
                val header = decrypted.header
                if (number >= 0 && spaces[header.space].dedup.insert(number)) {
                    // discarding possible duplicate packet
                    return
                } else if (state.isHandshake && header.isShort) {
                    // TODO (as in quinn): SHOULD buffer these to improve reordering tolerance.
                    return
                } else {
                    if (header is InitialHeader) {
                        val hs = state
                        if (hs is State.Handshake && side.isServer && header.token != hs.expectedToken) {
                            // Clients must send the same retry token in every Initial. Initial packets can be spoofed,
                            // so we discard rather than killing the connection.
                            return
                        }
                    }

                    if (!state.isClosed) {
                        val spin = (header as? Header.Short)?.spin ?: false
                        onPacketAuthenticated(now, header.space, ecn, number, spin, header.is1rtt)
                    }

                    try {
                        processDecryptedPacket(now, remote, number, decrypted)
                    } catch (e: TransportError) {
                        ConnectionError.Transport(e)
                    }
                }
            }
        }

        // State transitions for error cases
        if (result != null) {
            error = result
            state = when (result) {
                is ConnectionError.ApplicationClosed -> State.Closed(result.reason)
                is ConnectionError.ConnectionClosed -> State.Closed(result.reason)
                ConnectionError.Reset -> State.Drained
                is ConnectionError.Transport ->
                    if (result.error.code == TransportErrorCode.AEAD_LIMIT_REACHED) {
                        State.Drained
                    } else {
                        // closing connection due to transport error
                        State.Closed(Frame.ConnectionClose.from(result.error))
                    }
                ConnectionError.VersionMismatch -> State.Draining
                ConnectionError.TimedOut -> error("timeouts aren't generated by packet processing")
                ConnectionError.LocallyClosed -> error("LocallyClosed isn't generated by packet processing")
                ConnectionError.CidsExhausted -> error("CidsExhausted isn't generated by packet processing")
            }
        }

        if (!wasClosed && state.isClosed) {
            closeCommon()
            if (!state.isDrained) setCloseTimer(now)
        }
        if (!wasDrained && state.isDrained) {
            releaseKeys()
            endpointEvents.addLast(EndpointEvent.Drained)
            // Close timer may have been started previously, e.g. if we sent a close and got a stateless reset in
            // response
            timers.stop(Timer.Close)
        }

        // Transmit CONNECTION_CLOSE if necessary
        if (state is State.Closed) close = remote == path.remote
    }

    /**
     * mod.rs:2431; [number] is -1 for packets without a number. Returns the connection error (quinn's `Err` other than
     * a transport error, which is thrown), or `null`.
     */
    private fun processDecryptedPacket(now: Instant, remote: SocketAddress, number: Long, packet: Packet): ConnectionError? {
        val hs: State.Handshake
        when (val s = state) {
            State.Established -> {
                if (packet.header.space == SpaceId.Data) {
                    processPayload(now, remote, number, packet)
                } else if (packet.header.hasFrames) {
                    processEarlyPayload(now, packet)
                } else {
                    // discarding unexpected pre-handshake packet
                }
                return null
            }
            is State.Closed -> {
                val it = FrameIter(packet.data, packet.payloadStart, packet.payloadStart + packet.payloadLen)
                while (it.hasNext()) {
                    val frame = try {
                        it.next()
                    } catch (e: InvalidFrame) {
                        // frame decoding error
                        continue
                    }
                    if (frame === Frame.Padding) continue
                    stats.frameRx.record(frame)
                    if (frame is Frame.Close) {
                        // draining
                        state = State.Draining
                        break
                    }
                }
                return null
            }
            State.Draining, State.Drained -> return null
            is State.Handshake -> hs = s
        }

        when (val header = packet.header) {
            is Header.Retry -> {
                val remCid = header.srcCid
                if (side.isServer) throw TransportError.PROTOCOL_VIOLATION("client sent Retry")

                if (totalAuthedPackets > 1 ||
                    packet.payloadLen <= 16 || // token + 16 byte tag
                    !crypto.isValidRetry(remCids.active(), packet.headerData(), packet.payload())
                ) {
                    // discarding invalid Retry:
                    // - After the client has received and processed an Initial or Retry packet from the server, it MUST
                    //   discard any subsequent Retry packets that it receives.
                    // - A client MUST discard a Retry packet with a zero-length Retry Token field.
                    // - Clients MUST discard Retry packets that have a Retry Integrity Tag that cannot be validated
                    return null
                }

                // retrying with CID remCid
                val clientHello = hs.clientHello!!
                hs.clientHello = null
                retrySrcCid = remCid
                remCids.updateInitialCid(remCid)
                remHandshakeCid = remCid

                spaces[SpaceId.Initial].take(0)?.let { onPacketAcked(now, it) }

                discardSpace(now, SpaceId.Initial) // Make sure we clean up after any retransmitted Initials
                val initial = PacketSpace(now)
                initial.crypto = crypto.initialKeys(remCid, side.side)
                initial.nextPacketNumber = spaces[SpaceId.Initial].nextPacketNumber
                initial.cryptoOffset = clientHello.size.toLong()
                spaces[SpaceId.Initial.ordinal] = initial
                initial.pending.crypto.addLast(Frame.Crypto(0, clientHello))

                // Retransmit all 0-RTT data
                val data = spaces[SpaceId.Data]
                data.sentPackets.drain(drainScratch) { _, info ->
                    removeInFlight(info)
                    data.pending.orAssign(info.retransmits)
                }
                streams.retransmitAllFor0rtt()

                val tokenLen = packet.payloadLen - 16
                (side as ConnectionSide.Client).token = sliceOf(packet.data, packet.payloadStart, packet.payloadStart + tokenLen)
                state = State.Handshake(remCidSet = false, expectedToken = Bytes.EMPTY, clientHello = null)
                return null
            }
            is Header.Long -> if (header.ty == LongType.Handshake) {
                val remCid = header.srcCid
                if (remCid != remHandshakeCid) {
                    // discarding packet with mismatched remote CID
                    return null
                }
                onPathValidated()

                processEarlyPayload(now, packet)
                if (state.isClosed) return null

                if (crypto.isHandshaking) return null // handshake ongoing

                if (side.isClient) {
                    // Client-only because server params were set from the client's Initial
                    val params = crypto.transportParameters()
                        ?: throw TransportError(TransportErrorCode.crypto(0x6d), null, "transport parameters missing")

                    if (has0rtt()) {
                        if (crypto.earlyDataAccepted() != true) {
                            debugAssert(side.isClient) { "assertion failed: self.side.is_client()" }
                            // 0-RTT rejected
                            accepted0rtt = false
                            streams.zeroRttRejected()

                            // Discard already-queued frames
                            spaces[SpaceId.Data].pending = Retransmits()

                            // Discard 0-RTT packets
                            spaces[SpaceId.Data].sentPackets.drain(drainScratch) { _, info -> removeInFlight(info) }
                        } else {
                            accepted0rtt = true
                            params.validateResumptionFrom(peerParams)
                        }
                    }
                    params.statelessResetToken?.let {
                        endpointEvents.addLast(EndpointEvent.ResetTokenChanged(path.remote, it))
                    }
                    handlePeerParams(params)
                    issueFirstCids(now)
                } else {
                    // Server-only
                    spaces[SpaceId.Data].pending.handshakeDone = true
                    discardSpace(now, SpaceId.Handshake)
                }

                events.addLast(Event.Connected)
                state = State.Established
                return null
            } else {
                processPayload(now, remote, number, packet)
                return null
            }
            is InitialHeader -> {
                val remCid = header.srcCid
                if (!hs.remCidSet) {
                    // switching remote CID
                    remCids.updateInitialCid(remCid)
                    remHandshakeCid = remCid
                    origRemCid = remCid
                    hs.remCidSet = true
                } else if (remCid != remHandshakeCid) {
                    // discarding packet with mismatched remote CID
                    return null
                }

                val startingSpace = highestSpace
                processEarlyPayload(now, packet)

                if (side.isServer && startingSpace == SpaceId.Initial && highestSpace != SpaceId.Initial) {
                    val params = crypto.transportParameters()
                        ?: throw TransportError(TransportErrorCode.crypto(0x6d), null, "transport parameters missing")
                    handlePeerParams(params)
                    issueFirstCids(now)
                    init0rtt()
                }
                return null
            }
            is Header.VersionNegotiate -> {
                if (totalAuthedPackets > 1) return null
                var supported = false
                var at = packet.payloadStart
                val end = packet.payloadStart + packet.payloadLen
                while (at + 4 <= end) {
                    val v = ((packet.data[at].toInt() and 0xFF) shl 24) or ((packet.data[at + 1].toInt() and 0xFF) shl 16) or
                        ((packet.data[at + 2].toInt() and 0xFF) shl 8) or (packet.data[at + 3].toInt() and 0xFF)
                    if (v == version) supported = true
                    at += 4
                }
                if (supported) return null
                // remote doesn't support our version
                return ConnectionError.VersionMismatch
            }
            is Header.Short -> error("short packets received during handshake are discarded in handle_packet")
        }
    }

    /** Process an Initial or Handshake packet payload (mod.rs:2694). */
    private fun processEarlyPayload(now: Instant, packet: Packet) {
        val space = packet.header.space
        debugAssert(space != SpaceId.Data) { "assertion `left != right` failed" }
        val payloadLen = packet.payloadLen
        var ackEliciting = false
        val it = FrameIter(packet.data, packet.payloadStart, packet.payloadStart + payloadLen)
        while (it.hasNext()) {
            val frame = try {
                it.next()
            } catch (e: InvalidFrame) {
                throw e.toTransportError()
            }
            if (frame === Frame.Padding) continue

            stats.frameRx.record(frame)

            ackEliciting = ackEliciting || frame.isAckEliciting

            // Process frames
            when (frame) {
                Frame.Ping -> {}
                is Frame.Crypto -> readCrypto(space, frame, payloadLen)
                is Frame.Ack -> onAckReceived(now, space, frame)
                is Frame.Close -> {
                    error = frame.toConnectionError()
                    state = State.Draining
                    return
                }
                else -> throw frame.handshakeSpaceViolation()!!
            }
        }

        if (ackEliciting) {
            // In the initial and handshake spaces, ACKs must be sent immediately
            spaces[space].pendingAcks.setImmediateAckRequired()
        }

        writeCrypto()
    }

    /** mod.rs:2748 */
    private fun processPayload(now: Instant, remote: SocketAddress, number: Long, packet: Packet) {
        var isProbingPacket = true
        var close: Frame.Close? = null
        val payloadLen = packet.payloadLen
        var ackEliciting = false
        val is0rtt = packet.header.is0rtt
        val it = FrameIter(packet.data, packet.payloadStart, packet.payloadStart + payloadLen)
        while (it.hasNext()) {
            val frame = try {
                it.next()
            } catch (e: InvalidFrame) {
                throw e.toTransportError()
            }
            if (frame === Frame.Padding) continue

            stats.frameRx.record(frame)

            if (is0rtt) frame.zeroRttViolation()?.let { throw it }
            ackEliciting = ackEliciting || frame.isAckEliciting

            // Check whether this could be a probing packet
            when (frame) {
                is Frame.PathChallenge, is Frame.PathResponse, is Frame.NewConnectionId -> {}
                else -> isProbingPacket = false
            }
            when (frame) {
                is Frame.Crypto -> readCrypto(SpaceId.Data, frame, payloadLen)
                is Frame.Stream -> if (streams.received(frame, payloadLen).shouldTransmit) {
                    spaces[SpaceId.Data].pending.maxData = true
                }
                is Frame.Ack -> onAckReceived(now, SpaceId.Data, frame)
                Frame.Padding, Frame.Ping -> {}
                is Frame.Close -> close = frame
                is Frame.PathChallenge -> {
                    pathResponses.push(number, frame.token, remote)
                    if (remote == path.remote) {
                        // PATH_CHALLENGE on active path, possible off-path packet forwarding attack. Send a
                        // non-probing packet to recover the active path.
                        if (peerSupportsAckFrequency()) immediateAck() else ping()
                    }
                }
                is Frame.PathResponse -> {
                    if (path.challenge == frame.token && remote == path.remote) {
                        // new path validated
                        timers.stop(Timer.PathValidation)
                        path.challenge = null
                        path.validated = true
                        prevPath?.let {
                            it.challenge = null
                            it.challengePending = false
                        }
                    } else {
                        // ignoring invalid PATH_RESPONSE
                    }
                }
                is Frame.MaxData -> streams.receivedMaxData(frame.value)
                is Frame.MaxStreamData -> streams.receivedMaxStreamData(frame.id, frame.offset)
                is Frame.MaxStreams -> streams.receivedMaxStreams(frame.dir, frame.count)
                is Frame.ResetStream -> if (streams.receivedReset(frame).shouldTransmit) {
                    spaces[SpaceId.Data].pending.maxData = true
                }
                is Frame.DataBlocked -> {} // peer claims to be blocked at connection level
                is Frame.StreamDataBlocked -> {
                    if (frame.id.initiator == side.side && frame.id.dir == Dir.Uni) {
                        throw TransportError.STREAM_STATE_ERROR("STREAM_DATA_BLOCKED on send-only stream")
                    }
                    // peer claims to be blocked at stream level
                }
                is Frame.StreamsBlocked -> {
                    if (frame.limit > MAX_STREAM_COUNT) throw TransportError.FRAME_ENCODING_ERROR("unrepresentable stream limit")
                    // peer claims to be blocked opening more streams
                }
                is Frame.StopSending -> {
                    val id = frame.id
                    if (id.initiator != side.side) {
                        if (id.dir == Dir.Uni) throw TransportError.STREAM_STATE_ERROR("STOP_SENDING on recv-only stream")
                    } else if (streams.isLocalUnopened(id)) {
                        throw TransportError.STREAM_STATE_ERROR("STOP_SENDING on unopened stream")
                    }
                    streams.receivedStopSending(id, frame.errorCode)
                }
                is Frame.RetireConnectionId -> {
                    val allowMoreCids = localCidState.onCidRetirement(frame.sequence, peerParams.issueCidsLimit())
                    endpointEvents.addLast(EndpointEvent.RetireConnectionId(now, frame.sequence, allowMoreCids))
                }
                is Frame.NewConnectionId -> {
                    if (remCids.active().isEmpty()) {
                        throw TransportError.PROTOCOL_VIOLATION("NEW_CONNECTION_ID when CIDs aren't in use")
                    }
                    if (frame.retirePriorTo > frame.sequence) {
                        throw TransportError.PROTOCOL_VIOLATION("NEW_CONNECTION_ID retiring unissued CIDs")
                    }

                    val retired = try {
                        remCids.insert(frame)
                    } catch (e: CidQueue.InsertError.ExceedsLimit) {
                        throw TransportError.CONNECTION_ID_LIMIT_ERROR("")
                    } catch (e: CidQueue.InsertError.Retired) {
                        // discarding already-retired: RETIRE_CONNECTION_ID might not have been previously sent if e.g.
                        // a range of connection IDs larger than the active connection ID limit was retired all at once
                        // via retire_prior_to.
                        spaces[SpaceId.Data].pending.retireCids(frame.sequence, saturatingAddU(frame.sequence, 1))
                        continue
                    }
                    if (retired != null) {
                        spaces[SpaceId.Data].pending.retireCids(retired.start, retired.end)
                        setResetToken(retired.resetToken)
                    }

                    if (side.isServer && remCids.activeSeq() == 0L) {
                        // We're a server still using the initial remote CID for the client, so let's switch
                        // immediately to enable clientside stateless resets.
                        updateRemCid()
                    }
                }
                is Frame.NewToken -> {
                    val client = side as? ConnectionSide.Client
                        ?: throw TransportError.PROTOCOL_VIOLATION("client sent NEW_TOKEN")
                    if (frame.token.isEmpty) throw TransportError.FRAME_ENCODING_ERROR("empty token")
                    client.tokenStore.insert(client.serverName, frame.token)
                }
                is Frame.Datagram -> {
                    if (datagrams.received(frame.data, config.datagramReceiveBufferSize ?: -1L)) {
                        events.addLast(Event.DatagramReceived)
                    }
                }
                is Frame.AckFrequency -> {
                    // This frame can only be sent in the Data space
                    val space = spaces[SpaceId.Data]

                    if (!ackFrequency.ackFrequencyReceived(frame, space.pendingAcks)) {
                        // The AckFrequency frame is stale (we have already received a more recent one)
                        continue
                    }

                    // Our `max_ack_delay` has been updated, so we may need to adjust its associated timeout
                    val timeout = space.pendingAcks.maxAckDelayTimeout(ackFrequency.maxAckDelay)
                    if (timeout.isSome) timers.set(Timer.MaxAckDelay, timeout)
                }
                Frame.ImmediateAck -> {
                    // This frame can only be sent in the Data space
                    spaces[SpaceId.Data].pendingAcks.setImmediateAckRequired()
                }
                Frame.HandshakeDone -> {
                    if (side.isServer) throw TransportError.PROTOCOL_VIOLATION("client sent HANDSHAKE_DONE")
                    if (spaces[SpaceId.Handshake].crypto != null) discardSpace(now, SpaceId.Handshake)
                }
            }
        }

        val space = spaces[SpaceId.Data]
        if (space.pendingAcks.packetReceived(now, number, ackEliciting, space.dedup)) {
            timers.set(Timer.MaxAckDelay, now + ackFrequency.maxAckDelay)
            nextBundledAckTime = now
        }

        // Issue stream ID credit due to ACKs of outgoing finish/resets and incoming finish/resets on stopped streams.
        // Incoming finishes/resets on open streams are not handled here as they are only freed, and hence only issue
        // credit, once the application has been notified during a read on the stream.
        streams.queueMaxStreamId(spaces[SpaceId.Data].pending)

        if (close != null) {
            error = close.toConnectionError()
            state = State.Draining
            this.close = true
        }

        if (remote != path.remote && !isProbingPacket && number == spaces[SpaceId.Data].rxPacket) {
            val server = side as? ConnectionSide.Server ?: error("packets from unknown remote should be dropped by clients")
            debugAssert(server.serverConfig.migration) { "migration-initiating packets should have been dropped immediately" }
            migrate(now, remote)
            // Break linkability, if possible
            updateRemCid()
            spin = false
        }
    }

    /** mod.rs:3066 */
    private fun migrate(now: Instant, remote: SocketAddress) {
        // migration initiated
        pathCounter += 1
        // Reset rtt/congestion state for new path unless it looks like a NAT rebinding. Note that the congestion
        // window will not grow until validation terminates. Helps mitigate amplification attacks performed by spoofing
        // source addresses.
        val newPath = if (remote.isIpv4 && path.remote.isIpv4 && remote.ipBytes().contentEquals(path.remote.ipBytes())) {
            PathData.fromPrevious(remote, path, pathCounter, now)
        } else {
            val peerMaxUdpPayloadSize = minOf(peerParams.maxUdpPayloadSize.value, 0xFFFFL).toInt()
            PathData.new(remote, allowMtud, peerMaxUdpPayloadSize, pathCounter, now, config)
        }
        newPath.challenge = rng.nextLong()
        newPath.challengePending = true
        val prevPto = pto(SpaceId.Data)

        val prev = path
        path = newPath
        dropOversizedDatagrams()
        // Don't clobber the original path if the previous one hasn't been validated yet
        if (prev.challenge == null) {
            prev.challenge = rng.nextLong()
            prev.challengePending = true
            // We haven't updated the remote CID yet, this captures the remote CID we were using on the previous path.
            prevPathCid = remCids.active()
            prevPath = prev
        }

        timers.set(Timer.PathValidation, now + maxOf(pto(SpaceId.Data), prevPto) * 3)
    }

    /** Handle a change in the local address, i.e. an active migration (mod.rs:3109). */
    fun localAddressChanged() {
        updateRemCid()
        ping()
    }

    /** Switch to a previously unused remote connection ID, if possible (mod.rs:3115). */
    private fun updateRemCid() {
        val next = remCids.next() ?: return

        // Retire the current remote CID and any CIDs we had to skip.
        val retire = spaces[SpaceId.Data].pending.retireCids
        for (seq in next.start until next.end) retire.add(seq)
        setResetToken(next.resetToken)
    }

    private fun setResetToken(resetToken: ResetToken) {
        endpointEvents.addLast(EndpointEvent.ResetTokenChanged(path.remote, resetToken))
        peerParams.statelessResetToken = resetToken
    }

    /** Issue an initial set of connection IDs to the peer upon connection (mod.rs:3139). */
    private fun issueFirstCids(now: Instant) {
        if (localCidState.cidLen == 0) return

        // Subtract 1 to account for the CID we supplied while handshaking
        var n = peerParams.issueCidsLimit() - 1
        val server = side as? ConnectionSide.Server
        if (server != null && server.serverConfig.hasPreferredAddress()) {
            // We also sent a CID in the transport parameters
            n -= 1
        }
        endpointEvents.addLast(EndpointEvent.NeedIdentifiers(now, n))
    }

    /** Write the frames of one packet into [buf], recording them in [sentFrames] (mod.rs:3156). */
    private fun populatePacket(now: Instant, spaceId: SpaceId, buf: Buffer, maxSize: Int, pn: Long) {
        val sent = sentFrames
        sent.reset()
        val space = spaces[spaceId]
        val is0rtt = spaceId == SpaceId.Data && space.crypto == null
        space.pendingAcks.maybeAckNonEliciting()

        val prePayloadLen = buf.len

        // HANDSHAKE_DONE
        if (!is0rtt && space.pending.handshakeDone) {
            space.pending.handshakeDone = false
            FrameType.HANDSHAKE_DONE.encode(buf)
            sent.retransmits.getOrCreate().handshakeDone = true
            // This is just a u8 counter and the frame is typically just sent once
            stats.frameTx.handshakeDone = minOf(stats.frameTx.handshakeDone + 1, 255)
        }

        // PING
        if (space.pingPending) {
            space.pingPending = false
            FrameType.PING.encode(buf)
            sent.nonRetransmits = true
            stats.frameTx.ping += 1
        }

        // IMMEDIATE_ACK
        if (space.immediateAckPending) {
            space.immediateAckPending = false
            FrameType.IMMEDIATE_ACK.encode(buf)
            sent.nonRetransmits = true
            stats.frameTx.immediateAck += 1
        }

        // ACK
        if (space.pendingAcks.canSend()) tryPopulateAcks(now, receivingEcn, sent, space, buf, stats, maxSize)

        // ACK_FREQUENCY
        if (space.pending.ackFrequency) {
            space.pending.ackFrequency = false
            val sequenceNumber = ackFrequency.nextSequenceNumber()

            // Always provided when ACK frequency is enabled
            val cfg = config.ackFrequencyConfig!!

            // Ensure the delay is within bounds to avoid a PROTOCOL_VIOLATION error
            val maxAckDelay = ackFrequency.candidateMaxAckDelay(path.rtt.get(), cfg, peerParams)

            val requestMaxAckDelay = VarInt.fromLongOrNull(maxAckDelay.inWholeMicroseconds) ?: VarInt.MAX
            FrameType.ACK_FREQUENCY.encode(buf)
            buf.writeVar(sequenceNumber)
            buf.writeVar(cfg.ackElicitingThreshold)
            buf.writeVar(requestMaxAckDelay)
            buf.writeVar(cfg.reorderingThreshold)

            sent.retransmits.getOrCreate().ackFrequency = true

            ackFrequency.ackFrequencySent(pn, maxAckDelay)
            stats.frameTx.ackFrequency += 1
        }

        // PATH_CHALLENGE
        if (buf.len + 9 < maxSize && spaceId == SpaceId.Data) {
            // Transmit challenges with every outgoing frame on an unvalidated path
            val token = path.challenge
            if (token != null) {
                // But only send a packet solely for that purpose at most once
                path.challengePending = false
                sent.nonRetransmits = true
                sent.requiresPadding = true
                FrameType.PATH_CHALLENGE.encode(buf)
                buf.writeLong(token)
                stats.frameTx.pathChallenge += 1
            }
        }

        // PATH_RESPONSE
        if (buf.len + 9 < maxSize && spaceId == SpaceId.Data) {
            val token = pathResponses.popOnPath(path.remote)
            if (token != null) {
                sent.nonRetransmits = true
                sent.requiresPadding = true
                FrameType.PATH_RESPONSE.encode(buf)
                buf.writeLong(token)
                stats.frameTx.pathResponse += 1
            }
        }

        // CRYPTO
        while (buf.len + Frame.Crypto.SIZE_BOUND < maxSize && !is0rtt) {
            val frame = space.pending.crypto.removeFirstOrNull() ?: break

            // Calculate the maximum amount of crypto data we can store in the buffer. Since the offset is known, we can
            // reserve the exact size required to encode it. For length we reserve 2 bytes which allows to encode up to
            // 2^14, which is more than what fits into normally sized QUIC frames.
            val maxCryptoDataSize = maxSize - buf.len - 1 - varIntSize(frame.offset) - 2

            val len = minOf(frame.data.size, (1 shl 14) - 1, maxCryptoDataSize)

            val truncated = if (len == frame.data.size) frame else Frame.Crypto(frame.offset, frame.data.slice(0, len))
            truncated.encode(buf)
            stats.frameTx.crypto += 1
            sent.retransmits.getOrCreate().crypto.addLast(truncated)
            if (len < frame.data.size) {
                space.pending.crypto.addFirst(Frame.Crypto(frame.offset + len, frame.data.slice(len)))
            }
        }

        if (spaceId == SpaceId.Data) streams.writeControlFrames(buf, space.pending, sent.retransmits, stats.frameTx, maxSize)

        // NEW_CONNECTION_ID
        while (buf.len + Frame.NewConnectionId.SIZE_BOUND < maxSize) {
            val newCids = space.pending.newCids
            if (newCids.isEmpty()) break
            val issued = newCids.removeAt(newCids.size - 1)
            // Frame.NewConnectionId(...).encode(buf), without the frame object
            FrameType.NEW_CONNECTION_ID.encode(buf)
            buf.writeVar(issued.sequence)
            buf.writeVar(localCidState.retirePriorTo())
            buf.writeByte(issued.id.size.toByte())
            issued.id.encode(buf)
            issued.resetToken.encode(buf)
            sent.retransmits.getOrCreate().newCids.add(issued)
            stats.frameTx.newConnectionId += 1
        }

        // RETIRE_CONNECTION_ID
        while (buf.len + Frame.RetireConnectionId.SIZE_BOUND < maxSize) {
            val retireCids = space.pending.retireCids
            if (retireCids.isEmpty()) break
            val seq = retireCids.removeLast()
            FrameType.RETIRE_CONNECTION_ID.encode(buf)
            buf.writeVar(seq)
            sent.retransmits.getOrCreate().retireCids.add(seq)
            stats.frameTx.retireConnectionId += 1
        }

        // DATAGRAM
        var sentDatagrams = false
        while (buf.len + Frame.Datagram.SIZE_BOUND < maxSize && spaceId == SpaceId.Data) {
            if (datagrams.write(buf, maxSize)) {
                sentDatagrams = true
                sent.nonRetransmits = true
                stats.frameTx.datagram += 1
            } else {
                break
            }
        }
        if (datagrams.sendBlocked && sentDatagrams) {
            events.addLast(Event.DatagramsUnblocked)
            datagrams.sendBlocked = false
        }

        // NEW_TOKEN
        while (true) {
            val newTokens = space.pending.newTokens
            if (newTokens.isEmpty()) break
            val remoteAddr = newTokens.removeAt(newTokens.size - 1)
            debugAssert(spaceId == SpaceId.Data) { "assertion `left == right` failed" }
            val server = side as? ConnectionSide.Server ?: error("NEW_TOKEN frames should not be enqueued by clients")

            if (remoteAddr != path.remote) {
                // NEW_TOKEN frames contain tokens bound to a client's IP address, and are only useful if used from the
                // same IP address. Thus, we abandon enqueued NEW_TOKEN frames upon an path change. Instead, when the
                // new path becomes validated, NEW_TOKEN frames may be enqueued for the new path instead.
                continue
            }

            val serverConfig = server.serverConfig
            val token = Token.new(TokenPayload.Validation(remoteAddr.ipBytes(), serverConfig.timeSource.now()), rng)
            val encoded = token.encode(serverConfig.tokenKey)
            val newTokenSize = 1 + varIntSize(encoded.size.toLong()) + encoded.size

            if (buf.len + newTokenSize >= maxSize) {
                newTokens.add(remoteAddr)
                break
            }

            FrameType.NEW_TOKEN.encode(buf)
            buf.writeVar(encoded.size.toLong())
            buf.writeBytes(encoded)
            sent.retransmits.getOrCreate().newTokens.add(remoteAddr)
            stats.frameTx.newToken += 1
        }

        // STREAM
        if (spaceId == SpaceId.Data) {
            sent.streamFrames = streams.writeStreamFrames(buf, maxSize, config.sendFairness)
            stats.frameTx.stream += sent.streamFrames.size.toLong()
        }

        // Bundle ACK with other frames when there is room for them. We want to reuse encryption and underlying
        // protocol overhead, but sending multiple ACKs for a single incoming packet is a waste of peer's resources, so
        // we have next_bundled_ack_time to control when to send ACKs.
        val anyFramesSent = buf.len > prePayloadLen
        if (anyFramesSent && sent.largestAcked < 0 && nextBundledAckTime.isSome && nextBundledAckTime <= now &&
            space.pendingAcks.canSendWithOtherFrames()
        ) {
            tryPopulateAcks(now, receivingEcn, sent, space, buf, stats, maxSize)
        }
    }

    /**
     * Tries to write pending ACKs into a buffer if there is enough space (mod.rs:3448). If the ACK frame does not fit,
     * it is not sent at all. Assumes ACKs are pending.
     *
     * ⚖️ quinn encodes, then truncates the buffer if the frame did not fit; `Buffer` cannot truncate, so the encoded
     * size is computed first.
     */
    private fun tryPopulateAcks(
        now: Instant,
        receivingEcn: Boolean,
        sent: SentFrames,
        space: PacketSpace,
        buf: Buffer,
        stats: ConnectionStats,
        maxSize: Int,
    ) {
        val ranges = space.pendingAcks.ranges()
        debugAssert(!ranges.isEmpty()) { "assertion failed: !space.pending_acks.ranges().is_empty()" }

        // 0-RTT packets must never carry acks (which would have to be of handshake packets)
        debugAssert(space.crypto != null) { "tried to send ACK in 0-RTT" }
        val ecn = if (receivingEcn) space.ecnCounters else null

        val delayMicros = space.pendingAcks.ackDelay(now).inWholeMicroseconds

        // TODO (as in quinn): This should come from `TransportConfig` if that gets configurable.
        val delay = delayMicros ushr ACK_DELAY_EXPONENT

        if (buf.len + Frame.Ack.encodedSize(delay, ranges, ecn) > maxSize) {
            // The ACK frame is too large; don't send it.
            return
        }
        Frame.Ack.encode(delay, ranges, ecn, buf)
        sent.largestAcked = ranges.maxOrNone()
        stats.frameTx.acks += 1
    }

    private fun closeCommon() {
        // connection closed
        for (timer in TIMERS) timers.stop(timer)
    }

    private fun setCloseTimer(now: Instant) {
        timers.set(Timer.Close, now + pto(highestSpace) * 3)
    }

    /** Handle transport parameters received from the peer (mod.rs:3503). */
    private fun handlePeerParams(params: TransportParameters) {
        if (origRemCid != params.initialSrcCid ||
            (side.isClient && (initialDstCid != params.originalDstCid || retrySrcCid != params.retrySrcCid))
        ) {
            throw TransportError.TRANSPORT_PARAMETER_ERROR("CID authentication failure")
        }

        setPeerParams(params)
    }

    private fun setPeerParams(params: TransportParameters) {
        streams.setParams(params)
        idleTimeout = negotiateMaxIdleTimeout(config.maxIdleTimeout, params.maxIdleTimeout)
        params.preferredAddress?.let { info ->
            // The preferred address CID is the first received, and hence is guaranteed to be legal
            remCids.insert(Frame.NewConnectionId(1, 0, info.connectionId, info.statelessResetToken))
        }
        ackFrequency.peerMaxAckDelay = getMaxAckDelay(params)
        peerParams = params
        path.mtud.onPeerMaxUdpPayloadSizeReceived(minOf(params.maxUdpPayloadSize.value, 0xFFFFL).toInt())
    }

    /** Decrypt [packet] in place; returns its number, [NO_PACKET_NUMBER] or [DECRYPT_FAILED] (mod.rs:3539). */
    private fun decryptPacket(now: Instant, packet: Packet): Long {
        val number = decryptPacketBody(packet, spaces, zeroRttCrypto, keyPhase, prevCrypto, nextCrypto, decryptResult)
        if (number < 0) return number

        if (decryptResult.outgoingKeyUpdateAcked) {
            val prev = prevCrypto
            if (prev != null) {
                prev.endPacket = number
                prev.endPacketTime = now
                setKeyDiscardTimer(now, packet.header.space)
            }
        }

        if (decryptResult.incomingKeyUpdate) {
            // key update authenticated
            updateKeys(number, now, true)
            setKeyDiscardTimer(now, packet.header.space)
        }

        return number
    }

    /** mod.rs:3574; [endPacket] -1 for none. */
    private fun updateKeys(endPacket: Long, endPacketTime: Instant, remote: Boolean) {
        // Generate keys for the key phase after the one we're switching to, store them in `next_crypto`, make the
        // contents of `next_crypto` current, and move the current keys into `prev_crypto`.
        val new = crypto.next1rttKeys() ?: error("only called for `Data` packets")
        keyPhaseSize = saturatingSubU(new.local.confidentialityLimit, KEY_UPDATE_MARGIN)
        // safe because update_keys() can only be triggered by short packets
        val current = spaces[SpaceId.Data].crypto!!
        val old = current.packet
        spaces[SpaceId.Data].crypto = Keys(current.header, nextCrypto!!)
        nextCrypto = new
        spaces[SpaceId.Data].sentWithKeys = 0
        prevCrypto?.crypto?.close()           // an earlier phase still retained: its keys are retired now
        prevCrypto = PrevCrypto(old, endPacket, endPacketTime, remote)
        keyPhase = !keyPhase
    }

    private fun peerSupportsAckFrequency(): Boolean = peerParams.minAckDelay != null

    /**
     * Send an IMMEDIATE_ACK frame to the remote endpoint. According to the spec, this will result in an error if the
     * remote endpoint does not support the Acknowledgement Frequency extension.
     */
    internal fun immediateAck() {
        spaces[highestSpace].immediateAckPending = true
    }

    /**
     * Decodes a packet, returning its decrypted payload, so it can be inspected in tests (mod.rs:3618). Works on a copy
     * of the datagram (quinn clones the `PartialDecode`).
     */
    internal fun decodePacket(event: ConnectionEvent): ByteArray? {
        val datagram = event as? ConnectionEvent.Datagram ?: return null
        val first = datagram.firstDecode
        check(!first.hasRest) { "Packets should never be coalesced in tests" }

        val copy = first.data.copyOfRange(first.start, first.end)
        val partialDecode = try {
            PartialDecode.decode(copy, cidParser, ownVersion, endpointConfig.greaseQuicBit)
        } catch (e: PacketDecodeError) {
            return null
        }
        val headerCrypto: HeaderKey? = if (partialDecode.is0rtt) {
            zeroRttCrypto?.header ?: return null
        } else {
            val space = partialDecode.space
            if (space != null) spaces[space].crypto?.header?.remote ?: return null else null
        }
        val packet = try {
            partialDecode.finish(headerCrypto)
        } catch (e: PacketDecodeError) {
            return null
        }
        val number = try {
            decryptPacketBody(packet, spaces, zeroRttCrypto, keyPhase, prevCrypto, nextCrypto, DecryptPacketResult())
        } catch (e: TransportError) {
            return null
        }
        if (number == DECRYPT_FAILED) return null
        return packet.payload()
    }

    /** The number of bytes of packets containing retransmittable frames that have not been acknowledged or lost. */
    internal fun bytesInFlight(): Long = path.inFlight.bytes

    /** Number of bytes worth of non-ack-only packets that may be sent. */
    internal fun congestionWindow(): Long = saturatingSubU(path.congestion.window(), path.inFlight.bytes)

    /** Whether no timers but keepalive, idle, rtt, pushnewcid, and key discard are running (mod.rs:3671). */
    internal fun isIdle(): Boolean {
        var best: Timer? = null
        var bestTime = Instant.NONE
        for (t in TIMERS) {
            if (t == Timer.KeepAlive || t == Timer.PushNewCid || t == Timer.KeyDiscard) continue
            val time = timers.get(t)
            if (time.isNone) continue
            if (best == null || time < bestTime) {
                best = t
                bestTime = time
            }
        }
        return best == null || best == Timer.Idle
    }

    /** Whether explicit congestion notification is in use on outgoing packets. */
    internal fun usingEcn(): Boolean = path.sendingEcn

    /** The number of received bytes in the current path. */
    internal fun totalRecvd(): Long = path.totalRecvd

    internal fun activeLocalCidSeq(): Pair<Long, Long> = localCidState.activeSeqBounds()

    /**
     * Instruct the peer to replace previously issued CIDs by sending a NEW_CONNECTION_ID frame with updated
     * `retire_prior_to` field set to [v].
     */
    internal fun rotateLocalCid(v: Long, now: Instant) {
        val n = localCidState.assignRetireSeq(v)
        endpointEvents.addLast(EndpointEvent.NeedIdentifiers(now, n))
    }

    /** The current active remote CID sequence. */
    internal fun activeRemCidSeq(): Long = remCids.activeSeq()

    /** The detected maximum UDP payload size for the current path. */
    internal fun pathMtu(): Int = path.currentMtu()

    /** Whether we have 1-RTT data to send (mod.rs:3721). */
    private fun canSend1rtt(maxSize: Int): Boolean =
        streams.canSendStreamData() ||
            path.challengePending ||
            prevPath?.challengePending == true ||
            !pathResponses.isEmpty() ||
            datagrams.outgoing.canSend1rtt(maxSize)

    /** Update counters to account for a packet becoming acknowledged, lost, or abandoned. */
    private fun removeInFlight(packet: SentPacket) {
        // Visit known paths from newest to oldest to find the one `packet` was sent on
        if (path.removeInFlight(packet)) return
        prevPath?.removeInFlight(packet)
    }

    /**
     * ⚖️ Free every key the connection still holds when it drains (quinn drops them with the connection). The 1-RTT
     * header keys are shared by the current and the retired packet keys, so each key is closed once through its owner.
     * The crypto session is released too (the release contract of [CryptoSession]).
     */
    private fun releaseKeys() {
        for (space in spaces) {
            space.crypto?.close()
            space.crypto = null
        }
        nextCrypto?.close(); nextCrypto = null
        prevCrypto?.crypto?.close(); prevCrypto = null
        zeroRttCrypto?.close(); zeroRttCrypto = null
        crypto.close()
    }

    /**
     * Release the keys and the crypto session of a connection the endpoint discards without draining it (a server
     * connection whose first packet failed; quinn drops it).
     */
    internal fun releaseDiscarded() = releaseKeys()

    /** Terminate the connection instantly, without sending a close packet. */
    internal fun kill(reason: ConnectionError) {
        closeCommon()
        error = reason
        state = State.Drained
        releaseKeys()
            endpointEvents.addLast(EndpointEvent.Drained)
    }

    /**
     * Storage size required for the largest packet known to be supported by the current path. Buffers passed to
     * [pollTransmit] should be at least this large.
     */
    fun currentMtu(): Int = path.currentMtu()

    /**
     * Size of non-frame data for a 1-RTT packet (mod.rs:3766): the QUIC header and AEAD tag. [pn] -1 (quinn `None`)
     * gives the upper bound for any packet number length.
     */
    private fun predict1rttOverhead(pn: Long): Int {
        val pnLen = if (pn >= 0) {
            val largestAcked = spaces[SpaceId.Data].largestAckedPacket
            PacketNumber.new(pn, if (largestAcked < 0) 0 else largestAcked).len
        } else {
            // Upper bound
            4
        }

        // 1 byte for flags
        return 1 + remCids.active().size + pnLen + tagLen1rtt()
    }

    private fun tagLen1rtt(): Int {
        val key = spaces[SpaceId.Data].crypto?.packet?.local ?: zeroRttCrypto?.packet
        // If neither Data nor 0-RTT keys are available, make a reasonable tag length guess. As of this writing, all
        // QUIC cipher suites use 16-byte tags. We could return `None` instead, but that would needlessly prevent
        // sending datagrams during 0-RTT.
        return key?.tagLen ?: 16
    }

    /** Mark the path as validated, and enqueue NEW_TOKEN frames to be sent as appropriate (mod.rs:3793). */
    private fun onPathValidated() {
        path.validated = true
        val server = side as? ConnectionSide.Server ?: return
        val newTokens = spaces[SpaceId.Data].pending.newTokens
        newTokens.clear()
        repeat(server.serverConfig.validationToken.sent) { newTokens.add(path.remote) }
    }

    /** The client's token for outgoing Initial packets (empty on servers). */
    internal fun clientToken(): Bytes = (side as? ConnectionSide.Client)?.token ?: Bytes.EMPTY

    /** quinn `Datagrams::max_size` (datagrams.rs:84): -1 for `None`. */
    internal fun datagramMaxSize(): Long =
        DatagramState.maxSize(path.currentMtu(), predict1rttOverhead(-1), peerParams.maxDatagramFrameSize)

    /** quinn `Datagrams::drop_oversized` (datagrams.rs:58). */
    private fun dropOversizedDatagrams() {
        if (datagrams.dropOversizedAndUnblock(datagramMaxSize())) events.addLast(Event.DatagramsUnblocked)
    }

    override fun toString(): String = "Connection(handshakeCid=$handshakeCid)"

    private companion object {
        val SPACE_IDS = arrayOf(SpaceId.Initial, SpaceId.Handshake, SpaceId.Data)
        val TIMERS = Timer.entries.toTypedArray()
    }
}

/** Fields of a connection specific to it being client-side or server-side (mod.rs:3815). */
private sealed class ConnectionSide {
    class Client(
        /** Sent in every outgoing Initial packet. Always empty after Initial keys are discarded. */
        var token: Bytes,
        val tokenStore: TokenStore,
        val serverName: String,
    ) : ConnectionSide()

    class Server(val serverConfig: ServerConfig) : ConnectionSide()

    fun remoteMayMigrate(): Boolean = this is Server && serverConfig.migration

    val side: Side get() = if (this is Client) Side.Client else Side.Server
    val isClient: Boolean get() = this is Client
    val isServer: Boolean get() = this is Server
}

/** Parameters to create a connection specific to it being client-side or server-side (mod.rs:3872). */
internal sealed class SideArgs {
    class Client(val tokenStore: TokenStore, val serverName: String) : SideArgs()

    class Server(val serverConfig: ServerConfig, val prefAddrCid: ConnectionId?, val pathValidated: Boolean) : SideArgs()

    val side: Side get() = if (this is Client) Side.Client else Side.Server
}

/** Reasons why a connection might be lost (mod.rs:3909). */
sealed class ConnectionError(message: String) : Exception(message) {
    /** The peer doesn't implement any supported version. */
    data object VersionMismatch : ConnectionError("peer doesn't implement any supported version")

    /** The peer violated the QUIC specification as understood by this implementation. */
    data class Transport(val error: TransportError) : ConnectionError(error.message)

    /** The peer's QUIC stack aborted the connection automatically. */
    data class ConnectionClosed(val reason: Frame.ConnectionClose) : ConnectionError("aborted by peer: $reason")

    /** The peer closed the connection. */
    data class ApplicationClosed(val reason: Frame.ApplicationClose) : ConnectionError("closed by peer: $reason")

    /** The peer is unable to continue processing this connection, usually due to having restarted. */
    data object Reset : ConnectionError("reset by peer")

    /**
     * Communication with the peer has lapsed for longer than the negotiated idle timeout. If neither side is sending
     * keep-alives, a connection will time out after a long enough idle period even if the peer is still reachable.
     */
    data object TimedOut : ConnectionError("timed out")

    /** The local application closed the connection. */
    data object LocallyClosed : ConnectionError("closed")

    /** The connection could not be created because not enough of the CID space is available. */
    data object CidsExhausted : ConnectionError("CIDs exhausted")
}

/** quinn `From<Close> for ConnectionError`. */
internal fun Frame.Close.toConnectionError(): ConnectionError = when (this) {
    is Frame.ConnectionClose -> ConnectionError.ConnectionClosed(this)
    is Frame.ApplicationClose -> ConnectionError.ApplicationClosed(this)
}

/** Connection state (mod.rs:3969). */
internal sealed class State {
    class Handshake(
        /** Whether the remote CID has been set by the peer yet. Always set for servers. */
        var remCidSet: Boolean,
        /** Stateless retry token received in the first Initial by a server; must be in every Initial. */
        var expectedToken: Bytes,
        /** First cryptographic message; only set for clients. */
        var clientHello: Bytes?,
    ) : State()

    data object Established : State()

    class Closed(val reason: Frame.Close) : State()

    data object Draining : State()

    /** Waiting for application to call close so we can dispose of the resources. */
    data object Drained : State()

    val isHandshake: Boolean get() = this is Handshake
    val isEstablished: Boolean get() = this === Established
    val isClosed: Boolean get() = this is Closed || this === Draining || this === Drained
    val isDrained: Boolean get() = this === Drained
}

/**
 * Events of interest to the application (mod.rs:4031). ⚖️ quinn's `Event::Stream(StreamEvent)` is [StreamEvent]
 * itself, a subtype of this class.
 */
sealed class Event {
    /** The connection's handshake data is ready. */
    data object HandshakeDataReady : Event()

    /** The connection was successfully established. */
    data object Connected : Event()

    /** The connection was lost, because the peer closed it or an error was encountered. */
    data class ConnectionLost(val reason: ConnectionError) : Event()

    /** One or more application datagrams have been received. */
    data object DatagramReceived : Event()

    /** One or more application datagrams have been sent after blocking. */
    data object DatagramsUnblocked : Event()
}

/** The frames written into one packet (mod.rs:4081), reused across packets. */
internal class SentFrames {
    val retransmits = ThinRetransmits()

    /** The largest packet number acknowledged by an ACK frame in the packet; -1 for none. */
    var largestAcked = -1L
    var streamFrames: StreamMetaVec = StreamMetaVec.EMPTY

    /** Whether the packet contains non-retransmittable frames (like datagrams). */
    var nonRetransmits = false
    var requiresPadding = false

    fun reset() {
        retransmits.set(null)
        largestAcked = -1
        streamFrames = StreamMetaVec.EMPTY
        nonRetransmits = false
        requiresPadding = false
    }

    /** Whether the packet contains only ACKs. */
    fun isAckOnly(streams: StreamsState): Boolean =
        largestAcked >= 0 && !nonRetransmits && streamFrames.isEmpty() && retransmits.isEmpty(streams)
}

/**
 * API to control datagram traffic (quinn `Datagrams`, datagrams.rs:14): a view of a connection, valid while the
 * connection is not otherwise used.
 */
class Datagrams internal constructor(private val conn: Connection) {
    /**
     * Queue an unreliable, unordered datagram for immediate transmission. If [drop] is true, previously queued
     * datagrams which are still unsent may be discarded to make space for this datagram, in order of oldest to newest.
     * If [drop] is false and there isn't enough space, returns [SendDatagramError.Blocked]; `DatagramsUnblocked` is
     * emitted once datagrams have been sent. Returns `null` on success.
     */
    fun send(data: Bytes, drop: Boolean): SendDatagramError? = conn.datagrams.send(
        data,
        drop,
        conn.config.datagramReceiveBufferSize ?: -1L,
        conn.config.datagramSendBufferSize,
        conn.datagramMaxSize(),
    )

    /**
     * The maximum size of datagrams that may be passed to [send]; `null` if datagrams are unsupported by the peer or
     * disabled locally. This may change over the lifetime of a connection according to variation in the path MTU
     * estimate. Not necessarily the maximum size of received datagrams.
     */
    fun maxSize(): Int? {
        val n = conn.datagramMaxSize()
        return if (n < 0) null else n.toInt()
    }

    /** Receive an unreliable, unordered datagram. */
    fun recv(): Bytes? = conn.datagrams.recv()

    /**
     * Bytes available in the outgoing datagram buffer. When greater than zero, sending a datagram of at most this size
     * is guaranteed not to cause older datagrams to be dropped.
     */
    fun sendBufferSpace(): Long = conn.datagrams.sendBufferSpace(conn.config.datagramSendBufferSize)
}

/** mod.rs:4051 */
private fun getMaxAckDelay(params: TransportParameters): Duration = (params.maxAckDelay.value * 1000).microseconds

/**
 * Compute the negotiated idle timeout from the local and remote max_idle_timeout transport parameters (mod.rs:4107):
 * zero means disabled; otherwise the minimum of the two. `null` when both endpoints have opted out of idle timeout.
 */
internal fun negotiateMaxIdleTimeout(x: VarInt?, y: VarInt?): Duration? {
    val a = x?.value ?: 0L
    val b = y?.value ?: 0L
    return when {
        a == 0L && b == 0L -> null
        a == 0L -> b.milliseconds
        b == 0L -> a.milliseconds
        else -> minOf(a, b).milliseconds
    }
}

/** Rust `u32::saturating_add` for the small counters stored as `Int`. */
private fun saturatingAddU32(a: Int, b: Int): Int {
    val r = a.toLong() + b
    return if (r > Int.MAX_VALUE) Int.MAX_VALUE else r.toInt()
}

/** Prevents overflow and improves behavior in extreme circumstances. */
private const val MAX_BACKOFF_EXPONENT = 16

/**
 * Largest amount of space that could be occupied by a Handshake or 0-RTT packet's header, excluding
 * packet-type-specific fields such as packet number or Initial token: flags + version + dcid len + dcid + scid len +
 * scid + length + pn.
 */
private const val MAX_HANDSHAKE_OR_0RTT_HEADER_SIZE = 1 + 4 + 1 + MAX_CID_SIZE + 1 + MAX_CID_SIZE + 4 + 4

/**
 * Minimal remaining size to allow packet coalescing, excluding cryptographic tag (mod.rs:4065). This must be at least
 * as large as the header for a well-formed empty packet to be coalesced, plus some space for frames. We only care
 * about handshake headers because short header packets necessarily have smaller headers, and initial packets are only
 * ever the first packet in a datagram (because we coalesce in ascending packet space order and the only reason to
 * split a packet is when packet space changes).
 */
private const val MIN_PACKET_SPACE = MAX_HANDSHAKE_OR_0RTT_HEADER_SIZE + 32


/** Perform key updates this many packets before the AEAD confidentiality limit. */
private const val KEY_UPDATE_MARGIN = 10_000L

/** GSO batches end rather than pad a packet by more than this. */
private const val MAX_PADDING = 16

/** The ACK delay exponent we advertise (the transport parameter default). */
private const val ACK_DELAY_EXPONENT = 3
