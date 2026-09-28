package neton.quic.proto

import kotlin.time.Duration

// Connection statistics (quinn-proto `connection/stats.rs`).

/**
 * Statistics about UDP datagrams transmitted or received on a connection (stats.rs:10).
 *
 * All QUIC packets are carried by UDP datagrams. Hence, these statistics cover all traffic on a connection.
 */
class UdpStats {
    /** The amount of UDP datagrams observed. */
    var datagrams: Long = 0

    /** The total amount of bytes which have been transferred inside UDP datagrams. */
    var bytes: Long = 0

    /**
     * The amount of I/O operations executed.
     *
     * Can be less than `datagrams` when GSO, GRO, and/or batched system calls are in use.
     */
    var ios: Long = 0

    internal fun onSent(datagrams: Long, bytes: Int) {
        this.datagrams += datagrams
        this.bytes += bytes.toLong()
        this.ios += 1
    }

    /** quinn's `Copy`. */
    fun copy(): UdpStats = UdpStats().also { it.datagrams = datagrams; it.bytes = bytes; it.ios = ios }

    override fun toString(): String = "UdpStats { datagrams: $datagrams, bytes: $bytes, ios: $ios }"
}

/** Number of frames transmitted or received of each frame type (quinn-proto `connection/stats.rs:33`). */
class FrameStats {
    var acks: Long = 0
    var ackFrequency: Long = 0
    var crypto: Long = 0
    var connectionClose: Long = 0
    var dataBlocked: Long = 0
    var datagram: Long = 0

    /** A `u8` in quinn, saturating at 255. */
    var handshakeDone: Int = 0
    var immediateAck: Long = 0
    var maxData: Long = 0
    var maxStreamData: Long = 0
    var maxStreamsBidi: Long = 0
    var maxStreamsUni: Long = 0
    var newConnectionId: Long = 0
    var newToken: Long = 0
    var pathChallenge: Long = 0
    var pathResponse: Long = 0
    var ping: Long = 0
    var resetStream: Long = 0
    var retireConnectionId: Long = 0
    var streamDataBlocked: Long = 0
    var streamsBlockedBidi: Long = 0
    var streamsBlockedUni: Long = 0
    var stopSending: Long = 0
    var stream: Long = 0

    /** stats.rs:61 */
    internal fun record(frame: Frame) {
        when (frame) {
            Frame.Padding -> {}
            Frame.Ping -> ping += 1
            is Frame.Ack -> acks += 1
            is Frame.ResetStream -> resetStream += 1
            is Frame.StopSending -> stopSending += 1
            is Frame.Crypto -> crypto += 1
            is Frame.Datagram -> datagram += 1
            is Frame.NewToken -> newToken += 1
            is Frame.MaxData -> maxData += 1
            is Frame.MaxStreamData -> maxStreamData += 1
            is Frame.MaxStreams -> if (frame.dir == Dir.Bi) maxStreamsBidi += 1 else maxStreamsUni += 1
            is Frame.DataBlocked -> dataBlocked += 1
            is Frame.Stream -> stream += 1
            is Frame.StreamDataBlocked -> streamDataBlocked += 1
            is Frame.StreamsBlocked -> if (frame.dir == Dir.Bi) streamsBlockedBidi += 1 else streamsBlockedUni += 1
            is Frame.NewConnectionId -> newConnectionId += 1
            is Frame.RetireConnectionId -> retireConnectionId += 1
            is Frame.PathChallenge -> pathChallenge += 1
            is Frame.PathResponse -> pathResponse += 1
            is Frame.Close -> connectionClose += 1
            is Frame.AckFrequency -> ackFrequency += 1
            Frame.ImmediateAck -> immediateAck += 1
            Frame.HandshakeDone -> handshakeDone = minOf(handshakeDone + 1, 255)
        }
    }

    /** quinn's `Clone` / `Copy`. */
    fun copy(): FrameStats = FrameStats().also {
        it.acks = acks; it.ackFrequency = ackFrequency; it.crypto = crypto; it.connectionClose = connectionClose
        it.dataBlocked = dataBlocked; it.datagram = datagram; it.handshakeDone = handshakeDone
        it.immediateAck = immediateAck; it.maxData = maxData; it.maxStreamData = maxStreamData
        it.maxStreamsBidi = maxStreamsBidi; it.maxStreamsUni = maxStreamsUni; it.newConnectionId = newConnectionId
        it.newToken = newToken; it.pathChallenge = pathChallenge; it.pathResponse = pathResponse; it.ping = ping
        it.resetStream = resetStream; it.retireConnectionId = retireConnectionId
        it.streamDataBlocked = streamDataBlocked; it.streamsBlockedBidi = streamsBlockedBidi
        it.streamsBlockedUni = streamsBlockedUni; it.stopSending = stopSending; it.stream = stream
    }

    /** quinn's `Debug`. */
    override fun toString(): String =
        "FrameStats { ACK: $acks, ACK_FREQUENCY: $ackFrequency, CONNECTION_CLOSE: $connectionClose, CRYPTO: $crypto, " +
            "DATA_BLOCKED: $dataBlocked, DATAGRAM: $datagram, HANDSHAKE_DONE: $handshakeDone, " +
            "IMMEDIATE_ACK: $immediateAck, MAX_DATA: $maxData, MAX_STREAM_DATA: $maxStreamData, " +
            "MAX_STREAMS_BIDI: $maxStreamsBidi, MAX_STREAMS_UNI: $maxStreamsUni, " +
            "NEW_CONNECTION_ID: $newConnectionId, NEW_TOKEN: $newToken, PATH_CHALLENGE: $pathChallenge, " +
            "PATH_RESPONSE: $pathResponse, PING: $ping, RESET_STREAM: $resetStream, " +
            "RETIRE_CONNECTION_ID: $retireConnectionId, STREAM_DATA_BLOCKED: $streamDataBlocked, " +
            "STREAMS_BLOCKED_BIDI: $streamsBlockedBidi, STREAMS_BLOCKED_UNI: $streamsBlockedUni, " +
            "STOP_SENDING: $stopSending, STREAM: $stream }"
}


/** Statistics related to a transmission path (stats.rs:139). */
class PathStats {
    /** Current best estimate of this connection's latency (round-trip-time). */
    var rtt: Duration = Duration.ZERO

    /** Minimum RTT seen on this path, ignoring ack delay. */
    var minRtt: Duration = Duration.ZERO

    /** Current congestion window of the connection. */
    var cwnd: Long = 0

    /** Congestion events on the connection. */
    var congestionEvents: Long = 0

    /** The amount of packets lost on this path. */
    var lostPackets: Long = 0

    /** The amount of bytes lost on this path. */
    var lostBytes: Long = 0

    /** The amount of packets sent on this path. */
    var sentPackets: Long = 0

    /** The amount of PLPMTUD probe packets sent on this path (also counted by `sent_packets`). */
    var sentPlpmtudProbes: Long = 0

    /** The amount of PLPMTUD probe packets lost on this path (ignored by `lost_packets` and `lost_bytes`). */
    var lostPlpmtudProbes: Long = 0

    /** The number of times a black hole was detected in the path. */
    var blackHolesDetected: Long = 0

    /** Largest UDP payload size the path currently supports. */
    var currentMtu: Int = 0

    /** quinn's `Copy`. */
    fun copy(): PathStats = PathStats().also {
        it.rtt = rtt; it.minRtt = minRtt; it.cwnd = cwnd; it.congestionEvents = congestionEvents
        it.lostPackets = lostPackets; it.lostBytes = lostBytes; it.sentPackets = sentPackets
        it.sentPlpmtudProbes = sentPlpmtudProbes; it.lostPlpmtudProbes = lostPlpmtudProbes
        it.blackHolesDetected = blackHolesDetected; it.currentMtu = currentMtu
    }

    override fun toString(): String =
        "PathStats { rtt: $rtt, min_rtt: $minRtt, cwnd: $cwnd, congestion_events: $congestionEvents, " +
            "lost_packets: $lostPackets, lost_bytes: $lostBytes, sent_packets: $sentPackets, " +
            "sent_plpmtud_probes: $sentPlpmtudProbes, lost_plpmtud_probes: $lostPlpmtudProbes, " +
            "black_holes_detected: $blackHolesDetected, current_mtu: $currentMtu }"
}

/** Connection statistics (stats.rs:166). */
class ConnectionStats {
    /** Statistics about UDP datagrams transmitted on a connection. */
    var udpTx: UdpStats = UdpStats()

    /** Statistics about UDP datagrams received on a connection. */
    var udpRx: UdpStats = UdpStats()

    /** Statistics about frames transmitted on a connection. */
    var frameTx: FrameStats = FrameStats()

    /** Statistics about frames received on a connection. */
    var frameRx: FrameStats = FrameStats()

    /** Statistics related to the current transmission path. */
    var path: PathStats = PathStats()

    /** quinn's `Copy`. */
    fun copy(): ConnectionStats = ConnectionStats().also {
        it.udpTx = udpTx.copy(); it.udpRx = udpRx.copy(); it.frameTx = frameTx.copy(); it.frameRx = frameRx.copy()
        it.path = path.copy()
    }

    override fun toString(): String =
        "ConnectionStats { udp_tx: $udpTx, udp_rx: $udpRx, frame_tx: $frameTx, frame_rx: $frameRx, path: $path }"
}
