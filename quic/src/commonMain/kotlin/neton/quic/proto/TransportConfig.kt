package neton.quic.proto

import kotlin.time.Duration
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

// Transport configuration (quinn-proto `config/transport.rs`).
//
// quinn's `&mut self -> &mut Self` setters are fluent functions named after the option (returning this); the values
// are readable inside the protocol layer as same-named properties (quinn `pub(crate)` fields). ⚖️ Rust `u16`
// arguments (MTUs) are `Int`s and throw [IllegalArgumentException] outside 0..65535, where Rust's type would not
// compile; `u32` counts are non-negative `Int`s; `usize` buffer sizes are `Long`s.

private fun requireU16(value: Int) = require(value in 0..0xFFFF) { "$value is not a u16" }

/**
 * Parameters governing the core QUIC state machine (transport.rs:27).
 *
 * Default values should be suitable for most internet applications. Applications protocols which forbid
 * remotely-initiated streams should set `max_concurrent_bidi_streams` and `max_concurrent_uni_streams` to zero.
 *
 * In some cases, performance or resource requirements can be improved by tuning these values to suit a particular
 * application and/or network connection. In particular, data window sizes can be tuned for a particular expected
 * round trip time, link capacity, and memory availability. Tuning for higher bandwidths and latencies increases
 * worst-case memory consumption, but does not impair performance at lower bandwidths and latencies. The default
 * configuration is tuned for a 100Mbps link with a 100ms round trip time.
 *
 * ⛔ quinn's `qlog_stream` option is not ported (qlog is deferred, SPEC §8).
 */
class TransportConfig {
    internal var maxConcurrentBidiStreams: VarInt = VarInt(100); private set
    internal var maxConcurrentUniStreams: VarInt = VarInt(100); private set

    /** 30 second default recommended by RFC 9308 § 3.2; `null` is infinite. */
    internal var maxIdleTimeout: VarInt? = VarInt(30_000); private set
    internal var streamReceiveWindow: VarInt = VarInt(STREAM_RWND); private set
    internal var receiveWindow: VarInt = VarInt.MAX; private set
    internal var sendWindow: Long = 8 * STREAM_RWND; private set
    internal var sendFairness: Boolean = true; private set

    internal var packetThreshold: Int = 3; private set
    internal var timeThreshold: Float = 9.0f / 8.0f; private set

    /** Per spec, intentionally distinct from EXPECTED_RTT. */
    internal var initialRtt: Duration = 333.milliseconds; private set
    internal var initialMtu: Int = INITIAL_MTU; private set
    internal var minMtu: Int = INITIAL_MTU; private set
    internal var mtuDiscoveryConfig: MtuDiscoveryConfig? = MtuDiscoveryConfig(); private set
    internal var padToMtu: Boolean = false; private set
    internal var ackFrequencyConfig: AckFrequencyConfig? = null; private set

    internal var persistentCongestionThreshold: Int = 3; private set
    internal var keepAliveInterval: Duration? = null; private set
    internal var cryptoBufferSize: Long = 16 * 1024; private set
    internal var allowSpin: Boolean = true; private set
    internal var datagramReceiveBufferSize: Long? = STREAM_RWND; private set
    internal var datagramSendBufferSize: Long = 1024 * 1024; private set

    /** quinn's `#[cfg(test)]` option: whether to force every packet number to be used (⚖️ always present, internal). */
    internal var deterministicPacketNumbers: Boolean = false; private set

    internal var congestionControllerFactory: ControllerFactory = CubicConfig(); private set

    internal var enableSegmentationOffload: Boolean = true; private set

    /**
     * Maximum number of incoming bidirectional streams that may be open concurrently.
     *
     * Must be nonzero for the peer to open any bidirectional streams.
     *
     * Worst-case memory use is directly proportional to `max_concurrent_bidi_streams * stream_receive_window`, with
     * an upper bound proportional to `receive_window`.
     */
    fun maxConcurrentBidiStreams(value: VarInt): TransportConfig { maxConcurrentBidiStreams = value; return this }

    /** Variant of `max_concurrent_bidi_streams` affecting unidirectional streams. */
    fun maxConcurrentUniStreams(value: VarInt): TransportConfig { maxConcurrentUniStreams = value; return this }

    /**
     * Maximum duration of inactivity to accept before timing out the connection.
     *
     * The true idle timeout is the minimum of this and the peer's own max idle timeout. `null` represents an infinite
     * timeout. Defaults to 30 seconds.
     *
     * **WARNING**: If a peer or its network path malfunctions or acts maliciously, an infinite idle timeout can
     * result in permanently hung futures!
     */
    fun maxIdleTimeout(value: IdleTimeout?): TransportConfig { maxIdleTimeout = value?.value; return this }

    /**
     * Maximum number of bytes the peer may transmit without acknowledgement on any one stream before becoming
     * blocked.
     *
     * This should be set to at least the expected connection latency multiplied by the maximum desired throughput.
     * Setting this smaller than `receive_window` helps ensure that a single stream doesn't monopolize receive
     * buffers, which may otherwise occur if the application chooses not to read from a large stream for a time while
     * still requiring data on other streams.
     */
    fun streamReceiveWindow(value: VarInt): TransportConfig { streamReceiveWindow = value; return this }

    /**
     * Maximum number of bytes the peer may transmit across all streams of a connection before becoming blocked.
     *
     * This should be set to at least the expected connection latency multiplied by the maximum desired throughput.
     * Larger values can be useful to allow maximum throughput within a stream while another is blocked.
     */
    fun receiveWindow(value: VarInt): TransportConfig { receiveWindow = value; return this }

    /**
     * Maximum number of bytes retained from application writes across all streams of a connection.
     *
     * Acknowledged data continues to count against this limit until its storage is released. This can keep writes
     * blocked while earlier data is awaiting acknowledgment or only part of a buffer has been acknowledged.
     *
     * Limits memory use when communicating with peers that issue large amounts of flow control credit. Endpoints that
     * wish to handle large numbers of connections robustly should take care to set this low enough to avoid memory
     * exhaustion if every connection uses the entire window.
     *
     * The limit counts bytes accepted from application buffers. Slices of larger allocations can retain more memory
     * than this limit accounts for.
     */
    fun sendWindow(value: Long): TransportConfig {
        require(value >= 0) { "send window must not be negative" }
        sendWindow = value
        return this
    }

    /**
     * Whether to implement fair queuing for send streams having the same priority.
     *
     * When enabled, connections schedule data from outgoing streams having the same priority in a round-robin
     * fashion. When disabled, streams are scheduled in the order they are written to.
     *
     * Note that this only affects streams with the same priority. Higher priority streams always take precedence over
     * lower priority streams.
     *
     * Disabling fairness can reduce fragmentation and protocol overhead for workloads that use many small streams.
     */
    fun sendFairness(value: Boolean): TransportConfig { sendFairness = value; return this }

    /**
     * Maximum reordering in packet number space before FACK style loss detection considers a packet lost. Should not
     * be less than 3, per RFC5681.
     */
    fun packetThreshold(value: Int): TransportConfig {
        require(value >= 0) { "packet threshold must not be negative" }
        packetThreshold = value
        return this
    }

    /** Maximum reordering in time space before time based loss detection considers a packet lost, as a factor of RTT. */
    fun timeThreshold(value: Float): TransportConfig { timeThreshold = value; return this }

    /** The RTT used before an RTT sample is taken. */
    fun initialRtt(value: Duration): TransportConfig {
        require(!value.isNegative()) { "initial RTT must not be negative" }
        initialRtt = value
        return this
    }

    /**
     * The initial value to be used as the maximum UDP payload size before running MTU discovery (see
     * [mtuDiscoveryConfig]).
     *
     * Must be at least 1200, which is the default, and known to be safe for typical internet applications. Larger
     * values are more efficient, but increase the risk of packet loss due to exceeding the network path's IP MTU. If
     * the provided value is higher than what the network path actually supports, packet loss will eventually trigger
     * black hole detection and bring it down to [minMtu].
     */
    fun initialMtu(value: Int): TransportConfig {
        requireU16(value)
        initialMtu = maxOf(value, INITIAL_MTU)
        return this
    }

    internal fun getInitialMtu(): Int = maxOf(initialMtu, minMtu)

    /**
     * The maximum UDP payload size guaranteed to be supported by the network.
     *
     * Must be at least 1200, which is the default, and lower than or equal to [initialMtu].
     *
     * Real-world MTUs can vary according to ISP, VPN, and properties of intermediate network links outside of either
     * endpoint's control. Extreme care should be used when raising this value outside of private networks where these
     * factors are fully controlled. If the provided value is higher than what the network path actually supports, the
     * result will be unpredictable and catastrophic packet loss, without a possibility of repair. Prefer [initialMtu]
     * together with [mtuDiscoveryConfig] to set a maximum UDP payload size that robustly adapts to the network.
     */
    fun minMtu(value: Int): TransportConfig {
        requireU16(value)
        minMtu = maxOf(value, INITIAL_MTU)
        return this
    }

    /** Specifies the MTU discovery config (see [MtuDiscoveryConfig] for details). Enabled by default. */
    fun mtuDiscoveryConfig(value: MtuDiscoveryConfig?): TransportConfig { mtuDiscoveryConfig = value; return this }

    /**
     * Pad UDP datagrams carrying application data to current maximum UDP payload size.
     *
     * Disabled by default. UDP datagrams containing loss probes are exempt from padding.
     *
     * Enabling this helps mitigate traffic analysis by network observers, but it increases bandwidth usage. Without
     * this mitigation precise plain text size of application datagrams as well as the total size of stream write
     * bursts can be inferred by observers under certain conditions. This analysis requires either an uncongested
     * connection or application datagrams too large to be coalesced.
     */
    fun padToMtu(value: Boolean): TransportConfig { padToMtu = value; return this }

    /**
     * Specifies the ACK frequency config (see [AckFrequencyConfig] for details).
     *
     * The provided configuration will be ignored if the peer does not support the acknowledgement frequency QUIC
     * extension.
     *
     * Defaults to `null`, which disables controlling the peer's acknowledgement frequency. Even if set to `null`, the
     * local side still supports the acknowledgement frequency QUIC extension and may use it in other ways.
     */
    fun ackFrequencyConfig(value: AckFrequencyConfig?): TransportConfig { ackFrequencyConfig = value; return this }

    /** Number of consecutive PTOs after which network is considered to be experiencing persistent congestion. */
    fun persistentCongestionThreshold(value: Int): TransportConfig {
        require(value >= 0) { "persistent congestion threshold must not be negative" }
        persistentCongestionThreshold = value
        return this
    }

    /**
     * Period of inactivity before sending a keep-alive packet.
     *
     * Keep-alive packets prevent an inactive but otherwise healthy connection from timing out.
     *
     * `null` to disable, which is the default. Only one side of any given connection needs keep-alive enabled for the
     * connection to be preserved. Must be set lower than the idle_timeout of both peers to be effective.
     */
    fun keepAliveInterval(value: Duration?): TransportConfig { keepAliveInterval = value; return this }

    /** Maximum quantity of out-of-order crypto layer data to buffer. */
    fun cryptoBufferSize(value: Long): TransportConfig {
        require(value >= 0) { "crypto buffer size must not be negative" }
        cryptoBufferSize = value
        return this
    }

    /**
     * Whether the implementation is permitted to set the spin bit on this connection.
     *
     * This allows passive observers to easily judge the round trip time of a connection, which can be useful for
     * network administration but sacrifices a small amount of privacy.
     */
    fun allowSpin(value: Boolean): TransportConfig { allowSpin = value; return this }

    /**
     * Maximum number of incoming application datagram bytes to buffer, or `null` to disable incoming datagrams.
     *
     * The peer is forbidden to send single datagrams larger than this size. If the aggregate size of all datagrams
     * that have been received from the peer but not consumed by the application exceeds this value, old datagrams are
     * dropped until it is no longer exceeded.
     *
     * The amount of payload data buffered may be smaller than `value` due to overhead.
     */
    fun datagramReceiveBufferSize(value: Long?): TransportConfig {
        require(value == null || value >= 0) { "datagram receive buffer size must not be negative" }
        datagramReceiveBufferSize = value
        return this
    }

    /**
     * Maximum number of outgoing application datagram bytes to buffer.
     *
     * While datagrams are sent ASAP, it is possible for an application to generate data faster than the link, or even
     * the underlying hardware, can transmit them. This limits the amount of memory that may be consumed in that case.
     * When the send buffer is full and a new datagram is sent, older datagrams are dropped until sufficient space is
     * available.
     *
     * The amount of payload data buffered may be smaller than `value` due to overhead.
     */
    fun datagramSendBufferSize(value: Long): TransportConfig {
        require(value >= 0) { "datagram send buffer size must not be negative" }
        datagramSendBufferSize = value
        return this
    }

    /**
     * Whether to force every packet number to be used.
     *
     * By default, packet numbers are occasionally skipped to ensure peers aren't ACKing packets before they see them.
     */
    internal fun deterministicPacketNumbers(enabled: Boolean): TransportConfig { deterministicPacketNumbers = enabled; return this }

    /**
     * How to construct new congestion [Controller]s.
     *
     * Typically the configuration of a controller, e.g. a [NewRenoConfig]:
     * `TransportConfig().congestionControllerFactory(NewRenoConfig())`.
     */
    fun congestionControllerFactory(factory: ControllerFactory): TransportConfig {
        congestionControllerFactory = factory
        return this
    }

    /**
     * Whether to use "Generic Segmentation Offload" to accelerate transmits, when supported by the environment.
     *
     * Defaults to `true`.
     *
     * GSO dramatically reduces CPU consumption when sending large numbers of packets with the same headers, such as
     * when transmitting bulk data on a connection. However, it is not supported by all network interface drivers or
     * packet inspection tools. The datagram layer will attempt to disable GSO automatically when unavailable, but this
     * can lead to spurious packet loss at startup, temporarily degrading performance.
     */
    fun enableSegmentationOffload(enabled: Boolean): TransportConfig { enableSegmentationOffload = enabled; return this }

    /** quinn's `Debug` (the controller factory is not shown). */
    override fun toString(): String =
        "TransportConfig { max_concurrent_bidi_streams: $maxConcurrentBidiStreams, " +
            "max_concurrent_uni_streams: $maxConcurrentUniStreams, max_idle_timeout: $maxIdleTimeout, " +
            "stream_receive_window: $streamReceiveWindow, receive_window: $receiveWindow, send_window: $sendWindow, " +
            "send_fairness: $sendFairness, packet_threshold: $packetThreshold, time_threshold: $timeThreshold, " +
            "initial_rtt: $initialRtt, initial_mtu: $initialMtu, min_mtu: $minMtu, " +
            "mtu_discovery_config: $mtuDiscoveryConfig, pad_to_mtu: $padToMtu, " +
            "ack_frequency_config: $ackFrequencyConfig, persistent_congestion_threshold: $persistentCongestionThreshold, " +
            "keep_alive_interval: $keepAliveInterval, crypto_buffer_size: $cryptoBufferSize, allow_spin: $allowSpin, " +
            "datagram_receive_buffer_size: $datagramReceiveBufferSize, " +
            "datagram_send_buffer_size: $datagramSendBufferSize, " +
            "enable_segmentation_offload: $enableSegmentationOffload, .. }"

    private companion object {
        const val EXPECTED_RTT: Long = 100 // ms
        const val MAX_STREAM_BANDWIDTH: Long = 12500 * 1000 // bytes/s

        /** Window size needed to avoid pipeline stalls. */
        const val STREAM_RWND: Long = MAX_STREAM_BANDWIDTH / 1000 * EXPECTED_RTT
    }
}

/**
 * Parameters for controlling the peer's acknowledgement frequency (transport.rs:486).
 *
 * The parameters provided in this config will be sent to the peer at the beginning of the connection, so it can take
 * them into account when sending acknowledgements (see each parameter's description for details on how it influences
 * acknowledgement frequency).
 *
 * The implementation follows the fourth draft of the
 * [QUIC Acknowledgement Frequency extension](https://datatracker.ietf.org/doc/html/draft-ietf-quic-ack-frequency-04).
 * The defaults produce behavior slightly different than the behavior without this extension, because they change the
 * way reordered packets are handled (see [reorderingThreshold] for details).
 */
class AckFrequencyConfig {
    internal var ackElicitingThreshold: VarInt = VarInt(1); private set
    internal var maxAckDelay: Duration? = null; private set
    internal var reorderingThreshold: VarInt = VarInt(2); private set

    /**
     * The ack-eliciting threshold we will request the peer to use.
     *
     * This threshold represents the number of ack-eliciting packets an endpoint may receive without immediately
     * sending an ACK.
     *
     * The remote peer should send at least one ACK frame when more than this number of ack-eliciting packets have
     * been received. A value of 0 results in a receiver immediately acknowledging every ack-eliciting packet.
     *
     * Defaults to 1, which sends ACK frames for every other ack-eliciting packet.
     */
    fun ackElicitingThreshold(value: VarInt): AckFrequencyConfig { ackElicitingThreshold = value; return this }

    /**
     * The `max_ack_delay` we will request the peer to use.
     *
     * This parameter represents the maximum amount of time that an endpoint waits before sending an ACK when the
     * ack-eliciting threshold hasn't been reached.
     *
     * The effective `max_ack_delay` will be clamped to be at least the peer's `min_ack_delay` transport parameter, and
     * at most the greater of the current path RTT or 25ms.
     *
     * Defaults to `null`, in which case the peer's original `max_ack_delay` will be used, as obtained from its
     * transport parameters.
     */
    fun maxAckDelay(value: Duration?): AckFrequencyConfig { maxAckDelay = value; return this }

    /**
     * The reordering threshold we will request the peer to use.
     *
     * This threshold represents the amount of out-of-order packets that will trigger an endpoint to send an ACK,
     * without waiting for `ack_eliciting_threshold` to be exceeded or for `max_ack_delay` to be elapsed.
     *
     * A value of 0 indicates out-of-order packets do not elicit an immediate ACK. A value of 1 immediately
     * acknowledges any packets that are received out of order (this is also the behavior when the extension is
     * disabled).
     *
     * It is recommended to set this value to [TransportConfig.packetThreshold] minus one. Since the default value for
     * [TransportConfig.packetThreshold] is 3, this value defaults to 2.
     */
    fun reorderingThreshold(value: VarInt): AckFrequencyConfig { reorderingThreshold = value; return this }

    /** quinn's `Clone`. */
    fun copy(): AckFrequencyConfig = AckFrequencyConfig().also {
        it.ackElicitingThreshold = ackElicitingThreshold; it.maxAckDelay = maxAckDelay
        it.reorderingThreshold = reorderingThreshold
    }

    override fun toString(): String =
        "AckFrequencyConfig { ack_eliciting_threshold: $ackElicitingThreshold, max_ack_delay: $maxAckDelay, " +
            "reordering_threshold: $reorderingThreshold }"
}

/**
 * Parameters governing MTU discovery (transport.rs:697).
 *
 * # The why of MTU discovery
 *
 * By design, QUIC ensures during the handshake that the network path between the client and the server is able to
 * transmit unfragmented UDP packets with a body of 1200 bytes. In other words, once the connection is established,
 * we know that the network path's maximum transmission unit (MTU) is of at least 1200 bytes (plus IP and UDP
 * headers). Because of this, a QUIC endpoint can split outgoing data in packets of 1200 bytes, with confidence that
 * the network will be able to deliver them (if the endpoint were to send bigger packets, they could prove too big and
 * end up being dropped).
 *
 * There is, however, a significant overhead associated to sending a packet. If the same information can be sent in
 * fewer packets, that results in higher throughput. The amount of packets that need to be sent is inversely
 * proportional to the MTU: the higher the MTU, the bigger the packets that can be sent, and the fewer packets that
 * are needed to transmit a given amount of bytes.
 *
 * Most networks have an MTU higher than 1200. Through MTU discovery, endpoints can detect the path's MTU and, if it
 * turns out to be higher, start sending bigger packets.
 *
 * # MTU discovery internals
 *
 * MTU discovery is implemented through DPLPMTUD (Datagram Packetization Layer Path MTU Discovery), described in
 * [section 14.3 of RFC 9000](https://www.rfc-editor.org/rfc/rfc9000.html#section-14.3). This method consists of
 * sending QUIC packets padded to a particular size (called PMTU probes), and waiting to see if the remote peer
 * responds with an ACK. If an ACK is received, that means the probe arrived at the remote peer, which in turn means
 * that the network path's MTU is of at least the packet's size. If the probe is lost, it is sent another 2 times
 * before concluding that the MTU is lower than the packet's size.
 *
 * MTU discovery runs on a schedule (e.g. every 600 seconds) specified through [interval]. The first run happens right
 * after the handshake, and subsequent discoveries are scheduled to run when the interval has elapsed, starting from
 * the last time when MTU discovery completed.
 *
 * Since the search space for MTUs is quite big (the smallest possible MTU is 1200, and the highest is 65527), a
 * binary search keeps the number of probes as low as possible. The lower bound of the search is equal to
 * [TransportConfig.initialMtu] in the initial MTU discovery run, and is equal to the currently discovered MTU in
 * subsequent runs. The upper bound is determined by the minimum of [upperBound] and the `max_udp_payload_size`
 * transport parameter received from the peer during the handshake.
 *
 * # Black hole detection
 *
 * If, at some point, the network path no longer accepts packets of the detected size, packet loss will eventually
 * trigger black hole detection and reset the detected MTU to 1200. In that case, MTU discovery will be triggered after
 * [blackHoleCooldown] (ignoring the timer that was set based on [interval]).
 *
 * # Interaction between peers
 *
 * There is no guarantee that the MTU on the path between A and B is the same as the MTU of the path between B and A.
 * Therefore, each peer in the connection needs to run MTU discovery independently in order to discover the path's
 * MTU.
 */
class MtuDiscoveryConfig {
    internal var interval: Duration = 600.seconds; private set
    internal var upperBound: Int = 1452; private set
    internal var minimumChange: Int = 20; private set
    internal var blackHoleCooldown: Duration = 60.seconds; private set

    /**
     * Specifies the time to wait after completing MTU discovery before starting a new MTU discovery run.
     *
     * Defaults to 600 seconds, as recommended by [RFC 8899](https://www.rfc-editor.org/rfc/rfc8899).
     */
    fun interval(value: Duration): MtuDiscoveryConfig { interval = value; return this }

    /**
     * Specifies the upper bound to the max UDP payload size that MTU discovery will search for.
     *
     * Defaults to 1452, to stay within Ethernet's MTU when using IPv4 and IPv6. The highest allowed value is 65527,
     * which corresponds to the maximum permitted UDP payload on IPv6.
     *
     * It is safe to use an arbitrarily high upper bound, regardless of the network path's MTU. The only drawback is
     * that MTU discovery might take more time to finish.
     */
    fun upperBound(value: Int): MtuDiscoveryConfig {
        requireU16(value)
        upperBound = minOf(value, MAX_UDP_PAYLOAD)
        return this
    }

    /**
     * Specifies the amount of time that MTU discovery should wait after a black hole was detected before running
     * again. Defaults to one minute.
     *
     * Black hole detection can be spuriously triggered in case of congestion, so it makes sense to try MTU discovery
     * again after a short period of time.
     */
    fun blackHoleCooldown(value: Duration): MtuDiscoveryConfig { blackHoleCooldown = value; return this }

    /** Specifies the minimum MTU change to stop the MTU discovery phase. Defaults to 20. */
    fun minimumChange(value: Int): MtuDiscoveryConfig {
        requireU16(value)
        minimumChange = value
        return this
    }

    /** quinn's `Clone`. */
    fun copy(): MtuDiscoveryConfig = MtuDiscoveryConfig().also {
        it.interval = interval; it.upperBound = upperBound; it.minimumChange = minimumChange
        it.blackHoleCooldown = blackHoleCooldown
    }

    override fun toString(): String =
        "MtuDiscoveryConfig { interval: $interval, upper_bound: $upperBound, minimum_change: $minimumChange, " +
            "black_hole_cooldown: $blackHoleCooldown }"
}

/**
 * Maximum duration of inactivity to accept before timing out the connection (transport.rs:774).
 *
 * This wraps an underlying [VarInt], representing the duration in milliseconds. Values can be constructed from a
 * `VarInt` directly, or from a [Duration] with [of].
 */
value class IdleTimeout(val value: VarInt) : Comparable<IdleTimeout> {
    override fun compareTo(other: IdleTimeout): Int = value.compareTo(other.value)

    override fun toString(): String = value.toString()

    companion object {
        /** quinn `TryFrom<Duration>`: throws [VarIntBoundsExceeded] when the millisecond count is not a varint. */
        fun of(timeout: Duration): IdleTimeout {
            require(!timeout.isNegative()) { "negative idle timeout" }
            if (timeout.isInfinite()) throw VarIntBoundsExceeded()
            return IdleTimeout(VarInt.fromLong(timeout.inWholeMilliseconds))
        }
    }
}
