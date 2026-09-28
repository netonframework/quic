package neton.quic.proto

import neton.io.net.SocketAddress
import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

// Endpoint-level configuration (quinn-proto `config/mod.rs`). `EndpointConfig`'s default with a random HMAC-SHA256
// reset key is `EndpointConfig.default()`, and `ServerConfig.withCrypto` (a random HKDF token key) is in the native
// source set: both keys come from openssl-kotlin.

/**
 * Global configuration for the endpoint, affecting all connections (config/mod.rs:37).
 *
 * Default values should be suitable for most internet applications.
 */
class EndpointConfig(
    /** Key used to derive stateless reset tokens. */
    internal var resetKey: HmacKey,
) {
    internal var maxUdpPayloadSize: VarInt = VarInt(1500L - 28) // Ethernet MTU minus IP + UDP headers
        private set
    internal var connectionIdGeneratorFactory: () -> ConnectionIdGenerator = { HashedConnectionIdGenerator() }
        private set
    internal var supportedVersions: IntArray = DEFAULT_SUPPORTED_VERSIONS.copyOf()
        private set
    internal var greaseQuicBit: Boolean = true
        private set
    internal var minResetInterval: Duration = 20.milliseconds
        private set
    internal var rngSeed: ByteArray? = null
        private set

    /**
     * Supply a custom connection ID generator factory.
     *
     * Called once by each connection to generate its own connection IDs, which must not collide with those of other
     * connections of the endpoint. Defaults to [HashedConnectionIdGenerator].
     */
    fun cidGenerator(factory: () -> ConnectionIdGenerator): EndpointConfig { connectionIdGeneratorFactory = factory; return this }

    /** Private key used to send authenticated connection resets to peers who were communicating with a previous instance of this endpoint. */
    fun resetKey(key: HmacKey): EndpointConfig { resetKey = key; return this }

    /**
     * Maximum UDP payload size accepted from peers (excluding UDP and IP overhead).
     *
     * Must be greater or equal than 1200. Defaults to 1472, which is the largest UDP payload that can be transmitted
     * in the typical 1500 byte Ethernet MTU. Deployments on links with larger MTUs (e.g. loopback or Ethernet with
     * jumbo frames) can raise this to improve performance at the cost of a linear increase in datagram receive buffer
     * size. Throws [ConfigError.OutOfBounds] outside 1200..65527.
     */
    fun maxUdpPayloadSize(value: Int): EndpointConfig {
        if (value !in 1200..65_527) throw ConfigError.OutOfBounds()
        maxUdpPayloadSize = VarInt(value.toLong())
        return this
    }

    /**
     * Get the current value of [maxUdpPayloadSize].
     *
     * This must be exposed to allow higher-level layers to determine how large a receive buffer to allocate to
     * support an externally-defined `EndpointConfig`.
     */
    fun getMaxUdpPayloadSize(): Long = maxUdpPayloadSize.value

    /** Override supported QUIC versions. */
    fun supportedVersions(supportedVersions: IntArray): EndpointConfig {
        this.supportedVersions = supportedVersions.copyOf()
        return this
    }

    /**
     * Whether to accept QUIC packets containing any value for the fixed bit.
     *
     * Enabled by default. Helps protect against protocol ossification and makes traffic less identifiable to
     * observers. Disable if helping observers identify this traffic as QUIC is desired.
     */
    fun greaseQuicBit(value: Boolean): EndpointConfig { greaseQuicBit = value; return this }

    /**
     * Minimum interval between outgoing stateless reset packets.
     *
     * Defaults to 20ms. Limits the impact of attacks which flood an endpoint with garbage packets, e.g. on a
     * connection ID that no longer exists, which would otherwise elicit an equally large flood of stateless resets.
     * Lower values can make endpoint deployments with persistently long-lived connections more robust at scale.
     */
    fun minResetInterval(value: Duration): EndpointConfig { minResetInterval = value; return this }

    /**
     * Optional seed to be used internally for random number generation.
     *
     * By default, quinn will initialize an endpoint's rng using a platform entropy source. However, you can seed the
     * rng yourself through this method (e.g. if you need to run quinn deterministically or if you are using quinn in
     * an environment that doesn't have a source of entropy available). The seed must be 32 bytes.
     */
    fun rngSeed(seed: ByteArray?): EndpointConfig {
        require(seed == null || seed.size == 32) { "the RNG seed has 32 bytes" }
        rngSeed = seed?.copyOf()
        return this
    }

    /** quinn's `Debug` (the reset key and CID generator factory are not shown). */
    override fun toString(): String =
        "EndpointConfig { max_udp_payload_size: $maxUdpPayloadSize, supported_versions: " +
            supportedVersions.joinToString(", ", "[", "]") { it.toUInt().toString() } +
            ", grease_quic_bit: $greaseQuicBit, rng_seed: ${rngSeed?.toHex()}, .. }"

    companion object
}

/**
 * Configuration for sending and handling validation tokens (config/mod.rs:436).
 */
class ValidationTokenConfig {
    internal var lifetime: Duration = (2 * 7).days
        private set
    internal var log: TokenLog = BloomTokenLog()
        private set
    internal var sent: Int = 2
        private set

    /**
     * Duration after an address validation token was issued for which it's considered valid.
     *
     * This refers only to tokens sent in NEW_TOKEN frames, in contrast to retry tokens.
     *
     * Defaults to 2 weeks.
     */
    fun lifetime(value: Duration): ValidationTokenConfig { lifetime = value; return this }

    /**
     * Set a custom [TokenLog].
     *
     * Defaults to a [BloomTokenLog], which is suitable for most internet applications.
     *
     * If set to [NoneTokenLog], the server will ignore all address validation tokens sent by the client.
     */
    fun log(log: TokenLog): ValidationTokenConfig { this.log = log; return this }

    /**
     * Number of address validation tokens sent to a client when its path is validated.
     *
     * This refers only to tokens sent in NEW_TOKEN frames, in contrast to retry tokens.
     *
     * Defaults to 2.
     */
    fun sent(value: Int): ValidationTokenConfig {
        require(value >= 0) { "token count must not be negative" }
        sent = value
        return this
    }

    override fun toString(): String = "ServerValidationTokenConfig { lifetime: $lifetime, sent: $sent, .. }"
}

/**
 * Parameters governing incoming connections (config/mod.rs:197). Default values should be suitable for most internet
 * applications.
 *
 * ⚖️ quinn shares it as an `Arc` and clones it to derive variants; here it is a mutable object with [copy]. A pending
 * incoming connection keeps the instance it arrived with, so changing an instance in use affects connections that
 * refer to it (quinn's cannot change once shared).
 */
class ServerConfig(
    /** TLS configuration used for incoming connections; must be set to use TLS 1.3 only. */
    var crypto: CryptoServerConfig,
    /** Used to generate one-time AEAD keys to protect handshake tokens. */
    tokenKey: HandshakeTokenKey,
) {
    /** Transport configuration to use for incoming connections. */
    var transport: TransportConfig = TransportConfig()

    /** Configuration for sending and handling validation tokens. */
    var validationToken: ValidationTokenConfig = ValidationTokenConfig()

    internal var tokenKey: HandshakeTokenKey = tokenKey
        private set
    internal var retryTokenLifetime: Duration = 15.seconds
        private set
    internal var migration: Boolean = true
        private set
    internal var preferredAddressV4: SocketAddress? = null
        private set
    internal var preferredAddressV6: SocketAddress? = null
        private set
    internal var maxIncoming: Int = 1 shl 16
        private set
    internal var incomingBufferSize: Long = 10L shl 20
        private set
    internal var incomingBufferSizeTotal: Long = 100L shl 20
        private set
    internal var timeSource: TimeSource = StdSystemTime
        private set

    /** Set a custom [TransportConfig]. */
    fun transportConfig(transport: TransportConfig): ServerConfig { this.transport = transport; return this }

    /** Set a custom [ValidationTokenConfig]. */
    fun validationTokenConfig(validationToken: ValidationTokenConfig): ServerConfig { this.validationToken = validationToken; return this }

    /** Private key used to authenticate data included in handshake tokens. */
    fun tokenKey(value: HandshakeTokenKey): ServerConfig { tokenKey = value; return this }

    /** Duration after a retry token was issued for which it's considered valid. Defaults to 15 seconds. */
    fun retryTokenLifetime(value: Duration): ServerConfig { retryTokenLifetime = value; return this }

    /**
     * Whether to allow clients to migrate to new addresses. Improves behavior for clients that move between different
     * internet connections or suffer NAT rebinding. Enabled by default.
     */
    fun migration(value: Boolean): ServerConfig { migration = value; return this }

    /** The preferred IPv4 address that will be communicated to clients during handshaking. */
    fun preferredAddressV4(address: SocketAddress?): ServerConfig {
        require(address == null || address.isIpv4) { "not an IPv4 address" }
        preferredAddressV4 = address
        return this
    }

    /** The preferred IPv6 address that will be communicated to clients during handshaking. */
    fun preferredAddressV6(address: SocketAddress?): ServerConfig {
        require(address == null || address.isIpv6) { "not an IPv6 address" }
        preferredAddressV6 = address
        return this
    }

    /**
     * Maximum number of [Incoming] to allow to exist at a time. While this limit is reached, new incoming connection
     * attempts are dropped. Defaults to 65536.
     */
    fun maxIncoming(value: Int): ServerConfig {
        require(value >= 0) { "must not be negative" }
        maxIncoming = value
        return this
    }

    /**
     * Maximum number of received bytes to buffer for each [Incoming] (not counting its first packet). Packets received
     * in excess are dropped, which may cause 0-RTT or handshake data to have to be retransmitted. Defaults to 10 MiB.
     */
    fun incomingBufferSize(value: Long): ServerConfig {
        require(value >= 0) { "must not be negative" }
        incomingBufferSize = value
        return this
    }

    /** Maximum number of received bytes to buffer for all [Incoming] collectively. Defaults to 100 MiB. */
    fun incomingBufferSizeTotal(value: Long): ServerConfig {
        require(value >= 0) { "must not be negative" }
        incomingBufferSizeTotal = value
        return this
    }

    /** Object to get the current wall-clock time; defaults to [StdSystemTime]. */
    fun timeSource(value: TimeSource): ServerConfig { timeSource = value; return this }

    internal fun hasPreferredAddress(): Boolean = preferredAddressV4 != null || preferredAddressV6 != null

    /** quinn's `Clone`: the crypto configuration, keys, token log and time source are shared, as quinn's `Arc`s. */
    fun copy(): ServerConfig = ServerConfig(crypto, tokenKey).also {
        it.transport = transport
        it.validationToken = validationToken
        it.retryTokenLifetime = retryTokenLifetime
        it.migration = migration
        it.preferredAddressV4 = preferredAddressV4
        it.preferredAddressV6 = preferredAddressV6
        it.maxIncoming = maxIncoming
        it.incomingBufferSize = incomingBufferSize
        it.incomingBufferSizeTotal = incomingBufferSizeTotal
        it.timeSource = timeSource
    }

    override fun toString(): String =
        "ServerConfig { transport: $transport, retry_token_lifetime: $retryTokenLifetime, " +
            "validation_token: $validationToken, migration: $migration, preferred_address_v4: $preferredAddressV4, " +
            "preferred_address_v6: $preferredAddressV6, max_incoming: $maxIncoming, " +
            "incoming_buffer_size: $incomingBufferSize, incoming_buffer_size_total: $incomingBufferSizeTotal, .. }"

    companion object
}

/**
 * Configuration for outgoing connections (config/mod.rs:553). Default values should be suitable for most internet
 * applications.
 */
class ClientConfig(
    /** Cryptographic configuration to use. */
    internal val crypto: CryptoClientConfig,
) {
    internal var transport: TransportConfig = TransportConfig()
        private set
    internal var tokenStore: TokenStore = TokenMemoryCache()
        private set
    internal var initialDstCidProvider: () -> ConnectionId = { RandomConnectionIdGenerator(MAX_CID_SIZE).generateCid() }
        private set
    internal var version: Int = 1
        private set

    /**
     * Configure how to populate the destination CID of the initial packet when attempting to establish a new
     * connection. By default random bytes of reasonable length; a replacement MUST be at least 8 bytes long and
     * unpredictable (RFC 9000 §7.2).
     */
    fun initialDstCidProvider(provider: () -> ConnectionId): ClientConfig { initialDstCidProvider = provider; return this }

    /** Set a custom [TransportConfig]. */
    fun transportConfig(transport: TransportConfig): ClientConfig { this.transport = transport; return this }

    /** Set a custom [TokenStore]. Defaults to [TokenMemoryCache], which is suitable for most internet applications. */
    fun tokenStore(store: TokenStore): ClientConfig { tokenStore = store; return this }

    /** Set the QUIC version to use. */
    fun version(version: Int): ClientConfig { this.version = version; return this }

    /** quinn's `Clone`: the transport and crypto configurations and the token store are shared, as quinn's `Arc`s. */
    fun copy(): ClientConfig = ClientConfig(crypto).also {
        it.transport = transport
        it.tokenStore = tokenStore
        it.initialDstCidProvider = initialDstCidProvider
        it.version = version
    }

    override fun toString(): String = "ClientConfig { transport: $transport, version: $version, .. }"
}

/** Errors in the configuration of an endpoint (config/mod.rs:629). */
sealed class ConfigError(message: String) : IllegalArgumentException(message) {
    /** Value exceeds supported bounds. */
    class OutOfBounds : ConfigError("value exceeds supported bounds")
}

/** Object to get current wall-clock time, as a duration since the Unix epoch (config/mod.rs:651). */
fun interface TimeSource {
    /** Get the current wall-clock time. */
    fun now(): Duration
}

/** Default implementation of [TimeSource]: the system clock (config/mod.rs:657). */
object StdSystemTime : TimeSource {
    @OptIn(ExperimentalTime::class)
    override fun now(): Duration {
        val t = kotlin.time.Clock.System.now()
        return t.epochSeconds.seconds + t.nanosecondsOfSecond.nanoseconds
    }
}
