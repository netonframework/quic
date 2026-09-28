package neton.quic.proto

import kotlin.time.Duration
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.nanoseconds
import kotlin.time.Duration.Companion.seconds
import kotlin.time.ExperimentalTime

// Endpoint-level configuration (quinn-proto `config/mod.rs`): the parts the recovery, token and transport
// configuration need. `ServerConfig` and `ClientConfig` hold the TLS configurations and follow with the TLS layer
// (SPEC §4); `EndpointConfig`'s default with a random HMAC-SHA256 reset key is `EndpointConfig.default()` in the
// native source set (the HMAC comes from openssl-kotlin).

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
