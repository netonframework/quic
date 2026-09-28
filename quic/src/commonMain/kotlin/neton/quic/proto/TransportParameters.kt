package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.net.SocketAddress
import kotlin.random.Random

// QUIC transport parameters (quinn-proto `transport_parameters.rs`; RFC 9000 §18, RFC 9221 §3, RFC 9287 §3,
// draft-ietf-quic-ack-frequency). Exchanged in the TLS `quic_transport_parameters` extension; the crypto session
// calls [TransportParameters.write] / [TransportParameters.read].

/** Errors decoding transport parameters (transport_parameters.rs:283). */
sealed class TransportParameterError(message: String) : Exception(message) {
    /** Parameters that are semantically invalid. */
    object IllegalValue : TransportParameterError("parameter had illegal value")

    /** Catch-all for problems while decoding transport parameters. */
    object Malformed : TransportParameterError("parameters were malformed")

    /** The TRANSPORT_PARAMETER_ERROR to close the connection with (transport_parameters.rs:292). */
    fun toTransportError(): TransportError = when (this) {
        IllegalValue -> TransportError.TRANSPORT_PARAMETER_ERROR("illegal value")
        Malformed -> TransportError.TRANSPORT_PARAMETER_ERROR("malformed")
    }
}

/** Transport parameter identifiers (transport_parameters.rs:616). */
internal object TransportParameterId {
    // https://www.rfc-editor.org/rfc/rfc9000.html#iana-tp-table
    const val OriginalDestinationConnectionId = 0x00L
    const val MaxIdleTimeout = 0x01L
    const val StatelessResetToken = 0x02L
    const val MaxUdpPayloadSize = 0x03L
    const val InitialMaxData = 0x04L
    const val InitialMaxStreamDataBidiLocal = 0x05L
    const val InitialMaxStreamDataBidiRemote = 0x06L
    const val InitialMaxStreamDataUni = 0x07L
    const val InitialMaxStreamsBidi = 0x08L
    const val InitialMaxStreamsUni = 0x09L
    const val AckDelayExponent = 0x0AL
    const val MaxAckDelay = 0x0BL
    const val DisableActiveMigration = 0x0CL
    const val PreferredAddress = 0x0DL
    const val ActiveConnectionIdLimit = 0x0EL
    const val InitialSourceConnectionId = 0x0FL
    const val RetrySourceConnectionId = 0x10L

    /** Smallest possible ID of a reserved transport parameter (RFC 9000 §22.3). */
    const val ReservedTransportParameter = 0x1BL

    /** RFC 9221 §3. */
    const val MaxDatagramFrameSize = 0x20L

    /** RFC 9287 §3. */
    const val GreaseQuicBit = 0x2AB2L

    /** draft-ietf-quic-ack-frequency §10.1. */
    const val MinAckDelayDraft07 = 0xFF04DE1BL

    /** All supported transport parameter IDs, in the default write order (transport_parameters.rs:651). */
    val SUPPORTED: LongArray = longArrayOf(
        MaxIdleTimeout,
        MaxUdpPayloadSize,
        InitialMaxData,
        InitialMaxStreamDataBidiLocal,
        InitialMaxStreamDataBidiRemote,
        InitialMaxStreamDataUni,
        InitialMaxStreamsBidi,
        InitialMaxStreamsUni,
        AckDelayExponent,
        MaxAckDelay,
        ActiveConnectionIdLimit,
        ReservedTransportParameter,
        StatelessResetToken,
        DisableActiveMigration,
        MaxDatagramFrameSize,
        PreferredAddress,
        OriginalDestinationConnectionId,
        InitialSourceConnectionId,
        RetrySourceConnectionId,
        GreaseQuicBit,
        MinAckDelayDraft07,
    )

    fun isSupported(id: Long): Boolean = id in SUPPORTED

    /** The integer-valued parameters (quinn's `apply_params!` list) and their defaults. */
    fun isIntParam(id: Long): Boolean = id in MaxIdleTimeout..ActiveConnectionIdLimit &&
        id != StatelessResetToken && id != DisableActiveMigration && id != PreferredAddress

    fun intDefault(id: Long): Long = when (id) {
        MaxUdpPayloadSize -> 65527
        AckDelayExponent -> 3
        MaxAckDelay -> 25
        ActiveConnectionIdLimit -> 2
        else -> 0
    }
}

/**
 * A server's preferred address (transport_parameters.rs:220). [addressV4] must be an IPv4 and [addressV6] an IPv6
 * [SocketAddress]; at least one is present.
 */
data class PreferredAddress(
    val addressV4: SocketAddress?,
    val addressV6: SocketAddress?,
    val connectionId: ConnectionId,
    val statelessResetToken: ResetToken,
) {
    init {
        require(addressV4 == null || addressV4.isIpv4) { "addressV4 must be IPv4" }
        require(addressV6 == null || addressV6.isIpv6) { "addressV6 must be IPv6" }
    }

    internal fun wireSize(): Int = 4 + 2 + 16 + 2 + 1 + connectionId.size + 16

    internal fun write(w: Buffer) {
        w.writeBytes(addressV4?.ipBytes() ?: ByteArray(4))
        w.writeShort(addressV4?.port ?: 0)
        w.writeBytes(addressV6?.ipBytes() ?: ByteArray(16))
        w.writeShort(addressV6?.port ?: 0)
        w.writeByte(connectionId.size.toByte())
        connectionId.encode(w)
        statelessResetToken.encode(w)
    }

    internal companion object {
        fun read(r: Reader): PreferredAddress {
            val ipV4 = r.getBytes(4)
            val portV4 = r.getU16()
            val ipV6 = r.getBytes(16)
            val portV6 = r.getU16()
            val cidLen = r.getU8()
            if (r.remaining < cidLen || cidLen > MAX_CID_SIZE) throw TransportParameterError.Malformed
            val cid = ConnectionId.fromReader(r, cidLen)
            if (r.remaining < 16) throw TransportParameterError.Malformed
            val token = ResetToken.fromReader(r)
            val addressV4 = if (ipV4.all { it == 0.toByte() } && portV4 == 0) null else SocketAddress.of(ipV4, portV4)
            val addressV6 = if (ipV6.all { it == 0.toByte() } && portV6 == 0) null else SocketAddress.of(ipV6, portV6)
            if (addressV4 == null && addressV6 == null) throw TransportParameterError.IllegalValue
            return PreferredAddress(addressV4, addressV6, cid, token)
        }
    }
}

/**
 * A reserved transport parameter with an ID of the form `31 * N + 27` and a random payload
 * (transport_parameters.rs:548; RFC 9000 §18.1, §22.3). Sent to exercise the requirement that unknown parameters are
 * ignored; ignored when received.
 */
class ReservedTransportParameter internal constructor(
    internal val id: VarInt,
    private val payload: ByteArray,
    internal val payloadLen: Int,
) {
    internal fun write(w: Buffer) {
        w.writeVar(id)
        w.writeVar(payloadLen.toLong())
        w.writeBytes(payload, 0, payloadLen)
    }

    override fun equals(other: Any?): Boolean =
        other is ReservedTransportParameter && other.id == id && other.payloadLen == payloadLen &&
            (0 until payloadLen).all { other.payload[it] == payload[it] }

    override fun hashCode(): Int = id.hashCode() * 31 + payloadLen

    override fun toString(): String = "ReservedTransportParameter(id=$id, payload=${payload.toHex(0, payloadLen)})"

    internal companion object {
        /**
         * Not a specification limit; matches other implementations (quic-go, quiche).
         */
        const val MAX_PAYLOAD_LEN = 16

        /** A reserved parameter with a random ID and payload (transport_parameters.rs:565). */
        fun random(rng: Random): ReservedTransportParameter {
            val id = generateReservedId(rng)
            val payloadLen = rng.nextInt(0, MAX_PAYLOAD_LEN)
            val payload = ByteArray(MAX_PAYLOAD_LEN)
            rng.nextBytes(payload, 0, payloadLen)
            return ReservedTransportParameter(id, payload, payloadLen)
        }

        /** A random ID of the form `31 * N + 27` below 2^62 (transport_parameters.rs:593). */
        fun generateReservedId(rng: Random): VarInt {
            val rand = rng.nextLong(0, (1L shl 62) - 27)
            val n = rand / 31
            val id = 31 * n + 27
            check(id % 31 == 27L) { "generated id does not have the form of 31 * N + 27" }
            return VarInt.fromLong(id)
        }
    }
}

/**
 * Transport parameters used to negotiate connection-level preferences between peers
 * (transport_parameters.rs:71). A fresh instance holds the protocol defaults (the values assumed when the peer
 * omits a parameter); the fields are internal to the protocol layer, as in quinn (`pub(crate)`).
 */
class TransportParameters internal constructor() {
    /** Milliseconds, disabled if zero. */
    internal var maxIdleTimeout: VarInt = VarInt(0)

    /** Limits the size of UDP payloads that the endpoint is willing to receive. */
    internal var maxUdpPayloadSize: VarInt = VarInt(65527)

    /** Initial value for the maximum amount of data that can be sent on the connection. */
    internal var initialMaxData: VarInt = VarInt(0)

    /** Initial flow control limit for locally-initiated bidirectional streams. */
    internal var initialMaxStreamDataBidiLocal: VarInt = VarInt(0)

    /** Initial flow control limit for peer-initiated bidirectional streams. */
    internal var initialMaxStreamDataBidiRemote: VarInt = VarInt(0)

    /** Initial flow control limit for unidirectional streams. */
    internal var initialMaxStreamDataUni: VarInt = VarInt(0)

    /** Initial maximum number of bidirectional streams the peer may initiate. */
    internal var initialMaxStreamsBidi: VarInt = VarInt(0)

    /** Initial maximum number of unidirectional streams the peer may initiate. */
    internal var initialMaxStreamsUni: VarInt = VarInt(0)

    /** Exponent used to decode the ACK Delay field in the ACK frame. */
    internal var ackDelayExponent: VarInt = VarInt(3)

    /** Maximum amount of time in milliseconds by which the endpoint will delay sending acknowledgments. */
    internal var maxAckDelay: VarInt = VarInt(25)

    /** Maximum number of connection IDs from the peer that an endpoint is willing to store. */
    internal var activeConnectionIdLimit: VarInt = VarInt(2)

    /** Whether the endpoint does not support active connection migration. */
    internal var disableActiveMigration: Boolean = false

    /** Maximum size for datagram frames. */
    internal var maxDatagramFrameSize: VarInt? = null

    /** The Source Connection ID of the first Initial packet the endpoint sent. */
    internal var initialSrcCid: ConnectionId? = null

    /** The endpoint is willing to receive QUIC packets containing any value for the fixed bit. */
    internal var greaseQuicBit: Boolean = false

    /**
     * Minimum amount of time in microseconds by which the endpoint is able to delay sending acknowledgments.
     * If present, the endpoint supports QUIC Acknowledgement Frequency.
     */
    internal var minAckDelay: VarInt? = null

    // Server-only
    /** The Destination Connection ID of the first Initial packet sent by the client. */
    internal var originalDstCid: ConnectionId? = null

    /** The Source Connection ID the server put in a Retry packet. */
    internal var retrySrcCid: ConnectionId? = null

    /** Token used by the client to verify a stateless reset from the server. */
    internal var statelessResetToken: ResetToken? = null

    /** The server's preferred address for communication after handshake completion. */
    internal var preferredAddress: PreferredAddress? = null

    /** The random reserved parameter; written when present, ignored when read. */
    internal var greaseTransportParameter: ReservedTransportParameter? = null

    /**
     * The order in which parameters are written, as indices into the supported IDs. Set only for outgoing
     * parameters; `null` (the default order) for received ones.
     */
    internal var writeOrder: ByteArray? = null

    /** Check that these parameters are legal when resuming from [cached] ones (transport_parameters.rs:189). */
    internal fun validateResumptionFrom(cached: TransportParameters) {
        if (cached.activeConnectionIdLimit > activeConnectionIdLimit ||
            cached.initialMaxData > initialMaxData ||
            cached.initialMaxStreamDataBidiLocal > initialMaxStreamDataBidiLocal ||
            cached.initialMaxStreamDataBidiRemote > initialMaxStreamDataBidiRemote ||
            cached.initialMaxStreamDataUni > initialMaxStreamDataUni ||
            cached.initialMaxStreamsBidi > initialMaxStreamsBidi ||
            cached.initialMaxStreamsUni > initialMaxStreamsUni ||
            optionGreater(cached.maxDatagramFrameSize, maxDatagramFrameSize) ||
            cached.greaseQuicBit && !greaseQuicBit
        ) {
            throw TransportError.PROTOCOL_VIOLATION("0-RTT accepted with incompatible transport parameters")
        }
    }

    /**
     * Maximum number of CIDs to issue to this peer: the peer's active_connection_id_limit, capped by
     * [LOC_CID_COUNT] (transport_parameters.rs:211).
     */
    internal fun issueCidsLimit(): Long = minOf(activeConnectionIdLimit.value, LOC_CID_COUNT)

    private fun intParam(id: Long): VarInt = when (id) {
        TransportParameterId.MaxIdleTimeout -> maxIdleTimeout
        TransportParameterId.MaxUdpPayloadSize -> maxUdpPayloadSize
        TransportParameterId.InitialMaxData -> initialMaxData
        TransportParameterId.InitialMaxStreamDataBidiLocal -> initialMaxStreamDataBidiLocal
        TransportParameterId.InitialMaxStreamDataBidiRemote -> initialMaxStreamDataBidiRemote
        TransportParameterId.InitialMaxStreamDataUni -> initialMaxStreamDataUni
        TransportParameterId.InitialMaxStreamsBidi -> initialMaxStreamsBidi
        TransportParameterId.InitialMaxStreamsUni -> initialMaxStreamsUni
        TransportParameterId.AckDelayExponent -> ackDelayExponent
        TransportParameterId.MaxAckDelay -> maxAckDelay
        TransportParameterId.ActiveConnectionIdLimit -> activeConnectionIdLimit
        else -> throw IllegalArgumentException("not an integer parameter: $id")
    }

    private fun setIntParam(id: Long, v: VarInt) {
        when (id) {
            TransportParameterId.MaxIdleTimeout -> maxIdleTimeout = v
            TransportParameterId.MaxUdpPayloadSize -> maxUdpPayloadSize = v
            TransportParameterId.InitialMaxData -> initialMaxData = v
            TransportParameterId.InitialMaxStreamDataBidiLocal -> initialMaxStreamDataBidiLocal = v
            TransportParameterId.InitialMaxStreamDataBidiRemote -> initialMaxStreamDataBidiRemote = v
            TransportParameterId.InitialMaxStreamDataUni -> initialMaxStreamDataUni = v
            TransportParameterId.InitialMaxStreamsBidi -> initialMaxStreamsBidi = v
            TransportParameterId.InitialMaxStreamsUni -> initialMaxStreamsUni = v
            TransportParameterId.AckDelayExponent -> ackDelayExponent = v
            TransportParameterId.MaxAckDelay -> maxAckDelay = v
            TransportParameterId.ActiveConnectionIdLimit -> activeConnectionIdLimit = v
            else -> throw IllegalArgumentException("not an integer parameter: $id")
        }
    }

    /** Encode into [w] in [writeOrder] (transport_parameters.rs:309). */
    fun write(w: Buffer) {
        val order = writeOrder
        for (k in TransportParameterId.SUPPORTED.indices) {
            val id = TransportParameterId.SUPPORTED[if (order != null) order[k].toInt() else k]
            when (id) {
                TransportParameterId.ReservedTransportParameter -> greaseTransportParameter?.write(w)
                TransportParameterId.StatelessResetToken -> statelessResetToken?.let {
                    w.writeVar(id); w.writeVar(16); it.encode(w)
                }
                TransportParameterId.DisableActiveMigration -> if (disableActiveMigration) {
                    w.writeVar(id); w.writeVar(0)
                }
                TransportParameterId.MaxDatagramFrameSize -> maxDatagramFrameSize?.let {
                    w.writeVar(id); w.writeVar(it.size.toLong()); w.writeVar(it)
                }
                TransportParameterId.PreferredAddress -> preferredAddress?.let {
                    w.writeVar(id); w.writeVar(it.wireSize().toLong()); it.write(w)
                }
                TransportParameterId.OriginalDestinationConnectionId -> originalDstCid?.let { writeCid(w, id, it) }
                TransportParameterId.InitialSourceConnectionId -> initialSrcCid?.let { writeCid(w, id, it) }
                TransportParameterId.RetrySourceConnectionId -> retrySrcCid?.let { writeCid(w, id, it) }
                TransportParameterId.GreaseQuicBit -> if (greaseQuicBit) {
                    w.writeVar(id); w.writeVar(0)
                }
                TransportParameterId.MinAckDelayDraft07 -> minAckDelay?.let {
                    w.writeVar(id); w.writeVar(it.size.toLong()); w.writeVar(it)
                }
                else -> {
                    val v = intParam(id)
                    if (v.value != TransportParameterId.intDefault(id)) {
                        w.writeVar(id)
                        w.writeVar(v.size.toLong())
                        w.writeVar(v)
                    }
                }
            }
        }
    }

    private fun writeCid(w: Buffer, id: Long, cid: ConnectionId) {
        w.writeVar(id)
        w.writeVar(cid.size.toLong())
        cid.encode(w)
    }

    override fun equals(other: Any?): Boolean {
        if (other !is TransportParameters) return false
        return maxIdleTimeout == other.maxIdleTimeout && maxUdpPayloadSize == other.maxUdpPayloadSize &&
            initialMaxData == other.initialMaxData &&
            initialMaxStreamDataBidiLocal == other.initialMaxStreamDataBidiLocal &&
            initialMaxStreamDataBidiRemote == other.initialMaxStreamDataBidiRemote &&
            initialMaxStreamDataUni == other.initialMaxStreamDataUni &&
            initialMaxStreamsBidi == other.initialMaxStreamsBidi && initialMaxStreamsUni == other.initialMaxStreamsUni &&
            ackDelayExponent == other.ackDelayExponent && maxAckDelay == other.maxAckDelay &&
            activeConnectionIdLimit == other.activeConnectionIdLimit &&
            disableActiveMigration == other.disableActiveMigration &&
            maxDatagramFrameSize == other.maxDatagramFrameSize && initialSrcCid == other.initialSrcCid &&
            greaseQuicBit == other.greaseQuicBit && minAckDelay == other.minAckDelay &&
            originalDstCid == other.originalDstCid && retrySrcCid == other.retrySrcCid &&
            statelessResetToken == other.statelessResetToken && preferredAddress == other.preferredAddress &&
            greaseTransportParameter == other.greaseTransportParameter &&
            (writeOrder?.contentEquals(other.writeOrder ?: return false) ?: (other.writeOrder == null))
    }

    override fun hashCode(): Int = (initialMaxData.hashCode() * 31 + initialSrcCid.hashCode()) * 31 + maxUdpPayloadSize.hashCode()

    override fun toString(): String =
        "TransportParameters(maxIdleTimeout=$maxIdleTimeout, maxUdpPayloadSize=$maxUdpPayloadSize, " +
            "initialMaxData=$initialMaxData, initialMaxStreamDataBidiLocal=$initialMaxStreamDataBidiLocal, " +
            "initialMaxStreamDataBidiRemote=$initialMaxStreamDataBidiRemote, initialMaxStreamDataUni=$initialMaxStreamDataUni, " +
            "initialMaxStreamsBidi=$initialMaxStreamsBidi, initialMaxStreamsUni=$initialMaxStreamsUni, " +
            "ackDelayExponent=$ackDelayExponent, maxAckDelay=$maxAckDelay, activeConnectionIdLimit=$activeConnectionIdLimit, " +
            "disableActiveMigration=$disableActiveMigration, maxDatagramFrameSize=$maxDatagramFrameSize, " +
            "initialSrcCid=$initialSrcCid, greaseQuicBit=$greaseQuicBit, minAckDelay=$minAckDelay, " +
            "originalDstCid=$originalDstCid, retrySrcCid=$retrySrcCid, statelessResetToken=$statelessResetToken, " +
            "preferredAddress=$preferredAddress, greaseTransportParameter=$greaseTransportParameter, " +
            "writeOrder=${writeOrder?.joinToString(",")})"

    companion object {
        /** Protocol defaults, used for parameters the peer does not send (transport_parameters.rs:120). */
        internal fun default(): TransportParameters = TransportParameters()

        /**
         * The parameters an endpoint sends (transport_parameters.rs:145). quinn reads them from
         * `TransportConfig`, `EndpointConfig` and `ServerConfig`; until those are ported the relevant fields are
         * parameters here. [rng] is the endpoint's seedable generator (quinn passes its `StdRng`); it picks the
         * reserved parameter and shuffles the write order.
         *
         * @param serverMigration `null` on a client; on a server, whether active migration is allowed.
         * @param localCidLen length of the CIDs this endpoint issues (`ConnectionIdGenerator.cidLen`).
         * @param datagramReceiveBufferSize `null` disables datagrams.
         */
        internal fun new(
            initialSrcCid: ConnectionId,
            maxConcurrentBidiStreams: VarInt,
            maxConcurrentUniStreams: VarInt,
            receiveWindow: VarInt,
            streamReceiveWindow: VarInt,
            maxUdpPayloadSize: VarInt,
            maxIdleTimeout: VarInt?,
            serverMigration: Boolean?,
            localCidLen: Int,
            datagramReceiveBufferSize: Long?,
            greaseQuicBit: Boolean,
            rng: Random,
        ): TransportParameters = TransportParameters().apply {
            this.initialSrcCid = initialSrcCid
            initialMaxStreamsBidi = maxConcurrentBidiStreams
            initialMaxStreamsUni = maxConcurrentUniStreams
            initialMaxData = receiveWindow
            initialMaxStreamDataBidiLocal = streamReceiveWindow
            initialMaxStreamDataBidiRemote = streamReceiveWindow
            initialMaxStreamDataUni = streamReceiveWindow
            this.maxUdpPayloadSize = maxUdpPayloadSize
            this.maxIdleTimeout = maxIdleTimeout ?: VarInt(0)
            disableActiveMigration = serverMigration == false
            // 2 is the default, i.e. not sent, for zero-length CIDs; otherwise quinn's `CidQueue::LEN`.
            activeConnectionIdLimit = VarInt(if (localCidLen == 0) 2 else CID_QUEUE_LEN.toLong())
            maxDatagramFrameSize = datagramReceiveBufferSize?.let { VarInt(minOf(it, 65535L)) }
            this.greaseQuicBit = greaseQuicBit
            minAckDelay = VarInt.fromLong(TIMER_GRANULARITY.inWholeMicroseconds)
            greaseTransportParameter = ReservedTransportParameter.random(rng)
            writeOrder = ByteArray(TransportParameterId.SUPPORTED.size) { it.toByte() }.also { shuffle(it, rng) }
        }

        /** quinn `CidQueue::LEN`: remote CIDs stored at most (cid_queue.rs). */
        internal const val CID_QUEUE_LEN = 5

        /** Fisher-Yates, like rand's `SliceRandom::shuffle`. */
        private fun shuffle(a: ByteArray, rng: Random) {
            for (i in a.size - 1 downTo 1) {
                val j = rng.nextInt(i + 1)
                val t = a[i]; a[i] = a[j]; a[j] = t
            }
        }

        /**
         * Decode parameters sent by the peer of an endpoint on [side] (transport_parameters.rs:407). Throws
         * [TransportParameterError].
         */
        fun read(side: Side, r: Reader): TransportParameters {
            val params = TransportParameters()
            var got = 0L // bit per integer parameter id already seen
            try {
                while (r.hasRemaining()) {
                    val id = r.getVar()
                    val len = r.getVar()
                    if (r.remaining.toLong() < len) throw TransportParameterError.Malformed
                    val n = len.toInt()
                    if (!TransportParameterId.isSupported(id)) {
                        r.skip(n) // unknown transport parameters are ignored
                        continue
                    }
                    val remainingBefore = r.remaining
                    when (id) {
                        TransportParameterId.OriginalDestinationConnectionId ->
                            params.originalDstCid = decodeCid(n, params.originalDstCid, r)
                        TransportParameterId.StatelessResetToken -> {
                            if (n != 16 || params.statelessResetToken != null) throw TransportParameterError.Malformed
                            params.statelessResetToken = ResetToken.fromReader(r)
                        }
                        TransportParameterId.DisableActiveMigration -> {
                            if (n != 0 || params.disableActiveMigration) throw TransportParameterError.Malformed
                            params.disableActiveMigration = true
                        }
                        TransportParameterId.PreferredAddress -> {
                            if (params.preferredAddress != null) throw TransportParameterError.Malformed
                            // quinn reads through `r.take(len)`: the value cannot run past its declared length.
                            val sub = Reader(r.array, r.pos, r.pos + n)
                            params.preferredAddress = PreferredAddress.read(sub)
                            r.skip(sub.pos - r.pos)
                        }
                        TransportParameterId.InitialSourceConnectionId ->
                            params.initialSrcCid = decodeCid(n, params.initialSrcCid, r)
                        TransportParameterId.RetrySourceConnectionId ->
                            params.retrySrcCid = decodeCid(n, params.retrySrcCid, r)
                        TransportParameterId.MaxDatagramFrameSize -> {
                            if (n > 8 || params.maxDatagramFrameSize != null) throw TransportParameterError.Malformed
                            params.maxDatagramFrameSize = r.getVarInt()
                        }
                        TransportParameterId.GreaseQuicBit -> {
                            if (n != 0) throw TransportParameterError.Malformed
                            params.greaseQuicBit = true
                        }
                        TransportParameterId.MinAckDelayDraft07 -> params.minAckDelay = r.getVarInt()
                        else -> if (TransportParameterId.isIntParam(id)) {
                            val value = r.getVarInt()
                            val bit = 1L shl id.toInt()
                            if (n != value.size || got and bit != 0L) throw TransportParameterError.Malformed
                            params.setIntParam(id, value)
                            got = got or bit
                        } else {
                            r.skip(n) // the reserved parameter
                        }
                    }
                    if (remainingBefore - r.remaining != n) throw TransportParameterError.Malformed
                }
            } catch (e: UnexpectedEnd) {
                throw TransportParameterError.Malformed
            }

            // Semantic validation
            if (params.ackDelayExponent.value > 20 || // RFC 9000 §18.2 ack_delay_exponent
                params.maxAckDelay.value >= (1L shl 14) || // §18.2 max_ack_delay
                params.activeConnectionIdLimit.value < 2 || // §18.2 active_connection_id_limit
                params.maxUdpPayloadSize.value < 1200 || // §18.2 max_udp_payload_size
                params.initialMaxStreamsBidi.value > MAX_STREAM_COUNT || // §4.6
                params.initialMaxStreamsUni.value > MAX_STREAM_COUNT ||
                // draft-ietf-quic-ack-frequency §3: min_ack_delay (us) must not exceed max_ack_delay (ms)
                params.minAckDelay.let { it != null && it.value > params.maxAckDelay.value * 1000 } ||
                // §18.2: server-only parameters sent by a client
                (side.isServer && (params.originalDstCid != null || params.preferredAddress != null ||
                    params.retrySrcCid != null || params.statelessResetToken != null)) ||
                // §18.2 preferred_address: a zero-length connection ID is invalid
                params.preferredAddress?.connectionId?.isEmpty() == true
            ) {
                throw TransportParameterError.IllegalValue
            }
            return params
        }

        private fun decodeCid(len: Int, value: ConnectionId?, r: Reader): ConnectionId {
            if (len > MAX_CID_SIZE || value != null || r.remaining < len) throw TransportParameterError.Malformed
            return ConnectionId.fromReader(r, len)
        }

        /** quinn compares `Option<VarInt>` with `None < Some(_)`. */
        private fun optionGreater(a: VarInt?, b: VarInt?): Boolean = when {
            a == null -> false
            b == null -> true
            else -> a > b
        }
    }
}
