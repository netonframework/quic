package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import neton.io.core.secureRandomLong
import neton.io.net.EcnCodepoint
import neton.io.net.SocketAddress
import kotlin.random.Random
import kotlin.time.Duration.Companion.milliseconds

// The endpoint: routing datagrams to connections and handling what arrives for none (quinn-proto `endpoint.rs`).
//
// ⚖️ Deviations from quinn:
// - quinn's `Slab`s are [Slab] (same LIFO reuse of freed keys, which connection handles depend on).
// - quinn keys locally generated CIDs with FxHash and peer-chosen ones with SipHash; Kotlin's `HashMap` hashes a
//   `ConnectionId` by its content with `contentHashCode`, for both.
// - The RNG is a `kotlin.random.Random` seeded from a Long (see `Connection`); a 32-byte `rngSeed` is folded into it.
// - `connect`, `accept` and `retry` throw [ConnectError], [AcceptError] and [RetryError] instead of returning
//   `Result`s; `Incoming` is not checked for being dropped unhandled (quinn warns from `Drop`).

/**
 * The main entry point to the library (endpoint.rs:45). Performs no I/O whatsoever: it consumes incoming datagrams and
 * connection-generated events via [handle] and [handleEvent].
 *
 * [allowMtud] enables path MTU detection when requested by the connection configuration; this requires that outgoing
 * packets are never fragmented. [rngSeed] (32 bytes), if given, takes priority over [EndpointConfig.rngSeed].
 */
class Endpoint(
    private val config: EndpointConfig,
    private var serverConfig: ServerConfig?,
    /** Whether the underlying UDP socket promises not to fragment packets. */
    private val allowMtud: Boolean,
    rngSeed: ByteArray? = null,
) {
    private val rng: Random = Random((rngSeed ?: config.rngSeed)?.let { foldSeed(it) } ?: secureRandomLong())
    private val index = ConnectionIndex()
    private val connections = Slab<ConnectionMeta>()
    private val localCidGenerator: ConnectionIdGenerator = config.connectionIdGeneratorFactory()
    private val cidParser = FixedLengthConnectionIdParser(localCidGenerator.cidLen)

    /** Time at which a stateless reset was most recently sent; [Instant.NONE] for never. */
    private var lastStatelessReset = Instant.NONE

    /** Buffered Initial and 0-RTT messages for pending incoming connections. */
    private val incomingBuffers = Slab<IncomingBuffer>()
    private var allIncomingBuffersTotalBytes = 0L

    /**
     * Replace the server configuration, affecting new incoming connections only. Pending incoming connections retain
     * the configuration active when they first arrived.
     */
    fun setServerConfig(serverConfig: ServerConfig?) {
        this.serverConfig = serverConfig
    }

    /**
     * Process [EndpointEvent]s emitted from related connections (endpoint.rs:106). In turn, processing this event may
     * return a [ConnectionEvent] for the same connection.
     */
    fun handleEvent(ch: ConnectionHandle, event: EndpointEvent): ConnectionEvent? {
        when (event) {
            is EndpointEvent.NeedIdentifiers -> return sendNewIdentifiers(event.now, ch, event.n)
            is EndpointEvent.ResetTokenChanged -> {
                val meta = connections[ch.index]
                meta.resetTokenRemote?.let { index.connectionResetTokens.remove(it, meta.resetToken!!) }
                meta.resetTokenRemote = event.remote
                meta.resetToken = event.token
                // quinn warns on a duplicate reset token
                index.connectionResetTokens.insert(event.remote, event.token, ch)
            }
            is EndpointEvent.RetireConnectionId -> {
                val cid = connections[ch.index].locCids.remove(event.sequence)
                if (cid != null) {
                    // peer retired CID
                    index.retire(cid)
                    if (event.allowMoreCids) return sendNewIdentifiers(event.now, ch, 1)
                }
            }
            EndpointEvent.Drained -> {
                // An unknown handle indicates a bug in downstream code, which could cause spurious connection loss if
                // the CID was (re)allocated prior to the illegal call; quinn logs it and carries on.
                connections.tryRemove(ch.index)?.let { index.remove(it) }
            }
        }
        return null
    }

    /**
     * Process an incoming UDP datagram `data[start, end)` (endpoint.rs:148). The endpoint takes ownership of [data]:
     * packets are decrypted in place and frame payloads handed out as slices of it. A response the endpoint makes by
     * itself is written into [buf], which must have nothing readable.
     */
    fun handle(
        now: Instant,
        remote: SocketAddress,
        localIp: SocketAddress?,
        ecn: EcnCodepoint?,
        data: ByteArray,
        buf: Buffer,
        start: Int = 0,
        end: Int = data.size,
    ): DatagramEvent? {
        // Partially decode packet or short-circuit if unable
        val datagramLen = end - start
        val firstDecode = try {
            PartialDecode.decode(data, start, end, cidParser, config.supportedVersions, config.greaseQuicBit)
        } catch (e: PacketDecodeError.UnsupportedVersion) {
            if (serverConfig == null) {
                // dropping packet with unsupported version
                return null
            }
            // RFC 9000 §5.2.2: "Servers MUST drop smaller packets that specify unsupported versions." Responding to
            // short packets would let a spoofed source elicit a Version Negotiation packet larger than the datagram
            // that triggered it.
            if (datagramLen < MIN_INITIAL_SIZE) return null
            // sending version negotiation
            Header.VersionNegotiate(rng.nextInt(256) or 0x40, srcCid = e.dstCid, dstCid = e.srcCid).encode(buf)
            // Grease with a reserved version
            buf.writeInt(if (e.version == 0x0a1a_2a3a) 0x0a1a_2a4a else 0x0a1a_2a3a)
            for (version in config.supportedVersions) buf.writeInt(version)
            return DatagramEvent.Response(Transmit(remote, null, buf.len, null, localIp))
        } catch (e: PacketDecodeError) {
            // malformed header
            return null
        }
        val event = ConnectionEvent.Datagram(now, remote, ecn, firstDecode)

        val dstCid = firstDecode.dstCid

        val routeTo = index.get(remote, localIp, firstDecode)
        if (routeTo != null) {
            // Handle packet on existing connection
            when (routeTo) {
                is RouteDatagramTo.Incoming -> {
                    val incomingBuffer = incomingBuffers[routeTo.index]
                    val cfg = incomingBuffer.serverConfig
                    if (incomingBuffer.totalBytes + datagramLen <= cfg.incomingBufferSize &&
                        allIncomingBuffersTotalBytes + datagramLen <= cfg.incomingBufferSizeTotal
                    ) {
                        incomingBuffer.datagrams.add(event)
                        incomingBuffer.totalBytes += datagramLen
                        allIncomingBuffersTotalBytes += datagramLen
                    }
                    return null
                }
                is RouteDatagramTo.Connection -> return DatagramEvent.ConnectionEvent(routeTo.ch, event)
            }
        } else if (firstDecode.initialHeader != null) {
            // Potentially create a new connection
            return handleFirstPacket(datagramLen, event, FourTuple(remote, localIp), buf)
        } else if (firstDecode.hasLongHeader) {
            // ignoring non-initial packet for unknown connection
            return null
        } else if (!firstDecode.isInitial && !localCidGenerator.validate(dstCid)) {
            // dropping packet with invalid CID
            return null
        } else if (dstCid.isEmpty()) {
            // dropping unrecognized short packet without ID
            return null
        } else {
            // If we got this far, we're receiving a seemingly valid packet for an unknown connection. Send a stateless
            // reset if possible.
            return statelessReset(now, datagramLen, FourTuple(remote, localIp), dstCid, buf)?.let { DatagramEvent.Response(it) }
        }
    }

    /** endpoint.rs:275 */
    private fun statelessReset(
        now: Instant,
        incitingDgramLen: Int,
        addresses: FourTuple,
        dstCid: ConnectionId,
        buf: Buffer,
    ): Transmit? {
        if (lastStatelessReset.isSome && lastStatelessReset + config.minResetInterval > now) {
            // ignoring unexpected packet within minimum stateless reset interval
            return null
        }

        // Prevent amplification attacks and reset loops by ensuring we pad to at most 1 byte smaller than the inciting
        // packet.
        val headroom = incitingDgramLen - RESET_TOKEN_SIZE
        if (headroom <= MIN_PADDING_LEN) {
            // ignoring unexpected packet: not larger than minimum stateless reset size
            return null
        }
        val maxPaddingLen = headroom - 1

        // sending stateless reset
        lastStatelessReset = now
        // Resets with at least this much padding can't possibly be distinguished from real packets
        val paddingLen = if (maxPaddingLen <= IDEAL_MIN_PADDING_LEN) {
            maxPaddingLen
        } else {
            rng.nextInt(IDEAL_MIN_PADDING_LEN, maxPaddingLen)
        }
        val padding = ByteArray(paddingLen)
        rng.nextBytes(padding)
        padding[0] = (0b0100_0000 or ((padding[0].toInt() and 0xFF) ushr 2)).toByte()
        buf.writeBytes(padding)
        ResetToken.derive(config.resetKey, dstCid).encode(buf)

        debugAssert(buf.len < incitingDgramLen) { "assertion failed: buf.len() < inciting_dgram_len" }

        return Transmit(addresses.remote, null, buf.len, null, addresses.localIp)
    }

    /**
     * Initiate a connection (endpoint.rs:338). Throws [ConnectError]. Returns the handle and the connection, which the
     * caller drives.
     */
    fun connect(now: Instant, config: ClientConfig, remote: SocketAddress, serverName: String): Pair<ConnectionHandle, Connection> {
        if (cidsExhausted()) throw ConnectError.CidsExhausted()
        if (remote.port == 0 || remote.ipBytes().all { it == 0.toByte() }) throw ConnectError.InvalidRemoteAddress(remote)
        if (config.version !in this.config.supportedVersions) throw ConnectError.UnsupportedVersion()

        val remoteId = config.initialDstCidProvider()

        val ch = ConnectionHandle(connections.vacantKey())
        val locCid = newCid(ch)
        val params = transportParameters(config.transport, locCid, null)
        val tls = config.crypto.startSession(config.version, serverName, params)

        val conn = addConnection(
            ch,
            config.version,
            remoteId,
            locCid,
            remoteId,
            FourTuple(remote, null),
            now,
            tls,
            config.transport,
            SideArgs.Client(config.tokenStore, serverName),
        )
        return ch to conn
    }

    /** quinn `TransportParameters::new` (transport_parameters.rs:145). */
    private fun transportParameters(transport: TransportConfig, initialSrcCid: ConnectionId, server: ServerConfig?): TransportParameters =
        TransportParameters.new(
            initialSrcCid = initialSrcCid,
            maxConcurrentBidiStreams = transport.maxConcurrentBidiStreams,
            maxConcurrentUniStreams = transport.maxConcurrentUniStreams,
            receiveWindow = transport.receiveWindow,
            streamReceiveWindow = transport.streamReceiveWindow,
            maxUdpPayloadSize = config.maxUdpPayloadSize,
            maxIdleTimeout = transport.maxIdleTimeout,
            serverMigration = server?.migration,
            localCidLen = localCidGenerator.cidLen,
            datagramReceiveBufferSize = transport.datagramReceiveBufferSize,
            greaseQuicBit = config.greaseQuicBit,
            rng = rng,
        )

    private fun sendNewIdentifiers(now: Instant, ch: ConnectionHandle, num: Long): ConnectionEvent {
        val ids = ArrayList<IssuedCid>(num.toInt())
        for (i in 0 until num) {
            val id = newCid(ch)
            val meta = connections[ch.index]
            val sequence = meta.cidsIssued
            meta.cidsIssued += 1
            meta.locCids[sequence] = id
            ids.add(IssuedCid(sequence, id, ResetToken.derive(config.resetKey, id)))
        }
        return ConnectionEvent.NewIdentifiers(ids, now)
    }

    /** Generate a connection ID for [ch]. */
    private fun newCid(ch: ConnectionHandle): ConnectionId {
        while (true) {
            val cid = localCidGenerator.generateCid()
            if (cid.isEmpty()) {
                // Zero-length CID; nothing to track
                debugAssert(localCidGenerator.cidLen == 0) { "assertion `left == right` failed" }
                return cid
            }
            if (!index.connectionIds.containsKey(cid)) {
                index.connectionIds[cid] = ch
                return cid
            }
        }
    }

    /** endpoint.rs:431 */
    private fun handleFirstPacket(
        datagramLen: Int,
        event: ConnectionEvent.Datagram,
        addresses: FourTuple,
        buf: Buffer,
    ): DatagramEvent? {
        val firstDecode = event.firstDecode
        val dstCid = firstDecode.dstCid
        val header = firstDecode.initialHeader!!

        val serverConfig = serverConfig
        if (serverConfig == null) {
            // packet for unrecognized connection
            return statelessReset(event.now, datagramLen, addresses, dstCid, buf)?.let { DatagramEvent.Response(it) }
        }

        if (datagramLen < MIN_INITIAL_SIZE) {
            // ignoring short initial for connection
            return null
        }

        // Saturation only happens under heavy load, where deriving initial keys per Initial just to reply with
        // CONNECTION_REFUSED would starve packet processing for existing connections.
        if (cidsExhausted() || incomingBuffers.len >= serverConfig.maxIncoming) {
            // ignoring initial for connection due to saturation
            return null
        }

        val crypto = try {
            serverConfig.crypto.initialKeys(header.version, dstCid)
        } catch (e: UnsupportedVersion) {
            // This probably indicates that the user set supported_versions incorrectly in `EndpointConfig`.
            return null
        }

        earlyValidateFirstPacket(header)?.let { reason ->
            return DatagramEvent.Response(initialClose(header.version, addresses, crypto, header.srcCid, reason, buf))
        }

        val packet = try {
            firstDecode.finish(crypto.header.remote)
        } catch (e: PacketDecodeError) {
            // unable to decode initial packet
            return null
        }

        if (!packet.reservedBitsValid()) {
            // dropping connection attempt with invalid reserved bits
            return null
        }

        val initial = packet.header as? InitialHeader ?: error("non-initial packet in handle_first_packet()")

        val token = try {
            IncomingToken.fromHeader(
                initial,
                serverConfig.tokenKey,
                serverConfig.retryTokenLifetime,
                serverConfig.validationToken.lifetime,
                serverConfig.validationToken.log,
                serverConfig.timeSource.now(),
                addresses.remote,
            )
        } catch (e: InvalidRetryTokenError) {
            // rejecting invalid retry token
            return DatagramEvent.Response(
                initialClose(initial.version, addresses, crypto, initial.srcCid, TransportError.INVALID_TOKEN(""), buf),
            )
        }

        val incomingIdx = incomingBuffers.insert(IncomingBuffer(serverConfig))
        index.insertInitialIncoming(initial.dstCid, incomingIdx)

        return DatagramEvent.NewConnection(
            Incoming(event.now, addresses, event.ecn, packet, firstDecode, crypto, token, incomingIdx),
        )
    }

    /**
     * Attempt to accept this incoming connection (an error may still occur; endpoint.rs:549). Uses [serverConfig] if
     * given, else the configuration the attempt arrived with. Throws [AcceptError].
     */
    fun accept(incoming: Incoming, now: Instant, buf: Buffer, serverConfig: ServerConfig? = null): Pair<ConnectionHandle, Connection> {
        val remoteAddressValidated = incoming.remoteAddressValidated()
        incoming.consume()
        val incomingBuffer = incomingBuffers.remove(incoming.incomingIdx)
        allIncomingBuffersTotalBytes -= incomingBuffer.totalBytes

        val header = incoming.packet.header as InitialHeader
        val packetNumber = header.number.expand(0)
        val srcCid = header.srcCid
        val dstCid = header.dstCid
        val version = header.version
        val config = serverConfig ?: incomingBuffer.serverConfig

        val maxIdleTimeout = config.transport.maxIdleTimeout
        if (maxIdleTimeout != null && incoming.receivedAt + maxIdleTimeout.value.milliseconds <= now) {
            // abandoning accept of stale initial
            index.removeInitial(dstCid)
            throw AcceptError(ConnectionError.TimedOut, null)
        }

        if (cidsExhausted()) {
            // refusing connection
            index.removeInitial(dstCid)
            throw AcceptError(
                ConnectionError.CidsExhausted,
                initialClose(version, incoming.addresses, incoming.crypto, srcCid, TransportError.CONNECTION_REFUSED(""), buf),
            )
        }

        val packet = incoming.packet
        try {
            packet.payloadLen = incoming.crypto.packet.remote.decrypt(
                packetNumber,
                packet.data, packet.headerStart, packet.headerStart + packet.headerLen,
                packet.data, packet.payloadStart, packet.payloadStart + packet.payloadLen,
            )
        } catch (e: CryptoError) {
            // failed to authenticate initial packet
            index.removeInitial(dstCid)
            throw AcceptError(ConnectionError.Transport(TransportError.PROTOCOL_VIOLATION("authentication failed")), null)
        }

        val ch = ConnectionHandle(connections.vacantKey())
        val locCid = newCid(ch)
        val params = transportParameters(config.transport, locCid, config)
        params.statelessResetToken = ResetToken.derive(this.config.resetKey, locCid)
        params.originalDstCid = incoming.token.origDstCid
        params.retrySrcCid = incoming.token.retrySrcCid
        var prefAddrCid: ConnectionId? = null
        if (config.hasPreferredAddress()) {
            val cid = newCid(ch)
            prefAddrCid = cid
            params.preferredAddress = PreferredAddress(
                config.preferredAddressV4,
                config.preferredAddressV6,
                cid,
                ResetToken.derive(this.config.resetKey, cid),
            )
        }

        val tls = config.crypto.startSession(version, params)
        val conn = addConnection(
            ch,
            version,
            dstCid,
            locCid,
            srcCid,
            incoming.addresses,
            incoming.receivedAt,
            tls,
            config.transport,
            SideArgs.Server(config, prefAddrCid, remoteAddressValidated),
        )
        index.insertInitial(dstCid, ch)

        val error = conn.handleFirstPacket(
            incoming.receivedAt,
            incoming.addresses.remote,
            incoming.ecn,
            packetNumber,
            packet,
            incoming.rest,
        )
        if (error == null) {
            // new connection
            for (event in incomingBuffer.datagrams) conn.handleEvent(event)
            return ch to conn
        }

        // handshake failed
        handleEvent(ch, EndpointEvent.Drained)
        val response = if (error is ConnectionError.Transport) {
            initialClose(version, incoming.addresses, incoming.crypto, srcCid, error.error, buf)
        } else {
            null
        }
        throw AcceptError(error, response)
    }

    /** Check if we should refuse a connection attempt regardless of the packet's contents (endpoint.rs:702). */
    private fun earlyValidateFirstPacket(header: ProtectedHeader.Initial): TransportError? {
        // RFC9000 §7.2 dictates that initial (client-chosen) destination CIDs must be at least 8 bytes. If this is a
        // Retry packet, then the length must instead match our usual CID length. If we ever issue non-Retry address
        // validation tokens via `NEW_TOKEN`, then we'll also need to validate CID length for those after decoding the
        // token.
        if (header.dstCid.size < 8 &&
            (header.tokenStart == header.tokenEnd || header.dstCid.size != localCidGenerator.cidLen)
        ) {
            // rejecting connection due to invalid DCID length
            return TransportError.PROTOCOL_VIOLATION("invalid destination CID length")
        }
        return null
    }

    /** Reject this incoming connection attempt (endpoint.rs:727). */
    fun refuse(incoming: Incoming, buf: Buffer): Transmit {
        cleanUpIncoming(incoming)
        incoming.consume()

        val header = incoming.packet.header as InitialHeader
        return initialClose(header.version, incoming.addresses, incoming.crypto, header.srcCid, TransportError.CONNECTION_REFUSED(""), buf)
    }

    /**
     * Respond with a retry packet, requiring the client to retry with address validation (endpoint.rs:744). Throws
     * [RetryError] if [Incoming.mayRetry] is false.
     */
    fun retry(incoming: Incoming, buf: Buffer): Transmit {
        if (!incoming.mayRetry()) throw RetryError(incoming)

        val serverConfig = incomingBuffers[incoming.incomingIdx].serverConfig
        cleanUpIncoming(incoming)
        incoming.consume()

        // First Initial. The peer will use this as the DCID of its following Initials. Initial DCIDs are looked up
        // separately from Handshake/Data DCIDs, so there is no risk of collision with established connections. In the
        // unlikely event that a collision occurs between two connections in the initial phase, both will fail fast and
        // may be retried by the application layer.
        val locCid = localCidGenerator.generateCid()

        val header = incoming.packet.header as InitialHeader
        val payload = TokenPayload.Retry(incoming.addresses.remote, header.dstCid, serverConfig.timeSource.now())
        val token = Token.new(payload, rng).encode(serverConfig.tokenKey)

        val retry = Header.Retry(dstCid = header.srcCid, srcCid = locCid, version = header.version)

        val encode = retry.encode(buf)
        buf.writeBytes(token)
        val tag = serverConfig.crypto.retryTag(header.version, header.dstCid, buf.backingArray(), buf.readerIndex(), buf.len)
        buf.writeBytes(tag)
        encode.finish(buf, incoming.crypto.header.local, null, 0)

        return Transmit(incoming.addresses.remote, null, buf.len, null, incoming.addresses.localIp)
    }

    /**
     * Ignore this incoming connection attempt, not sending any packet in response (endpoint.rs:798). Doing this
     * actively, rather than merely dropping the [Incoming], is necessary to prevent memory leaks due to state within
     * the endpoint tracking the incoming connection.
     */
    fun ignore(incoming: Incoming) {
        cleanUpIncoming(incoming)
        incoming.consume()
    }

    /** Clean up endpoint data structures associated with an [Incoming]. */
    private fun cleanUpIncoming(incoming: Incoming) {
        index.removeInitial((incoming.packet.header as InitialHeader).dstCid)
        val incomingBuffer = incomingBuffers.remove(incoming.incomingIdx)
        allIncomingBuffersTotalBytes -= incomingBuffer.totalBytes
    }

    private fun addConnection(
        ch: ConnectionHandle,
        version: Int,
        initCid: ConnectionId,
        locCid: ConnectionId,
        remCid: ConnectionId,
        addresses: FourTuple,
        now: Instant,
        tls: CryptoSession,
        transportConfig: TransportConfig,
        sideArgs: SideArgs,
    ): Connection {
        val rngSeed = rng.nextLong()
        val side = sideArgs.side
        val prefAddrCid = (sideArgs as? SideArgs.Server)?.prefAddrCid
        val conn = Connection(
            config,
            transportConfig,
            initCid,
            locCid,
            remCid,
            addresses.remote,
            addresses.localIp,
            tls,
            localCidGenerator,
            now,
            version,
            allowMtud,
            rngSeed,
            sideArgs,
        )

        var cidsIssued = 0L
        val locCids = HashMap<Long, ConnectionId>()

        locCids[cidsIssued] = locCid
        cidsIssued += 1

        if (prefAddrCid != null) {
            debugAssert(cidsIssued == 1L) { "preferred address cid seq must be 1" }
            locCids[cidsIssued] = prefAddrCid
            cidsIssued += 1
        }

        val id = connections.insert(ConnectionMeta(initCid, cidsIssued, locCids, addresses, side))
        debugAssert(id == ch.index) { "connection handle allocation out of sync" }

        index.insertConn(addresses, locCid, ch, side)

        return conn
    }

    /** endpoint.rs:871 */
    private fun initialClose(
        version: Int,
        addresses: FourTuple,
        crypto: Keys,
        remoteId: ConnectionId,
        reason: TransportError,
        buf: Buffer,
    ): Transmit {
        // We don't need to worry about CID collisions in initial closes because the peer shouldn't respond, and if it
        // does, and the CID collides, we'll just drop the unexpected response.
        val localId = localCidGenerator.generateCid()
        val number = PacketNumber.U8(0)
        val header = InitialHeader(remoteId, localId, Bytes.EMPTY, number, version)

        val partialEncode = header.encode(buf)
        val maxLen = INITIAL_MTU - partialEncode.headerLen - crypto.packet.local.tagLen
        Frame.Close.from(reason).encode(buf, maxLen)
        buf.writeZeros(crypto.packet.local.tagLen)
        partialEncode.finish(buf, crypto.header.local, crypto.packet.local, 0)
        return Transmit(addresses.remote, null, buf.len, null, addresses.localIp)
    }

    /** The configuration used by this endpoint. */
    fun config(): EndpointConfig = config

    /** Number of connections that are currently open. */
    fun openConnections(): Int = connections.len

    /** Bytes currently used in the buffers for Initial and 0-RTT messages of pending incoming connections. */
    fun incomingBufferBytes(): Long = allIncomingBuffersTotalBytes

    internal fun knownConnections(): Int {
        val x = connections.len
        debugAssert(x == index.connectionIdsInitial.size) { "assertion `left == right` failed: $x != ${index.connectionIdsInitial.size}" }
        // Not all connections have known reset tokens
        debugAssert(x >= index.connectionResetTokens.size) { "assertion failed: x >= reset tokens" }
        // Not all connections have unique remotes, and 0-length CIDs might not be in use.
        debugAssert(x >= index.incomingConnectionRemotes.size) { "assertion failed: x >= incoming remotes" }
        debugAssert(x >= index.outgoingConnectionRemotes.size) { "assertion failed: x >= outgoing remotes" }
        return x
    }

    internal fun knownCids(): Int = index.connectionIds.size

    /**
     * Whether we've used up 3/4 of the available CID space (endpoint.rs:945). We leave some space unused so that
     * [newCid] can be relied upon to finish quickly. We don't bother to check when CIDs longer than 4 bytes are used
     * because 2^40 connections is a lot.
     */
    private fun cidsExhausted(): Boolean {
        val len = localCidGenerator.cidLen
        if (len > 4 || len == 0) return false
        val space = 1L shl (len * 8)
        return space - index.connectionIds.size < 1L shl (len * 8 - 2)
    }

    override fun toString(): String =
        "Endpoint(connections=${connections.len}, config=$config, serverConfig=$serverConfig, " +
            "incomingBuffers=${incomingBuffers.len}, allIncomingBuffersTotalBytes=$allIncomingBuffersTotalBytes)"

    private companion object {
        /** Minimum amount of padding for the stateless reset to look like a short-header packet. */
        const val MIN_PADDING_LEN = 5

        /** Resets with at least this much padding can't possibly be distinguished from real packets. */
        const val IDEAL_MIN_PADDING_LEN = MIN_PADDING_LEN + MAX_CID_SIZE

        /** A 32-byte RNG seed as the Long seed of `kotlin.random.Random`. */
        fun foldSeed(seed: ByteArray): Long {
            var h = 0L
            for (b in seed) h = h * 31 + (b.toLong() and 0xFF) xor (h ushr 29)
            return h
        }
    }
}

/** Buffered Initial and 0-RTT messages for a pending incoming connection (endpoint.rs:973). */
private class IncomingBuffer(val serverConfig: ServerConfig) {
    val datagrams = ArrayList<ConnectionEvent.Datagram>()
    var totalBytes = 0L
}

/** Part of protocol state incoming datagrams can be routed to (endpoint.rs:981). */
private sealed class RouteDatagramTo {
    class Incoming(val index: Int) : RouteDatagramTo()
    class Connection(val ch: ConnectionHandle) : RouteDatagramTo()
}

/** Maps packets to existing connections (endpoint.rs:988). */
private class ConnectionIndex {
    /** Identifies connections based on the initial DCID the peer utilized. Used by the server, not the client. */
    val connectionIdsInitial = HashMap<ConnectionId, RouteDatagramTo>()

    /** Identifies connections based on locally created CIDs. */
    val connectionIds = HashMap<ConnectionId, ConnectionHandle>()

    /** Identifies incoming connections with zero-length CIDs. */
    val incomingConnectionRemotes = HashMap<FourTuple, ConnectionHandle>()

    /**
     * Identifies outgoing connections with zero-length CIDs. We don't yet support explicit source addresses for client
     * connections, and zero-length CIDs require a unique four-tuple, so at most one client connection with zero-length
     * local CIDs may be established per remote. We must omit the local address from the key because we don't
     * necessarily know what address we're sending from, and hence receiving at.
     */
    val outgoingConnectionRemotes = HashMap<SocketAddress, ConnectionHandle>()

    /**
     * Reset tokens provided by the peer for the CID each connection is currently sending to. Incoming stateless resets
     * do not have correct CIDs, so we need this to identify the correct recipient, if any.
     */
    val connectionResetTokens = ResetTokenTable()

    /** Associate an incoming connection with its initial destination CID. */
    fun insertInitialIncoming(dstCid: ConnectionId, incomingKey: Int) {
        if (dstCid.isEmpty()) return
        connectionIdsInitial[dstCid] = RouteDatagramTo.Incoming(incomingKey)
    }

    /** Remove an association with an initial destination CID. */
    fun removeInitial(dstCid: ConnectionId) {
        if (dstCid.isEmpty()) return
        val removed = connectionIdsInitial.remove(dstCid)
        debugAssert(removed != null) { "assertion failed: removed.is_some()" }
    }

    /** Associate a connection with its initial destination CID. */
    fun insertInitial(dstCid: ConnectionId, connection: ConnectionHandle) {
        if (dstCid.isEmpty()) return
        connectionIdsInitial[dstCid] = RouteDatagramTo.Connection(connection)
    }

    /** Associate a connection with its first locally-chosen destination CID if used, or otherwise its 4-tuple. */
    fun insertConn(addresses: FourTuple, dstCid: ConnectionId, connection: ConnectionHandle, side: Side) {
        if (dstCid.isEmpty()) {
            when (side) {
                Side.Server -> incomingConnectionRemotes[addresses] = connection
                Side.Client -> outgoingConnectionRemotes[addresses.remote] = connection
            }
        } else {
            connectionIds[dstCid] = connection
        }
    }

    /** Discard a connection ID. */
    fun retire(dstCid: ConnectionId) {
        connectionIds.remove(dstCid)
    }

    /** Remove all references to a connection. */
    fun remove(conn: ConnectionMeta) {
        if (conn.side.isServer) removeInitial(conn.initCid)
        for (cid in conn.locCids.values) connectionIds.remove(cid)
        incomingConnectionRemotes.remove(conn.addresses)
        outgoingConnectionRemotes.remove(conn.addresses.remote)
        val remote = conn.resetTokenRemote
        if (remote != null) connectionResetTokens.remove(remote, conn.resetToken!!)
    }

    /**
     * Find the existing connection that [datagram] from [remote] to [localIp] should be routed to, if any
     * (endpoint.rs:1095).
     */
    fun get(remote: SocketAddress, localIp: SocketAddress?, datagram: PartialDecode): RouteDatagramTo? {
        val dstCid = datagram.dstCid
        if (!dstCid.isEmpty()) {
            connectionIds[dstCid]?.let { return RouteDatagramTo.Connection(it) }
        }
        if (datagram.isInitial || datagram.is0rtt) {
            connectionIdsInitial[dstCid]?.let { return it }
        }
        if (dstCid.isEmpty()) {
            incomingConnectionRemotes[FourTuple(remote, localIp)]?.let { return RouteDatagramTo.Connection(it) }
            outgoingConnectionRemotes[remote]?.let { return RouteDatagramTo.Connection(it) }
        }
        if (datagram.len < RESET_TOKEN_SIZE) return null
        return connectionResetTokens.get(remote, datagram.data, datagram.end - RESET_TOKEN_SIZE)
            ?.let { RouteDatagramTo.Connection(it) }
    }
}

/** endpoint.rs:1126 */
private class ConnectionMeta(
    val initCid: ConnectionId,
    /** Number of local connection IDs that have been issued in NEW_CONNECTION_ID frames. */
    var cidsIssued: Long,
    val locCids: HashMap<Long, ConnectionId>,
    /**
     * Remote/local addresses the connection began with. Only needed to support connections with zero-length CIDs,
     * which cannot migrate, so we don't bother keeping it up to date.
     */
    val addresses: FourTuple,
    val side: Side,
) {
    /** Reset token provided by the peer for the CID we're currently sending to, and the address being sent to. */
    var resetTokenRemote: SocketAddress? = null
    var resetToken: ResetToken? = null
}

/** Internal identifier for a [Connection] currently associated with an endpoint (endpoint.rs:1144). */
value class ConnectionHandle(val index: Int) {
    override fun toString(): String = "ConnectionHandle($index)"
}

/** Event resulting from processing a single datagram (endpoint.rs:1166). */
sealed class DatagramEvent {
    /** The datagram is redirected to its connection. */
    class ConnectionEvent(val ch: ConnectionHandle, val event: neton.quic.proto.ConnectionEvent) : DatagramEvent()

    /** The datagram may result in starting a new connection. */
    class NewConnection(val incoming: Incoming) : DatagramEvent()

    /** Response generated directly by the endpoint. */
    class Response(val transmit: Transmit) : DatagramEvent()
}

/**
 * An incoming connection for which the server has not yet begun its part of the handshake (endpoint.rs:1176). Pass
 * it to exactly one of [Endpoint.accept], [Endpoint.refuse], [Endpoint.retry] or [Endpoint.ignore].
 */
class Incoming internal constructor(
    internal val receivedAt: Instant,
    internal val addresses: FourTuple,
    internal val ecn: EcnCodepoint?,
    internal val packet: Packet,
    /** The first packet's decode, for the coalesced packets after it (quinn's `rest`). */
    internal val rest: PartialDecode,
    internal val crypto: Keys,
    internal val token: IncomingToken,
    internal val incomingIdx: Int,
) {
    private var consumed = false

    internal fun consume() {
        check(!consumed) { "this Incoming was already accepted, refused, retried or ignored" }
        consumed = true
    }

    /** The local IP address which was used when the peer established the connection (see [Connection.localIp]). */
    fun localIp(): SocketAddress? = addresses.localIp

    /** The peer's UDP address. */
    fun remoteAddress(): SocketAddress = addresses.remote

    /**
     * Whether the socket address that is initiating this connection has been validated: the sender of the initial
     * packet has proved that they can receive traffic sent to [remoteAddress]. If false, [mayRetry] is guaranteed to
     * be true; the inverse is not guaranteed.
     */
    fun remoteAddressValidated(): Boolean = token.validated

    /** Whether it is legal to respond with a retry packet. */
    fun mayRetry(): Boolean = token.retrySrcCid == null

    /** The original destination connection ID sent by the client. */
    fun origDstCid(): ConnectionId = token.origDstCid

    override fun toString(): String = "Incoming(addresses=$addresses, ecn=$ecn, token=$token, incomingIdx=$incomingIdx)"
}

/** Errors in the parameters being used to create a new connection (endpoint.rs:1261). */
sealed class ConnectError(message: String) : Exception(message) {
    /** The endpoint can no longer create new connections. */
    class EndpointStopping : ConnectError("endpoint stopping")

    /** The connection could not be created because not enough of the CID space is available. */
    class CidsExhausted : ConnectError("CIDs exhausted")

    /** The given server name was malformed. */
    class InvalidServerName(val name: String) : ConnectError("invalid server name: $name")

    /** The remote address supplied was malformed (e.g. port 0 or an unspecified address). */
    class InvalidRemoteAddress(val address: SocketAddress) : ConnectError("invalid remote address: $address")

    /** No default client configuration was set up. */
    class NoDefaultClientConfig : ConnectError("no default client config")

    /** The local endpoint does not support the QUIC version specified in the client configuration. */
    class UnsupportedVersion : ConnectError("unsupported QUIC version")

    override fun equals(other: Any?): Boolean = other is ConnectError && other::class == this::class && other.message == message
    override fun hashCode(): Int = message.hashCode()
}

/** Error for attempting to accept an [Incoming] (endpoint.rs:1292). */
class AcceptError(
    /** Underlying error describing reason for failure. */
    override val cause: ConnectionError,
    /** Optional response to transmit back. */
    val response: Transmit?,
) : Exception(cause.message, cause)

/** Error for attempting to retry an [Incoming] which already bears a token from a previous retry (endpoint.rs:1302). */
class RetryError(private val incoming: Incoming) : Exception("retry() with validated Incoming") {
    /** The [Incoming]. */
    fun intoIncoming(): Incoming = incoming
}

/**
 * Reset tokens which are associated with peer socket addresses (endpoint.rs:1316). Both are peer-generated; Kotlin's
 * `HashMap` is used for both levels.
 */
private class ResetTokenTable {
    private val map = HashMap<SocketAddress, HashMap<ResetToken, ConnectionHandle>>()

    val size: Int get() = map.values.sumOf { it.size }

    /** Returns whether a token was replaced. */
    fun insert(remote: SocketAddress, token: ResetToken, ch: ConnectionHandle): Boolean =
        map.getOrPut(remote) { HashMap() }.put(token, ch) != null

    fun remove(remote: SocketAddress, token: ResetToken) {
        val inner = map[remote] ?: return
        inner.remove(token)
        if (inner.isEmpty()) map.remove(remote)
    }

    fun get(remote: SocketAddress, data: ByteArray, offset: Int): ConnectionHandle? {
        val inner = map[remote] ?: return null
        return inner[ResetToken(data.copyOfRange(offset, offset + RESET_TOKEN_SIZE))]
    }
}

/**
 * Identifies a connection by the combination of remote and local addresses (endpoint.rs:1351). Including the local
 * ensures good behavior when the host has multiple IP addresses on the same subnet and zero-length connection IDs are
 * in use.
 */
internal data class FourTuple(
    val remote: SocketAddress,
    /** A single socket can only listen on a single port, so no need to store it explicitly. */
    val localIp: SocketAddress?,
)

/**
 * A slab of values keyed by small integers (the `slab` crate as quinn uses it): freed keys are reused, most recently
 * freed first, so a connection created after another was drained gets its handle.
 */
internal class Slab<T : Any> {
    private val entries = ArrayList<T?>()
    private val free = ArrayList<Int>()

    /** Number of stored values. */
    var len = 0
        private set

    /** The key the next [insert] will use. */
    fun vacantKey(): Int = if (free.isEmpty()) entries.size else free[free.size - 1]

    fun insert(value: T): Int {
        val key = vacantKey()
        if (key == entries.size) entries.add(value) else {
            free.removeAt(free.size - 1)
            entries[key] = value
        }
        len++
        return key
    }

    operator fun get(key: Int): T = entries.getOrNull(key) ?: throw IllegalStateException("invalid slab key $key")

    fun remove(key: Int): T = tryRemove(key) ?: throw IllegalStateException("invalid slab key $key")

    fun tryRemove(key: Int): T? {
        val v = entries.getOrNull(key) ?: return null
        entries[key] = null
        free.add(key)
        len--
        return v
    }
}
