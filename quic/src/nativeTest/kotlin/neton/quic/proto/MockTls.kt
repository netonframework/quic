package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import neton.openssl.Crypto
import kotlin.random.Random

// A deterministic stand-in for the TLS 1.3 layer, for tests only (SPEC §4): it exists in the test source set and no
// production configuration can reach it.
//
// It is not TLS. The two sides exchange fixed, TLS-shaped handshake messages over CRYPTO frames (ClientHello /
// ServerHello at the Initial level; EncryptedExtensions, Certificate and Finished at the Handshake level; a
// NewSessionTicket at the 1-RTT level), in TLS 1.3's flight structure, so the connection sees the same sequence of
// key changes, handshake data and transport parameters as with rustls in quinn's tests. Keys are real: the handshake,
// 1-RTT, 0-RTT and exporter secrets are HKDF-derived from the two randoms (and the resumption secret of a ticket), and
// packets are protected with the production `PacketProtection` keys, Initial keys, key updates and Retry integrity
// tags. It supports transport parameters, ALPN selection (server preference; no common protocol fails with
// no_application_protocol, like rustls for QUIC), session tickets with 0-RTT and its acceptance flag, key updates,
// the exporter and a server identity blob of configurable size (standing in for a certificate chain). It does no
// authentication: certificates, signatures and client authentication need the real TLS layer.

/** Handshake message types, with TLS 1.3's numbers. */
private object Msg {
    const val CLIENT_HELLO = 1
    const val SERVER_HELLO = 2
    const val NEW_SESSION_TICKET = 4
    const val ENCRYPTED_EXTENSIONS = 8
    const val CERTIFICATE = 11
    const val FINISHED = 20
}

/** TLS alert descriptions used by the mock. */
internal object MockAlert {
    const val UNEXPECTED_MESSAGE = 10
    const val DECODE_ERROR = 50
    const val DECRYPT_ERROR = 51
    const val NO_APPLICATION_PROTOCOL = 120
}

/** What [MockSession.handshakeData] returns (quinn's rustls `HandshakeData`). */
class MockHandshakeData(val protocol: ByteArray?, val serverName: String?)

/** A session ticket as the client and the server remember it. */
internal class MockTicket(
    val id: ByteArray,
    val resumptionSecret: ByteArray,
    val suite: CipherSuite,
    val alpn: ByteArray?,
    /** The server's transport parameters, encoded (clients only). */
    val params: ByteArray?,
    val maxEarlyData: Boolean,
)

/** Server side of the mock TLS layer. */
class MockServerCrypto(
    /** Supported application protocols, in preference order; empty for none. */
    var alpn: List<ByteArray> = emptyList(),
    /** The server's identity (a certificate chain stand-in) sent in the Certificate message on full handshakes. */
    var identity: ByteArray = defaultIdentity(),
    var suite: CipherSuite = CipherSuite.TLS13_AES_128_GCM_SHA256,
    /** Whether tickets allow 0-RTT (rustls `max_early_data_size`, which quinn sets to `u32::MAX`). */
    var enableEarlyData: Boolean = true,
) : CryptoServerConfig {
    internal val rng = Random(0x5e11)
    internal val tickets = HashMap<String, MockTicket>()

    override fun initialKeys(version: Int, dstCid: ConnectionId): Keys = neton.quic.proto.initialKeys(version, dstCid, Side.Server)

    override fun retryTag(version: Int, origDstCid: ConnectionId, packet: ByteArray, offset: Int, length: Int): ByteArray =
        neton.quic.proto.retryTag(version, origDstCid, packet, offset, length)

    override fun startSession(version: Int, params: TransportParameters): CryptoSession =
        MockSession(Side.Server, version, params, server = this)

    companion object {
        fun defaultIdentity(): ByteArray = ByteArray(400) { (it * 7 + 3).toByte() }
    }
}

/** Client side of the mock TLS layer. */
class MockClientCrypto(
    /** Offered application protocols; empty for none. */
    var alpn: List<ByteArray> = emptyList(),
    /** Whether to send 0-RTT data when a ticket allows it (rustls `enable_early_data`, set by quinn). */
    var enableEarlyData: Boolean = true,
) : CryptoClientConfig {
    internal val rng = Random(0xc11e)

    /** Session tickets by server name (single use, like rustls's client session cache). */
    internal val tickets = HashMap<String, MockTicket>()

    override fun startSession(version: Int, serverName: String, params: TransportParameters): CryptoSession =
        MockSession(Side.Client, version, params, client = this, serverName = serverName)
}

/** One side of a mock handshake. */
class MockSession internal constructor(
    private val side: Side,
    private val version: Int,
    params: TransportParameters,
    private val server: MockServerCrypto? = null,
    private val client: MockClientCrypto? = null,
    private var serverName: String? = null,
) : CryptoSession {
    private val tlsVersion = TlsQuicVersion.of(version)
    private val ownParams: ByteArray = Buffer(128).also { params.write(it) }.readAll()
    private val rng = (server?.rng ?: client!!.rng)

    /** What [writeHandshake] hands out: handshake bytes of the current level, or the keys of the next one. */
    private val outgoing = ArrayDeque<Any>()

    /** Received handshake bytes not yet parsed into complete messages. */
    private var inbound = ByteArray(0)

    private var expected = if (side == Side.Client) Msg.SERVER_HELLO else Msg.CLIENT_HELLO
    private var handshaking = true
    private var gotHandshakeData = false

    private var suite = server?.suite ?: CipherSuite.TLS13_AES_128_GCM_SHA256
    private val random = ByteArray(32).also { rng.nextBytes(it) }
    private var clientRandom = ByteArray(0)
    private var serverRandom = ByteArray(0)

    private var ticket: MockTicket? = null
    private var earlyOffered = false
    private var earlyAccepted = false
    private var earlyKeys: EarlyKeys? = null

    private var peerParams: ByteArray? = null
    private var alpnSelected: ByteArray? = null
    private var peerIdentity: ByteArray? = null

    private var clientHsSecret = ByteArray(0)
    private var serverHsSecret = ByteArray(0)
    private var masterSecret: ByteArray? = null
    private var nextSecrets: Secrets? = null

    init {
        if (side == Side.Client) startClient()
    }

    private val hash get() = suite.hash
    private val hashLen get() = suite.hash.outputSize

    private fun startClient() {
        val cfg = client!!
        clientRandom = random
        val ticket = cfg.tickets.remove(serverName!!)
        this.ticket = ticket
        if (ticket != null) {
            suite = ticket.suite
            if (ticket.maxEarlyData && cfg.enableEarlyData) {
                earlyOffered = true
                earlyKeys = earlyKeys(ticket.resumptionSecret, clientRandom)
            }
        }
        val body = Buffer(256)
        body.writeBytes(clientRandom)
        writeU16Bytes(body, serverName!!.encodeToByteArray())
        body.writeShort(cfg.alpn.size)
        for (p in cfg.alpn) writeU8Bytes(body, p)
        writeU16Bytes(body, ownParams)
        if (ticket != null) {
            body.writeByte(1.toByte())
            writeU8Bytes(body, ticket.id)
            body.writeByte((if (earlyOffered) 1 else 0).toByte())
        } else {
            body.writeByte(0.toByte())
        }
        // Key share and the other extensions of a real ClientHello, so that the first flight has a realistic size
        writeU16Bytes(body, CLIENT_HELLO_EXTENSIONS)
        outgoing.addLast(message(Msg.CLIENT_HELLO, body.readAll()))
    }

    override fun initialKeys(dstCid: ConnectionId, side: Side): Keys = neton.quic.proto.initialKeys(version, dstCid, side)

    override fun handshakeData(): Any? =
        if (gotHandshakeData) MockHandshakeData(alpnSelected?.copyOf(), if (side == Side.Server) serverName else null) else null

    override fun peerIdentity(): Any? = peerIdentity?.copyOf()

    override fun earlyCrypto(): EarlyKeys? = earlyKeys

    override fun earlyDataAccepted(): Boolean? = if (side == Side.Client) earlyAccepted else null

    override val isHandshaking: Boolean get() = handshaking

    override fun readHandshake(buf: Bytes): Boolean {
        inbound += buf.toByteArray()
        var becameAvailable = false
        while (inbound.size >= 4) {
            val len = ((inbound[1].toInt() and 0xFF) shl 16) or ((inbound[2].toInt() and 0xFF) shl 8) or (inbound[3].toInt() and 0xFF)
            if (inbound.size < 4 + len) break
            val type = inbound[0].toInt() and 0xFF
            val body = inbound.copyOfRange(4, 4 + len)
            inbound = inbound.copyOfRange(4 + len, inbound.size)
            try {
                if (handle(type, body)) becameAvailable = true
            } catch (e: UnexpectedEnd) {
                throw alert(MockAlert.DECODE_ERROR, "malformed handshake message")
            }
        }
        return becameAvailable
    }

    /** Process one message; returns whether handshake data became available. */
    private fun handle(type: Int, body: ByteArray): Boolean {
        if (type == Msg.NEW_SESSION_TICKET && side == Side.Client && !handshaking) {
            readNewSessionTicket(body)
            return false
        }
        if (type != expected) {
            throw alert(MockAlert.UNEXPECTED_MESSAGE, "unexpected message $type")
        }
        return when (type) {
            Msg.CLIENT_HELLO -> readClientHello(body)
            Msg.SERVER_HELLO -> { readServerHello(body); false }
            Msg.ENCRYPTED_EXTENSIONS -> readEncryptedExtensions(body)
            Msg.CERTIFICATE -> { peerIdentity = body; expected = Msg.FINISHED; false }
            Msg.FINISHED -> readFinished(body)
            else -> throw alert(MockAlert.UNEXPECTED_MESSAGE, "unexpected message $type")
        }
    }

    // ---- server ----

    private fun readClientHello(body: ByteArray): Boolean {
        val cfg = server!!
        val r = Reader(body)
        clientRandom = r.getBytes(32)
        serverName = r.getBytes(r.getU16()).decodeToString()
        val offered = List(r.getU16()) { r.getBytes(r.getU8()) }
        peerParams = r.getBytes(r.getU16())
        var ticketId: ByteArray? = null
        if (r.getU8() == 1) {
            ticketId = r.getBytes(r.getU8())
            earlyOffered = r.getU8() == 1
        }
        r.getBytes(r.getU16()) // extensions

        // ALPN: server preference; QUIC requires agreement when either side uses it (rustls: no_application_protocol)
        if (cfg.alpn.isNotEmpty() || offered.isNotEmpty()) {
            alpnSelected = cfg.alpn.firstOrNull { p -> offered.any { it.contentEquals(p) } }
                ?: throw alert(MockAlert.NO_APPLICATION_PROTOCOL, "no application protocol")
        }

        // Validate the peer's transport parameters now (rustls reports them after the ClientHello)
        transportParameters()

        val ticket = ticketId?.let { cfg.tickets.remove(it.toHex()) }?.takeIf { it.suite == suite }
        this.ticket = ticket
        if (ticket != null && earlyOffered && ticket.maxEarlyData && cfg.enableEarlyData &&
            sameAlpn(ticket.alpn, alpnSelected)
        ) {
            earlyAccepted = true
            earlyKeys = earlyKeys(ticket.resumptionSecret, clientRandom)
        }

        serverRandom = random
        deriveHandshakeSecrets()

        val hello = Buffer(64)
        hello.writeBytes(serverRandom)
        hello.writeByte((if (ticket != null) 1 else 0).toByte())
        hello.writeByte(suite.ordinal.toByte())
        outgoing.addLast(message(Msg.SERVER_HELLO, hello.readAll()))
        outgoing.addLast(Secrets(clientHsSecret, serverHsSecret, suite, side, tlsVersion).keys())

        val ee = Buffer(128)
        writeU8Bytes(ee, alpnSelected ?: ByteArray(0))
        writeU16Bytes(ee, ownParams)
        ee.writeByte((if (earlyAccepted) 1 else 0).toByte())
        var flight = message(Msg.ENCRYPTED_EXTENSIONS, ee.readAll())
        if (ticket == null) flight += message(Msg.CERTIFICATE, cfg.identity)
        flight += message(Msg.FINISHED, finishedKey(serverHsSecret))
        outgoing.addLast(flight)
        outgoing.addLast(oneRttKeys())

        expected = Msg.FINISHED
        gotHandshakeData = true
        return true
    }

    // ---- client ----

    private fun readServerHello(body: ByteArray) {
        val r = Reader(body)
        serverRandom = r.getBytes(32)
        val resumed = r.getU8() == 1
        suite = CipherSuite.entries[r.getU8()]
        if (!resumed) ticket = null
        deriveHandshakeSecrets()
        outgoing.addLast(Secrets(clientHsSecret, serverHsSecret, suite, side, tlsVersion).keys())
        expected = Msg.ENCRYPTED_EXTENSIONS
    }

    private fun readEncryptedExtensions(body: ByteArray): Boolean {
        val r = Reader(body)
        val alpn = r.getBytes(r.getU8())
        peerParams = r.getBytes(r.getU16())
        earlyAccepted = r.getU8() == 1 && earlyOffered
        if (alpn.isNotEmpty()) {
            if (client!!.alpn.none { it.contentEquals(alpn) }) throw alert(MockAlert.NO_APPLICATION_PROTOCOL, "server chose an unoffered protocol")
            alpnSelected = alpn
        }
        expected = if (ticket != null) Msg.FINISHED else Msg.CERTIFICATE
        if (alpnSelected != null && !gotHandshakeData) {
            gotHandshakeData = true
            return true
        }
        return false
    }

    // ---- both ----

    private fun readFinished(body: ByteArray): Boolean {
        val peerHs = if (side == Side.Client) serverHsSecret else clientHsSecret
        if (!Crypto.constantTimeEquals(body, finishedKey(peerHs))) throw alert(MockAlert.DECRYPT_ERROR, "bad Finished")
        handshaking = false
        if (side == Side.Client) {
            outgoing.addLast(message(Msg.FINISHED, finishedKey(clientHsSecret)))
            outgoing.addLast(oneRttKeys())
            expected = -1
            if (!gotHandshakeData) {
                gotHandshakeData = true
                return true
            }
        } else {
            // Issue a session ticket at the 1-RTT level, as rustls does after the client's Finished
            val cfg = server!!
            val id = ByteArray(16).also { rng.nextBytes(it) }
            cfg.tickets[id.toHex()] = MockTicket(id, resumptionSecret(), suite, alpnSelected, null, cfg.enableEarlyData)
            val nst = Buffer(32)
            writeU8Bytes(nst, id)
            nst.writeByte((if (cfg.enableEarlyData) 1 else 0).toByte())
            outgoing.addLast(message(Msg.NEW_SESSION_TICKET, nst.readAll()))
            expected = -1
        }
        return false
    }

    private fun readNewSessionTicket(body: ByteArray) {
        val r = Reader(body)
        val id = r.getBytes(r.getU8())
        val maxEarly = r.getU8() == 1
        client!!.tickets[serverName!!] = MockTicket(id, resumptionSecret(), suite, alpnSelected, peerParams, maxEarly)
    }

    override fun transportParameters(): TransportParameters? {
        val bytes = peerParams ?: ticket?.params ?: return null
        return try {
            TransportParameters.read(side, Reader(bytes))
        } catch (e: TransportParameterError) {
            throw e.toTransportError()
        }
    }

    override fun writeHandshake(buf: Buffer): Keys? {
        while (true) {
            when (val step = outgoing.removeFirstOrNull() ?: return null) {
                is ByteArray -> buf.writeBytes(step)
                is Keys -> return step
            }
        }
    }

    override fun next1rttKeys(): KeyPair<PacketKey>? = nextSecrets?.nextPacketKeys()

    override fun isValidRetry(origDstCid: ConnectionId, header: ByteArray, payload: ByteArray): Boolean =
        neton.quic.proto.isValidRetry(version, origDstCid, header, payload)

    override fun exportKeyingMaterial(output: ByteArray, label: ByteArray, context: ByteArray) {
        val master = masterSecret ?: throw ExportKeyingMaterialError()
        if (output.size > 255 * hashLen) throw ExportKeyingMaterialError()
        val exporter = expandLabel(hash, master, "exp master", hashLen)
        Crypto.hkdfExpand(hash, exporter, label + byteArrayOf(0) + context, output)
    }

    // ---- key schedule ----

    private fun deriveHandshakeSecrets() {
        val psk = ticket?.resumptionSecret ?: ByteArray(hashLen)
        val hs = ByteArray(hashLen)
        Crypto.hkdfExtract(hash, psk, clientRandom + serverRandom, hs)
        clientHsSecret = expandLabel(hash, hs, "c hs traffic", hashLen)
        serverHsSecret = expandLabel(hash, hs, "s hs traffic", hashLen)
        masterSecret = expandLabel(hash, hs, "master", hashLen)
    }

    private fun oneRttKeys(): Keys {
        val master = masterSecret!!
        val secrets = Secrets(
            expandLabel(hash, master, "c ap traffic", hashLen),
            expandLabel(hash, master, "s ap traffic", hashLen),
            suite, side, tlsVersion,
        )
        val keys = secrets.oneRttKeys()
        nextSecrets = secrets
        return keys
    }

    private fun resumptionSecret(): ByteArray = expandLabel(hash, masterSecret!!, "res master", hashLen)

    private fun finishedKey(hsSecret: ByteArray): ByteArray = expandLabel(hash, hsSecret, "finished", hashLen)

    private fun earlyKeys(resumptionSecret: ByteArray, clientRandom: ByteArray): EarlyKeys {
        val early = ByteArray(suite.hash.outputSize)
        Crypto.hkdfExtract(suite.hash, clientRandom, resumptionSecret, early)
        val secret = expandLabel(suite.hash, early, "c e traffic", suite.hash.outputSize)
        return EarlyKeys(headerKey(suite, secret), packetKey(suite, secret))
    }

    private companion object {
        /** A key share (32 bytes) and the other extensions of a rustls ClientHello, as opaque filler. */
        val CLIENT_HELLO_EXTENSIONS = ByteArray(160) { (it * 13 + 1).toByte() }

        fun message(type: Int, body: ByteArray): ByteArray {
            val m = ByteArray(4 + body.size)
            m[0] = type.toByte()
            m[1] = (body.size ushr 16).toByte()
            m[2] = (body.size ushr 8).toByte()
            m[3] = body.size.toByte()
            body.copyInto(m, 4)
            return m
        }

        fun writeU8Bytes(b: Buffer, bytes: ByteArray) {
            b.writeByte(bytes.size.toByte())
            b.writeBytes(bytes)
        }

        fun writeU16Bytes(b: Buffer, bytes: ByteArray) {
            b.writeShort(bytes.size)
            b.writeBytes(bytes)
        }

        fun sameAlpn(a: ByteArray?, b: ByteArray?): Boolean = if (a == null || b == null) a === null && b === null else a.contentEquals(b)

        fun alert(description: Int, reason: String): TransportError =
            TransportError(TransportErrorCode.crypto(description), null, reason)
    }
}
