package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import neton.openssl.Crypto
import neton.openssl.OpenSsl
import neton.openssl.QuicTls
import neton.openssl.QuicTlsCallback
import neton.openssl.QuicTlsFailure

// The TLS 1.3 session for QUIC (quinn-proto `crypto/rustls.rs` `TlsSession`) on OpenSSL's third-party QUIC TLS
// interface (`SSL_set_quic_tls_cbs`, OpenSSL 3.5+), through openssl-kotlin's QUIC TLS facade (`QuicTls`): OpenSSL's
// callbacks run in C there and queue the CRYPTO bytes to send per level, take received CRYPTO bytes one record at a
// time, keep each level's read and write secrets, the peer's transport parameters and the alert sent; this file takes
// that after each OpenSSL call and turns it into quinn's `crypto::Session` semantics:
//
// - `readHandshake` queues the bytes and drives `SSL_do_handshake` (`SSL_read` of 0 bytes once the handshake is done,
//   for post-handshake messages) until OpenSSL wants more input; it returns `true` the first time handshake data
//   became available (rustls's hack in quinn: the ALPN protocol is known, or the server saw the client's SNI, or the
//   handshake is over).
// - `writeHandshake` hands out the bytes of the level the connection is at, then — once both directions' secrets of
//   the next level are known — that level's keys (rustls `write_hs` returning a `KeyChange`). Bytes sent after a key
//   change are held per level, so the order in which OpenSSL yields the two directions does not matter.
//   ⚖️ OpenSSL yields the server's 1-RTT read secret only after the client's Finished (for QUIC it sets up write keys
//   before read keys), so the server gets its 1-RTT keys then, not right after its own flight as with rustls: the
//   server sends no 0.5-RTT data. quinn's state machine handles both orders (HANDSHAKE_DONE is queued after the keys).
// - The 1-RTT keys come from the application secrets with [Secrets.oneRttKeys], and later key updates from
//   [Secrets.nextPacketKeys] ("quic ku"), exactly as quinn does with rustls; Initial keys and Retry tags are the
//   existing `PacketProtection` functions.
// - Alerts become CRYPTO_ERROR (0x100 + alert); a failure without an alert is PROTOCOL_VIOLATION, like quinn.
//
// The C boundary (SPEC §11.9; openssl-kotlin docs/QUIC_TLS.md): no Kotlin code runs inside an OpenSSL call. A callback
// records its first failure and returns 0 (fatal for OpenSSL); the facade reports it after the call and it is thrown
// here. Received CRYPTO bytes not yet taken by OpenSSL are limited to [MAX_INCOMING] (CRYPTO_BUFFER_EXCEEDED); a read
// secret arriving while some are still queued fails with unexpected_message (data after a key change); outgoing bytes
// not yet taken by `writeHandshake` are limited to [MAX_OUTGOING] (INTERNAL_ERROR). Transport parameters, ours and the
// peer's, are copied by the facade.
//
// Ownership (SPEC §11.6 standard): the session exclusively owns its facade connection. [close] frees it exactly once
// (OpenSSL first, then its buffers, wiped) and wipes the secrets kept here; the connection calls it when it drains or
// is discarded, and on every failure path of session creation; a GC cleaner only backs it up. What the application
// may still ask after the release (handshake data, peer identity, transport parameters) is kept in Kotlin; the
// exporter needs the live session and fails afterwards.

/** Handshake data of a TLS session (quinn `crypto::rustls::HandshakeData`). */
class TlsHandshakeData(
    /** The negotiated application protocol, if ALPN is in use. */
    val protocol: ByteArray?,
    /** The server name specified by the client (servers only; `null` for outgoing connections). */
    val serverName: String?,
)

// OpenSSL protection levels (ssl.h OSSL_RECORD_PROTECTION_LEVEL_*).
private const val LEVEL_NONE = 0
private const val LEVEL_HANDSHAKE = 2
private const val LEVEL_APPLICATION = 3

/** Largest record handed to OpenSSL at once (a TLS record's plaintext limit; enforced by the facade). */
internal const val MAX_RECORD = 16384

/** Received CRYPTO bytes not yet taken by OpenSSL (enforced by the facade). */
internal const val MAX_INCOMING = 64 * 1024

/** Handshake bytes produced by OpenSSL and not yet taken by `writeHandshake` (enforced by the facade). */
internal const val MAX_OUTGOING = 1024 * 1024

private const val ALERT_UNEXPECTED_MESSAGE = 10
private const val ALERT_NO_APPLICATION_PROTOCOL = 120

/** Callbacks a test can make fail (C-boundary tests); the facade's [QuicTlsCallback] by name. */
internal enum class TlsCallback { CRYPTO_SEND, CRYPTO_RECV_RCD, CRYPTO_RELEASE_RCD, YIELD_SECRET, GOT_TRANSPORT_PARAMS, ALERT, ALPN_SELECT, CLIENT_HELLO, NEW_SESSION }

/**
 * The facade connection a session exclusively owns. [release] frees it exactly once (explicit close or the cleaner,
 * whichever is first); it does not reference the session, so the cleaner can run once the session is unreachable.
 */
internal class TlsNative(val tls: QuicTls) {
    private val once = OnceRelease {
        tls.close()
        NativeTls.sessionFreed()
    }

    init { NativeTls.sessionOpened() }

    val isReleased: Boolean get() = once.isReleased

    fun release() = once.release()
}

/**
 * A TLS 1.3 session for one QUIC connection (quinn `crypto::rustls::TlsSession`). Created by [TlsClientConfig] and
 * [TlsServerConfig]; the connection drives it and [close]s it when it drains.
 */
class TlsSession private constructor(
    private val side: Side,
    private val version: Int,
    private val tlsVersion: TlsQuicVersion,
    private val clientAlpnOffered: Boolean,
    private val native: TlsNative,
    private val keyLog: KeyLog?,
) : CryptoSession {
    private val tls: QuicTls get() = native.tls
    private var inCall = false
    private var closeRequested = false

    // Only a backstop: the connection closes the session when it drains.
    @Suppress("unused")
    private val cleaner = backstopCleaner(native) { it.release() }

    /** Which level's keys the connection has: NONE (Initial keys only), HANDSHAKE, then APPLICATION. */
    private var handedLevel = LEVEL_NONE
    private var handshakeComplete = false
    private var gotHandshakeData = false
    private var failed: TransportError? = null
    private var nextSecrets: Secrets? = null

    // Secrets taken from the facade, per level and direction, with their suite; wiped once used or on close.
    private val readSecrets = arrayOfNulls<ByteArray>(4)
    private val writeSecrets = arrayOfNulls<ByteArray>(4)
    private val suites = arrayOfNulls<CipherSuite>(4)

    // ---- resumption and 0-RTT ----
    /** Client: where received tickets go, and under which server name. */
    private var ticketSink: TicketCache? = null
    private var serverName: String? = null
    /** Client resuming: the server's transport parameters remembered with the ticket (the 0-RTT limits). */
    private var rememberedParams: ByteArray? = null
    /** The early traffic secret (client: write, server: read) and its suite; it changes no CRYPTO level. */
    private var earlySecret: ByteArray? = null
    private var earlySuite: CipherSuite? = null
    private var earlyKeys: EarlyKeys? = null
    private var earlyAccepted = false

    // Kept in Kotlin so they stay available after the native session is released
    private var peerParams: ByteArray? = null
    private var alpnSelected: ByteArray? = null
    private var sniSeen: String? = null
    private var peerCerts: List<ByteArray>? = null

    /** Whether the native session has been released. */
    val isClosed: Boolean get() = native.isReleased

    /** Tickets that could not be kept (their callback failed); the connection is not affected. */
    internal var droppedTickets = 0
        private set

    override fun initialKeys(dstCid: ConnectionId, side: Side): Keys = neton.quic.proto.initialKeys(version, dstCid, side)

    /** A [TlsHandshakeData], once available. */
    override fun handshakeData(): Any? =
        if (gotHandshakeData) TlsHandshakeData(alpnSelected?.copyOf(), if (side == Side.Server) sniSeen else null) else null

    /** The peer's certificate chain as presented, leaf first, as DER (`List<ByteArray>`, rustls `Vec<CertificateDer>`). */
    override fun peerIdentity(): Any? = peerCerts?.map { it.copyOf() }

    /**
     * The 0-RTT keys (rustls `zero_rtt_keys`): a client's once it resumed a session whose ticket allows early data, a
     * server's once it accepted the client's early data. Derived once; the secret is then wiped.
     */
    override fun earlyCrypto(): EarlyKeys? {
        earlyKeys?.let { return it }
        val secret = earlySecret ?: return null
        val suite = earlySuite!!
        val keys = EarlyKeys(headerKey(suite, secret), packetKey(suite, secret))
        Crypto.wipe(secret)
        earlySecret = null
        earlyKeys = keys
        return keys
    }

    /** Client: whether the server accepted the 0-RTT data (known once the handshake completed); null on servers. */
    override fun earlyDataAccepted(): Boolean? = if (side == Side.Client) earlyAccepted else null

    override val isHandshaking: Boolean get() = !handshakeComplete

    override fun readHandshake(buf: Bytes): Boolean {
        failed?.let { throw it }
        if (isClosed) throw TransportError.INTERNAL_ERROR("TLS session closed")
        if (!tls.provide(buf.toByteArray())) {
            throw failWith(TransportError.CRYPTO_BUFFER_EXCEEDED("more than $MAX_INCOMING bytes of CRYPTO data not taken by TLS"))
        }
        drive()
        if (!gotHandshakeData && (alpnSelected != null || (side == Side.Server && sniSeen != null) || handshakeComplete)) {
            gotHandshakeData = true
            return true
        }
        return false
    }

    override fun transportParameters(): TransportParameters? {
        // A client resuming uses the ones remembered with its ticket until the server's arrive (rustls).
        val bytes = peerParams ?: rememberedParams ?: return null
        return try {
            TransportParameters.read(side, Reader(bytes))
        } catch (e: TransportParameterError) {
            throw e.toTransportError()
        }
    }

    override fun writeHandshake(buf: Buffer): Keys? {
        if (isClosed) return null
        buf.writeBytes(tls.takeOutgoing(handedLevel))
        val next = when (handedLevel) {
            LEVEL_NONE -> LEVEL_HANDSHAKE
            LEVEL_HANDSHAKE -> LEVEL_APPLICATION
            else -> return null
        }
        val read = readSecrets[next] ?: return null
        val write = writeSecrets[next] ?: return null
        val suite = suites[next]!!
        val (client, server) = if (side == Side.Client) write to read else read to write
        val secrets = Secrets(client, server, suite, side, tlsVersion)
        Crypto.wipe(read)
        Crypto.wipe(write)
        readSecrets[next] = null
        writeSecrets[next] = null
        handedLevel = next
        return if (next == LEVEL_HANDSHAKE) {
            secrets.keys().also { secrets.wipe() }
        } else {
            secrets.oneRttKeys().also { nextSecrets = secrets }
        }
    }

    override fun next1rttKeys(): KeyPair<PacketKey>? {
        if (isClosed) return null
        return nextSecrets?.nextPacketKeys()
    }

    override fun isValidRetry(origDstCid: ConnectionId, header: ByteArray, payload: ByteArray): Boolean =
        neton.quic.proto.isValidRetry(version, origDstCid, header, payload)

    override fun exportKeyingMaterial(output: ByteArray, label: ByteArray, context: ByteArray) {
        if (isClosed || !handshakeComplete || failed != null) throw ExportKeyingMaterialError()
        // ⚖️ Labels are printable ASCII (RFC 5705 §4 / RFC 8446 §7.5 use ASCII labels); other bytes are refused rather
        // than re-encoded.
        if (label.isEmpty() || label.any { it < 0x20 || it > 0x7e }) throw ExportKeyingMaterialError()
        OpenSsl.clearErrors()
        val ok = tls.exportKeyingMaterial(output, label.decodeToString(), context)
        drainOpenSslErrors()
        if (!ok) throw ExportKeyingMaterialError()
    }

    /**
     * Release the native session (OpenSSL first, then the facade's buffers, wiped) and wipe the secrets kept here.
     * Exactly once, shared with the GC cleaner; idempotent. Handshake data, the peer identity and the transport
     * parameters stay available; the exporter does not.
     */
    override fun close() {
        if (inCall) {
            closeRequested = true
            return
        }
        // QUIC ends a connection with CONNECTION_CLOSE, never TLS's close_notify: tell OpenSSL this one ended cleanly,
        // or SSL_free drops the session of the last ticket from the server's cache (ssl_clear_bad_session), and a
        // client resuming with that ticket gets a full handshake. rustls never forgets a session on close.
        if (handshakeComplete && !native.isReleased) tls.markCleanShutdown()
        native.release()
        nextSecrets?.wipe()
        nextSecrets = null
        earlySecret?.let { Crypto.wipe(it) }
        earlySecret = null
        for (a in arrayOf(readSecrets, writeSecrets)) {
            for (i in a.indices) {
                a[i]?.let { Crypto.wipe(it) }
                a[i] = null
            }
        }
    }

    /** Make a callback fail on purpose (C-boundary tests). */
    internal fun injectCallbackFailure(cb: TlsCallback) {
        tls.injectCallbackFailure(QuicTlsCallback.valueOf(cb.name))
    }

    // ---- driving OpenSSL ----

    private fun failWith(e: TransportError): TransportError {
        if (failed == null) failed = e
        return failed!!
    }

    /** Run OpenSSL until it wants more input; throws the handshake's [TransportError]. */
    private fun drive() {
        if (isClosed) throw TransportError.INTERNAL_ERROR("TLS session closed")
        val t = tls
        while (true) {
            val wasComplete = handshakeComplete
            val inputBefore = t.incoming
            OpenSsl.clearErrors()
            inCall = true
            val ret = try {
                t.drive(wasComplete)
            } finally {
                inCall = false
            }
            val detail = drainOpenSslErrors()
            collect(t)
            if (closeRequested) {
                close()
                throw failWith(TransportError.INTERNAL_ERROR("TLS session closed during a call"))
            }
            val message = t.failureMessage
            when (t.failure) {
                QuicTlsFailure.NONE -> {}
                QuicTlsFailure.INTERNAL -> throw failWith(TransportError.INTERNAL_ERROR(message))
                QuicTlsFailure.UNEXPECTED_MESSAGE ->
                    throw failWith(TransportError(TransportErrorCode.crypto(ALERT_UNEXPECTED_MESSAGE), null, message))
                QuicTlsFailure.CALLBACK -> throw failWith(TransportError.INTERNAL_ERROR("TLS callback failed: $message"))
            }
            if (ret < 0) {
                val alert = t.alert
                throw failWith(
                    if (alert >= 0) {
                        TransportError(TransportErrorCode.crypto(alert), null, "TLS alert $alert${if (detail.isEmpty()) "" else ": $detail"}")
                    } else {
                        TransportError.PROTOCOL_VIOLATION("TLS error: ${detail.ifEmpty { "handshake failed" }}")
                    },
                )
            }
            // A server accepting early data returns 1 once its own Finished is out, to let it read 0-RTT data: the
            // handshake goes on until the client's Finished. rustls reports a handshake complete only after that.
            if (!wasComplete && ret == 1 && !t.initFinished) {
                if (t.incoming in 1 until inputBefore) continue
                return
            }
            if (!wasComplete && ret == 1) {
                handshakeComplete = true
                if (side == Side.Client) earlyAccepted = t.earlyDataAccepted
                if (side == Side.Client && clientAlpnOffered && alpnSelected == null) {
                    // rustls for QUIC: an ALPN offer must be answered
                    throw failWith(
                        TransportError(TransportErrorCode.crypto(ALERT_NO_APPLICATION_PROTOCOL), null, "server selected no application protocol"),
                    )
                }
                // Post-handshake messages may already be queued
                if (t.incoming > 0) continue
            }
            return
        }
    }

    /**
     * Take what the call produced: the secrets (kept until the connection takes the keys), the early secret, the
     * peer's transport parameters, what the application may ask for later (ALPN, SNI, the peer's certificates),
     * session tickets (client) and key-log lines.
     */
    private fun collect(t: QuicTls) {
        for (level in LEVEL_HANDSHAKE..LEVEL_APPLICATION) {
            t.takeSecret(level, 0)?.let { s ->
                readSecrets[level]?.let { Crypto.wipe(it) }
                readSecrets[level] = s
                suites[level] = cipherSuiteOf(t.suite(level))
            }
            t.takeSecret(level, 1)?.let { s ->
                writeSecrets[level]?.let { Crypto.wipe(it) }
                writeSecrets[level] = s
                suites[level] = cipherSuiteOf(t.suite(level))
            }
        }
        t.takeEarlySecret()?.let { s ->
            earlySecret?.let { Crypto.wipe(it) }
            earlySecret = s
            earlySuite = cipherSuiteOf(t.suite(1))
        }
        if (peerParams == null) peerParams = t.peerTransportParameters()
        // Session tickets (client): kept with the server's transport parameters for the next connection.
        val tickets = t.takeTickets()
        if (tickets.isNotEmpty()) {
            val sink = ticketSink
            val name = serverName
            if (sink != null && name != null) {
                for ((der, early) in tickets) sink.add(name, ClientTicket(der, peerParams?.copyOf(), early))
            }
        }
        droppedTickets = t.droppedTickets
        if (alpnSelected == null) alpnSelected = t.selectedAlpn()
        if (side == Side.Server && sniSeen == null) sniSeen = t.serverName()
        if (peerCerts == null) peerCerts = t.peerCertificates().takeIf { it.isNotEmpty() }
        // Like the ticket callback, the key log never fails the connection: whatever it throws is dropped.
        val log = keyLog
        if (log != null) {
            for (line in t.takeKeyLog()) {
                try { logKeyLine(log, line) } catch (_: Throwable) { }
            }
        }
    }

    internal companion object {
        fun client(config: TlsClientConfig, version: Int, serverName: String, params: TransportParameters): TlsSession {
            val v = try { TlsQuicVersion.of(version) } catch (e: UnsupportedVersion) { throw ConnectError.UnsupportedVersion() }
            val own = Buffer(128).also { params.write(it) }.readAll()
            val tls = config.ctx.use { ctx -> ctx.newConnection(own) }
            val session = TlsSession(Side.Client, version, v, config.alpn.isNotEmpty(), TlsNative(tls), config.keyLog)
            try {
                setServerName(tls, serverName)
                session.ticketSink = config.tickets
                session.serverName = serverName
                config.tickets.take(serverName)?.let { session.resume(it, config.enableEarlyData, config.alpnWire) }
                if (config.alpnWire.isNotEmpty()) check(tls.offerAlpn(config.alpnWire)) { "SSL_set_alpn_protos: ${drainOpenSslErrors()}" }
                // The ClientHello (rustls creates it with the connection)
                session.drive()
                return session
            } catch (t: Throwable) {
                session.close()
                OpenSsl.clearErrors()
                throw t
            }
        }

        fun server(config: TlsServerConfig, version: Int, params: TransportParameters): TlsSession {
            val v = TlsQuicVersion.of(version)
            val own = Buffer(128).also { params.write(it) }.readAll()
            val tls = config.ctx.use { ctx -> ctx.newConnection(own, alpnWire(config.alpn)) }
            val session = TlsSession(Side.Server, version, v, false, TlsNative(tls), config.keyLog)
            try {
                // max_early_data 0xffffffff for this session; OpenSSL then also turns on its replay protection.
                if (config.earlyData) check(tls.enableEarlyData()) { "early data: ${drainOpenSslErrors()}" }
                return session
            } catch (t: Throwable) {
                session.close()
                throw t
            }
        }

        /** Verify the server's certificate against [name] (DNS or IP SAN) and send it as SNI when it is a DNS name. */
        private fun setServerName(tls: QuicTls, name: String) {
            if (name.isEmpty() || name.length > 253 || name.any { it.code <= 0x20 || it.code >= 0x7f }) {
                throw ConnectError.InvalidServerName(name)
            }
            val ip = name.trimStart('[').trimEnd(']')
            val isIp = looksLikeIp(ip)
            if (!tls.setServerName(if (isIp) ip else name, isIp)) {
                drainOpenSslErrors()
                throw ConnectError.InvalidServerName(name)
            }
        }

        private fun looksLikeIp(s: String): Boolean =
            ':' in s || (s.count { it == '.' } == 3 && s.all { it.isDigit() || it == '.' })
    }

    /**
     * Resume [ticket] (rustls with a cached session): offer it, use the server parameters remembered with it until the
     * server's arrive, and send 0-RTT data when it allows early data and [enableEarlyData]. A ticket that no longer
     * parses is dropped and the handshake is a full one.
     * ⚖️ OpenSSL fails the handshake when the ticket's protocol is not among those offered now
     * (INCONSISTENT_EARLY_DATA_ALPN); rustls sends the 0-RTT data and the server rejects it. Here the session is resumed
     * without 0-RTT (the facade checks the protocol), so a client that changed its protocols still connects.
     */
    private fun resume(ticket: ClientTicket, enableEarlyData: Boolean, offeredAlpnWire: ByteArray) {
        if (!tls.resume(ticket.session, enableEarlyData && ticket.earlyData, offeredAlpnWire)) {
            drainOpenSslErrors()
            return
        }
        rememberedParams = ticket.params
    }
}
