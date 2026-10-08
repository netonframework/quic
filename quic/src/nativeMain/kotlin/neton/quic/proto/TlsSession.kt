@file:OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)

package neton.quic.proto

import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner
import kotlinx.cinterop.COpaquePointer
import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.IntVar
import kotlinx.cinterop.StableRef
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.UIntVar
import kotlinx.cinterop.ULongVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.asStableRef
import kotlinx.cinterop.convert
import kotlinx.cinterop.free
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.nativeHeap
import kotlinx.cinterop.plus
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.set
import kotlinx.cinterop.staticCFunction
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import neton.openssl.Crypto
import neton.openssl.c.ERR_clear_error
import neton.openssl.c.OPENSSL_sk_num
import neton.openssl.c.OPENSSL_sk_value
import neton.openssl.c.OSSL_DISPATCH
import neton.openssl.c.OSSL_FUNC_SSL_QUIC_TLS_ALERT
import neton.openssl.c.OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD
import neton.openssl.c.OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD
import neton.openssl.c.OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND
import neton.openssl.c.OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS
import neton.openssl.c.OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET
import neton.openssl.c.SSL
import neton.openssl.c.SSL_CIPHER_get_protocol_id
import neton.openssl.c.SSL_ERROR_WANT_READ
import neton.openssl.c.SSL_SESSION
import neton.openssl.c.SSL_SESSION_free
import neton.openssl.c.SSL_SESSION_get0_alpn_selected
import neton.openssl.c.SSL_SESSION_get0_cipher
import neton.openssl.c.SSL_SESSION_get_max_early_data
import neton.openssl.c.SSL_TLSEXT_ERR_ALERT_FATAL
import neton.openssl.c.SSL_TLSEXT_ERR_OK
import neton.openssl.c.SSL_client_hello_get0_ext
import neton.openssl.c.SSL_do_handshake
import neton.openssl.c.SSL_export_keying_material
import neton.openssl.c.SSL_free
import neton.openssl.c.SSL_get0_alpn_selected
import neton.openssl.c.SSL_get0_peer_certificate
import neton.openssl.c.SSL_get_current_cipher
import neton.openssl.c.SSL_get_early_data_status
import neton.openssl.c.SSL_get_error
import neton.openssl.c.SSL_get_ex_data
import neton.openssl.c.SSL_get_peer_cert_chain
import neton.openssl.c.SSL_get_pending_cipher
import neton.openssl.c.SSL_get_servername
import neton.openssl.c.SSL_get_session
import neton.openssl.c.SSL_is_init_finished
import neton.openssl.c.SSL_new
import neton.openssl.c.SSL_read
import neton.openssl.c.SSL_set1_dnsname
import neton.openssl.c.SSL_set1_ipaddr
import neton.openssl.c.SSL_set_accept_state
import neton.openssl.c.SSL_set_alpn_protos
import neton.openssl.c.SSL_set_connect_state
import neton.openssl.c.SSL_set_ex_data
import neton.openssl.c.SSL_set_hostflags
import neton.openssl.c.SSL_set_quic_tls_cbs
import neton.openssl.c.SSL_set_quic_tls_early_data_enabled
import neton.openssl.c.SSL_set_quic_tls_transport_params
import neton.openssl.c.SSL_set_session
import neton.openssl.c.SSL_set_shutdown
import neton.openssl.c.X509
import neton.openssl.c.X509_cmp
import neton.openssl.c.d2i_SSL_SESSION
import neton.openssl.c.i2d_SSL_SESSION

// The TLS 1.3 session for QUIC (quinn-proto `crypto/rustls.rs` `TlsSession`) on OpenSSL's third-party QUIC TLS
// interface (`SSL_set_quic_tls_cbs`, OpenSSL 3.5+; used through openssl-kotlin's raw bindings). OpenSSL runs the
// handshake and calls back with the CRYPTO bytes to send (per the current write level), asks for received CRYPTO bytes
// one record at a time, yields each level's read and write secrets, delivers the peer's transport parameters and
// reports the alert it sends. This file turns that into quinn's `crypto::Session` semantics:
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
// Contracts of the C boundary (SPEC §11.9):
// - Callbacks are `staticCFunction`s whose argument is a StableRef to the session's [TlsCore]. No Kotlin exception
//   crosses into C: each callback catches everything, records the first failure in the core and returns 0 (fatal for
//   OpenSSL); the failure is thrown after the OpenSSL call returns.
// - The record handed out by CRYPTO_RECV_RCD is a native copy that is neither moved nor changed until
//   CRYPTO_RELEASE_RCD releases it (OpenSSL releases whole records; a partial release keeps the rest pinned). Only one
//   record is outstanding at a time, as OpenSSL requires; it is at most [MAX_RECORD] bytes.
// - Bounded queues: received CRYPTO bytes not yet taken by OpenSSL are limited to [MAX_INCOMING] per level (the
//   connection hands them over in order and OpenSSL consumes them within the same call, so only a peer sending data
//   OpenSSL does not ask for can fill it) — exceeding it fails with CRYPTO_BUFFER_EXCEEDED; bytes still queued when
//   OpenSSL moves to the next read level fail with unexpected_message (data after a key change). Outgoing bytes not
//   yet taken by `writeHandshake` are limited to [MAX_OUTGOING] (the connection drains them after every call; only a
//   pathological own certificate chain could exceed it) — exceeding it fails the call with INTERNAL_ERROR.
// - Transport parameters from the peer are copied during the callback. Our own are copied into native memory that
//   stays valid until the SSL is freed (OpenSSL keeps the pointer until it sends them).
//
// Ownership (SPEC §11.6 standard): the session exclusively owns its SSL, its StableRef and its native buffers.
// [close] frees them exactly once: SSL first (no callback can run after that), then the StableRef, then the buffers;
// the connection calls it when it drains or is discarded, and on every failure path of session creation; a GC cleaner
// only backs it up. What the application may still ask after the release (handshake data, peer identity, transport
// parameters) is kept in Kotlin; the exporter needs the live session and fails afterwards.

/** Handshake data of a TLS session (quinn `crypto::rustls::HandshakeData`). */
class TlsHandshakeData(
    /** The negotiated application protocol, if ALPN is in use. */
    val protocol: ByteArray?,
    /** The server name specified by the client (servers only; `null` for outgoing connections). */
    val serverName: String?,
)

// OpenSSL protection levels (ssl.h OSSL_RECORD_PROTECTION_LEVEL_*).
private const val LEVEL_NONE = 0
private const val LEVEL_EARLY = 1
private const val LEVEL_HANDSHAKE = 2
private const val LEVEL_APPLICATION = 3
private const val SSL_EARLY_DATA_ACCEPTED = 2
private const val SSL_SENT_SHUTDOWN = 1
private const val SSL_RECEIVED_SHUTDOWN = 2

/** Largest record handed to OpenSSL at once (a TLS record's plaintext limit). */
internal const val MAX_RECORD = 16384

/** Received CRYPTO bytes not yet taken by OpenSSL, per level. */
internal const val MAX_INCOMING = 64 * 1024

/** Handshake bytes produced by OpenSSL and not yet taken by `writeHandshake`. */
internal const val MAX_OUTGOING = 1024 * 1024

private const val ALERT_UNEXPECTED_MESSAGE = 10
private const val ALERT_NO_APPLICATION_PROTOCOL = 120
private const val ALERT_INTERNAL_ERROR = 80
private const val TLSEXT_TYPE_ALPN = 16u
private const val X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS = 0x4u
private const val X509_CHECK_FLAG_NEVER_CHECK_SUBJECT = 0x20u

/** Callbacks a test can make fail (C-boundary tests). */
internal enum class TlsCallback { CRYPTO_SEND, CRYPTO_RECV_RCD, CRYPTO_RELEASE_RCD, YIELD_SECRET, GOT_TRANSPORT_PARAMS, ALERT, ALPN_SELECT, CLIENT_HELLO, NEW_SESSION }

/**
 * The state OpenSSL's callbacks work on, reached through a StableRef. It does not reference the [TlsSession], so the
 * session can become unreachable (and its cleaner run) while the StableRef still pins this core.
 */
internal class TlsCore(val side: Side, val serverAlpn: List<ByteArray>?) {
    /** Set first thing when the session is released; callbacks then refuse to run. */
    var released = false

    /** The first failure recorded by a callback, thrown after the OpenSSL call returns. */
    var failure: Throwable? = null

    /** The alert OpenSSL sent, or -1. */
    var alert = -1

    /** A callback to fail on purpose (C-boundary tests). */
    var injectFailure: TlsCallback? = null

    /** The configuration's key log, if any. */
    var keyLog: KeyLog? = null

    // ---- incoming CRYPTO bytes ----
    private val incoming = ArrayDeque<ByteArray>()
    private var incomingHead = 0
    var incomingBytes = 0
        private set
    var readLevel = LEVEL_NONE
        private set

    /** The outstanding record (native copy), its length and how much of it OpenSSL released. */
    var record: CPointer<UByteVar>? = null
        private set
    private var recordLen = 0
    private var recordReleased = 0

    // ---- outgoing CRYPTO bytes, per protection level ----
    val outgoing = Array(4) { ArrayDeque<ByteArray>() }
    var outgoingBytes = 0
    var writeLevel = LEVEL_NONE
        private set

    // ---- secrets, per level and direction ----
    val readSecrets = arrayOfNulls<ByteArray>(4)
    val writeSecrets = arrayOfNulls<ByteArray>(4)
    val suites = arrayOfNulls<CipherSuite>(4)

    /** The peer's transport parameters (copied). */
    var peerParams: ByteArray? = null

    // ---- 0-RTT: the early traffic secret (client: write, server: read) and its suite; it changes no CRYPTO level ----
    var earlySecret: ByteArray? = null
    var earlySuite: CipherSuite? = null

    /** Session tickets received (client), DER-encoded, with whether each allows 0-RTT; moved out after each call. */
    val newTickets = ArrayList<Pair<ByteArray, Boolean>>()

    /** Tickets that could not be kept (their callback failed); the connection is not affected. */
    var droppedTickets = 0

    fun fail(t: Throwable) {
        if (failure == null) failure = t
    }

    fun checkInjected(cb: TlsCallback) {
        if (injectFailure == cb) {
            injectFailure = null
            throw IllegalStateException("injected failure in $cb")
        }
    }

    fun queueIncoming(bytes: ByteArray) {
        if (bytes.isEmpty()) return
        if (incomingBytes + bytes.size > MAX_INCOMING) {
            throw TransportError.CRYPTO_BUFFER_EXCEEDED("more than $MAX_INCOMING bytes of CRYPTO data not taken by TLS")
        }
        incoming.addLast(bytes)
        incomingBytes += bytes.size
    }

    /** CRYPTO_RECV_RCD: hand out up to [MAX_RECORD] queued bytes as one native record, or nothing. */
    fun recvRecord(buf: CPointer<CPointerVar<UByteVar>>, bytesRead: CPointer<ULongVar>) {
        check(record == null) { "OpenSSL asked for a record while one is outstanding" }
        val n = minOf(incomingBytes, MAX_RECORD)
        if (n == 0) {
            buf.pointed.value = null
            bytesRead.pointed.value = 0u
            return
        }
        val rec = nativeHeap.allocArray<UByteVar>(n)
        var at = 0
        while (at < n) {
            val chunk = incoming.first()
            val take = minOf(chunk.size - incomingHead, n - at)
            for (i in 0 until take) rec[at + i] = chunk[incomingHead + i].toUByte()
            at += take
            incomingHead += take
            if (incomingHead == chunk.size) {
                incoming.removeFirst()
                incomingHead = 0
            }
        }
        incomingBytes -= n
        record = rec
        recordLen = n
        recordReleased = 0
        buf.pointed.value = rec
        bytesRead.pointed.value = n.convert()
    }

    /** CRYPTO_RELEASE_RCD: the record (or a prefix of it) is no longer needed. */
    fun releaseRecord(n: Int) {
        val rec = checkNotNull(record) { "release without an outstanding record" }
        check(n >= 0 && recordReleased + n <= recordLen) { "released $n of ${recordLen - recordReleased} bytes" }
        recordReleased += n
        if (recordReleased == recordLen) {
            nativeHeap.free(rec)
            record = null
            recordLen = 0
            recordReleased = 0
        }
    }

    fun send(buf: CPointer<UByteVar>, len: Int) {
        if (outgoingBytes + len > MAX_OUTGOING) {
            throw TransportError.INTERNAL_ERROR("more than $MAX_OUTGOING bytes of handshake output pending")
        }
        if (len == 0) return
        outgoing[writeLevel].addLast(buf.readBytes(len))
        outgoingBytes += len
    }

    fun yieldSecret(ssl: CPointer<SSL>, level: Int, direction: Int, secret: CPointer<UByteVar>, len: Int) {
        if (level == LEVEL_EARLY) {
            // The client's early write secret (with its ClientHello) or the server's early read secret (0-RTT
            // accepted). CRYPTO data never travels at this level, so the CRYPTO levels stay as they are.
            check(direction == (if (side == Side.Client) 1 else 0)) { "early secret in the wrong direction" }
            val cipher = SSL_get_pending_cipher(ssl) ?: SSL_get_session(ssl)?.let { SSL_SESSION_get0_cipher(it) }
            val suite = cipher?.let { cipherSuiteOf(SSL_CIPHER_get_protocol_id(it).toInt()) }
                ?: throw TransportError.INTERNAL_ERROR("0-RTT cipher suite not usable with QUIC")
            check(len == suite.hash.outputSize) { "a ${suite.name} secret has ${suite.hash.outputSize} bytes, got $len" }
            earlySecret?.let { Crypto.wipe(it) }
            earlySecret = secret.readBytes(len)
            earlySuite = suite
            return
        }
        check(level == LEVEL_HANDSHAKE || level == LEVEL_APPLICATION) { "unexpected secret for protection level $level" }
        val cipher = SSL_get_pending_cipher(ssl) ?: SSL_get_current_cipher(ssl)
        val suite = cipher?.let { cipherSuiteOf(SSL_CIPHER_get_protocol_id(it).toInt()) }
            ?: throw TransportError.INTERNAL_ERROR("negotiated cipher suite not usable with QUIC")
        check(len == suite.hash.outputSize) { "a ${suite.name} secret has ${suite.hash.outputSize} bytes, got $len" }
        val bytes = secret.readBytes(len)
        suites[level] = suite
        if (direction == 0) {
            if (incomingBytes != 0) {
                Crypto.wipe(bytes)
                throw TransportError(TransportErrorCode.crypto(ALERT_UNEXPECTED_MESSAGE), null, "CRYPTO data after a key change")
            }
            readSecrets[level]?.let { Crypto.wipe(it) }
            readSecrets[level] = bytes
            readLevel = level
        } else {
            writeSecrets[level]?.let { Crypto.wipe(it) }
            writeSecrets[level] = bytes
            writeLevel = level
        }
    }

    /** Wipe the secrets and free the outstanding record; after the SSL is freed. */
    fun wipe() {
        earlySecret?.let { Crypto.wipe(it) }
        earlySecret = null
        for (a in arrayOf(readSecrets, writeSecrets)) {
            for (i in a.indices) {
                a[i]?.let { Crypto.wipe(it) }
                a[i] = null
            }
        }
        record?.let { nativeHeap.free(it) }
        record = null
        incoming.clear()
        incomingBytes = 0
        for (q in outgoing) q.clear()
        outgoingBytes = 0
    }
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
    serverAlpn: List<ByteArray>?,
) : CryptoSession {
    internal val core = TlsCore(side, serverAlpn)

    /** The native objects; it does not reference this session, so the cleaner can run once the session is unreachable. */
    private val native = TlsNative(core)
    private val ssl: CPointer<SSL>? get() = if (native.isReleased) null else native.ssl
    private var inCall = false
    private var closeRequested = false

    // Only a backstop: the connection closes the session when it drains.
    @Suppress("unused")
    private val cleaner = createCleaner(native) { it.release() }

    /** Which level's keys the connection has: NONE (Initial keys only), HANDSHAKE, then APPLICATION. */
    private var handedLevel = LEVEL_NONE
    private var handshakeComplete = false
    private var gotHandshakeData = false
    private var failed: TransportError? = null
    private var nextSecrets: Secrets? = null

    // ---- resumption and 0-RTT ----
    /** Client: where received tickets go, and under which server name. */
    private var ticketSink: TicketCache? = null
    private var serverName: String? = null
    /** Client resuming: the server's transport parameters remembered with the ticket (the 0-RTT limits). */
    private var rememberedParams: ByteArray? = null
    private var earlyKeys: EarlyKeys? = null
    private var earlyAccepted = false

    // Kept in Kotlin so they stay available after the native session is released
    private var alpnSelected: ByteArray? = null
    private var sniSeen: String? = null
    private var peerCerts: List<ByteArray>? = null

    /** Whether the native session has been released. */
    val isClosed: Boolean get() = native.isReleased

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
        val secret = core.earlySecret ?: return null
        val suite = core.earlySuite!!
        val keys = EarlyKeys(headerKey(suite, secret), packetKey(suite, secret))
        Crypto.wipe(secret)
        core.earlySecret = null
        earlyKeys = keys
        return keys
    }

    /** Client: whether the server accepted the 0-RTT data (known once the handshake completed); null on servers. */
    override fun earlyDataAccepted(): Boolean? = if (side == Side.Client) earlyAccepted else null

    override val isHandshaking: Boolean get() = !handshakeComplete

    override fun readHandshake(buf: Bytes): Boolean {
        failed?.let { throw it }
        if (isClosed) throw TransportError.INTERNAL_ERROR("TLS session closed")
        try {
            core.queueIncoming(buf.toByteArray())
        } catch (e: TransportError) {
            throw failWith(e)
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
        val bytes = core.peerParams ?: rememberedParams ?: return null
        return try {
            TransportParameters.read(side, Reader(bytes))
        } catch (e: TransportParameterError) {
            throw e.toTransportError()
        }
    }

    override fun writeHandshake(buf: Buffer): Keys? {
        if (isClosed) return null
        val q = core.outgoing[handedLevel]
        while (true) {
            val chunk = q.removeFirstOrNull() ?: break
            buf.writeBytes(chunk)
            core.outgoingBytes -= chunk.size
        }
        val next = when (handedLevel) {
            LEVEL_NONE -> LEVEL_HANDSHAKE
            LEVEL_HANDSHAKE -> LEVEL_APPLICATION
            else -> return null
        }
        val read = core.readSecrets[next] ?: return null
        val write = core.writeSecrets[next] ?: return null
        val suite = core.suites[next]!!
        val (client, server) = if (side == Side.Client) write to read else read to write
        val secrets = Secrets(client, server, suite, side, tlsVersion)
        Crypto.wipe(read)
        Crypto.wipe(write)
        core.readSecrets[next] = null
        core.writeSecrets[next] = null
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
        val s = ssl
        if (s == null || isClosed || !handshakeComplete || failed != null) throw ExportKeyingMaterialError()
        // ⚖️ The binding takes the label as a C string: labels are ASCII (RFC 5705 §4 / RFC 8446 §7.5 use ASCII
        // labels); other bytes are refused rather than re-encoded.
        if (label.any { it <= 0 }) throw ExportKeyingMaterialError()
        ERR_clear_error()
        val ok = output.usePinnedOrEmpty { out ->
            context.usePinnedOrEmpty { c ->
                SSL_export_keying_material(
                    s, out, output.size.convert(), label.decodeToString(), label.size.convert(), c, context.size.convert(), 1,
                )
            }
        }
        drainOpenSslErrors()
        if (ok != 1) {
            Crypto.wipe(output)
            throw ExportKeyingMaterialError()
        }
    }

    /**
     * Release the native session: the SSL (after which no callback can run), then the StableRef, then the native
     * buffers, and wipe the secrets. Exactly once, shared with the GC cleaner; idempotent. Handshake data, the peer
     * identity and the transport parameters stay available; the exporter does not.
     */
    override fun close() {
        if (inCall) {
            closeRequested = true
            return
        }
        // QUIC ends a connection with CONNECTION_CLOSE, never TLS's close_notify: tell OpenSSL this one ended cleanly,
        // or SSL_free drops the session of the last ticket from the server's cache (ssl_clear_bad_session), and a
        // client resuming with that ticket gets a full handshake. rustls never forgets a session on close.
        if (handshakeComplete) ssl?.let { SSL_set_shutdown(it, SSL_SENT_SHUTDOWN or SSL_RECEIVED_SHUTDOWN) }
        native.release()
        nextSecrets?.wipe()
        nextSecrets = null
    }

    /** Make a callback fail on purpose (C-boundary tests). */
    internal fun injectCallbackFailure(cb: TlsCallback) {
        core.injectFailure = cb
    }

    // ---- driving OpenSSL ----

    private fun failWith(e: TransportError): TransportError {
        if (failed == null) failed = e
        return failed!!
    }

    /** Run OpenSSL until it wants more input; throws the handshake's [TransportError]. */
    private fun drive() {
        val s = ssl ?: throw TransportError.INTERNAL_ERROR("TLS session closed")
        while (true) {
            val wasComplete = handshakeComplete
            val inputBefore = core.incomingBytes
            ERR_clear_error()
            inCall = true
            val ret: Int
            val err: Int
            try {
                ret = if (!wasComplete) SSL_do_handshake(s) else SSL_read(s, null, 0)
                err = if (ret <= 0) SSL_get_error(s, ret) else 0
            } finally {
                inCall = false
            }
            val detail = drainOpenSslErrors()
            capturePeerState(s)
            if (closeRequested) {
                close()
                throw failWith(TransportError.INTERNAL_ERROR("TLS session closed during a call"))
            }
            core.failure?.let { f ->
                throw failWith(f as? TransportError ?: TransportError.INTERNAL_ERROR("TLS callback failed: ${f.message}"))
            }
            if (ret <= 0 && err != SSL_ERROR_WANT_READ) {
                val alert = core.alert
                throw failWith(
                    if (alert >= 0) {
                        TransportError(TransportErrorCode.crypto(alert), null, "TLS alert $alert${if (detail.isEmpty()) "" else ": $detail"}")
                    } else {
                        TransportError.PROTOCOL_VIOLATION("TLS error: ${detail.ifEmpty { "SSL_get_error $err" }}")
                    },
                )
            }
            // A server accepting early data returns 1 once its own Finished is out, to let it read 0-RTT data: the
            // handshake goes on until the client's Finished. rustls reports a handshake complete only after that.
            if (!wasComplete && ret == 1 && SSL_is_init_finished(s) != 1) {
                if (core.incomingBytes in 1 until inputBefore) continue
                return
            }
            if (!wasComplete && ret == 1) {
                handshakeComplete = true
                if (side == Side.Client) earlyAccepted = SSL_get_early_data_status(s) == SSL_EARLY_DATA_ACCEPTED
                if (side == Side.Client && clientAlpnOffered && alpnSelected == null) {
                    // rustls for QUIC: an ALPN offer must be answered
                    throw failWith(
                        TransportError(TransportErrorCode.crypto(ALERT_NO_APPLICATION_PROTOCOL), null, "server selected no application protocol"),
                    )
                }
                // Post-handshake messages may already be queued
                if (core.incomingBytes > 0) continue
            }
            return
        }
    }

    /** Copy what the application may ask for later: the ALPN protocol, the SNI, the peer's certificates. */
    private fun capturePeerState(s: CPointer<SSL>) {
        // Session tickets (client): kept with the server's transport parameters for the next connection.
        if (core.newTickets.isNotEmpty()) {
            val sink = ticketSink
            val name = serverName
            if (sink != null && name != null) {
                for ((der, early) in core.newTickets) sink.add(name, ClientTicket(der, core.peerParams?.copyOf(), early))
            }
            core.newTickets.clear()
        }
        if (alpnSelected == null) {
            memScoped {
                val data = alloc<CPointerVar<UByteVar>>()
                val len = alloc<UIntVar>()
                SSL_get0_alpn_selected(s, data.ptr, len.ptr)
                val p = data.value
                if (p != null && len.value > 0u) alpnSelected = p.readBytes(len.value.toInt())
            }
        }
        if (side == Side.Server && sniSeen == null) {
            sniSeen = SSL_get_servername(s, TLSEXT_NAMETYPE_HOST_NAME)?.toKString()
        }
        if (peerCerts == null) {
            val leaf = SSL_get0_peer_certificate(s)
            if (leaf != null) {
                val certs = arrayListOf(toDer(leaf))
                val chain = SSL_get_peer_cert_chain(s)
                if (chain != null) {
                    val n = OPENSSL_sk_num(chain.reinterpret())
                    for (i in 0 until n) {
                        val x = OPENSSL_sk_value(chain.reinterpret(), i)?.reinterpret<X509>() ?: continue
                        if (X509_cmp(x, leaf) != 0) certs += toDer(x)
                    }
                }
                peerCerts = certs
            }
        }
    }

    internal companion object {
        fun client(config: TlsClientConfig, version: Int, serverName: String, params: TransportParameters): TlsSession {
            val v = try { TlsQuicVersion.of(version) } catch (e: UnsupportedVersion) { throw ConnectError.UnsupportedVersion() }
            val session = TlsSession(Side.Client, version, v, config.alpn.isNotEmpty(), null)
            session.core.keyLog = config.keyLog
            config.ctx.use { ctx -> session.open(ctx, params) }
            try {
                val s = session.ssl!!
                ERR_clear_error()
                SSL_set_connect_state(s)
                setServerName(s, serverName)
                session.ticketSink = config.tickets
                session.serverName = serverName
                config.tickets.take(serverName)?.let { session.resume(s, it, config.enableEarlyData, config.alpn) }
                if (config.alpnWire.isNotEmpty()) {
                    val r = config.alpnWire.usePinned { SSL_set_alpn_protos(s, it.addressOf(0).reinterpret(), config.alpnWire.size.convert()) }
                    check(r == 0) { "SSL_set_alpn_protos: ${drainOpenSslErrors()}" }
                }
                // The ClientHello (rustls creates it with the connection)
                session.drive()
                return session
            } catch (t: Throwable) {
                session.close()
                ERR_clear_error()
                throw t
            }
        }

        fun server(config: TlsServerConfig, version: Int, params: TransportParameters): TlsSession {
            val v = TlsQuicVersion.of(version)
            val session = TlsSession(Side.Server, version, v, false, config.alpn)
            session.core.keyLog = config.keyLog
            config.ctx.use { ctx -> session.open(ctx, params) }
            try {
                SSL_set_accept_state(session.ssl!!)
                // max_early_data 0xffffffff for this session; OpenSSL then also turns on its replay protection.
                if (config.earlyData) check(SSL_set_quic_tls_early_data_enabled(session.ssl!!, 1) == 1) { "early data: ${drainOpenSslErrors()}" }
                return session
            } catch (t: Throwable) {
                session.close()
                throw t
            }
        }

        /** The SSL_SESSION in [der], or null when it no longer parses. */
        private fun parseSession(der: ByteArray): CPointer<SSL_SESSION>? = memScoped {
            der.usePinned { pinned ->
                val p = alloc<CPointerVar<UByteVar>>()
                p.value = pinned.addressOf(0).reinterpret()
                d2i_SSL_SESSION(null, p.ptr, der.size.convert())
            }
        }

        /** Verify the server's certificate against [name] (DNS or IP SAN) and send it as SNI when it is a DNS name. */
        private fun setServerName(s: CPointer<SSL>, name: String) {
            if (name.isEmpty() || name.length > 253 || name.any { it.code <= 0x20 || it.code >= 0x7f }) {
                throw ConnectError.InvalidServerName(name)
            }
            val ip = name.trimStart('[').trimEnd(']')
            if (looksLikeIp(ip)) {
                if (SSL_set1_ipaddr(s, ip) != 1) { drainOpenSslErrors(); throw ConnectError.InvalidServerName(name) }
            } else {
                SSL_set_hostflags(s, X509_CHECK_FLAG_NO_PARTIAL_WILDCARDS or X509_CHECK_FLAG_NEVER_CHECK_SUBJECT)
                if (SSL_set1_dnsname(s, name) != 1 || !sslSetTlsextHostName(s, name)) {
                    drainOpenSslErrors()
                    throw ConnectError.InvalidServerName(name)
                }
            }
        }

        private fun looksLikeIp(s: String): Boolean =
            ':' in s || (s.count { it == '.' } == 3 && s.all { it.isDigit() || it == '.' })
    }

    /**
     * Resume [ticket] (rustls with a cached session): offer it, use the server parameters remembered with it until the
     * server's arrive, and send 0-RTT data when it allows early data and [enableEarlyData]. A ticket that no longer
     * parses is dropped and the handshake is a full one.
     */
    private fun resume(s: CPointer<SSL>, ticket: ClientTicket, enableEarlyData: Boolean, offeredAlpn: List<ByteArray>) {
        val sess = parseSession(ticket.session) ?: run { drainOpenSslErrors(); return }
        try {
            if (SSL_set_session(s, sess) != 1) { drainOpenSslErrors(); return }
        } finally {
            SSL_SESSION_free(sess)                          // the SSL holds its own reference
        }
        rememberedParams = ticket.params
        // ⚖️ OpenSSL fails the handshake when the ticket's protocol is not among those offered now
        // (INCONSISTENT_EARLY_DATA_ALPN); rustls sends the 0-RTT data and the server rejects it. Here the session is
        // resumed without 0-RTT, so a client that changed its protocols still connects.
        if (!alpnOffered(s, offeredAlpn)) return
        // OpenSSL refuses (0) unless the session's max_early_data is 0xffffffff: then there is no 0-RTT, only resumption.
        if (enableEarlyData && ticket.earlyData && SSL_set_quic_tls_early_data_enabled(s, 1) != 1) drainOpenSslErrors()
    }

    /** Whether the protocol the resumed session negotiated (if any) is among [offered]. */
    private fun alpnOffered(s: CPointer<SSL>, offered: List<ByteArray>): Boolean = memScoped {
        val sess = SSL_get_session(s) ?: return@memScoped true
        val data = alloc<CPointerVar<UByteVar>>()
        val len = alloc<ULongVar>()
        SSL_SESSION_get0_alpn_selected(sess, data.ptr, len.ptr)
        val p = data.value ?: return@memScoped true
        val selected = p.readBytes(len.value.toInt())
        offered.any { it.contentEquals(selected) }
    }

    /** Create the SSL and wire the callbacks; on failure everything created so far is released. */
    private fun open(ctx: CPointer<neton.openssl.c.SSL_CTX>, params: TransportParameters) {
        ERR_clear_error()
        val s = SSL_new(ctx) ?: throw IllegalStateException("SSL_new failed: ${drainOpenSslErrors()}")
        native.ssl = s
        NativeTls.sessionOpened()
        try {
            val r = StableRef.create(core)
            native.ref = r
            NativeTls.refCreated()
            check(SSL_set_ex_data(s, 0, r.asCPointer()) == 1) { "SSL_set_ex_data: ${drainOpenSslErrors()}" }
            memScoped {
                val table = allocArray<OSSL_DISPATCH>(7)
                val entries = listOf(
                    OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_SEND to CRYPTO_SEND,
                    OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RECV_RCD to CRYPTO_RECV_RCD,
                    OSSL_FUNC_SSL_QUIC_TLS_CRYPTO_RELEASE_RCD to CRYPTO_RELEASE_RCD,
                    OSSL_FUNC_SSL_QUIC_TLS_YIELD_SECRET to YIELD_SECRET,
                    OSSL_FUNC_SSL_QUIC_TLS_GOT_TRANSPORT_PARAMS to GOT_TRANSPORT_PARAMS,
                    OSSL_FUNC_SSL_QUIC_TLS_ALERT to ALERT,
                )
                entries.forEachIndexed { i, (id, fn) ->
                    table[i].function_id = id
                    table[i].function = fn
                }
                table[6].function_id = 0
                table[6].function = null
                // OpenSSL copies the function pointers; the table only has to live during the call.
                check(SSL_set_quic_tls_cbs(s, table, r.asCPointer()) == 1) { "SSL_set_quic_tls_cbs: ${drainOpenSslErrors()}" }
            }
            val own = Buffer(128).also { params.write(it) }.readAll()
            val copy = nativeHeap.allocArray<UByteVar>(own.size)
            native.params = copy
            for (i in own.indices) copy[i] = own[i].toUByte()
            check(SSL_set_quic_tls_transport_params(s, copy, own.size.convert()) == 1) {
                "SSL_set_quic_tls_transport_params: ${drainOpenSslErrors()}"
            }
            check(SSL_set_quic_tls_early_data_enabled(s, 0) == 1) { "early data: ${drainOpenSslErrors()}" }
        } catch (t: Throwable) {
            close()
            ERR_clear_error()
            throw t
        }
    }
}

/**
 * The native objects a session exclusively owns: its SSL, the StableRef OpenSSL's callbacks get, and our transport
 * parameters' native copy. [release] frees them exactly once (explicit close or the cleaner, whichever is first), in
 * the order that guarantees no callback runs after release: mark the core released, free the SSL, dispose the
 * StableRef, then free the buffers and wipe the secrets.
 */
internal class TlsNative(private val core: TlsCore) {
    var ssl: CPointer<SSL>? = null
    var ref: StableRef<TlsCore>? = null
    var params: CPointer<UByteVar>? = null
    private val once = OnceRelease { free() }

    val isReleased: Boolean get() = once.isReleased

    fun release() = once.release()

    private fun free() {
        core.released = true
        ssl?.let {
            SSL_set_ex_data(it, 0, null)
            SSL_free(it)
            ERR_clear_error()
            NativeTls.sessionFreed()
        }
        ref?.let {
            it.dispose()
            NativeTls.refDisposed()
        }
        params?.let { nativeHeap.free(it) }
        core.wipe()
    }
}

private inline fun <R> ByteArray.usePinnedOrEmpty(block: (CPointer<UByteVar>?) -> R): R =
    if (isEmpty()) block(null) else usePinned { block(it.addressOf(0).reinterpret()) }

// ---- the C callbacks: never let an exception out, never run after release ----

/** Run [block] on the core behind [arg]; any throwable is recorded and turned into OpenSSL's failure value 0. */
private inline fun callback(arg: COpaquePointer?, cb: TlsCallback, block: (TlsCore) -> Unit): Int {
    try {
        val core = arg?.asStableRef<TlsCore>()?.get() ?: return 0
        if (core.released) return 0
        return try {
            core.checkInjected(cb)
            block(core)
            1
        } catch (t: Throwable) {
            core.fail(t)
            0
        }
    } catch (t: Throwable) {
        return 0
    }
}

private val CRYPTO_SEND = staticCFunction { _: CPointer<SSL>?, buf: CPointer<UByteVar>?, len: ULong, consumed: CPointer<ULongVar>?, arg: COpaquePointer? ->
    callback(arg, TlsCallback.CRYPTO_SEND) { core ->
        val n = len.toInt()
        check(n >= 0 && len <= Int.MAX_VALUE.toULong()) { "handshake output too large" }
        if (n > 0) core.send(buf!!, n)
        consumed!!.pointed.value = len
    }
}.reinterpret<kotlinx.cinterop.CFunction<() -> Unit>>()

private val CRYPTO_RECV_RCD = staticCFunction { _: CPointer<SSL>?, buf: CPointer<CPointerVar<UByteVar>>?, bytesRead: CPointer<ULongVar>?, arg: COpaquePointer? ->
    callback(arg, TlsCallback.CRYPTO_RECV_RCD) { core -> core.recvRecord(buf!!, bytesRead!!) }
}.reinterpret<kotlinx.cinterop.CFunction<() -> Unit>>()

private val CRYPTO_RELEASE_RCD = staticCFunction { _: CPointer<SSL>?, bytesRead: ULong, arg: COpaquePointer? ->
    callback(arg, TlsCallback.CRYPTO_RELEASE_RCD) { core -> core.releaseRecord(bytesRead.toInt()) }
}.reinterpret<kotlinx.cinterop.CFunction<() -> Unit>>()

private val YIELD_SECRET = staticCFunction { ssl: CPointer<SSL>?, level: UInt, direction: Int, secret: CPointer<UByteVar>?, len: ULong, arg: COpaquePointer? ->
    callback(arg, TlsCallback.YIELD_SECRET) { core -> core.yieldSecret(ssl!!, level.toInt(), direction, secret!!, len.toInt()) }
}.reinterpret<kotlinx.cinterop.CFunction<() -> Unit>>()

private val GOT_TRANSPORT_PARAMS = staticCFunction { _: CPointer<SSL>?, params: CPointer<UByteVar>?, len: ULong, arg: COpaquePointer? ->
    callback(arg, TlsCallback.GOT_TRANSPORT_PARAMS) { core ->
        // The bytes are only valid during the callback: copy them
        core.peerParams = if (len == 0uL) ByteArray(0) else params!!.readBytes(len.toInt())
    }
}.reinterpret<kotlinx.cinterop.CFunction<() -> Unit>>()

private val ALERT = staticCFunction { _: CPointer<SSL>?, alert: UByte, arg: COpaquePointer? ->
    callback(arg, TlsCallback.ALERT) { core -> if (core.alert < 0) core.alert = alert.toInt() }
}.reinterpret<kotlinx.cinterop.CFunction<() -> Unit>>()

/** The server's ALPN choice (server preference; none in common, or none configured while the client offers → 120). */
internal val ALPN_SELECT = staticCFunction {
        ssl: CPointer<SSL>?, out: CPointer<CPointerVar<UByteVar>>?, outLen: CPointer<UByteVar>?, input: CPointer<UByteVar>?, inLen: UInt, _: COpaquePointer? ->
    var result = SSL_TLSEXT_ERR_ALERT_FATAL
    callback(SSL_get_ex_data(ssl, 0), TlsCallback.ALPN_SELECT) { core ->
        val offered = input!!.readBytes(inLen.toInt())
        for (p in core.serverAlpn.orEmpty()) {
            var at = 0
            while (at < offered.size) {
                val len = offered[at].toInt() and 0xFF
                if (at + 1 + len > offered.size) break
                if (len == p.size && (0 until len).all { offered[at + 1 + it] == p[it] }) {
                    // Point into the client's list: OpenSSL copies the selection before the buffer goes away
                    out!!.pointed.value = input + (at + 1)
                    outLen!!.pointed.value = len.toUByte()
                    result = SSL_TLSEXT_ERR_OK
                    return@callback
                }
                at += 1 + len
            }
        }
    }
    result
}

/** A client that offers no ALPN while the server has protocols fails with no_application_protocol (rustls for QUIC). */
internal val CLIENT_HELLO = staticCFunction { ssl: CPointer<SSL>?, al: CPointer<IntVar>?, _: COpaquePointer? ->
    var ok = 0
    val r = callback(SSL_get_ex_data(ssl, 0), TlsCallback.CLIENT_HELLO) { core ->
        if (core.serverAlpn.isNullOrEmpty()) {
            ok = 1
        } else {
            memScoped {
                val data = alloc<CPointerVar<UByteVar>>()
                val len = alloc<ULongVar>()
                ok = SSL_client_hello_get0_ext(ssl, TLSEXT_TYPE_ALPN, data.ptr, len.ptr)
            }
        }
    }
    when {
        r == 1 && ok == 1 -> 1
        r == 1 -> { al?.pointed?.value = ALERT_NO_APPLICATION_PROTOCOL; 0 }
        else -> { al?.pointed?.value = ALERT_INTERNAL_ERROR; 0 }
    }
}

/**
 * A secret to log (SSL_CTX_set_keylog_callback, installed only when the configuration has a [KeyLog]). Like the ticket
 * callback it never fails the connection: whatever the log throws is dropped.
 */
internal val KEY_LOG = staticCFunction { ssl: CPointer<SSL>?, line: CPointer<ByteVar>? ->
    try {
        val core = SSL_get_ex_data(ssl, 0)?.asStableRef<TlsCore>()?.get()
        val log = core?.keyLog
        if (log != null && !core.released && line != null) logKeyLine(log, line.toKString())
    } catch (t: Throwable) {
    }
}

/**
 * A session ticket arrived (client; SSL_CTX_sess_set_new_cb): keep it DER-encoded on the core; the session moves it
 * into its configuration's [TicketCache] after the call. Returns 0: OpenSSL keeps ownership of the SSL_SESSION.
 * Unlike the other callbacks a failure here does not fail the connection: the ticket is dropped and counted (a
 * resumption cache is an optimisation; rustls does not fail a connection over storing a ticket either).
 */
internal val NEW_SESSION = staticCFunction { ssl: CPointer<SSL>?, sess: CPointer<SSL_SESSION>? ->
    try {
        val core = SSL_get_ex_data(ssl, 0)?.asStableRef<TlsCore>()?.get()
        if (core != null && !core.released) {
            try {
                core.checkInjected(TlsCallback.NEW_SESSION)
                keepTicket(core, sess)
            } catch (t: Throwable) {
                core.droppedTickets++
            }
        }
    } catch (t: Throwable) {
    }
    0
}

private fun keepTicket(core: TlsCore, sess: CPointer<SSL_SESSION>?) {
    run {
        val n = i2d_SSL_SESSION(sess, null)
        if (n > 0) {
            val der = ByteArray(n)
            memScoped {
                der.usePinned { pinned ->
                    val p = alloc<CPointerVar<UByteVar>>()
                    p.value = pinned.addressOf(0).reinterpret()
                    check(i2d_SSL_SESSION(sess, p.ptr) == n) { "i2d_SSL_SESSION" }
                }
            }
            core.newTickets += der to (SSL_SESSION_get_max_early_data(sess) == 0xffffffffu)
        }
    }
}
