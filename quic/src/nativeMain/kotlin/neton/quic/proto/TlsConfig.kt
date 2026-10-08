@file:OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)

package neton.quic.proto

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.COpaquePointer
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.convert
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.staticCFunction
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import neton.openssl.c.BIO
import neton.openssl.c.BIO_free
import neton.openssl.c.BIO_new_mem_buf
import neton.openssl.c.ERR_clear_error
import neton.openssl.c.EVP_PKEY
import neton.openssl.c.EVP_PKEY_free
import neton.openssl.c.OPENSSL_sk_free
import neton.openssl.c.OPENSSL_sk_new_null
import neton.openssl.c.OPENSSL_sk_push
import neton.openssl.c.PEM_read_bio_PrivateKey
import neton.openssl.c.PEM_read_bio_X509
import neton.openssl.c.SSL
import neton.openssl.c.SSL_CTX
import neton.openssl.c.SSL_CTX_free
import neton.openssl.c.SSL_CTX_get_cert_store
import neton.openssl.c.SSL_CTX_new
import neton.openssl.c.SSL_CTX_sess_set_new_cb
import neton.openssl.c.SSL_CTX_set_alpn_select_cb
import neton.openssl.c.SSL_CTX_set_ciphersuites
import neton.openssl.c.SSL_CTX_set_client_hello_cb
import neton.openssl.c.SSL_CTX_set_options
import neton.openssl.c.SSL_CTX_set_session_id_context
import neton.openssl.c.SSL_CTX_set_verify
import neton.openssl.c.SSL_CTX_use_cert_and_key
import neton.openssl.c.SSL_VERIFY_FAIL_IF_NO_PEER_CERT
import neton.openssl.c.SSL_VERIFY_NONE
import neton.openssl.c.SSL_VERIFY_PEER
import neton.openssl.c.TLS_method
import neton.openssl.c.X509
import neton.openssl.c.X509_STORE_add_cert
import neton.openssl.c.X509_free
import neton.openssl.c.d2i_AutoPrivateKey
import neton.openssl.c.d2i_X509
import neton.openssl.c.i2d_X509
import neton.openssl.c.neton_openssl_tls13_only
import neton.openssl.c.neton_tls_groups
import kotlin.concurrent.AtomicInt
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner

// The TLS 1.3 configurations of the real QUIC TLS layer (quinn-proto `crypto/rustls.rs` `QuicClientConfig` /
// `QuicServerConfig`, with the certificate handling of quinn's `ClientConfig::with_root_certificates` and
// `ServerConfig::with_single_cert`), on OpenSSL 4.0.2's third-party QUIC TLS interface through openssl-kotlin's raw
// bindings (`neton.openssl.c`). The session state machine is in `TlsSession.kt`.
//
// Ownership: a configuration owns one SSL_CTX reference and releases it in [TlsClientConfig.close] /
// [TlsServerConfig.close] (a GC cleaner only backs this up). Every session holds its own reference to the SSL_CTX
// (OpenSSL's SSL_new / SSL_free count it), so closing a configuration while its sessions are still running is safe:
// they keep working, and the SSL_CTX is freed with the last of them. Starting a session on a closed configuration
// throws [IllegalStateException].
//
// No insecure defaults: TLS 1.3 only; the three QUIC cipher suites only (RFC 9001 §5.3; CCM is left out as in
// rustls); a client verifies the server's certificate chain against trust anchors it is given explicitly (there is no
// implicit system trust store) and the server name (DNS SAN, or IP SAN for an IP address); a client without trust
// anchors can only be made with [TlsClientConfig.dangerousNoServerVerificationForTestsOnly]. Session tickets, resumption
// and 0-RTT are off (0-RTT is a later, separate batch, SPEC §11.9).

/** X.509 certificates, kept as DER (quinn / rustls `CertificateDer`). */
class Certificates private constructor(internal val der: List<ByteArray>) {
    /** The certificates' DER encodings, in order (copies). */
    fun toDer(): List<ByteArray> = der.map { it.copyOf() }

    val size: Int get() = der.size

    companion object {
        /** Certificates from their DER encodings; each is parsed to check it is a certificate. */
        fun der(certificates: List<ByteArray>): Certificates {
            require(certificates.isNotEmpty()) { "no certificates" }
            for (c in certificates) parseDer(c).also { X509_free(it) }
            return Certificates(certificates.map { it.copyOf() })
        }

        fun der(vararg certificates: ByteArray): Certificates = der(certificates.toList())

        /** Every `CERTIFICATE` block of a PEM document, in order. */
        fun pem(pem: ByteArray): Certificates {
            val out = ArrayList<ByteArray>()
            withMemBio(pem) { bio ->
                while (true) {
                    val x = PEM_read_bio_X509(bio, null, null, null) ?: break
                    try { out += toDer(x) } finally { X509_free(x) }
                }
            }
            ERR_clear_error() // the "no start line" that ends the loop
            require(out.isNotEmpty()) { "no PEM certificate found" }
            return Certificates(out)
        }

        fun pem(pem: String): Certificates = pem(pem.encodeToByteArray())
    }
}

/** A private key (PKCS#8, or a traditional RSA / EC key), as DER or PEM (unencrypted). */
class PrivateKey private constructor(private val bytes: ByteArray, private val isPem: Boolean) {
    /** Parse into a fresh EVP_PKEY owned by the caller. */
    internal fun load(): CPointer<EVP_PKEY> {
        ERR_clear_error()
        val key = if (isPem) {
            withMemBio(bytes) { bio -> PEM_read_bio_PrivateKey(bio, null, NO_PASSWORD, null) }
        } else {
            bytes.usePinned { pinned ->
                memScoped {
                    val p = alloc<CPointerVar<UByteVar>>()
                    p.value = pinned.addressOf(0).reinterpret()
                    d2i_AutoPrivateKey(null, p.ptr, bytes.size.convert())
                }
            }
        }
        return key ?: throw IllegalArgumentException("invalid private key: ${drainOpenSslErrors()}")
    }

    companion object {
        fun der(der: ByteArray): PrivateKey {
            require(der.isNotEmpty()) { "empty private key" }
            return PrivateKey(der.copyOf(), false).also { EVP_PKEY_free(it.load()) }
        }

        fun pem(pem: ByteArray): PrivateKey {
            require(pem.isNotEmpty()) { "empty private key" }
            return PrivateKey(pem.copyOf(), true).also { EVP_PKEY_free(it.load()) }
        }

        fun pem(pem: String): PrivateKey = pem(pem.encodeToByteArray())
    }
}

/** Whether a server asks clients for certificates, and the trust anchors it verifies them against. */
sealed class ClientAuth {
    /** No client certificates (the default). */
    object None : ClientAuth()

    /** Ask for a client certificate; a client without one is accepted, a client with an unverifiable one is not. */
    class Request(val trustAnchors: Certificates) : ClientAuth()

    /** Require a verifiable client certificate (TLS alert certificate_required, 116, when there is none). */
    class Require(val trustAnchors: Certificates) : ClientAuth()
}

/**
 * Client-side TLS configuration for QUIC (quinn `crypto::rustls::QuicClientConfig`). The server's certificate chain is
 * verified against [trustAnchors], and its name against the server name of each connection.
 */
class TlsClientConfig private constructor(
    trustAnchors: Certificates?,
    alpnProtocols: List<ByteArray>,
    clientCertificate: Certificates?,
    clientKey: PrivateKey?,
    cipherSuites: List<CipherSuite>,
    groups: String?,
    @Suppress("UNUSED_PARAMETER") insecure: Boolean,
    /** Send 0-RTT data when a session ticket allows it (rustls `enable_early_data`, which quinn sets). */
    internal val enableEarlyData: Boolean,
) : CryptoClientConfig, AutoCloseable {

    /**
     * @param trustAnchors the CA certificates (or self-signed server certificates) the server's chain must lead to.
     * @param alpnProtocols the application protocols offered, in preference order; empty for none. When some are
     *   offered, the server must select one (else the handshake fails with no_application_protocol, like rustls for
     *   QUIC).
     * @param clientCertificate the certificate chain (leaf first) to present when the server asks, with [clientKey].
     * @param cipherSuites the TLS 1.3 cipher suites offered, in preference order.
     * @param groups the key exchange groups, in OpenSSL's list syntax (e.g. `"X25519:P-256"`); `null` keeps OpenSSL's
     *   default, which sends an X25519MLKEM768 (post-quantum hybrid) and an X25519 key share — a ClientHello of about
     *   1.5 KB, sent in two Initial datagrams. `"X25519"` fits the ClientHello in one.
     * @param enableEarlyData send 0-RTT data when a session ticket from the server allows it (quinn: on). Session
     *   tickets are kept in memory per server name, each used once (rustls's client session cache).
     */
    constructor(
        trustAnchors: Certificates,
        alpnProtocols: List<ByteArray> = emptyList(),
        clientCertificate: Certificates? = null,
        clientKey: PrivateKey? = null,
        cipherSuites: List<CipherSuite> = CipherSuite.entries,
        groups: String? = null,
        enableEarlyData: Boolean = true,
    ) : this(trustAnchors, alpnProtocols, clientCertificate, clientKey, cipherSuites, groups, false, enableEarlyData)

    internal val alpn: List<ByteArray> = validateAlpn(alpnProtocols)
    internal val alpnWire: ByteArray = alpnWire(alpn)
    internal val ctx: SslContextResource

    /**
     * Session tickets from servers, for resumption and 0-RTT (rustls `ClientSessionMemoryCache`). Tests share one
     * between configurations, as quinn's tests change a rustls config's protocols and keep its resumption store.
     */
    internal var tickets = TicketCache()

    init {
        require((clientCertificate == null) == (clientKey == null)) { "a client certificate needs its private key" }
        ctx = SslContextResource(newQuicContext(cipherSuites, groups) { ctx ->
            if (trustAnchors != null) {
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, null)
                addTrustAnchors(ctx, trustAnchors)
            } else {
                SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, null)
            }
            if (clientCertificate != null) useIdentity(ctx, clientCertificate, clientKey!!)
            // Tickets reach the session through the new-session callback; OpenSSL keeps no client cache of its own.
            sslCtxSetSessionCacheMode(ctx, SSL_SESS_CACHE_CLIENT or SSL_SESS_CACHE_NO_INTERNAL_STORE)
            SSL_CTX_sess_set_new_cb(ctx, NEW_SESSION)
        })
    }

    @Suppress("unused")
    private val cleaner = createCleaner(ctx) { it.close() }

    override fun startSession(version: Int, serverName: String, params: TransportParameters): CryptoSession =
        TlsSession.client(this, version, serverName, params)

    /** Release this configuration's SSL_CTX reference; sessions already started keep theirs. Idempotent. */
    override fun close() = ctx.close()

    companion object {
        /**
         * **Insecure, for tests only — never use in production.** A client that accepts any server certificate and
         * any server name: anyone on the path can impersonate the server. Exists for local tests against servers with
         * throwaway certificates; everything else should pass the server's CA to the primary constructor.
         */
        fun dangerousNoServerVerificationForTestsOnly(
            alpnProtocols: List<ByteArray> = emptyList(),
            cipherSuites: List<CipherSuite> = CipherSuite.entries,
            groups: String? = null,
            enableEarlyData: Boolean = true,
        ): TlsClientConfig = TlsClientConfig(null, alpnProtocols, null, null, cipherSuites, groups, true, enableEarlyData)
    }
}

/**
 * Server-side TLS configuration for QUIC (quinn `crypto::rustls::QuicServerConfig` with `with_single_cert`): one
 * certificate chain (leaf first) and its private key, the application protocols it accepts, and optional client
 * authentication.
 *
 * @param alpnProtocols supported application protocols in preference order (the server's order decides); empty for
 *   none. A client offering none of them, or offering none while the server has some, fails the handshake with
 *   no_application_protocol (120), as rustls does for QUIC.
 * @param groups the key exchange groups accepted, in OpenSSL's list syntax; `null` keeps OpenSSL's default (with the
 *   X25519MLKEM768 hybrid).
 * @param earlyData accept 0-RTT data on resumed sessions (quinn sets rustls `max_early_data_size` to `u32::MAX`). The
 *   server issues two session tickets per connection (OpenSSL's default; rustls sends two too) and keeps the sessions
 *   in its cache; with early data on, OpenSSL's replay protection makes each ticket single-use (a second use falls back
 *   to a full handshake), as rustls's stateful resumption does.
 */
class TlsServerConfig(
    certificateChain: Certificates,
    privateKey: PrivateKey,
    alpnProtocols: List<ByteArray> = emptyList(),
    clientAuth: ClientAuth = ClientAuth.None,
    cipherSuites: List<CipherSuite> = CipherSuite.entries,
    groups: String? = null,
    internal val earlyData: Boolean = true,
) : CryptoServerConfig, AutoCloseable {
    internal val alpn: List<ByteArray> = validateAlpn(alpnProtocols)
    internal val ctx: SslContextResource = SslContextResource(newQuicContext(cipherSuites, groups) { ctx ->
        useIdentity(ctx, certificateChain, privateKey)
        when (clientAuth) {
            ClientAuth.None -> SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, null)
            is ClientAuth.Request -> {
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, null)
                addTrustAnchors(ctx, clientAuth.trustAnchors)
            }
            is ClientAuth.Require -> {
                SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER or SSL_VERIFY_FAIL_IF_NO_PEER_CERT, null)
                addTrustAnchors(ctx, clientAuth.trustAnchors)
            }
        }
        // ALPN selection and the "client offered no ALPN" check find the session through the SSL's app data, so that
        // nothing here points into this configuration (sessions outlive a closed configuration).
        SSL_CTX_set_alpn_select_cb(ctx, ALPN_SELECT, null)
        SSL_CTX_set_client_hello_cb(ctx, CLIENT_HELLO, null)
        // Resumption needs a session ID context once client certificates are verified; one per configuration.
        val sid = "neton-quic".encodeToByteArray()
        check(sid.usePinned { SSL_CTX_set_session_id_context(ctx, it.addressOf(0).reinterpret(), sid.size.toUInt()) } == 1) {
            "session id context: ${drainOpenSslErrors()}"
        }
    })

    @Suppress("unused")
    private val cleaner = createCleaner(ctx) { it.close() }

    override fun initialKeys(version: Int, dstCid: ConnectionId): Keys = neton.quic.proto.initialKeys(version, dstCid, Side.Server)

    override fun retryTag(version: Int, origDstCid: ConnectionId, packet: ByteArray, offset: Int, length: Int): ByteArray =
        neton.quic.proto.retryTag(version, origDstCid, packet, offset, length)

    override fun startSession(version: Int, params: TransportParameters): CryptoSession =
        TlsSession.server(this, version, params)

    /** Release this configuration's SSL_CTX reference; sessions already started keep theirs. Idempotent. */
    override fun close() = ctx.close()
}

/**
 * The configuration's SSL_CTX reference. [use] lends it for SSL_new; [close] releases it once no [use] is running
 * (the last [use] to finish after [close] releases it), exactly once, whether by the owner or its cleaner.
 */
internal class SslContextResource(private val ctx: CPointer<SSL_CTX>) {
    /** Number of running [use]s, or -1 once released. */
    private val users = AtomicInt(0)
    private val closed = AtomicInt(0)

    init { NativeTls.contextOpened() }

    fun <T> use(block: (CPointer<SSL_CTX>) -> T): T {
        while (true) {
            val n = users.value
            check(n >= 0 && closed.value == 0) { "the TLS configuration is closed" }
            if (users.compareAndSet(n, n + 1)) break
        }
        try {
            return block(ctx)
        } finally {
            if (users.decrementAndGet() == 0 && closed.value != 0) free()
        }
    }

    fun close() {
        closed.value = 1
        free()
    }

    private fun free() {
        if (!users.compareAndSet(0, -1)) return
        SSL_CTX_free(ctx)
        NativeTls.contextFreed()
    }
}

// ---- helpers ----

internal const val SSL_CTRL_SET_TLSEXT_HOSTNAME = 55
internal const val TLSEXT_NAMETYPE_HOST_NAME = 0

/** `SSL_set_tlsext_host_name` (a macro over `SSL_ctrl`, whose C `long` differs between targets). */
internal expect fun sslSetTlsextHostName(ssl: CPointer<SSL>, name: String): Boolean

/** SSL_CTX_set_session_cache_mode, per platform: SSL_CTX_ctrl takes a C `long` (32-bit on Windows). */
internal expect fun sslCtxSetSessionCacheMode(ctx: CPointer<SSL_CTX>, mode: Int)

/** OpenSSL's names of the cipher suites. */
internal val CipherSuite.openSslName: String
    get() = when (this) {
        CipherSuite.TLS13_AES_128_GCM_SHA256 -> "TLS_AES_128_GCM_SHA256"
        CipherSuite.TLS13_AES_256_GCM_SHA384 -> "TLS_AES_256_GCM_SHA384"
        CipherSuite.TLS13_CHACHA20_POLY1305_SHA256 -> "TLS_CHACHA20_POLY1305_SHA256"
    }

/** The suite of a TLS 1.3 cipher suite code point, or `null` for one QUIC cannot use here. */
internal fun cipherSuiteOf(protocolId: Int): CipherSuite? = when (protocolId) {
    0x1301 -> CipherSuite.TLS13_AES_128_GCM_SHA256
    0x1302 -> CipherSuite.TLS13_AES_256_GCM_SHA384
    0x1303 -> CipherSuite.TLS13_CHACHA20_POLY1305_SHA256
    else -> null
}

private const val SSL_OP_NO_COMPRESSION = 0x20000uL // SSL_OP_BIT(17)
internal const val SSL_CTRL_SET_SESS_CACHE_MODE = 44
private const val SSL_SESS_CACHE_CLIENT = 0x0001
private const val SSL_SESS_CACHE_NO_INTERNAL_STORE = 0x0300 // NO_INTERNAL_LOOKUP | NO_INTERNAL_STORE

/** A session ticket a client keeps (rustls `Tls13ClientSessionValue` with its QUIC parameters). */
internal class ClientTicket(
    /** The SSL_SESSION, DER-encoded (i2d_SSL_SESSION). */
    val session: ByteArray,
    /** The server's transport parameters on the connection that issued it (the 0-RTT limits, RFC 9000 §7.4.1). */
    val params: ByteArray?,
    /** The ticket allows 0-RTT (max_early_data 0xffffffff, the only non-zero value QUIC permits). */
    val earlyData: Boolean,
)

/**
 * Tickets per server name, each used once (rustls `ClientSessionMemoryCache`: up to [PER_SERVER] per name, [SERVERS]
 * names, the oldest name evicted first). A configuration can serve endpoints on several reactor threads, so access is
 * serialized by a spin lock (every operation is a few map updates).
 */
internal class TicketCache {
    private val lock = AtomicInt(0)
    private val byServer = LinkedHashMap<String, ArrayDeque<ClientTicket>>()

    private inline fun <T> locked(block: () -> T): T {
        while (!lock.compareAndSet(0, 1)) { }
        try { return block() } finally { lock.value = 0 }
    }

    fun add(server: String, ticket: ClientTicket) = locked {
        val q = byServer.remove(server) ?: ArrayDeque()
        q.addLast(ticket)
        while (q.size > PER_SERVER) q.removeFirst()
        byServer[server] = q
        while (byServer.size > SERVERS) byServer.remove(byServer.keys.first())
    }

    /** The newest ticket for [server], removed (single use). */
    fun take(server: String): ClientTicket? = locked {
        val q = byServer[server] ?: return@locked null
        val t = q.removeLastOrNull()
        if (q.isEmpty()) byServer.remove(server)
        t
    }

    internal val size: Int get() = locked { byServer.values.sumOf { it.size } }

    private companion object {
        const val PER_SERVER = 8
        const val SERVERS = 256
    }
}

/** An SSL_CTX for QUIC: TLS 1.3 only, the given suites; [configure] adds the rest (tickets and early data per side). */
private inline fun newQuicContext(suites: List<CipherSuite>, groups: String?, configure: (CPointer<SSL_CTX>) -> Unit): CPointer<SSL_CTX> {
    require(suites.isNotEmpty()) { "no cipher suites" }
    require(groups == null || (groups.isNotEmpty() && '\u0000' !in groups)) { "invalid groups" }
    ERR_clear_error()
    val ctx = SSL_CTX_new(TLS_method()) ?: throw IllegalStateException("SSL_CTX_new failed: ${drainOpenSslErrors()}")
    try {
        check(neton_openssl_tls13_only(ctx) == 1) { "TLS 1.3 only: ${drainOpenSslErrors()}" }
        SSL_CTX_set_options(ctx, SSL_OP_NO_COMPRESSION)
        val names = suites.distinct().joinToString(":") { it.openSslName }
        require(SSL_CTX_set_ciphersuites(ctx, names) == 1) { "cipher suites $names: ${drainOpenSslErrors()}" }
        if (groups != null) require(neton_tls_groups(ctx, groups) == 1) { "groups $groups: ${drainOpenSslErrors()}" }
        configure(ctx)
        return ctx
    } catch (t: Throwable) {
        SSL_CTX_free(ctx)
        ERR_clear_error()
        throw t
    }
}

private fun addTrustAnchors(ctx: CPointer<SSL_CTX>, anchors: Certificates) {
    val store = SSL_CTX_get_cert_store(ctx) ?: throw IllegalStateException("no certificate store")
    for (der in anchors.der) {
        val x = parseDer(der)
        try {
            require(X509_STORE_add_cert(store, x) == 1) { "trust anchor: ${drainOpenSslErrors()}" }
        } finally {
            X509_free(x)
        }
    }
}

/** Install a certificate chain (leaf first) and its private key; OpenSSL checks that they match. */
private fun useIdentity(ctx: CPointer<SSL_CTX>, chain: Certificates, key: PrivateKey) {
    val certs = chain.der.map { parseDer(it) }
    val stack = OPENSSL_sk_new_null() ?: run { certs.forEach { X509_free(it) }; throw IllegalStateException("out of memory") }
    val pkey = try { key.load() } catch (t: Throwable) { OPENSSL_sk_free(stack); certs.forEach { X509_free(it) }; throw t }
    try {
        for (c in certs.drop(1)) check(OPENSSL_sk_push(stack, c) > 0) { "out of memory" }
        // Copies the chain and takes its own references to the certificate and key.
        require(SSL_CTX_use_cert_and_key(ctx, certs[0], pkey, stack.reinterpret(), 1) == 1) {
            "certificate chain / private key: ${drainOpenSslErrors()}"
        }
    } finally {
        OPENSSL_sk_free(stack)
        EVP_PKEY_free(pkey)
        certs.forEach { X509_free(it) }
    }
}

internal fun parseDer(der: ByteArray): CPointer<X509> {
    require(der.isNotEmpty()) { "empty certificate" }
    ERR_clear_error()
    val x = der.usePinned { pinned ->
        memScoped {
            val p = alloc<CPointerVar<UByteVar>>()
            p.value = pinned.addressOf(0).reinterpret()
            val x = d2i_X509(null, p.ptr, der.size.convert())
            // Trailing bytes after the certificate are rejected.
            if (x != null && p.value?.rawValue != pinned.addressOf(0).rawValue + der.size.toLong()) {
                X509_free(x)
                null
            } else x
        }
    }
    return x ?: throw IllegalArgumentException("invalid DER certificate: ${drainOpenSslErrors()}")
}

internal fun toDer(x: CPointer<X509>): ByteArray {
    val len = i2d_X509(x, null)
    check(len > 0) { "i2d_X509: ${drainOpenSslErrors()}" }
    val out = ByteArray(len)
    out.usePinned { pinned ->
        memScoped {
            val p = alloc<CPointerVar<UByteVar>>()
            p.value = pinned.addressOf(0).reinterpret()
            check(i2d_X509(x, p.ptr) == len) { "i2d_X509: ${drainOpenSslErrors()}" }
        }
    }
    return out
}

private inline fun <T> withMemBio(bytes: ByteArray, block: (CPointer<BIO>) -> T): T {
    require(bytes.isNotEmpty()) { "empty input" }
    return bytes.usePinned { pinned ->
        val bio = BIO_new_mem_buf(pinned.addressOf(0), bytes.size) ?: throw IllegalStateException("BIO_new_mem_buf failed")
        try { block(bio) } finally { BIO_free(bio) }
    }
}

/** The PEM password callback: encrypted keys are refused instead of prompting on the terminal. */
private val NO_PASSWORD = staticCFunction { _: CPointer<ByteVar>?, _: Int, _: Int, _: COpaquePointer? -> 0 }

internal fun validateAlpn(protocols: List<ByteArray>): List<ByteArray> {
    var total = 0
    for (p in protocols) {
        require(p.size in 1..255) { "an ALPN protocol has 1 to 255 bytes" }
        total += 1 + p.size
    }
    require(total <= 65535) { "ALPN list too long" }
    return protocols.map { it.copyOf() }
}

/** The ALPN wire format: each protocol prefixed by its length. */
internal fun alpnWire(protocols: List<ByteArray>): ByteArray {
    val out = ByteArray(protocols.sumOf { 1 + it.size })
    var at = 0
    for (p in protocols) {
        out[at++] = p.size.toByte()
        p.copyInto(out, at)
        at += p.size
    }
    return out
}
