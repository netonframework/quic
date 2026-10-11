@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package neton.quic.proto

import neton.openssl.QuicTlsContext
import neton.openssl.QuicTlsCredentials
import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.decrementAndFetch

// The TLS 1.3 configurations of the real QUIC TLS layer (quinn-proto `crypto/rustls.rs` `QuicClientConfig` /
// `QuicServerConfig`, with the certificate handling of quinn's `ClientConfig::with_root_certificates` and
// `ServerConfig::with_single_cert`), on OpenSSL 4.0.2's third-party QUIC TLS interface through openssl-kotlin's QUIC TLS
// facade (`QuicTlsContext`, its callbacks in C). The session state machine is in `TlsSession.kt`.
//
// Ownership: a configuration owns one SSL_CTX reference and releases it in [TlsClientConfig.close] /
// [TlsServerConfig.close] (a GC cleaner only backs this up). Every session holds its own reference to the SSL_CTX
// (OpenSSL's SSL_new / SSL_free count it), so closing a configuration while its sessions are still running is safe:
// they keep working, and the SSL_CTX is freed with the last of them. Starting a session on a closed configuration
// throws [IllegalStateException].
//
// No insecure defaults: TLS 1.3 only; the three QUIC cipher suites only (RFC 9001 §5.3; CCM is left out as in
// rustls); a client verifies the server's certificate chain against trust anchors it is given explicitly (the
// system's roots only through Certificates.system(), never implicitly) and the server name (DNS SAN, or IP SAN for an IP address); a client without trust
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
            for (c in certificates) {
                require(c.isNotEmpty()) { "empty certificate" }
                require(QuicTlsCredentials.isCertificate(c)) { "invalid DER certificate" }
            }
            return Certificates(certificates.map { it.copyOf() })
        }

        fun der(vararg certificates: ByteArray): Certificates = der(certificates.toList())

        /** Every `CERTIFICATE` block of a PEM document, in order. */
        fun pem(pem: ByteArray): Certificates {
            require(pem.isNotEmpty()) { "empty input" }
            val out = QuicTlsCredentials.pemCertificates(pem)
            require(out.isNotEmpty()) { "no PEM certificate found" }
            return Certificates(out)
        }

        fun pem(pem: String): Certificates = pem(pem.encodeToByteArray())

        /**
         * The operating system's trusted root certificates (rustls-native-certs `load_native_certs`), for a client that
         * verifies servers on the public Internet: `TlsClientConfig(Certificates.system(), ...)`. `SSL_CERT_FILE` (a PEM
         * bundle) and `SSL_CERT_DIR` (PEM directories, ':'-separated) replace the platform's store when set. Otherwise:
         * Linux, the distribution's CA bundle (or `/etc/ssl/certs`); Android, the system CA directory; macOS, the
         * Security framework's anchor certificates; Windows, the system ROOT store. Read on every call; keep the result.
         *
         * @throws UnsupportedOperationException on iOS, which has no API to list them.
         * @throws IllegalStateException when no certificate is found.
         */
        fun system(): Certificates {
            val der = systemRootsDer()
            check(der.isNotEmpty()) { "no system root certificates found (set SSL_CERT_FILE or pass trust anchors)" }
            return Certificates(der)
        }
    }
}

/** A private key (PKCS#8, or a traditional RSA / EC key), as DER or PEM (unencrypted). */
class PrivateKey private constructor(internal val bytes: ByteArray, internal val isPem: Boolean) {
    companion object {
        fun der(der: ByteArray): PrivateKey {
            require(der.isNotEmpty()) { "empty private key" }
            require(QuicTlsCredentials.isPrivateKey(der, pem = false)) { "invalid private key" }
            return PrivateKey(der.copyOf(), false)
        }

        fun pem(pem: ByteArray): PrivateKey {
            require(pem.isNotEmpty()) { "empty private key" }
            require(QuicTlsCredentials.isPrivateKey(pem, pem = true)) { "invalid private key" }
            return PrivateKey(pem.copyOf(), true)
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
    /** Where the sessions' secrets go (rustls `key_log`); none by default. */
    internal val keyLog: KeyLog?,
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
     * @param keyLog receives each session's secrets (rustls `key_log`, e.g. [KeyLogFile]); `null` logs nothing.
     */
    constructor(
        trustAnchors: Certificates,
        alpnProtocols: List<ByteArray> = emptyList(),
        clientCertificate: Certificates? = null,
        clientKey: PrivateKey? = null,
        cipherSuites: List<CipherSuite> = CipherSuite.entries,
        groups: String? = null,
        enableEarlyData: Boolean = true,
        keyLog: KeyLog? = null,
    ) : this(trustAnchors, alpnProtocols, clientCertificate, clientKey, cipherSuites, groups, false, enableEarlyData, keyLog)

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
        // Tickets reach the session through the facade's new-session callback; OpenSSL keeps no client cache of its own.
        ctx = SslContextResource(quicContext(cipherSuites, groups) { suites, g ->
            QuicTlsContext(
                server = false, cipherSuites = suites, groups = g,
                verifyMode = if (trustAnchors != null) 1 else 0,
                trustAnchorsDer = trustAnchors?.der.orEmpty(),
                certificateChainDer = clientCertificate?.der, privateKey = clientKey?.bytes, privateKeyIsPem = clientKey?.isPem ?: false,
                keyLog = keyLog != null,
            )
        })
    }

    @Suppress("unused")
    private val cleaner = backstopCleaner(ctx) { it.close() }

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
            keyLog: KeyLog? = null,
        ): TlsClientConfig = TlsClientConfig(null, alpnProtocols, null, null, cipherSuites, groups, true, enableEarlyData, keyLog)
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
 * @param keyLog receives each session's secrets (rustls `key_log`, e.g. [KeyLogFile]); `null` logs nothing.
 */
class TlsServerConfig(
    certificateChain: Certificates,
    privateKey: PrivateKey,
    alpnProtocols: List<ByteArray> = emptyList(),
    clientAuth: ClientAuth = ClientAuth.None,
    cipherSuites: List<CipherSuite> = CipherSuite.entries,
    groups: String? = null,
    internal val earlyData: Boolean = true,
    internal val keyLog: KeyLog? = null,
) : CryptoServerConfig, AutoCloseable {
    internal val alpn: List<ByteArray> = validateAlpn(alpnProtocols)
    // ALPN selection and the "client offered no ALPN" check run in the facade's context callbacks with the protocols
    // each session carries, so nothing points into this configuration (sessions outlive a closed configuration). The
    // facade also sets the session ID context resumption needs once client certificates are verified.
    internal val ctx: SslContextResource = SslContextResource(quicContext(cipherSuites, groups) { suites, g ->
        val (mode, anchors) = when (clientAuth) {
            ClientAuth.None -> 0 to emptyList()
            is ClientAuth.Request -> 1 to clientAuth.trustAnchors.der
            is ClientAuth.Require -> 2 to clientAuth.trustAnchors.der
        }
        QuicTlsContext(
            server = true, cipherSuites = suites, groups = g, verifyMode = mode, trustAnchorsDer = anchors,
            certificateChainDer = certificateChain.der, privateKey = privateKey.bytes, privateKeyIsPem = privateKey.isPem,
            keyLog = keyLog != null,
        )
    })

    @Suppress("unused")
    private val cleaner = backstopCleaner(ctx) { it.close() }

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
internal class SslContextResource(private val ctx: QuicTlsContext) {
    /** Number of running [use]s, or -1 once released. */
    private val users = AtomicInt(0)
    private val closed = AtomicInt(0)

    init { NativeTls.contextOpened() }

    fun <T> use(block: (QuicTlsContext) -> T): T {
        while (true) {
            val n = users.load()
            check(n >= 0 && closed.load() == 0) { "the TLS configuration is closed" }
            if (users.compareAndSet(n, n + 1)) break
        }
        try {
            return block(ctx)
        } finally {
            if (users.decrementAndFetch() == 0 && closed.load() != 0) free()
        }
    }

    fun close() {
        closed.store(1)
        free()
    }

    private fun free() {
        if (!users.compareAndSet(0, -1)) return
        ctx.close()
        NativeTls.contextFreed()
    }
}

// ---- helpers ----

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
        try { return block() } finally { lock.store(0) }
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

/**
 * A QUIC TLS context: TLS 1.3 only, no compression, the given suites (the facade sets them); [create] makes it from the
 * suites' OpenSSL names and the groups. Bad suites, groups or credentials are refused with the OpenSSL errors.
 */
private inline fun quicContext(suites: List<CipherSuite>, groups: String?, create: (List<String>, String?) -> QuicTlsContext): QuicTlsContext {
    require(suites.isNotEmpty()) { "no cipher suites" }
    require(groups == null || (groups.isNotEmpty() && '\u0000' !in groups)) { "invalid groups" }
    return try {
        create(suites.distinct().map { it.openSslName }, groups)
    } catch (e: neton.openssl.OpenSslException) {
        throw IllegalArgumentException("TLS configuration: ${e.message}", e)
    }
}

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
