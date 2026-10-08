@file:OptIn(ExperimentalForeignApi::class)

package neton.quic.proto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import neton.quic.testkit.MockClientCrypto
import neton.quic.testkit.MockHandshakeData
import neton.quic.testkit.MockServerCrypto
import neton.quic.testkit.TestCa
import neton.quic.testkit.TestIdentity
import neton.quic.testkit.TestPki
import platform.posix.getenv

/** Which TLS layer the shared test harness uses by default. */
internal enum class TestTlsKind { Mock, Real }

/**
 * The TLS layer of the test harnesses (`PairUtil`, `DriverTestUtil`): the test double (`MockTls`, the default) or the
 * real TLS session on OpenSSL. `NETON_QUIC_TEST_TLS=real` makes the harness defaults real, so that the whole suite
 * can be run on real TLS; tests that need one or the other ask for it explicitly. The certificates are generated
 * once per test process: a test CA, and a server certificate it issued for `localhost`, 127.0.0.1 and ::1, which the
 * default real client trusts through the CA.
 */
internal object TestTls {
    val kind: TestTlsKind =
        if (getenv("NETON_QUIC_TEST_TLS")?.toKString().equals("real", ignoreCase = true)) TestTlsKind.Real else TestTlsKind.Mock

    /** Key exchange groups of the harness's real clients (`NETON_QUIC_TEST_TLS_GROUPS`; OpenSSL's default if unset). */
    val groups: String? = getenv("NETON_QUIC_TEST_TLS_GROUPS")?.toKString()?.ifEmpty { null }

    val ca: TestCa by lazy { TestCa.create() }

    val server: TestIdentity by lazy { ca.issue("localhost", listOf("localhost"), listOf("127.0.0.1", "::1")) }

    val client: TestIdentity by lazy { ca.issue("quic test client", listOf("client.test")) }

    fun serverCrypto(
        alpn: List<ByteArray> = emptyList(),
        clientAuth: ClientAuth = ClientAuth.None,
        identity: TestIdentity = server,
        cipherSuites: List<CipherSuite> = CipherSuite.entries,
    ): TlsServerConfig = TlsServerConfig(identity.certificates, identity.privateKey, alpn, clientAuth, cipherSuites)

    fun clientCrypto(
        alpn: List<ByteArray> = emptyList(),
        trust: neton.quic.proto.Certificates = ca.trustAnchors,
        identity: TestIdentity? = null,
        cipherSuites: List<CipherSuite> = CipherSuite.entries,
        groups: String? = this.groups,
    ): TlsClientConfig = TlsClientConfig(trust, alpn, identity?.certificates, identity?.privateKey, cipherSuites, groups)

    /** The harness default: [kind]'s server crypto. */
    fun defaultServerCrypto(alpn: List<ByteArray> = emptyList()): CryptoServerConfig =
        if (kind == TestTlsKind.Real) serverCrypto(alpn) else MockServerCrypto(alpn = alpn)

    /** The harness default: [kind]'s client crypto. */
    fun defaultClientCrypto(alpn: List<ByteArray> = emptyList()): CryptoClientConfig =
        if (kind == TestTlsKind.Real) clientCrypto(alpn) else MockClientCrypto(alpn = alpn)

    /**
     * [kind]'s client crypto with a ClientHello that fits one Initial datagram, for quinn tests that count datagrams
     * or `Incoming`s and so assume one (rustls's ring provider in quinn's tests sends only an X25519 key share).
     * OpenSSL's default ClientHello also carries an X25519MLKEM768 share and takes two datagrams; on real TLS this
     * offers X25519 only. The test double's ClientHello is always one datagram. The two-datagram ClientHello is
     * exercised explicitly in `RealTlsConnectionTest`.
     */
    fun oneDatagramHelloClientCrypto(alpn: List<ByteArray> = emptyList()): CryptoClientConfig =
        if (kind == TestTlsKind.Real) clientCrypto(alpn, groups = "X25519") else MockClientCrypto(alpn = alpn)

    /**
     * The application protocol in a session's handshake data, whichever TLS layer produced it ([TlsHandshakeData] or
     * the test double's `MockHandshakeData`; quinn downcasts to rustls's `HandshakeData`).
     */
    fun negotiatedProtocol(handshakeData: Any?): ByteArray? = when (handshakeData) {
        is TlsHandshakeData -> handshakeData.protocol
        is MockHandshakeData -> handshakeData.protocol
        else -> throw AssertionError("no handshake data of a known TLS layer: $handshakeData")
    }

    /** The server name in a server session's handshake data, whichever TLS layer produced it. */
    fun serverName(handshakeData: Any?): String? = when (handshakeData) {
        is TlsHandshakeData -> handshakeData.serverName
        is MockHandshakeData -> handshakeData.serverName
        else -> throw AssertionError("no handshake data of a known TLS layer: $handshakeData")
    }

    /** A self-signed certificate with many names, too big for the first flight's amplification limit (quinn `big_cert_and_key`). */
    val bigSelfSigned: TestIdentity by lazy { TestPki.selfSigned(listOf("localhost") + (0 until 1000).map { "foo_$it" }) }
}
