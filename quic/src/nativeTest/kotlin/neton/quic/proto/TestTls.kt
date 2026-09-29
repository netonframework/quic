@file:OptIn(ExperimentalForeignApi::class)

package neton.quic.proto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import neton.quic.testkit.MockClientCrypto
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

    /** A self-signed certificate with many names, too big for the first flight's amplification limit (quinn `big_cert_and_key`). */
    val bigSelfSigned: TestIdentity by lazy { TestPki.selfSigned(listOf("localhost") + (0 until 1000).map { "foo_$it" }) }
}
