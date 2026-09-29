package neton.quic.proto

import neton.io.bytes.Bytes
import neton.quic.testkit.TestPki
import kotlin.native.runtime.GC
import kotlin.native.runtime.NativeRuntimeApi
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail
import kotlin.time.Duration.Companion.seconds

// quinn-proto `tests/mod.rs` tests that need real TLS (SPEC §11.5: waiting for real TLS), and those that passed on the
// test double and must be re-verified on real TLS, run through the two-endpoint simulation (`PairUtil`) on the real
// TLS session. Where quinn builds rustls configurations with rcgen certificates, these use `TestTls` (a test CA and a
// server certificate for localhost, generated with OpenSSL at test time).
class RealTlsConnectionTest {
    private fun bytes(s: String): Bytes = Bytes.wrap(s.encodeToByteArray())
    private fun alpn(vararg p: String) = p.map { it.encodeToByteArray() }
    private fun realServerConfig(vararg protocols: String) = ServerConfig.withCrypto(TestTls.serverCrypto(alpn(*protocols)))
    private fun realClient(vararg protocols: String) = ClientConfig(TestTls.clientCrypto(alpn(*protocols)))

    private fun ConnPair.assertClientLost(clientCh: ConnectionHandle): ConnectionError {
        val e = clientConn(clientCh).poll()
        assertIs<Event.ConnectionLost>(e, "expected ConnectionLost, got $e")
        return e.reason
    }

    // mod.rs:195 on real TLS: handshake, ECN, application close, everything forgotten afterwards
    @Test
    fun lifecycle() {
        val pair = ConnPair.real()
        val (clientCh, serverCh) = pair.connectWith(realClient())
        assertNull(pair.clientConn(clientCh).poll())
        val reason = bytes("whee")
        pair.clientConn(clientCh).close(pair.time, VarInt(42), reason)
        pair.drive()
        assertEquals(
            Event.ConnectionLost(ConnectionError.ApplicationClosed(Frame.ApplicationClose(VarInt(42), reason))),
            pair.serverConn(serverCh).poll(),
        )
        assertEquals(0, pair.client.endpoint.knownConnections())
        assertEquals(0, pair.server.endpoint.knownConnections())
    }

    // mod.rs:223
    @Test
    fun draftVersionCompat() {
        val pair = ConnPair.real()
        val (clientCh, serverCh) = pair.connectWith(realClient().version(0xff00_0020.toInt()))
        pair.clientConn(clientCh).close(pair.time, VarInt(0), Bytes.EMPTY)
        pair.drive()
        assertIs<Event.ConnectionLost>(pair.serverConn(serverCh).poll())
    }

    // mod.rs:487: the client does not trust the server's certificate
    @Test
    fun rejectSelfSignedServerCert() {
        val pair = ConnPair.real()
        // A self-signed certificate with a different name than the default issuer, trusted by the client instead
        val other = TestPki.selfSigned(commonName = "Crazy Quinn's House of Certificates")
        val clientCh = pair.beginConnect(ClientConfig(TestTls.clientCrypto(trust = other.certificates)))
        pair.drive()
        val reason = pair.assertClientLost(clientCh)
        assertIs<ConnectionError.Transport>(reason)
        assertEquals(TransportErrorCode.crypto(48), reason.error.code) // UnknownCA
    }

    // mod.rs:515: the server requires a client certificate the client does not have
    @Test
    fun rejectMissingClientCert() {
        val server = TestTls.serverCrypto(clientAuth = ClientAuth.Require(TestTls.server.certificates))
        val pair = ConnPair.real(server)
        val clientCh = pair.beginConnect(realClient())
        pair.drive()
        // The client completes the connection, but finds it immediately closed
        assertEquals(Event.HandshakeDataReady, pair.clientConn(clientCh).poll())
        assertEquals(Event.Connected, pair.clientConn(clientCh).poll())
        val reason = pair.assertClientLost(clientCh)
        assertIs<ConnectionError.ConnectionClosed>(reason)
        assertEquals(TransportErrorCode.crypto(116), reason.reason.errorCode) // CertificateRequired
    }

    @Test
    fun acceptClientCertIssuedByTheTrustedCa() {
        val server = TestTls.serverCrypto(clientAuth = ClientAuth.Require(TestTls.ca.trustAnchors))
        val pair = ConnPair.real(server)
        val (_, serverCh) = pair.connectWith(ClientConfig(TestTls.clientCrypto(identity = TestTls.client)))
        val chain = pair.serverConn(serverCh).cryptoSession().peerIdentity() as List<*>
        assertContentEquals(TestTls.client.certDer, chain.first() as ByteArray)
    }

    // mod.rs:869
    @Test
    fun alpnSuccess() {
        val pair = ConnPair.new(EndpointConfig.default(), realServerConfig("foo", "bar", "baz"))
        val clientCh = pair.beginConnect(realClient("bar", "quux", "corge"))
        pair.drive()
        val serverCh = pair.server.assertAccept()
        assertEquals(Event.HandshakeDataReady, pair.serverConn(serverCh).poll())
        assertEquals(Event.Connected, pair.serverConn(serverCh).poll())
        val hd = pair.clientConn(clientCh).cryptoSession().handshakeData() as TlsHandshakeData
        assertContentEquals("bar".encodeToByteArray(), hd.protocol)
        val shd = pair.serverConn(serverCh).cryptoSession().handshakeData() as TlsHandshakeData
        assertEquals("localhost", shd.serverName)
    }

    private fun assertNoApplicationProtocol(pair: ConnPair, clientCh: ConnectionHandle) {
        val reason = pair.assertClientLost(clientCh)
        assertIs<ConnectionError.ConnectionClosed>(reason, "$reason")
        assertEquals(TransportErrorCode.crypto(0x78), reason.reason.errorCode)
    }

    // mod.rs:908
    @Test
    fun serverAlpnUnset() {
        val pair = ConnPair.new(EndpointConfig.default(), realServerConfig())
        val clientCh = pair.beginConnect(realClient("foo"))
        pair.drive()
        assertNoApplicationProtocol(pair, clientCh)
    }

    // mod.rs:922
    @Test
    fun clientAlpnUnset() {
        val pair = ConnPair.new(EndpointConfig.default(), realServerConfig("foo", "bar", "baz"))
        val clientCh = pair.beginConnect(realClient())
        pair.drive()
        assertNoApplicationProtocol(pair, clientCh)
    }

    // mod.rs:940
    @Test
    fun alpnMismatch() {
        val pair = ConnPair.new(EndpointConfig.default(), realServerConfig("foo", "bar", "baz"))
        val clientCh = pair.beginConnect(realClient("quux", "corge"))
        pair.drive()
        assertNoApplicationProtocol(pair, clientCh)
    }

    // mod.rs:360
    @Test
    fun exportKeyingMaterial() {
        val pair = ConnPair.real()
        val (clientCh, serverCh) = pair.connectWith(realClient())
        val label = "test_label".encodeToByteArray()
        val context = "test_context".encodeToByteArray()
        val clientBuf = ByteArray(64)
        pair.clientConn(clientCh).cryptoSession().exportKeyingMaterial(clientBuf, label, context)
        val serverBuf = ByteArray(64)
        pair.serverConn(serverCh).cryptoSession().exportKeyingMaterial(serverBuf, label, context)
        assertContentEquals(clientBuf, serverBuf)
    }

    // mod.rs:1370
    @Test
    fun keyUpdateSimple() {
        val pair = ConnPair.real()
        val (clientCh, serverCh) = pair.connectWith(realClient())
        val s = pair.clientStreams(clientCh).open(Dir.Bi) ?: fail("couldn't open first stream")
        val msg1 = "hello1".encodeToByteArray()
        pair.clientSend(clientCh, s).writeOk(msg1)
        pair.drive()
        assertEquals(StreamEvent.Opened(Dir.Bi), pair.serverConn(serverCh).poll())
        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Bi))
        assertNull(pair.serverConn(serverCh).poll())
        var chunks = pair.serverRecv(serverCh, s).read(false)
        assertChunk(chunks.next(Int.MAX_VALUE), 0, msg1)
        chunks.finalize()

        pair.clientConn(clientCh).forceKeyUpdate()
        val msg2 = "hello2".encodeToByteArray()
        pair.clientSend(clientCh, s).writeOk(msg2)
        pair.drive()
        assertEquals(StreamEvent.Readable(s), pair.serverConn(serverCh).poll())
        assertNull(pair.serverConn(serverCh).poll())
        chunks = pair.serverRecv(serverCh, s).read(false)
        assertChunk(chunks.next(Int.MAX_VALUE), 6, msg2)
        chunks.finalize()
        assertEquals(0L, pair.clientConn(clientCh).stats().path.lostPackets)
        assertEquals(0L, pair.serverConn(serverCh).stats().path.lostPackets)
    }

    // mod.rs:1423
    @Test
    fun keyUpdateReordered() {
        val pair = ConnPair.real()
        val (clientCh, serverCh) = pair.connectWith(realClient())
        val s = pair.clientStreams(clientCh).open(Dir.Bi) ?: fail("couldn't open first stream")
        val msg1 = "1".encodeToByteArray()
        pair.clientSend(clientCh, s).writeOk(msg1)
        pair.client.drive(pair.time, pair.server.addr)
        assertTrue(pair.client.outbound.isNotEmpty())
        pair.client.delayOutbound()
        pair.clientConn(clientCh).forceKeyUpdate()
        val msg2 = "two".encodeToByteArray()
        pair.clientSend(clientCh, s).writeOk(msg2)
        pair.client.drive(pair.time, pair.server.addr)
        pair.client.finishDelay()
        pair.drive()
        assertEquals(0L, pair.clientConn(clientCh).stats().path.lostPackets)
        assertEquals(StreamEvent.Opened(Dir.Bi), pair.serverConn(serverCh).poll())
        assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Bi))
        val chunks = pair.serverRecv(serverCh, s).read(true)
        assertContentEquals(msg1, chunks.nextChunk().bytes.toByteArray())
        assertContentEquals(msg2, chunks.nextChunk().bytes.toByteArray())
        chunks.finalize()
        assertEquals(0L, pair.serverConn(serverCh).stats().path.lostPackets)
    }

    /** Many key updates, alternating sides, with data both ways between them. */
    @Test
    fun manyKeyUpdatesBothSides() {
        val pair = ConnPair.real()
        val (clientCh, serverCh) = pair.connectWith(realClient())
        val s = pair.clientStreams(clientCh).open(Dir.Bi)!!
        var sent = 0
        repeat(12) { i ->
            val msg = "update $i".encodeToByteArray()
            pair.clientSend(clientCh, s).writeOk(msg)
            sent += msg.size
            pair.drive()
            if (i % 2 == 0) pair.clientConn(clientCh).forceKeyUpdate() else pair.serverConn(serverCh).forceKeyUpdate()
            pair.drive()
        }
        pair.serverConn(serverCh).drainEvents()
        pair.serverStreams(serverCh).accept(Dir.Bi)
        val chunks = pair.serverRecv(serverCh, s).read(true)
        var got = 0
        while (true) {
            val c = chunks.next(Int.MAX_VALUE) as? Chunk ?: break
            got += c.bytes.size
        }
        chunks.finalize()
        assertEquals(sent, got)
        assertEquals(0L, pair.clientConn(clientCh).stats().path.lostPackets)
    }

    // mod.rs:2550
    @Test
    fun largeInitial() {
        val server = ServerConfig.withCrypto(TestTls.serverCrypto(listOf(byteArrayOf(0, 0, 0, 42))))
        val pair = ConnPair.new(EndpointConfig.default(), server)
        val protocols = (0 until 1000).map { x -> byteArrayOf((x ushr 24).toByte(), (x ushr 16).toByte(), (x ushr 8).toByte(), x.toByte()) }
        val clientCh = pair.beginConnect(ClientConfig(TestTls.clientCrypto(protocols)))
        pair.drive()
        val serverCh = pair.server.assertAccept()
        pair.assertClientConnectedAfterDrive(clientCh)
        assertEquals(Event.HandshakeDataReady, pair.serverConn(serverCh).poll())
        assertEquals(Event.Connected, pair.serverConn(serverCh).poll())
    }

    private fun bigCertPair(): Pair<ConnPair, ClientConfig> {
        val big = TestTls.bigSelfSigned
        val pair = ConnPair.real(TestTls.serverCrypto(identity = big))
        return pair to ClientConfig(TestTls.clientCrypto(trust = big.certificates))
    }

    // mod.rs:2735
    @Test
    fun handshakeAntiDeadlockProbe() {
        val (pair, client) = bigCertPair()
        val clientCh = pair.beginConnect(client)
        pair.driveClient()
        pair.driveServer()
        pair.driveClient()
        pair.server.inbound.clear()
        pair.drive()
        pair.assertClientConnectedAfterDrive(clientCh)
    }

    // mod.rs:2764
    @Test
    fun serverCanSend3InitalPackets() {
        val (pair, client) = bigCertPair()
        val clientCh = pair.beginConnect(client)
        pair.driveClient()
        // ⚖️ OpenSSL's default ClientHello carries an X25519MLKEM768 key share and spans two Initial datagrams
        // (rustls's in quinn's test fits one); the anti-amplification limit is three times what the server received.
        val fromClient = pair.server.inbound.size
        assertEquals(if (TestTls.groups == null) 2 else 1, fromClient)
        pair.driveServer()
        assertEquals(3 * fromClient, pair.client.inbound.size)
        pair.drive()
        pair.assertClientConnectedAfterDrive(clientCh)
    }

    /** With only an X25519 key share the ClientHello fits one Initial datagram (OpenSSL's default needs two). */
    @Test
    fun clientHelloInOneDatagramWithX25519() {
        val pair = ConnPair.real()
        val clientCh = pair.beginConnect(ClientConfig(TestTls.clientCrypto(groups = "X25519")))
        pair.driveClient()
        assertEquals(1, pair.server.inbound.size)
        pair.drive()
        pair.server.assertAccept()
        pair.assertClientConnectedAfterDrive(clientCh)
    }

    /** A stateless Retry before the handshake, on real TLS (the Retry integrity tag and the re-sent ClientHello). */
    @Test
    fun retryThenHandshake() {
        val pair = ConnPair.real()
        pair.server.handleIncoming = { validateIncoming(it) }
        val (clientCh, _) = pair.connectWith(realClient())
        assertNull(pair.clientConn(clientCh).poll())
    }

    /** Bulk data after the handshake over a lossy-free link with every cipher suite. */
    @Test
    fun eachCipherSuiteCarriesData() {
        for (suite in CipherSuite.entries) {
            val pair = ConnPair.real()
            val (clientCh, serverCh) = pair.connectWith(ClientConfig(TestTls.clientCrypto(cipherSuites = listOf(suite))))
            val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
            val data = ByteArray(100_000) { it.toByte() }
            var at = 0
            while (at < data.size) {
                val n = when (val r = pair.clientSend(clientCh, s).write(data.copyOfRange(at, data.size))) {
                    is Written -> r.bytes
                    else -> 0
                }
                at += n
                pair.drive()
            }
            pair.clientSend(clientCh, s).finish()
            pair.drive()
            pair.serverConn(serverCh).drainEvents()
            assertEquals(s, pair.serverStreams(serverCh).accept(Dir.Uni))
            val chunks = pair.serverRecv(serverCh, s).read(true)
            var got = 0
            while (true) {
                val c = chunks.next(Int.MAX_VALUE) as? Chunk ?: break
                got += c.bytes.size
            }
            chunks.finalize()
            assertEquals(data.size, got, "$suite")
        }
    }

    // ---- OpenSSL's default two-datagram ClientHello with address validation (SPEC §11.11) ----
    //
    // quinn's `validate_then_reject_manually`, `use_token_then_retry` and the refused / retried key-lifecycle test
    // count `Incoming`s and assume a one-datagram ClientHello; on the harness they run with an X25519-only client.
    // Here the same scenarios run with OpenSSL's default ClientHello (X25519MLKEM768 + X25519, two Initial datagrams):
    // every Initial datagram that does not belong to a connection is an `Incoming` of its own, and the harness (like
    // quinn's) decides on each one as it arrives, so the application is asked once per datagram. The client acts on
    // the first Retry only (RFC 9000 §17.2.5.2) and on the first CONNECTION_REFUSED.

    private fun twoDatagramHelloClient() = ClientConfig(TestTls.clientCrypto(groups = null))

    private fun ConnPair.beginTwoDatagramConnect(config: ClientConfig = twoDatagramHelloClient()): ConnectionHandle {
        val clientCh = beginConnect(config)
        driveClient()
        assertEquals(2, server.inbound.size, "OpenSSL's default ClientHello spans two Initial datagrams")
        return clientCh
    }

    @Test
    fun validateThenRejectWithATwoDatagramClientHello() {
        val pair = ConnPair.real()
        val seen = ArrayList<Boolean>()
        pair.server.handleIncoming = { incoming ->
            seen.add(incoming.remoteAddressValidated())
            if (incoming.remoteAddressValidated()) IncomingConnectionBehavior.Reject else IncomingConnectionBehavior.Retry
        }
        val clientCh = pair.beginTwoDatagramConnect()
        pair.drive()
        // two Retries for the first ClientHello, the client answers the first; two refusals for the second
        assertEquals(listOf(false, false, true, true), seen)
        pair.server.assertNoAccept()
        val client = pair.clientConn(clientCh)
        assertTrue(client.isClosed)
        val lost = client.poll() as Event.ConnectionLost
        assertEquals(TransportErrorCode.CONNECTION_REFUSED, (lost.reason as ConnectionError.ConnectionClosed).reason.errorCode)
        pair.drive()
        assertNull(pair.clientConn(clientCh).poll())
        assertEquals(0, pair.client.endpoint.knownConnections())
        assertEquals(0, pair.client.endpoint.knownCids())
        assertEquals(0, pair.server.endpoint.knownConnections())
        assertEquals(0, pair.server.endpoint.knownCids())
    }

    @Test
    fun useTokenThenRetryWithATwoDatagramClientHello() {
        val pair = ConnPair.real()
        val config = twoDatagramHelloClient()
        run {
            val (clientCh, _) = pair.connectWith(config.copy())
            pair.clientConn(clientCh).close(pair.time, VarInt(42), Bytes.EMPTY)
            pair.drive()
        }
        val seen = ArrayList<Pair<Boolean, Boolean>>()
        pair.server.handleIncoming = { incoming ->
            seen.add(incoming.remoteAddressValidated() to incoming.mayRetry())
            if (incoming.mayRetry()) IncomingConnectionBehavior.Retry else IncomingConnectionBehavior.Accept
        }
        val clientCh = pair.beginTwoDatagramConnect(config)
        pair.drive()
        val serverCh = pair.server.assertAccept()
        // Both datagrams of the first ClientHello carry the NEW_TOKEN token. The first validates the address and is
        // retried; the token is then spent, so for the second it is a reuse and does not validate (quinn's token log,
        // `use_same_token_twice`), and it is retried too. The first datagram of the ClientHello after the Retry
        // carries the Retry token and is accepted; the second belongs to the new connection.
        assertEquals(listOf(true to true, false to true, true to false), seen)
        pair.assertClientConnectedAfterDrive(clientCh)
        pair.clientConn(clientCh).close(pair.time, VarInt(42), Bytes.EMPTY)
        pair.drive()
        assertIs<Event.ConnectionLost>(pair.serverConn(serverCh).drainEvents().last())
        assertEquals(0, pair.client.endpoint.knownConnections())
        assertEquals(0, pair.server.endpoint.knownConnections())
        assertEquals(0, pair.server.endpoint.knownCids())
    }

    /**
     * `KeyLifecycleTest.refusedAndRetriedAttemptsReleaseTheirInitialKeys` with the two-datagram ClientHello: the
     * application is asked about both datagrams of the validated ClientHello (so `validated` is 2, not quinn's 1), and
     * every Initial key, TLS session and StableRef of the four `Incoming`s and the refused client is released.
     */
    @Test
    fun refusedAndRetriedAttemptsWithATwoDatagramClientHello() {
        settle()
        val sessions = NativeTls.liveSessions
        val refs = NativeTls.liveStableRefs
        val keys = NativeKeys.live
        repeat(10) {
            val pair = ConnPair.real()
            var validated = 0
            pair.server.handleIncoming = { incoming ->
                if (incoming.remoteAddressValidated()) { validated++; IncomingConnectionBehavior.Reject } else IncomingConnectionBehavior.Retry
            }
            val clientCh = pair.beginTwoDatagramConnect()
            pair.drive()
            assertTrue(pair.clientConn(clientCh).isClosed)
            pair.drive()
            assertEquals(2, validated)
            assertEquals(0, pair.client.endpoint.knownConnections())
            assertEquals(0, pair.server.endpoint.knownConnections())
        }
        assertEquals(sessions, NativeTls.liveSessions, "TLS sessions left after refused / retried attempts")
        assertEquals(refs, NativeTls.liveStableRefs)
        assertEquals(keys, NativeKeys.live, "native key contexts left after refused / retried attempts")
    }

    // ---- 0-RTT is declined cleanly (not in this batch, SPEC §11.9 / §11.11) ----

    /**
     * A client that connected before connects again with the same configuration: there is no ticket, so no 0-RTT
     * keys, no early streams, and the second connection is an ordinary full handshake (quinn's `zero_rtt_happypath`
     * up to the point where it needs a ticket).
     */
    @Test
    fun zeroRttIsDeclinedOnReconnect() {
        val pair = ConnPair.real()
        val config = realClient()
        run {
            val (clientCh, _) = pair.connectWith(config.copy())
            pair.clientConn(clientCh).close(pair.time, VarInt(0), Bytes.EMPTY)
            pair.drive()
        }
        pair.client.addr = localhostV6(nextClientPort())
        val clientCh = pair.beginConnect(config)
        assertFalse(pair.clientConn(clientCh).has0rtt())
        assertNull(pair.clientConn(clientCh).cryptoSession().earlyCrypto())
        // Without 0-RTT the server's stream limits are unknown until the handshake: no early stream.
        assertNull(pair.clientStreams(clientCh).open(Dir.Uni))
        pair.drive()
        val serverCh = pair.server.assertAccept()
        pair.assertClientConnectedAfterDrive(clientCh)
        assertFalse(pair.clientConn(clientCh).accepted0rtt())
        assertEquals(false, pair.clientConn(clientCh).cryptoSession().earlyDataAccepted())
        assertNull(pair.serverConn(serverCh).cryptoSession().earlyDataAccepted())

        val s = pair.clientStreams(clientCh).open(Dir.Uni)!!
        val msg = "Hello, 1-RTT!".encodeToByteArray()
        pair.clientSend(clientCh, s).writeOk(msg)
        pair.clientSend(clientCh, s).finish()
        pair.drive()
        val chunks = pair.serverRecv(serverCh, s).read(false)
        assertContentEquals(msg, chunks.nextChunk().bytes.toByteArray())
        chunks.finalize()
        assertEquals(0L, pair.clientConn(clientCh).stats().path.lostPackets)
    }

    /**
     * 0-RTT packets arriving at a real-TLS server (as a client that assumes a ticket would send them) are dropped for
     * want of 0-RTT keys, before and after the server has handshake keys; the handshake completes normally.
     */
    @Test
    fun zeroRttPacketsAtARealServerAreDropped() {
        val pair = ConnPair.real()
        val clientCh = pair.beginTwoDatagramConnect()
        val first = pair.server.inbound.first()
        val hello = first.data
        // Long header: form, fixed bit, type 0-RTT (1), 4-byte packet number; version; DCID; SCID (RFC 9000 §17.2.3)
        val dcidLen = hello[5].toInt() and 0xff
        val scidLen = hello[6 + dcidLen].toInt() and 0xff
        val cids = hello.copyOfRange(5, 7 + dcidLen + scidLen)
        val payload = ByteArray(200) { (it * 31 + 7).toByte() }
        val length = 4 + payload.size
        val forged = byteArrayOf(0xd3.toByte()) + hello.copyOfRange(1, 5) + cids +
            byteArrayOf((0x40 or (length ushr 8)).toByte(), length.toByte()) + byteArrayOf(0, 0, 0, 1) + payload
        pair.server.inbound.add(1, first.copy(data = forged))
        pair.server.inbound.addLast(first.copy(data = forged.copyOf()))
        pair.drive()
        val serverCh = pair.server.assertAccept()
        pair.assertClientConnectedAfterDrive(clientCh)
        assertEquals(Event.HandshakeDataReady, pair.serverConn(serverCh).poll())
        assertEquals(Event.Connected, pair.serverConn(serverCh).poll())
        assertNull(pair.serverConn(serverCh).poll())
        pair.clientConn(clientCh).close(pair.time, VarInt(0), Bytes.EMPTY)
        pair.drive()
        assertIs<Event.ConnectionLost>(pair.serverConn(serverCh).poll())
    }

    // ---- native resources back to baseline (SPEC §11.6 standard, extended to the TLS sessions) ----

    /**
     * Let the cleaners of earlier tests' unreachable sessions and keys run first, so that they do not move the counts
     * while a test measures its own.
     */
    @OptIn(NativeRuntimeApi::class)
    private fun settle() {
        var last = -1L
        var stable = 0
        while (stable < 3) {
            GC.collect()
            kotlin.native.concurrent.Worker.current.park(20_000)
            val now = NativeTls.liveSessions + NativeKeys.live + NativeTls.liveContexts
            if (now == last) stable++ else stable = 0
            last = now
        }
    }

    @Test
    fun manyConnectionsWithKeyUpdatesReleaseSessionsAndKeys() {
        settle()
        val sessions = NativeTls.liveSessions
        val refs = NativeTls.liveStableRefs
        val keys = NativeKeys.live
        repeat(20) { round ->
            val pair = ConnPair.real()
            val (clientCh, serverCh) = pair.connectWith(realClient())
            assertTrue(NativeTls.liveSessions >= sessions + 2, "open connections hold their sessions")
            val s = pair.clientStreams(clientCh).open(Dir.Bi)!!
            repeat(3) { i ->
                pair.clientSend(clientCh, s).writeOk("round $round update $i".encodeToByteArray())
                pair.drive()
                if (i % 2 == 0) pair.clientConn(clientCh).forceKeyUpdate() else pair.serverConn(serverCh).forceKeyUpdate()
                pair.drive()
            }
            pair.clientConn(clientCh).close(pair.time, VarInt(0), bytes("done"))
            pair.drive()
            assertEquals(0, pair.client.endpoint.knownConnections())
            assertEquals(0, pair.server.endpoint.knownConnections())
        }
        assertEquals(sessions, NativeTls.liveSessions, "TLS sessions left after the connections drained")
        assertEquals(refs, NativeTls.liveStableRefs)
        assertEquals(keys, NativeKeys.live, "native key contexts left after the connections drained")
    }

    @Test
    fun failedHandshakesReleaseSessionsAndKeys() {
        settle()
        val sessions = NativeTls.liveSessions
        val refs = NativeTls.liveStableRefs
        val keys = NativeKeys.live
        repeat(10) { round ->
            val pair = when (round % 4) {
                0 -> ConnPair.new(EndpointConfig.default(), realServerConfig("foo")) // client offers another protocol
                1 -> ConnPair.real(TestTls.serverCrypto(clientAuth = ClientAuth.Require(TestTls.ca.trustAnchors))) // no client cert
                2 -> ConnPair.real() // untrusted server (client trusts another root)
                else -> ConnPair.new(EndpointConfig.default(), realServerConfig("foo")) // client offers none
            }
            val client = when (round % 4) {
                0 -> realClient("bar")
                2 -> ClientConfig(TestTls.clientCrypto(trust = TestPki.selfSigned().certificates))
                else -> realClient()
            }
            val clientCh = pair.beginConnect(client)
            pair.drive()
            val events = pair.clientConn(clientCh).drainEvents()
            assertTrue(events.any { it is Event.ConnectionLost }, "round $round: $events")
            // let every connection drain
            repeat(50) { pair.time = pair.time + 1.seconds; pair.drive() }
            assertEquals(0, pair.client.endpoint.knownConnections(), "round $round")
            assertEquals(0, pair.server.endpoint.knownConnections(), "round $round")
        }
        assertEquals(sessions, NativeTls.liveSessions, "TLS sessions left after failed handshakes")
        assertEquals(refs, NativeTls.liveStableRefs)
        assertEquals(keys, NativeKeys.live, "native key contexts left after failed handshakes")
    }

    @OptIn(NativeRuntimeApi::class)
    @Test
    fun theCleanerIsOnlyABackstopForSessions() {
        settle()
        val sessions = NativeTls.liveSessions
        val cfg = TestTls.serverCrypto()
        fun leak() { cfg.startSession(1, TransportParameters.default()) } // never closed
        leak()
        assertEquals(sessions + 1, NativeTls.liveSessions)
        var tries = 0
        while (NativeTls.liveSessions != sessions && tries++ < 200) { GC.collect(); kotlin.native.concurrent.Worker.current.park(10_000) }
        assertEquals(sessions, NativeTls.liveSessions, "the cleaner did not release an unreachable session")
        cfg.close()
    }
}
