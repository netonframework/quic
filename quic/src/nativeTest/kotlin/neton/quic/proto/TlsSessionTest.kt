@file:OptIn(ExperimentalForeignApi::class)

package neton.quic.proto

import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.ULongVar
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.toKString
import kotlinx.cinterop.get
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.value
import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import neton.openssl.c.ERR_peek_error
import neton.openssl.c.ERR_new
import neton.openssl.c.ERR_set_error
import neton.quic.testkit.TestCa
import neton.quic.testkit.TestPki
import kotlin.test.AfterTest
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotNull
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Two real TLS sessions talking to each other in memory, without QUIC: the connection's side of the `CryptoSession`
 * contract (CRYPTO bytes per packet space, keys at the right moments) is played by [Side].
 */
class TlsSessionTest {
    private val sessionsBefore = NativeTls.liveSessions
    private val refsBefore = NativeTls.liveStableRefs
    private val keysBefore = NativeKeys.live
    private val opened = ArrayList<AutoCloseable>()

    private fun <T : AutoCloseable> own(t: T): T = t.also { opened += it }

    @AfterTest
    fun releaseAll() {
        opened.asReversed().forEach { it.close() }
        opened.clear()
    }

    /** One endpoint of the in-memory exchange: which packet space it is in and what it received per space. */
    private inner class End(val session: TlsSession, val name: String) {
        var space = 0 // 0 Initial, 1 Handshake, 2 1-RTT
        val keys = ArrayList<Keys>()
        val events = ArrayList<String>()
        var handshakeDataReady = 0

        /** The connection's `writeCrypto` loop; returns the bytes to send per space. */
        fun write(): List<Pair<Int, ByteArray>> {
            val out = ArrayList<Pair<Int, ByteArray>>()
            while (true) {
                val buf = Buffer(256)
                val at = space
                val k = session.writeHandshake(buf)
                if (buf.readableBytes > 0) {
                    out += at to buf.readAll()
                    events += "send@$at"
                }
                if (k != null) {
                    keys += own(KeysCloser(k)).keys
                    space++
                    events += "keys@$space"
                    continue
                }
                if (buf.readableBytes == 0) break
            }
            return out
        }

        fun read(bytes: ByteArray) {
            if (session.readHandshake(Bytes.wrap(bytes))) handshakeDataReady++
        }
    }

    private class KeysCloser(val keys: Keys) : AutoCloseable {
        override fun close() = keys.close()
    }

    private fun params(side: Side): TransportParameters {
        val p = TransportParameters.default()
        p.initialSrcCid = ConnectionId.of(ByteArray(8) { (it + if (side == Side.Client) 1 else 100).toByte() })
        if (side == Side.Server) p.originalDstCid = ConnectionId.of(ByteArray(8) { 7 })
        return p
    }

    private fun start(
        client: TlsClientConfig,
        server: TlsServerConfig,
        serverName: String = "localhost",
    ): Pair<End, End> {
        val c = own(client.startSession(1, serverName, params(Side.Client)) as TlsSession)
        val s = own(server.startSession(1, params(Side.Server)) as TlsSession)
        return End(c, "client") to End(s, "server")
    }

    /**
     * Exchange flights until neither side has anything to send; each space's bytes are delivered as a separate
     * `readHandshake` (as the connection does, packet space by packet space). Throws the first TransportError.
     */
    private fun exchange(c: End, s: End) {
        var pending = c.write().map { Triple(s, it.first, it.second) }
        var rounds = 0
        while (pending.isNotEmpty()) {
            check(rounds++ < 20) { "handshake does not converge" }
            val next = ArrayList<Triple<End, Int, ByteArray>>()
            for ((to, _, bytes) in pending) {
                to.read(bytes)
                val from = if (to === s) c else s
                val peer = if (to === s) c else s
                next += to.write().map { Triple(peer, it.first, it.second) }
                check(from === peer)
            }
            pending = next
        }
    }

    private fun handshake(client: TlsClientConfig = own(TestTls.clientCrypto()), server: TlsServerConfig = own(TestTls.serverCrypto())): Pair<End, End> {
        val (c, s) = start(client, server)
        exchange(c, s)
        return c to s
    }

    /** A packet protected with [local] opens with [remote]. */
    private fun assertAgree(local: PacketKey, remote: PacketKey) {
        val header = byteArrayOf(0x40, 1, 2, 3)
        val body = "hello".encodeToByteArray()
        val packet = header + body + ByteArray(local.tagLen)
        local.encrypt(42, packet, 0, packet.size, header.size)
        val n = remote.decrypt(42, packet, 0, header.size, packet, header.size, packet.size)
        assertContentEquals(body, packet.copyOfRange(header.size, header.size + n))
    }

    private fun assertCryptoError(alert: Int, block: () -> Unit): TransportError {
        val e = assertFailsWith<TransportError> { block() }
        assertEquals(TransportErrorCode.crypto(alert), e.code, "expected alert $alert, got ${e.code}: ${e.reason}")
        return e
    }

    @Test
    fun fullHandshakeLevelsAndKeysInOrder() {
        val (c, s) = handshake()
        assertFalse(c.session.isHandshaking)
        assertFalse(s.session.isHandshaking)
        // client: ClientHello at Initial; Handshake keys after the ServerHello; its Finished at Handshake; then 1-RTT
        assertEquals(listOf("send@0", "keys@1", "send@1", "keys@2"), c.events)
        // server: ServerHello at Initial, Handshake keys, its flight at Handshake; 1-RTT keys after the client's
        // Finished (OpenSSL yields the server's 1-RTT read secret then); then its session tickets at 1-RTT (rustls
        // sends NewSessionTicket at 1-RTT too)
        assertEquals(listOf("send@0", "keys@1", "send@1", "keys@2", "send@2"), s.events)
        assertEquals(1, c.handshakeDataReady)
        assertEquals(1, s.handshakeDataReady)
        // Handshake and 1-RTT keys agree in both directions, packet and header protection
        for (level in 0..1) {
            assertAgree(c.keys[level].packet.local, s.keys[level].packet.remote)
            assertAgree(s.keys[level].packet.local, c.keys[level].packet.remote)
            val sample = ByteArray(40) { it.toByte() }
            val copy = sample.copyOf()
            c.keys[level].header.local.encrypt(1, sample, 0, sample.size)
            s.keys[level].header.remote.decrypt(1, sample, 0, sample.size)
            assertContentEquals(copy, sample)
        }
        assertNull(c.session.earlyCrypto())
        assertEquals(false, c.session.earlyDataAccepted())
        assertNull(s.session.earlyDataAccepted())
    }

    @Test
    fun transportParametersAreExchangedAsRawBytes() {
        val (c, s) = handshake()
        val atServer = assertNotNull(s.session.transportParameters())
        val atClient = assertNotNull(c.session.transportParameters())
        assertEquals(params(Side.Client).initialSrcCid, atServer.initialSrcCid)
        assertEquals(params(Side.Server).initialSrcCid, atClient.initialSrcCid)
        assertEquals(params(Side.Server).originalDstCid, atClient.originalDstCid)
    }

    @Test
    fun serverKnowsClientParametersAfterClientHello() {
        val (c, s) = start(own(TestTls.clientCrypto()), own(TestTls.serverCrypto()))
        assertNull(s.session.transportParameters())
        val hello = c.write().single()
        s.read(hello.second)
        assertNotNull(s.session.transportParameters())
        assertNull(c.session.transportParameters())
    }

    @Test
    fun next1rttKeysAgreeAcrossUpdates() {
        val (c, s) = handshake()
        repeat(3) {
            val ck = assertNotNull(c.session.next1rttKeys())
            val sk = assertNotNull(s.session.next1rttKeys())
            assertAgree(ck.local, sk.remote)
            assertAgree(sk.local, ck.remote)
            ck.close(); sk.close()
        }
    }

    @Test
    fun exporterMatchesOnBothSides() {
        val (c, s) = handshake()
        val a = ByteArray(64)
        val b = ByteArray(64)
        c.session.exportKeyingMaterial(a, "EXPORTER-test".encodeToByteArray(), "ctx".encodeToByteArray())
        s.session.exportKeyingMaterial(b, "EXPORTER-test".encodeToByteArray(), "ctx".encodeToByteArray())
        assertContentEquals(a, b)
        assertFalse(a.all { it == 0.toByte() })
        val other = ByteArray(64)
        s.session.exportKeyingMaterial(other, "EXPORTER-test".encodeToByteArray(), "other".encodeToByteArray())
        assertFalse(a.contentEquals(other))
        // Too long an output (HKDF-Expand is limited to 255 hash lengths)
        assertFailsWith<ExportKeyingMaterialError> { c.session.exportKeyingMaterial(ByteArray(255 * 48 + 1), "x".encodeToByteArray(), ByteArray(0)) }
    }

    @Test
    fun exporterFailsBeforeTheHandshakeAndAfterClose() {
        val (c, s) = start(own(TestTls.clientCrypto()), own(TestTls.serverCrypto()))
        assertFailsWith<ExportKeyingMaterialError> { c.session.exportKeyingMaterial(ByteArray(16), "x".encodeToByteArray(), ByteArray(0)) }
        exchange(c, s)
        c.session.close()
        assertFailsWith<ExportKeyingMaterialError> { c.session.exportKeyingMaterial(ByteArray(16), "x".encodeToByteArray(), ByteArray(0)) }
    }

    @Test
    fun eachCipherSuite() {
        for (suite in CipherSuite.entries) {
            val (c, s) = handshake(own(TestTls.clientCrypto(cipherSuites = listOf(suite))), own(TestTls.serverCrypto()))
            assertAgree(c.keys[1].packet.local, s.keys[1].packet.remote)
            assertEquals(suite.confidentialityLimit, c.keys[1].packet.local.confidentialityLimit)
            val nc = c.session.next1rttKeys()!!
            val ns = s.session.next1rttKeys()!!
            assertAgree(nc.local, ns.remote)
            nc.close(); ns.close()
        }
    }

    /** A [KeyLog] that keeps what it is given. */
    private class Recorder : KeyLog {
        val lines = ArrayList<Triple<String, ByteArray, ByteArray>>()
        override fun log(label: String, clientRandom: ByteArray, secret: ByteArray) {
            lines += Triple(label, clientRandom, secret)
        }
    }

    @Test
    fun keyLogGetsTheSameSecretsOnBothSides() {
        val cl = Recorder()
        val sl = Recorder()
        val client = own(TlsClientConfig(TestTls.ca.trustAnchors, keyLog = cl))
        val server = own(TlsServerConfig(TestTls.server.certificates, TestTls.server.privateKey, keyLog = sl))
        handshake(client, server)
        val labels = setOf(
            "CLIENT_HANDSHAKE_TRAFFIC_SECRET", "SERVER_HANDSHAKE_TRAFFIC_SECRET",
            "CLIENT_TRAFFIC_SECRET_0", "SERVER_TRAFFIC_SECRET_0", "EXPORTER_SECRET",
        )
        assertEquals(labels, cl.lines.map { it.first }.toSet())
        assertEquals(labels, sl.lines.map { it.first }.toSet())
        // One session: one client random, 32 bytes, the same on both sides; and the same secrets
        val random = cl.lines.first().second
        assertEquals(32, random.size)
        for ((label, r, secret) in cl.lines) {
            assertContentEquals(random, r)
            val other = assertNotNull(sl.lines.firstOrNull { it.first == label })
            assertContentEquals(random, other.second)
            assertContentEquals(secret, other.third, label)
        }
    }

    @Test
    fun noKeyLogByDefaultAndAThrowingLogDoesNotFailTheHandshake() {
        val throwing = object : KeyLog {
            var calls = 0
            override fun log(label: String, clientRandom: ByteArray, secret: ByteArray) {
                calls++
                error("log failed")
            }
        }
        val (c, s) = handshake(own(TlsClientConfig(TestTls.ca.trustAnchors, keyLog = throwing)), own(TestTls.serverCrypto()))
        assertFalse(c.session.isHandshaking)
        assertFalse(s.session.isHandshaking)
        assertEquals(5, throwing.calls)
    }

    @Test
    fun keyLogFileWritesNssLines() {
        val dir = platform.posix.getenv("TMPDIR")?.toKString()
            ?: platform.posix.getenv("TEMP")?.toKString() ?: "/tmp"
        val path = "$dir/neton-quic-keylog-${kotlin.random.Random.nextLong().toULong()}.txt"
        assertFalse(KeyLogFile(null).isOpen)
        val file = KeyLogFile(path)
        assertTrue(file.isOpen)
        val cl = Recorder()
        val both = object : KeyLog {
            override fun log(label: String, clientRandom: ByteArray, secret: ByteArray) {
                cl.log(label, clientRandom, secret)
                file.log(label, clientRandom, secret)
            }
        }
        handshake(own(TlsClientConfig(TestTls.ca.trustAnchors, keyLog = both)), own(TestTls.serverCrypto()))
        val text = readText(path)
        platform.posix.remove(path)
        val hex = { b: ByteArray -> b.joinToString("") { (it.toInt() and 0xff).toString(16).padStart(2, '0') } }
        val expected = cl.lines.joinToString("") { "${it.first} ${hex(it.second)} ${hex(it.third)}\n" }
        assertEquals(expected, text)
        // And the parsing of OpenSSL's lines drops malformed ones
        val r = Recorder()
        logKeyLine(r, "CLIENT_RANDOM 0a0B zz")
        logKeyLine(r, "ONLY_TWO 0a")
        logKeyLine(r, "LABEL 0a0B ff")
        assertEquals(1, r.lines.size)
        assertContentEquals(byteArrayOf(0x0a, 0x0b), r.lines[0].second)
    }

    private fun readText(path: String): String {
        val f = assertNotNull(platform.posix.fopen(path, "rb"))
        val out = StringBuilder()
        memScoped {
            val buf = allocArray<kotlinx.cinterop.ByteVar>(4096)
            while (true) {
                val n = platform.posix.fread(buf, 1u, 4096u, f).toInt()
                if (n <= 0) break
                out.append(buf.readBytes(n).decodeToString())
            }
        }
        platform.posix.fclose(f)
        return out.toString()
    }

    @Test
    fun alpnServerPreferenceAndHandshakeData() {
        val (c, s) = handshake(
            own(TestTls.clientCrypto(alpn = listOf("bar", "quux", "foo").map { it.encodeToByteArray() })),
            own(TestTls.serverCrypto(alpn = listOf("foo", "bar", "baz").map { it.encodeToByteArray() })),
        )
        val ch = c.session.handshakeData() as TlsHandshakeData
        val sh = s.session.handshakeData() as TlsHandshakeData
        assertEquals("foo", ch.protocol!!.decodeToString())
        assertEquals("foo", sh.protocol!!.decodeToString())
        assertNull(ch.serverName)
        assertEquals("localhost", sh.serverName)
    }

    @Test
    fun alpnMismatchIsNoApplicationProtocol() {
        val (c, s) = start(
            own(TestTls.clientCrypto(alpn = listOf("quux".encodeToByteArray()))),
            own(TestTls.serverCrypto(alpn = listOf("foo".encodeToByteArray()))),
        )
        assertCryptoError(120) { exchange(c, s) }
    }

    @Test
    fun alpnOnlyOnOneSideIsNoApplicationProtocol() {
        // Server has ALPN, client offers none; then the reverse
        val (c1, s1) = start(own(TestTls.clientCrypto()), own(TestTls.serverCrypto(alpn = listOf("foo".encodeToByteArray()))))
        assertCryptoError(120) { exchange(c1, s1) }
        val (c2, s2) = start(own(TestTls.clientCrypto(alpn = listOf("foo".encodeToByteArray()))), own(TestTls.serverCrypto()))
        assertCryptoError(120) { exchange(c2, s2) }
    }

    @Test
    fun noAlpnOnEitherSide() {
        val (c, _) = handshake()
        assertNull((c.session.handshakeData() as TlsHandshakeData).protocol)
    }

    @Test
    fun hostnameMismatchFailsVerification() {
        val (c, s) = start(own(TestTls.clientCrypto()), own(TestTls.serverCrypto()), serverName = "example.com")
        assertCryptoError(42) { exchange(c, s) } // bad_certificate
    }

    @Test
    fun ipAddressServerNamesUseIpSans() {
        handshake().first.session.close()
        val (c, s) = start(own(TestTls.clientCrypto()), own(TestTls.serverCrypto()), serverName = "127.0.0.1")
        exchange(c, s)
        assertFalse(c.session.isHandshaking)
        assertNull((s.session.handshakeData() as TlsHandshakeData).serverName) // no SNI for an IP address
        val (c2, s2) = start(own(TestTls.clientCrypto()), own(TestTls.serverCrypto()), serverName = "10.0.0.1")
        assertCryptoError(42) { exchange(c2, s2) }
    }

    @Test
    fun invalidServerNameIsAConnectError() {
        val cfg = own(TestTls.clientCrypto())
        assertFailsWith<ConnectError.InvalidServerName> { cfg.startSession(1, "bad name", params(Side.Client)) }
        assertFailsWith<ConnectError.InvalidServerName> { cfg.startSession(1, "", params(Side.Client)) }
        assertFailsWith<ConnectError.UnsupportedVersion> { cfg.startSession(0x0a1a2a3a, "localhost", params(Side.Client)) }
        assertEquals(sessionsBefore, NativeTls.liveSessions)
    }

    @Test
    fun untrustedCaIsUnknownCa() {
        val other = TestCa.create("another CA")
        val (c, s) = start(own(TestTls.clientCrypto(trust = other.trustAnchors)), own(TestTls.serverCrypto()))
        assertCryptoError(48) { exchange(c, s) }
        assertNull(c.session.handshakeData())
    }

    @Test
    fun selfSignedServerNotTrustedIsUnknownCa() {
        val (c, s) = start(
            own(TestTls.clientCrypto(trust = TestPki.selfSigned(commonName = "Crazy Quinn's House of Certificates").certificates)),
            own(TestTls.serverCrypto()),
        )
        assertCryptoError(48) { exchange(c, s) }
    }

    @Test
    fun trustedSelfSignedServer() {
        val id = TestPki.selfSigned()
        val (c, _) = handshake(own(TestTls.clientCrypto(trust = id.certificates)), own(TestTls.serverCrypto(identity = id)))
        val certs = c.session.peerIdentity() as List<*>
        assertContentEquals(id.certDer, certs.single() as ByteArray)
    }

    @Test
    fun expiredServerCertificate() {
        val expired = TestTls.ca.issue("localhost", listOf("localhost"), validFromDays = -30, validUntilDays = -1)
        val (c, s) = start(own(TestTls.clientCrypto()), own(TestTls.serverCrypto(identity = expired)))
        assertCryptoError(45) { exchange(c, s) } // certificate_expired
    }

    @Test
    fun peerIdentityIsTheServerChain() {
        val (c, s) = handshake()
        val chain = c.session.peerIdentity() as List<*>
        assertContentEquals(TestTls.server.certDer, chain.first() as ByteArray)
        assertNull(s.session.peerIdentity())
        // still available after the native session is released
        c.session.close()
        assertContentEquals(TestTls.server.certDer, (c.session.peerIdentity() as List<*>).first() as ByteArray)
        assertNotNull(c.session.handshakeData())
        assertNotNull(c.session.transportParameters())
    }

    @Test
    fun clientAuthRequiredAndPresented() {
        val (c, s) = handshake(
            own(TestTls.clientCrypto(identity = TestTls.client)),
            own(TestTls.serverCrypto(clientAuth = ClientAuth.Require(TestTls.ca.trustAnchors))),
        )
        assertFalse(s.session.isHandshaking)
        assertContentEquals(TestTls.client.certDer, (s.session.peerIdentity() as List<*>).first() as ByteArray)
        assertNotNull(c.session.peerIdentity())
    }

    @Test
    fun clientAuthRequiredButMissingIsCertificateRequired() {
        val (c, s) = start(own(TestTls.clientCrypto()), own(TestTls.serverCrypto(clientAuth = ClientAuth.Require(TestTls.ca.trustAnchors))))
        assertCryptoError(116) { exchange(c, s) }
        // the client finished its side of the handshake before the server rejected it (as with rustls)
        assertFalse(c.session.isHandshaking)
    }

    @Test
    fun clientAuthRequestedIsOptional() {
        val (_, s) = handshake(own(TestTls.clientCrypto()), own(TestTls.serverCrypto(clientAuth = ClientAuth.Request(TestTls.ca.trustAnchors))))
        assertFalse(s.session.isHandshaking)
        assertNull(s.session.peerIdentity())
    }

    @Test
    fun clientCertificateFromAnotherCaIsRejected() {
        val stranger = TestCa.create("stranger CA").issue("stranger")
        val (c, s) = start(
            own(TestTls.clientCrypto(identity = stranger)),
            own(TestTls.serverCrypto(clientAuth = ClientAuth.Require(TestTls.ca.trustAnchors))),
        )
        assertCryptoError(48) { exchange(c, s) }
    }

    @Test
    fun clientWithoutTrustAnchorsNeedsTheLoudTestOnlyMode() {
        val other = TestCa.create("unknown CA").issue("localhost", listOf("localhost"))
        val insecure = own(TlsClientConfig.dangerousNoServerVerificationForTestsOnly())
        val (c, _) = handshake(insecure, own(TestTls.serverCrypto(identity = other)))
        assertFalse(c.session.isHandshaking)
    }

    @Test
    fun afterAFailureTheSessionKeepsFailing() {
        val (c, s) = start(own(TestTls.clientCrypto(alpn = listOf("x".encodeToByteArray()))), own(TestTls.serverCrypto(alpn = listOf("y".encodeToByteArray()))))
        val hello = c.write().single().second
        val first = assertCryptoError(120) { s.read(hello) }
        val again = assertFailsWith<TransportError> { s.read(ByteArray(10)) }
        assertEquals(first.code, again.code)
    }

    @Test
    fun dataAfterAKeyChangeIsUnexpectedMessage() {
        val (c, s) = start(own(TestTls.clientCrypto()), own(TestTls.serverCrypto()))
        s.read(c.write().single().second)
        val flight = s.write()
        // ServerHello (Initial) and the server's Handshake flight delivered as one chunk
        val joined = flight[0].second + flight[1].second
        assertCryptoError(10) { c.read(joined) }
    }

    @Test
    fun tooMuchUntakenCryptoDataIsCryptoBufferExceeded() {
        val (_, s) = start(own(TestTls.clientCrypto()), own(TestTls.serverCrypto()))
        val e = assertFailsWith<TransportError> { s.read(ByteArray(MAX_INCOMING + 1)) }
        assertEquals(TransportErrorCode.CRYPTO_BUFFER_EXCEEDED, e.code)
    }

    @Test
    fun garbageIsATlsAlert() {
        val (_, s) = start(own(TestTls.clientCrypto()), own(TestTls.serverCrypto()))
        val e = assertFailsWith<TransportError> { s.read(ByteArray(100) { 0x16 }) }
        assertTrue(e.code.value in 0x100L..0x1ffL, "a TLS alert, got ${e.code}")
    }

    @Test
    fun largeClientHelloAndLargeCertificate() {
        val many = (0 until 1000).map { byteArrayOf(0, (it shr 8).toByte(), it.toByte(), 42) }
        val (c, s) = handshake(
            own(TestTls.clientCrypto(alpn = many + listOf(byteArrayOf(0, 0, 0, 42)), trust = TestTls.bigSelfSigned.certificates)),
            own(TestTls.serverCrypto(alpn = listOf(byteArrayOf(0, 0, 0, 42)), identity = TestTls.bigSelfSigned)),
        )
        assertContentEquals(byteArrayOf(0, 0, 0, 42), (c.session.handshakeData() as TlsHandshakeData).protocol)
        assertFalse(s.session.isHandshaking)
    }

    // ---- the record lifetime contract, on the callback core directly ----

    @Test
    fun recordStaysPinnedUntilReleasedAndQueuesAreBounded() = memScoped {
        val core = TlsCore(Side.Server, null)
        core.queueIncoming(ByteArray(MAX_RECORD + 10) { it.toByte() })
        val buf = alloc<CPointerVar<kotlinx.cinterop.UByteVar>>()
        val len = alloc<ULongVar>()
        core.recvRecord(buf.ptr, len.ptr)
        assertEquals(MAX_RECORD.toULong(), len.value)
        val rec = buf.value!!
        // more data arriving does not touch the outstanding record
        core.queueIncoming(ByteArray(100) { 0x55 })
        for (i in 0 until MAX_RECORD) assertEquals(i.toByte(), rec[i].toByte())
        // only one record at a time
        assertFailsWith<IllegalStateException> { core.recvRecord(buf.ptr, len.ptr) }
        // partial release keeps it
        core.releaseRecord(1000)
        assertEquals(rec, core.record)
        assertEquals(3.toByte(), rec[3].toByte())
        core.releaseRecord(MAX_RECORD - 1000)
        assertNull(core.record)
        core.recvRecord(buf.ptr, len.ptr)
        assertEquals(110uL, len.value)
        assertFailsWith<IllegalStateException> { core.releaseRecord(111) }
        core.releaseRecord(110)
        core.recvRecord(buf.ptr, len.ptr)
        assertEquals(0uL, len.value)
        assertFailsWith<TransportError> { core.queueIncoming(ByteArray(MAX_INCOMING + 1)) }
        core.wipe()
    }

    // ---- the C boundary ----

    @Test
    fun aFailingCallbackNeitherCrashesNorLeaks() {
        for (cb in TlsCallback.entries) {
            val serverAlpn = if (cb == TlsCallback.CLIENT_HELLO || cb == TlsCallback.ALPN_SELECT) listOf("h3".encodeToByteArray()) else emptyList()
            val clientCfg = own(TestTls.clientCrypto(alpn = serverAlpn))
            val serverCfg = own(TestTls.serverCrypto(alpn = serverAlpn))
            val c = own(clientCfg.startSession(1, "localhost", params(Side.Client)) as TlsSession)
            val s = own(serverCfg.startSession(1, params(Side.Server)) as TlsSession)
            val cEnd = End(c, "client")
            val sEnd = End(s, "server")
            // The alert callback only runs on a failure: make the server fail with an ALPN mismatch for it
            // A ticket the client cannot keep is dropped; the connection goes on
            if (cb == TlsCallback.NEW_SESSION) {
                c.injectCallbackFailure(cb)
                exchange(cEnd, sEnd)
                assertFalse(c.isHandshaking)
                assertEquals(1, c.core.droppedTickets, "the ticket whose callback failed was dropped")
                continue
            }
            if (cb == TlsCallback.ALERT) {
                s.injectCallbackFailure(cb)
                val bad = own(own(TestTls.clientCrypto(alpn = listOf("zz".encodeToByteArray()))).startSession(1, "localhost", params(Side.Client)) as TlsSession)
                val e = assertFailsWith<TransportError> { sEnd.read(End(bad, "bad").write().single().second) }
                assertEquals(TransportErrorCode.INTERNAL_ERROR, e.code, "$cb: ${e.reason}")
                assertTrue("injected" in e.reason, e.reason)
                continue
            }
            s.injectCallbackFailure(cb)
            val e = assertFailsWith<TransportError>("$cb") { exchange(cEnd, sEnd) }
            // the server's own callback failed: reported as an internal error with the Kotlin failure's message
            if (e.code == TransportErrorCode.INTERNAL_ERROR) {
                assertTrue("injected" in e.reason, "$cb: ${e.reason}")
            } else {
                // the client saw the server's internal_error alert (80) first, for callbacks the server hits late
                fail("$cb: unexpected ${e.code} ${e.reason}")
            }
        }
        releaseAll()
        assertEquals(sessionsBefore, NativeTls.liveSessions)
        assertEquals(refsBefore, NativeTls.liveStableRefs)
    }

    // ---- error queue isolation ----

    @Test
    fun staleOpenSslErrorsDoNotLeakIntoAHandshake() {
        // Leave junk on this thread's error queue, as another library (or a failed call elsewhere) might
        repeat(2) {
            ERR_new()
            ERR_set_error(20, 65, null)
        }
        val (c, s) = handshake()
        assertFalse(c.session.isHandshaking)
        assertFalse(s.session.isHandshaking)
        // and a failed handshake leaves nothing behind for the next caller
        val (c2, s2) = start(own(TestTls.clientCrypto(trust = TestCa.create("x").trustAnchors)), own(TestTls.serverCrypto()))
        assertFailsWith<TransportError> { exchange(c2, s2) }
        assertEquals(0uL, ERR_peek_error().toULong())
    }

    // ---- ownership and release ----

    @Test
    fun closeReleasesExactlyOnceAndIsIdempotent() {
        val (c, s) = handshake()
        assertEquals(sessionsBefore + 2, NativeTls.liveSessions)
        c.session.close()
        c.session.close()
        assertEquals(sessionsBefore + 1, NativeTls.liveSessions)
        assertTrue(c.session.isClosed)
        assertNull(c.session.next1rttKeys())
        assertNull(c.session.writeHandshake(Buffer(16)))
        assertFailsWith<TransportError> { c.session.readHandshake(Bytes.wrap(ByteArray(1))) }
        s.session.close()
        assertEquals(sessionsBefore, NativeTls.liveSessions)
        assertEquals(refsBefore, NativeTls.liveStableRefs)
    }

    @Test
    fun manyHandshakesSucceedingAndFailingReturnToBaseline() {
        val contextsBefore = NativeTls.liveContexts
        repeat(30) { i ->
            val client = TestTls.clientCrypto(alpn = listOf("a".encodeToByteArray()))
            val server = TestTls.serverCrypto(alpn = listOf(if (i % 3 == 1) "b" else "a").map { it.encodeToByteArray() })
            val c = client.startSession(1, if (i % 3 == 2) "wrong.example" else "localhost", params(Side.Client)) as TlsSession
            val s = server.startSession(1, params(Side.Server)) as TlsSession
            val cEnd = End(c, "c")
            val sEnd = End(s, "s")
            // configurations may be closed while their sessions run: each SSL holds its own SSL_CTX reference
            client.close()
            server.close()
            val result = runCatching { exchange(cEnd, sEnd) }
            assertEquals(i % 3 == 0, result.isSuccess, "round $i: $result")
            c.close()
            s.close()
            (cEnd.keys + sEnd.keys).forEach { it.close() }
        }
        opened.clear()
        assertEquals(sessionsBefore, NativeTls.liveSessions)
        assertEquals(refsBefore, NativeTls.liveStableRefs)
        assertEquals(contextsBefore, NativeTls.liveContexts)
        assertEquals(keysBefore, NativeKeys.live)
    }

    @Test
    fun aClosedConfigurationStartsNoSession() {
        val cfg = TestTls.serverCrypto()
        cfg.close()
        cfg.close()
        assertFailsWith<IllegalStateException> { cfg.startSession(1, params(Side.Server)) }
    }
}
