package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import neton.openssl.AeadAlgorithm
import neton.openssl.DigestAlgorithm
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue
import neton.openssl.AeadKey as OpenSslAeadKey

/**
 * Packet protection, key schedule, Retry integrity and token / reset keys against published vectors: RFC 9001
 * Appendix A (all five sections), draft-ietf-quic-tls-29 Appendix A (the draft salt and Retry key), rustls's
 * `key_update_test_vector`, RFC 4231 (HMAC-SHA256) and RFC 5869 (HKDF-SHA256 with an empty salt).
 */
class CryptoTest {

    private val v1 = 0x00000001
    private val draft29 = 0xff00_001d.toInt()
    private val rfcDcid = ConnectionId.of(hex("8394c8f03e515708"))
    private val rfcScid = ConnectionId.of(hex("f067a5502a4262b5"))

    // ---- RFC 9001 A.1 / draft-29 A.1: Initial secrets and keys ----

    private fun checkInitialKeys(
        version: TlsQuicVersion, clientSecret: String, serverSecret: String,
        clientKey: String, clientIv: String, clientHp: String,
        serverKey: String, serverIv: String, serverHp: String,
    ) {
        val secrets = initialSecrets(version, rfcDcid, Side.Client)
        assertContentEquals(hex(clientSecret), secrets.client)
        assertContentEquals(hex(serverSecret), secrets.server)
        val h = DigestAlgorithm.SHA256
        assertContentEquals(hex(clientKey), expandLabel(h, secrets.client, "quic key", 16))
        assertContentEquals(hex(clientIv), expandLabel(h, secrets.client, "quic iv", 12))
        assertContentEquals(hex(clientHp), expandLabel(h, secrets.client, "quic hp", 16))
        assertContentEquals(hex(serverKey), expandLabel(h, secrets.server, "quic key", 16))
        assertContentEquals(hex(serverIv), expandLabel(h, secrets.server, "quic iv", 12))
        assertContentEquals(hex(serverHp), expandLabel(h, secrets.server, "quic hp", 16))
    }

    @Test
    fun rfc9001InitialKeys() = checkInitialKeys(
        TlsQuicVersion.V1,
        clientSecret = "c00cf151ca5be075ed0ebfb5c80323c42d6b7db67881289af4008f1f6c357aea",
        serverSecret = "3c199828fd139efd216c155ad844cc81fb82fa8d7446fa7d78be803acdda951b",
        clientKey = "1f369613dd76d5467730efcbe3b1a22d", clientIv = "fa044b2f42a3fd3b46fb255c",
        clientHp = "9f50449e04a0e810283a1e9933adedd2",
        serverKey = "cf3a5331653c364c88f0f379b6067e37", serverIv = "0ac1493ca1905853b0bba03e",
        serverHp = "c206b8d9b9f0f37644430b490eeaa314",
    )

    @Test
    fun draft29InitialKeys() = checkInitialKeys(
        TlsQuicVersion.V1Draft,
        clientSecret = "0088119288f1d866733ceeed15ff9d50902cf82952eee27e9d4d4918ea371d87",
        serverSecret = "006f881359244dd9ad1acf85f595bad67c13f9f5586f5e64e1acae1d9ea8f616",
        clientKey = "175257a31eb09dea9366d8bb79ad80ba", clientIv = "6b26114b9cba2b63a9e8dd4f",
        clientHp = "9ddd12c994c0698b89374a9c077a3077",
        serverKey = "149d0b1662ab871fbe63c49b5e655a5d", serverIv = "bab2b12a4c76016ace47856d",
        serverHp = "c0c499a65a60024a18a250974ea01dfa",
    )

    @Test
    fun versionMapping() {
        // quinn `interpret_version`: drafts 29-32 use the draft salt, drafts 33-34 and v1 the RFC 9001 one.
        val expected = listOf(
            TlsQuicVersion.V1, TlsQuicVersion.V1Draft, TlsQuicVersion.V1Draft, TlsQuicVersion.V1Draft,
            TlsQuicVersion.V1Draft, TlsQuicVersion.V1, TlsQuicVersion.V1,
        )
        assertEquals(expected, DEFAULT_SUPPORTED_VERSIONS.map { TlsQuicVersion.of(it) })
        for (v in intArrayOf(0, 2, 0xff00_001c.toInt(), 0xff00_0023.toInt(), 0x6b3343cf, 0x1a2a3a4a)) {
            assertEquals(v, assertFailsWith<UnsupportedVersion> { initialKeys(v, rfcDcid, Side.Client) }.version)
            assertFailsWith<UnsupportedVersion> { retryTag(v, rfcDcid, ByteArray(8)) }
        }
    }

    @Test
    fun initialKeysInteroperateForEverySupportedVersion() {
        for (version in DEFAULT_SUPPORTED_VERSIONS) {
            val client = initialKeys(version, rfcDcid, Side.Client)
            val server = initialKeys(version, rfcDcid, Side.Server)
            roundTrip(client.packet.local, server.packet.remote, 7)
            roundTrip(server.packet.local, client.packet.remote, 9)
            assertFailsWith<CryptoError> { roundTrip(client.packet.local, client.packet.remote, 7) }
        }
    }

    // ---- RFC 9001 A.2: client Initial ----

    @Test
    fun rfc9001ClientInitial() {
        val client = initialKeys(v1, rfcDcid, Side.Client)
        val header = InitialHeader(rfcDcid, ConnectionId.EMPTY, Bytes.EMPTY, PacketNumber.U32(2), v1)
        val buf = Buffer(1300)
        val encode = header.encode(buf)
        val payload = CLIENT_INITIAL_CRYPTO.copyOf(1162) // the CRYPTO frame, then PADDING
        buf.writeBytes(payload)
        buf.writeBytes(ByteArray(client.packet.local.tagLen))
        encode.finish(buf, client.header.local, client.packet.local, 2)
        val bytes = buf.bytes()
        assertContentEquals(CLIENT_INITIAL_PROTECTED, bytes)

        // The server's view.
        val server = initialKeys(v1, rfcDcid, Side.Server)
        val packet = unprotect(bytes, 8, server.header.remote, server.packet.remote)
        assertContentEquals(hex("c300000001088394c8f03e5157080000449e00000002"), packet.headerData())
        assertEquals(PacketNumber.U32(2), assertIs<InitialHeader>(packet.header).number)
        assertContentEquals(payload, packet.payload())
    }

    // ---- RFC 9001 A.3: server Initial ----

    @Test
    fun rfc9001ServerInitial() {
        val server = initialKeys(v1, rfcDcid, Side.Server)
        val header = InitialHeader(ConnectionId.EMPTY, rfcScid, Bytes.EMPTY, PacketNumber.U16(1), v1)
        val buf = Buffer(256)
        val encode = header.encode(buf)
        buf.writeBytes(SERVER_INITIAL_PAYLOAD)
        buf.writeBytes(ByteArray(server.packet.local.tagLen))
        encode.finish(buf, server.header.local, server.packet.local, 1)
        val bytes = buf.bytes()
        assertContentEquals(SERVER_INITIAL_PROTECTED, bytes)

        // The client's view.
        val client = initialKeys(v1, rfcDcid, Side.Client)
        val packet = unprotect(bytes, 0, client.header.remote, client.packet.remote)
        assertContentEquals(hex("c1000000010008f067a5502a4262b50040750001"), packet.headerData())
        assertContentEquals(SERVER_INITIAL_PAYLOAD, packet.payload())
    }

    // ---- RFC 9001 A.4 / draft-29 A.4: Retry ----

    private fun checkRetry(version: Int, retry: ByteArray) {
        val tagStart = retry.size - 16
        assertContentEquals(retry.copyOfRange(tagStart, retry.size), retryTag(version, rfcDcid, retry, 0, tagStart))

        val packet = PartialDecode.decode(retry, FixedLengthConnectionIdParser(0), DEFAULT_SUPPORTED_VERSIONS, false).finish(null)
        assertIs<Header.Retry>(packet.header)
        val header = packet.headerData()
        val payload = packet.payload()
        assertContentEquals(hex("746f6b656e"), payload.copyOf(payload.size - 16)) // "token"
        assertTrue(isValidRetry(version, rfcDcid, header, payload))
        assertTrue(isValidRetry(version, rfcDcid, packet.data, packet.headerStart, packet.headerLen, packet.data, packet.payloadStart, packet.payloadLen))
        // The original destination CID is authenticated...
        assertFalse(isValidRetry(version, rfcScid, header, payload))
        // ... and so are the header, the token and the tag.
        for (i in retry.indices) {
            val bad = retry.copyOf()
            bad[i] = (bad[i].toInt() xor 0x01).toByte()
            val hl = header.size
            assertFalse(isValidRetry(version, rfcDcid, bad.copyOf(hl), bad.copyOfRange(hl, bad.size)), "flipped byte $i")
        }
        // Too short to hold a tag.
        assertFalse(isValidRetry(version, rfcDcid, header, payload.copyOf(15)))
    }

    @Test
    fun rfc9001Retry() = checkRetry(v1, hex("ff000000010008f067a5502a4262b5746f6b656e04a265ba2eff4d829058fb3f0f2496ba"))

    @Test
    fun draft29Retry() = checkRetry(draft29, hex("ffff00001d0008f067a5502a4262b5746f6b656ed16926d81f6f9ca2953a8aa4575e1e49"))

    @Test
    fun retryVersionsUseTheirOwnKey() {
        val retry = hex("ff000000010008f067a5502a4262b5746f6b656e")
        val tag = retryTag(v1, rfcDcid, retry)
        for (version in DEFAULT_SUPPORTED_VERSIONS) {
            val same = TlsQuicVersion.of(version) == TlsQuicVersion.V1
            assertEquals(same, tag.contentEquals(retryTag(version, rfcDcid, retry)))
        }
    }

    // ---- RFC 9001 A.5: ChaCha20-Poly1305 short header ----

    @Test
    fun rfc9001ChaCha20ShortHeader() {
        val secret = hex("9ac312a7f877468ebe69422748ad00a15443f18203a07d6060f688f30f21632b")
        val suite = CipherSuite.TLS13_CHACHA20_POLY1305_SHA256
        val h = suite.hash
        assertContentEquals(hex("c6d98ff3441c3fe1b2182094f69caa2ed4b716b65488960a7a984979fb23e1c8"), expandLabel(h, secret, "quic key", 32))
        assertContentEquals(hex("e0459b3474bdd0e44a41c144"), expandLabel(h, secret, "quic iv", 12))
        assertContentEquals(hex("25a282b9e82f06f21f488917a4fc8f1b73573685608597d0efcb076b0ab7a7a4"), expandLabel(h, secret, "quic hp", 32))
        val ku = hex("1223504755036d556342ee9361d253421a826c9ecdf3c7148684b36b714881f9")
        val secrets = Secrets(secret, secret, suite, Side.Server, TlsQuicVersion.V1)
        secrets.update()
        assertContentEquals(ku, secrets.server)

        val pn = 654360564L
        val packetKey = packetKey(suite, secret)
        val headerKey = headerKey(suite, secret)
        val buf = Buffer(64)
        val encode = Header.Short(false, false, ConnectionId.EMPTY, PacketNumber.U24(0x00bff4)).encode(buf)
        buf.writeByte(0x01) // PING
        buf.writeBytes(ByteArray(16))
        encode.finish(buf, headerKey, packetKey, pn)
        val bytes = buf.bytes()
        assertContentEquals(hex("4cfe4189655e5cd55c41f69080575d7999c25a5bfb"), bytes)

        val packet = PartialDecode.decode(bytes, FixedLengthConnectionIdParser(0), DEFAULT_SUPPORTED_VERSIONS, false).finish(headerKey)
        assertContentEquals(hex("4200bff4"), packet.headerData())
        val number = packet.header.number!!.expand(pn - 1)
        assertEquals(pn, number)
        packet.payloadLen = packetKey.decrypt(
            number, packet.data, packet.headerStart, packet.headerStart + packet.headerLen,
            packet.data, packet.payloadStart, packet.payloadStart + packet.payloadLen,
        )
        assertContentEquals(hex("01"), packet.payload())
    }

    // ---- key updates ----

    /** rustls `crypto/ring/quic.rs` `key_update_test_vector`. */
    @Test
    fun keyUpdateTestVector() {
        val secrets = Secrets(
            hex("b8767708f8772358a6ea9fc43e4add2c961b3f5287a6d1467ee0aeab33724dbf"),
            hex("42dc972140e0f2e39845b767613439dc6758ca43259b878506824eb1e438d855"),
            CipherSuite.TLS13_AES_128_GCM_SHA256, Side.Client, TlsQuicVersion.V1,
        )
        secrets.update()
        assertContentEquals(hex("42cac8c91cd5eb40682e432edf2d2be9f41a52ca6b22d8e6cdb1e8aca9061fce"), secrets.client)
        assertContentEquals(hex("eb7f5e2a123f407db499e361cae590d4d992e14b7ace03c244e0422115b6d38a"), secrets.server)
    }

    @Test
    fun keyUpdateGenerations() {
        for (suite in CipherSuite.entries) {
            val n = suite.hash.outputSize
            val c = ByteArray(n) { it.toByte() }
            val s = ByteArray(n) { (0x80 + it).toByte() }
            val client = Secrets(c, s, suite, Side.Client, TlsQuicVersion.V1)
            val server = Secrets(c, s, suite, Side.Server, TlsQuicVersion.V1)

            // Generation 0, as the TLS layer hands out 1-RTT keys, leaving the secrets one generation ahead.
            val c0 = client.oneRttKeys()
            val s0 = server.oneRttKeys()
            roundTrip(c0.packet.local, s0.packet.remote, 1)
            roundTrip(s0.packet.local, c0.packet.remote, 2)
            assertEquals(16, c0.header.local.sampleSize)

            // Generations 1 and 2 (quinn `next_1rtt_keys`); a key only opens packets of its own generation.
            val c1 = client.nextPacketKeys()
            val s1 = server.nextPacketKeys()
            roundTrip(c1.local, s1.remote, 3)
            roundTrip(s1.local, c1.remote, 4)
            assertFailsWith<CryptoError> { roundTrip(c1.local, s0.packet.remote, 5) }
            assertFailsWith<CryptoError> { roundTrip(c0.packet.local, s1.remote, 6) }
            val c2 = client.nextPacketKeys()
            val s2 = server.nextPacketKeys()
            roundTrip(c2.local, s2.remote, 7)
            assertFailsWith<CryptoError> { roundTrip(c2.local, s1.remote, 8) }

            // The generation after the one handed out is the "quic ku" expansion of the current secret.
            val expected = expandLabel(suite.hash, expandLabel(suite.hash, expandLabel(suite.hash, c, "quic ku", n), "quic ku", n), "quic ku", n)
            assertContentEquals(expected, client.client)
        }
    }

    @Test
    fun suiteParameters() {
        val limits = CipherSuite.entries.associateWith { suite ->
            val key = packetKey(suite, ByteArray(suite.hash.outputSize))
            assertEquals(16, key.tagLen)
            key.confidentialityLimit to key.integrityLimit
        }
        assertEquals((1L shl 23) to (1L shl 52), limits[CipherSuite.TLS13_AES_128_GCM_SHA256])
        assertEquals((1L shl 23) to (1L shl 52), limits[CipherSuite.TLS13_AES_256_GCM_SHA384])
        assertEquals(Long.MAX_VALUE to (1L shl 36), limits[CipherSuite.TLS13_CHACHA20_POLY1305_SHA256])
        assertEquals(CipherSuite.TLS13_AES_128_GCM_SHA256, INITIAL_SUITE)
        assertFailsWith<IllegalArgumentException> {
            Secrets(ByteArray(32), ByteArray(32), CipherSuite.TLS13_AES_256_GCM_SHA384, Side.Client, TlsQuicVersion.V1)
        }
    }

    @Test
    fun decryptFailures() {
        val keys = initialKeys(v1, rfcDcid, Side.Client)
        val server = initialKeys(v1, rfcDcid, Side.Server)
        val packet = ByteArray(10 + 20 + 16) { it.toByte() }
        keys.packet.local.encrypt(3, packet, 0, packet.size, 10)
        // Wrong packet number, tampered header, tampered payload, tampered tag.
        assertFailsWith<CryptoError> { server.packet.remote.decrypt(4, packet, 0, 10, packet.copyOf(), 10, packet.size) }
        for (i in packet.indices) {
            val bad = packet.copyOf()
            bad[i] = (bad[i].toInt() xor 0x80).toByte()
            assertFailsWith<CryptoError> { server.packet.remote.decrypt(3, bad, 0, 10, bad, 10, bad.size) }
        }
        // Shorter than a tag.
        assertFailsWith<CryptoError> { server.packet.remote.decrypt(3, packet, 0, 10, packet, 10, 25) }
        // Intact: the plaintext comes back in place.
        assertEquals(20, server.packet.remote.decrypt(3, packet, 0, 10, packet, 10, packet.size))
        assertContentEquals(ByteArray(20) { (10 + it).toByte() }, packet.copyOfRange(10, 30))
    }

    @Test
    fun packetNumberIsInTheNonce() {
        // Nonce = IV XOR the 62-bit packet number: large packet numbers use the full 8 bytes.
        val client = initialKeys(v1, rfcDcid, Side.Client)
        val server = initialKeys(v1, rfcDcid, Side.Server)
        for (pn in longArrayOf(0, 1, 0xff, 0x100, 0xffff_ffffL, 0x1_0000_0000L, (1L shl 62) - 1)) {
            roundTrip(client.packet.local, server.packet.remote, pn)
            assertFailsWith<CryptoError> {
                val p = ByteArray(40)
                client.packet.local.encrypt(pn, p, 0, p.size, 4)
                server.packet.remote.decrypt(pn xor 1, p, 0, 4, p, 4, p.size)
            }
        }
    }

    // ---- reset token and address validation token keys ----

    @Test
    fun hmacSha256() {
        // RFC 4231 test case 2.
        val key = HmacSha256Key("Jefe".encodeToByteArray())
        val data = "what do ya want for nothing?".encodeToByteArray()
        val expected = hex("5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843")
        val out = ByteArray(34)
        key.sign(data, 0, data.size, out, 2)
        assertContentEquals(expected, out.copyOfRange(2, 34))
        key.verify(data, 0, data.size, expected, 0, 32)
        val wrapped = ByteArray(3) + data + ByteArray(2)
        key.verify(wrapped, 3, data.size, out, 2, 32)
        assertFailsWith<CryptoError> { key.verify(data, 0, data.size - 1, expected, 0, 32) }
        assertFailsWith<CryptoError> { key.verify(data, 0, data.size, expected, 0, 16) }
        val bad = expected.copyOf().also { it[31] = (it[31].toInt() xor 1).toByte() }
        assertFailsWith<CryptoError> { key.verify(data, 0, data.size, bad, 0, 32) }
    }

    @Test
    fun resetTokenDerivation() {
        // quinn `ResetToken::new`: the first 16 bytes of HMAC-SHA256(reset key, CID).
        val key = HmacSha256Key(ByteArray(64) { it.toByte() })
        val cid = ConnectionId.of(hex("0102030405060708"))
        val sig = ByteArray(32)
        key.sign(hex("0102030405060708"), 0, 8, sig, 0)
        assertEquals(ResetToken(sig.copyOf(16)), ResetToken.derive(key, cid))
        assertEquals(ResetToken.derive(key, cid), ResetToken.derive(key, cid))
        assertFalse(ResetToken.derive(key, cid) == ResetToken.derive(key, ConnectionId.of(hex("0102030405060709"))))
        assertFalse(ResetToken.derive(key, cid) == ResetToken.derive(HmacSha256Key.random(), cid))
    }

    @Test
    fun hkdfTokenKey() {
        // RFC 5869 test case 3 (empty salt, as quinn's `Salt::new(HKDF_SHA256, &[])`).
        val key = HkdfSha256TokenKey.fromMasterKey(ByteArray(22) { 0x0b })
        val okm = hex("8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d")
        // PRK 19ef24a3...: expanding with empty info gives the first 32 bytes of the RFC's OKM, which is the
        // AES-256-GCM key; sealing under it with a zero nonce must match a key built from those bytes.
        val aead = key.aeadFromHkdf(ByteArray(0))
        val plain = "address validation".encodeToByteArray()
        val ad = byteArrayOf(1, 2, 3)
        val sealed = aead.seal(plain, ad)
        val reference = plain.copyOf(plain.size + 16)
        OpenSslAeadKey(AeadAlgorithm.AES_256_GCM, okm).use { it.seal(reference, 0, plain.size, ByteArray(12), ad) }
        assertContentEquals(reference, sealed)
        assertContentEquals(plain, aead.open(sealed, ad))
        assertFailsWith<CryptoError> { aead.open(sealed, byteArrayOf(1, 2)) }
        assertFailsWith<CryptoError> { aead.open(sealed.copyOf(15), ad) }
        // Different random bytes, different key.
        assertFailsWith<CryptoError> { key.aeadFromHkdf(ByteArray(16)).open(sealed, ad) }
        assertFailsWith<CryptoError> { HkdfSha256TokenKey.random().aeadFromHkdf(ByteArray(0)).open(sealed, ad) }
    }

    // ---- helpers ----

    /** Encrypt a packet with [local] and decrypt it with [remote]. */
    private fun roundTrip(local: PacketKey, remote: PacketKey, pn: Long) {
        val headerLen = 9
        val packet = ByteArray(headerLen + 30 + local.tagLen) { (it * 3).toByte() }
        val plain = packet.copyOfRange(headerLen, headerLen + 30)
        local.encrypt(pn, packet, 0, packet.size, headerLen)
        assertFalse(plain.contentEquals(packet.copyOfRange(headerLen, headerLen + 30)))
        assertEquals(30, remote.decrypt(pn, packet, 0, headerLen, packet, headerLen, packet.size))
        assertContentEquals(plain, packet.copyOfRange(headerLen, headerLen + 30))
    }

    private fun unprotect(bytes: ByteArray, localCidLen: Int, headerKey: HeaderKey, packetKey: PacketKey): Packet {
        val decode = PartialDecode.decode(bytes.copyOf(), FixedLengthConnectionIdParser(localCidLen), DEFAULT_SUPPORTED_VERSIONS, false)
        assertFalse(decode.hasRest)
        val packet = decode.finish(headerKey)
        val number = packet.header.number!!.expand(0)
        packet.payloadLen = packetKey.decrypt(
            number, packet.data, packet.headerStart, packet.headerStart + packet.headerLen,
            packet.data, packet.payloadStart, packet.payloadStart + packet.payloadLen,
        )
        return packet
    }
}

// RFC 9001 Appendix A.2 / A.3.
private val CLIENT_INITIAL_CRYPTO = hex(
    "060040f1010000ed0303ebf8fa56f12939b9584a3896472ec40bb863cfd3e868" +
    "04fe3a47f06a2b69484c00000413011302010000c000000010000e00000b6578" +
    "616d706c652e636f6dff01000100000a00080006001d00170018001000070005" +
    "04616c706e000500050100000000003300260024001d00209370b2c9caa47fba" +
    "baf4559fedba753de171fa71f50f1ce15d43e994ec74d748002b000302030400" +
    "0d0010000e0403050306030203080408050806002d00020101001c0002400100" +
    "3900320408ffffffffffffffff05048000ffff07048000ffff08011001048000" +
    "75300901100f088394c8f03e51570806048000ffff",
)
private val CLIENT_INITIAL_PROTECTED = hex(
    "c000000001088394c8f03e5157080000449e7b9aec34d1b1c98dd7689fb8ec11" +
    "d242b123dc9bd8bab936b47d92ec356c0bab7df5976d27cd449f63300099f399" +
    "1c260ec4c60d17b31f8429157bb35a1282a643a8d2262cad67500cadb8e7378c" +
    "8eb7539ec4d4905fed1bee1fc8aafba17c750e2c7ace01e6005f80fcb7df6212" +
    "30c83711b39343fa028cea7f7fb5ff89eac2308249a02252155e2347b63d58c5" +
    "457afd84d05dfffdb20392844ae812154682e9cf012f9021a6f0be17ddd0c208" +
    "4dce25ff9b06cde535d0f920a2db1bf362c23e596d11a4f5a6cf3948838a3aec" +
    "4e15daf8500a6ef69ec4e3feb6b1d98e610ac8b7ec3faf6ad760b7bad1db4ba3" +
    "485e8a94dc250ae3fdb41ed15fb6a8e5eba0fc3dd60bc8e30c5c4287e53805db" +
    "059ae0648db2f64264ed5e39be2e20d82df566da8dd5998ccabdae053060ae6c" +
    "7b4378e846d29f37ed7b4ea9ec5d82e7961b7f25a9323851f681d582363aa5f8" +
    "9937f5a67258bf63ad6f1a0b1d96dbd4faddfcefc5266ba6611722395c906556" +
    "be52afe3f565636ad1b17d508b73d8743eeb524be22b3dcbc2c7468d54119c74" +
    "68449a13d8e3b95811a198f3491de3e7fe942b330407abf82a4ed7c1b311663a" +
    "c69890f4157015853d91e923037c227a33cdd5ec281ca3f79c44546b9d90ca00" +
    "f064c99e3dd97911d39fe9c5d0b23a229a234cb36186c4819e8b9c5927726632" +
    "291d6a418211cc2962e20fe47feb3edf330f2c603a9d48c0fcb5699dbfe58964" +
    "25c5bac4aee82e57a85aaf4e2513e4f05796b07ba2ee47d80506f8d2c25e50fd" +
    "14de71e6c418559302f939b0e1abd576f279c4b2e0feb85c1f28ff18f58891ff" +
    "ef132eef2fa09346aee33c28eb130ff28f5b766953334113211996d20011a198" +
    "e3fc433f9f2541010ae17c1bf202580f6047472fb36857fe843b19f5984009dd" +
    "c324044e847a4f4a0ab34f719595de37252d6235365e9b84392b061085349d73" +
    "203a4a13e96f5432ec0fd4a1ee65accdd5e3904df54c1da510b0ff20dcc0c77f" +
    "cb2c0e0eb605cb0504db87632cf3d8b4dae6e705769d1de354270123cb11450e" +
    "fc60ac47683d7b8d0f811365565fd98c4c8eb936bcab8d069fc33bd801b03ade" +
    "a2e1fbc5aa463d08ca19896d2bf59a071b851e6c239052172f296bfb5e724047" +
    "90a2181014f3b94a4e97d117b438130368cc39dbb2d198065ae3986547926cd2" +
    "162f40a29f0c3c8745c0f50fba3852e566d44575c29d39a03f0cda721984b6f4" +
    "40591f355e12d439ff150aab7613499dbd49adabc8676eef023b15b65bfc5ca0" +
    "6948109f23f350db82123535eb8a7433bdabcb909271a6ecbcb58b936a88cd4e" +
    "8f2e6ff5800175f113253d8fa9ca8885c2f552e657dc603f252e1a8e308f76f0" +
    "be79e2fb8f5d5fbbe2e30ecadd220723c8c0aea8078cdfcb3868263ff8f09400" +
    "54da48781893a7e49ad5aff4af300cd804a6b6279ab3ff3afb64491c85194aab" +
    "760d58a606654f9f4400e8b38591356fbf6425aca26dc85244259ff2b19c41b9" +
    "f96f3ca9ec1dde434da7d2d392b905ddf3d1f9af93d1af5950bd493f5aa731b4" +
    "056df31bd267b6b90a079831aaf579be0a39013137aac6d404f518cfd4684064" +
    "7e78bfe706ca4cf5e9c5453e9f7cfd2b8b4c8d169a44e55c88d4a9a7f9474241" +
    "e221af44860018ab0856972e194cd934",
)
private val SERVER_INITIAL_PAYLOAD = hex(
    "02000000000600405a020000560303eefce7f7b37ba1d1632e96677825ddf739" +
    "88cfc79825df566dc5430b9a045a1200130100002e00330024001d00209d3c94" +
    "0d89690b84d08a60993c144eca684d1081287c834d5311bcf32bb9da1a002b00" +
    "020304",
)
private val SERVER_INITIAL_PROTECTED = hex(
    "cf000000010008f067a5502a4262b5004075c0d95a482cd0991cd25b0aac406a" +
    "5816b6394100f37a1c69797554780bb38cc5a99f5ede4cf73c3ec2493a1839b3" +
    "dbcba3f6ea46c5b7684df3548e7ddeb9c3bf9c73cc3f3bded74b562bfb19fb84" +
    "022f8ef4cdd93795d77d06edbb7aaf2f58891850abbdca3d20398c276456cbc4" +
    "2158407dd074ee",
)
