package neton.quic.proto

import neton.io.bytes.Bytes
import neton.io.core.secureRandom
import neton.io.net.SocketAddress
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

/**
 * A NON-cryptographic stand-in for the HKDF + AES-GCM token key (test code only, SPEC §4): a keyed FxHash
 * keystream and a 16-byte keyed tag. It makes seal/open round-trip and reject garbage, which is all the token
 * format tests below need; the real key comes from the crypto layer.
 */
private class FakeTokenKey(private val master: ByteArray) : HandshakeTokenKey {
    override fun aeadFromHkdf(randomBytes: ByteArray): AeadKey {
        val k = FxHasher().apply { write(master, 0, master.size); write(randomBytes, 0, randomBytes.size) }.finish()
        return object : AeadKey {
            fun stream(i: Int): Byte = FxHasher().apply { writeU64(k); writeU64(i.toLong()) }.finish().toByte()
            fun tag(ct: ByteArray, n: Int): ByteArray = ByteArray(16) { j ->
                FxHasher().apply { writeU64(k xor j.toLong()); write(ct, 0, n) }.finish().toByte()
            }

            override fun seal(data: ByteArray, additionalData: ByteArray): ByteArray {
                val ct = ByteArray(data.size) { (data[it].toInt() xor stream(it).toInt()).toByte() }
                return ct + tag(ct, ct.size)
            }

            override fun open(data: ByteArray, additionalData: ByteArray): ByteArray {
                if (data.size < 16) throw CryptoError()
                val n = data.size - 16
                if (!constantTimeEquals(tag(data, n), data.copyOfRange(n, data.size))) throw CryptoError()
                return ByteArray(n) { (data[it].toInt() xor stream(it).toInt()).toByte() }
            }
        }
    }
}

class TokenTest {

    private fun masterKey() = ByteArray(64).also { secureRandom(it) }

    private fun tokenRoundTrip(payload: TokenPayload): TokenPayload {
        val token = Token.new(payload, Random.Default)
        val key = FakeTokenKey(masterKey())
        val encoded = token.encode(key)
        val decoded = Token.decode(key, encoded) ?: throw AssertionError("token didn't decrypt / decode")
        assertEquals(token.nonce, decoded.nonce)
        return decoded.payload
    }

    // ---- token.rs tests (with the stand-in key; see FakeTokenKey) ----

    @Test
    fun retryTokenSanity() {
        val address1 = SocketAddress.of(ByteArray(16).also { it[15] = 1 }, 4433)
        val origDstCid1 = RandomConnectionIdGenerator(MAX_CID_SIZE).generateCid()
        val issued1 = 42.seconds // fractional seconds would be lost
        val p = assertIs<TokenPayload.Retry>(tokenRoundTrip(TokenPayload.Retry(address1, origDstCid1, issued1)))
        assertEquals(address1, p.address)
        assertEquals(origDstCid1, p.origDstCid)
        assertEquals(issued1, p.issued)
    }

    @Test
    fun validationTokenSanity() {
        val ip1 = ByteArray(16).also { it[15] = 1 }
        val issued1 = 42.seconds
        val p = assertIs<TokenPayload.Validation>(tokenRoundTrip(TokenPayload.Validation(ip1, issued1)))
        assertEquals(ip1.toList(), p.ip.toList())
        assertEquals(issued1, p.issued)
    }

    @Test
    fun invalidTokenReturnsErr() {
        val key = FakeTokenKey(masterKey())
        val invalidToken = ByteArray(32).also { secureRandom(it) }
        // Garbage sealed data returns an error.
        assertNull(Token.decode(key, invalidToken))
    }

    // ---- IncomingToken::from_header ----

    private val remote = SocketAddress.ipv4(192, 0, 2, 1, 5000)
    private val dcid = ConnectionId.of(hex("0102030405060708"))
    private val key = FakeTokenKey(ByteArray(64) { it.toByte() })

    private fun header(token: ByteArray) =
        InitialHeader(dcid, ConnectionId.of(byteArrayOf(9)), Bytes.wrap(token), PacketNumber.U8(0), 1)

    private fun incoming(token: ByteArray, now: Duration, log: TokenLog = NoneTokenLog) =
        IncomingToken.fromHeader(header(token), key, 15.seconds, 1000.seconds, log, now, remote)

    @Test
    fun incomingTokenValidation() {
        // No token: unvalidated.
        assertEquals(IncomingToken(null, dcid, false), incoming(ByteArray(0), 100.seconds))
        // Undecodable token: treated as none.
        assertEquals(IncomingToken(null, dcid, false), incoming(ByteArray(40), 100.seconds))

        val orig = ConnectionId.of(hex("aabbccdd"))
        val retry = Token.new(TokenPayload.Retry(remote, orig, 100.seconds), Random(1)).encode(key)
        assertEquals(IncomingToken(dcid, orig, true), incoming(retry, 110.seconds))
        assertFailsWith<InvalidRetryTokenError> { incoming(retry, 116.seconds) } // expired
        val otherAddr = Token.new(TokenPayload.Retry(SocketAddress.ipv4(192, 0, 2, 1, 5001), orig, 100.seconds), Random(1)).encode(key)
        assertFailsWith<InvalidRetryTokenError> { incoming(otherAddr, 101.seconds) }

        val validation = Token.new(TokenPayload.Validation(remote.ipBytes(), 100.seconds), Random(2)).encode(key)
        // NoneTokenLog never accepts a token.
        assertEquals(IncomingToken(null, dcid, false), incoming(validation, 200.seconds))
        val acceptAll = object : TokenLog {
            override fun checkAndInsert(nonce: U128, issued: Duration, lifetime: Duration) {}
        }
        assertEquals(IncomingToken(null, dcid, true), incoming(validation, 200.seconds, acceptAll))
        assertEquals(IncomingToken(null, dcid, false), incoming(validation, 2000.seconds, acceptAll)) // expired
    }

    @Test
    fun nullStores() {
        NoneTokenStore.insert("example.com", Bytes.wrap(byteArrayOf(1)))
        assertNull(NoneTokenStore.take("example.com"))
        assertFailsWith<TokenReuseError> { NoneTokenLog.checkAndInsert(U128(1, 2), 0.seconds, 1.seconds) }
        assertEquals(U128(0x0102030405060708L, -1L), U128.fromLeBytes(U128(0x0102030405060708L, -1L).toLeBytes()))
    }
}
