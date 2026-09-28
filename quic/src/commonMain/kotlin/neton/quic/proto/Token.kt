package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import neton.io.net.SocketAddress
import kotlin.random.Random
import kotlin.time.Duration
import kotlin.time.Duration.Companion.seconds

// Address validation tokens (quinn-proto `token.rs`). The token *format* and the validation rules are here; sealing
// needs an AEAD, which comes from the crypto layer through [HandshakeTokenKey]. Wall-clock times ("SystemTime") are
// durations since the Unix epoch.

/** A 128-bit value (quinn's `u128` token nonce), little-endian halves. */
data class U128(val lo: Long, val hi: Long) {
    fun toLeBytes(): ByteArray = ByteArray(16).also {
        for (i in 0 until 8) it[i] = (lo ushr (8 * i)).toByte()
        for (i in 0 until 8) it[8 + i] = (hi ushr (8 * i)).toByte()
    }

    companion object {
        fun fromLeBytes(b: ByteArray, at: Int = 0): U128 {
            var lo = 0L; var hi = 0L
            for (i in 7 downTo 0) lo = (lo shl 8) or (b[at + i].toLong() and 0xFF)
            for (i in 7 downTo 0) hi = (hi shl 8) or (b[at + 8 + i].toLong() and 0xFF)
            return U128(lo, hi)
        }

        fun random(rng: Random): U128 = U128(rng.nextLong(), rng.nextLong())
    }
}

/**
 * Limits clients' ability to reuse validation tokens (token.rs:31; RFC 9000 §8.1.4). Pertains only to tokens
 * provided in NEW_TOKEN frames. False negatives and false positives are both permissible.
 */
interface TokenLog {
    /**
     * Record that the token was used; ideally throw [TokenReuseError] if it may have been used before.
     * [issued] is the issue time since the Unix epoch; [lifetime] the validation token lifetime.
     */
    fun checkAndInsert(nonce: U128, issued: Duration, lifetime: Duration)
}

/** A validation token may have been reused (token.rs:67). */
class TokenReuseError : Exception("token may have been reused")

/** Null [TokenLog], which never accepts tokens (token.rs:70). */
object NoneTokenLog : TokenLog {
    override fun checkAndInsert(nonce: U128, issued: Duration, lifetime: Duration) = throw TokenReuseError()
}

/** Stores validation tokens received from servers for use in later connections (token.rs:80). */
interface TokenStore {
    /** Potentially store a token for later one-time use (a NEW_TOKEN frame was received). */
    fun insert(serverName: String, token: Bytes)

    /** Take a token stored for [serverName]; the same token must never be returned twice. */
    fun take(serverName: String): Bytes?
}

/** Null [TokenStore], which stores nothing (token.rs:96). */
object NoneTokenStore : TokenStore {
    override fun insert(serverName: String, token: Bytes) {}
    override fun take(serverName: String): Bytes? = null
}

/** The token is unambiguously from a Retry packet and invalid: the connection cannot be established (token.rs:196). */
class InvalidRetryTokenError : Exception("invalid retry token")

/** State of an incoming connection determined by its token or the lack of one (token.rs:107). */
data class IncomingToken(val retrySrcCid: ConnectionId?, val origDstCid: ConnectionId, val validated: Boolean) {
    companion object {
        /**
         * Validate the token of a client's first Initial [header] (token.rs:116). quinn reads the server config;
         * its relevant fields are the parameters here. Throws [InvalidRetryTokenError] when the connection must
         * be refused.
         */
        fun fromHeader(
            header: InitialHeader,
            tokenKey: HandshakeTokenKey,
            retryTokenLifetime: Duration,
            validationTokenLifetime: Duration,
            validationTokenLog: TokenLog,
            /** Current wall-clock time since the Unix epoch (quinn's `time_source.now()`). */
            now: Duration,
            remoteAddress: SocketAddress,
        ): IncomingToken {
            val unvalidated = IncomingToken(null, header.dstCid, false)
            if (header.token.isEmpty) return unvalidated

            // A token that does not decrypt / decode may come from an incompatible endpoint (another version, a
            // neighbour behind the same load balancer): proceed as if there were none (RFC 9000 §8.1.3).
            val retry = Token.decode(tokenKey, header.token.toByteArray()) ?: return unvalidated

            return when (val p = retry.payload) {
                is TokenPayload.Retry -> {
                    if (p.address != remoteAddress) throw InvalidRetryTokenError()
                    if (p.issued + retryTokenLifetime < now) throw InvalidRetryTokenError()
                    IncomingToken(header.dstCid, p.origDstCid, true)
                }
                is TokenPayload.Validation -> {
                    if (!p.ip.contentEquals(remoteAddress.ipBytes())) return unvalidated
                    if (p.issued + validationTokenLifetime < now) return unvalidated
                    try {
                        validationTokenLog.checkAndInsert(retry.nonce, p.issued, validationTokenLifetime)
                    } catch (e: TokenReuseError) {
                        return unvalidated
                    }
                    IncomingToken(null, header.dstCid, true)
                }
            }
        }
    }
}

/** Retry or validation token (token.rs:199): the payload, encrypted from the client, and a visible random nonce. */
class Token(val payload: TokenPayload, val nonce: U128) {

    /** Encode and encrypt: sealed payload followed by the nonce, little-endian (token.rs:216). */
    fun encode(key: HandshakeTokenKey): ByteArray {
        val buf = Buffer(64)
        when (payload) {
            is TokenPayload.Retry -> {
                buf.writeByte(TOKEN_TYPE_RETRY.toByte())
                encodeAddr(buf, payload.address)
                payload.origDstCid.encodeLong(buf)
                encodeUnixSecs(buf, payload.issued)
            }
            is TokenPayload.Validation -> {
                buf.writeByte(TOKEN_TYPE_VALIDATION.toByte())
                encodeIp(buf, payload.ip)
                encodeUnixSecs(buf, payload.issued)
            }
        }
        val nonceBytes = nonce.toLeBytes()
        val sealed = key.aeadFromHkdf(nonceBytes).use { it.seal(buf.readAll(), ByteArray(0)) }
        return sealed + nonceBytes
    }

    companion object {
        /** Construct with newly sampled randomness (token.rs:208). */
        fun new(payload: TokenPayload, rng: Random): Token = Token(payload, U128.random(rng))

        /** Decrypt and decode; `null` if the token is not valid (token.rs:247). */
        fun decode(key: HandshakeTokenKey, raw: ByteArray): Token? {
            if (raw.size < 16) return null
            val nonceStart = raw.size - 16
            val nonceBytes = raw.copyOfRange(nonceStart, raw.size)
            val nonce = U128.fromLeBytes(nonceBytes)
            val data = try {
                key.aeadFromHkdf(nonceBytes).use { it.open(raw.copyOfRange(0, nonceStart), ByteArray(0)) }
            } catch (e: CryptoError) {
                return null
            }
            val r = Reader(data)
            val payload = try {
                when (r.getU8()) {
                    TOKEN_TYPE_RETRY -> TokenPayload.Retry(
                        decodeAddr(r) ?: return null,
                        ConnectionId.decodeLong(r) ?: return null,
                        decodeUnixSecs(r),
                    )
                    TOKEN_TYPE_VALIDATION -> TokenPayload.Validation(decodeIp(r) ?: return null, decodeUnixSecs(r))
                    else -> return null
                }
            } catch (e: UnexpectedEnd) {
                return null
            }
            // Extra bytes are a decoding error (the token may be from an incompatible endpoint).
            if (r.hasRemaining()) return null
            return Token(payload, nonce)
        }

        private const val TOKEN_TYPE_RETRY = 0
        private const val TOKEN_TYPE_VALIDATION = 1

        private fun encodeAddr(buf: Buffer, address: SocketAddress) {
            encodeIp(buf, address.ipBytes())
            buf.writeShort(address.port)
        }

        private fun decodeAddr(r: Reader): SocketAddress? {
            val ip = decodeIp(r) ?: return null
            val port = r.getU16()
            return SocketAddress.of(ip, port)
        }

        private fun encodeIp(buf: Buffer, ip: ByteArray) {
            buf.writeByte((if (ip.size == 4) 0 else 1).toByte())
            buf.writeBytes(ip)
        }

        private fun decodeIp(r: Reader): ByteArray? = when (r.getU8()) {
            0 -> r.getBytes(4)
            1 -> r.getBytes(16)
            else -> null
        }

        private fun encodeUnixSecs(buf: Buffer, time: Duration) = buf.writeLong(if (time.isNegative()) 0 else time.inWholeSeconds)

        private fun decodeUnixSecs(r: Reader): Duration = r.getU64().seconds
    }
}

/** Content of a [Token] that is encrypted from the client (token.rs:284). */
sealed class TokenPayload {
    /** Token from a Retry packet: the client's address, the first DCID it used, and the issue time. */
    data class Retry(val address: SocketAddress, val origDstCid: ConnectionId, val issued: Duration) : TokenPayload()

    /** Token from a NEW_TOKEN frame: the client's IP (4 or 16 bytes; its port is likely to change) and the issue time. */
    class Validation(val ip: ByteArray, val issued: Duration) : TokenPayload() {
        override fun equals(other: Any?): Boolean = other is Validation && other.ip.contentEquals(ip) && other.issued == issued
        override fun hashCode(): Int = ip.contentHashCode() * 31 + issued.hashCode()
    }
}
