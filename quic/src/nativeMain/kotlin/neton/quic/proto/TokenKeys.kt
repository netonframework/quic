@file:OptIn(ExperimentalNativeApi::class)

package neton.quic.proto

import neton.io.core.secureRandom
import neton.openssl.AeadAlgorithm
import neton.openssl.Crypto
import neton.openssl.DigestAlgorithm
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner
import neton.openssl.AeadKey as OpenSslAeadKey

// Keys for stateless reset tokens and address validation tokens on OpenSSL primitives (quinn-proto
// `crypto/ring_like.rs`: *ring*'s `hmac::Key`, `hkdf::Prk` and `aead::LessSafeKey`).

/**
 * HMAC-SHA256 key (quinn's `HmacKey` impl for *ring* `hmac::Key`), used to derive stateless reset tokens
 * ([ResetToken.derive]).
 */
class HmacSha256Key(key: ByteArray) : HmacKey {
    private val key = key.copyOf()

    override val signatureLen: Int get() = 32

    override fun sign(data: ByteArray, offset: Int, length: Int, signatureOut: ByteArray, outOffset: Int) {
        Crypto.hmac(DigestAlgorithm.SHA256, key, region(data, offset, length), signatureOut, outOffset)
    }

    override fun verify(data: ByteArray, offset: Int, length: Int, signature: ByteArray, sigOffset: Int, sigLength: Int) {
        val expected = ByteArray(signatureLen)
        sign(data, offset, length, expected, 0)
        if (!Crypto.constantTimeEquals(expected, region(signature, sigOffset, sigLength))) throw CryptoError()
    }

    companion object {
        /** A key from 64 random bytes, as quinn's `EndpointConfig::default` makes its `reset_key` (config/mod.rs:186). */
        fun random(): HmacSha256Key {
            val bytes = ByteArray(64)
            secureRandom(bytes)
            return HmacSha256Key(bytes).also { Crypto.wipe(bytes) }
        }
    }
}

/**
 * An HKDF-SHA256 pseudorandom key (quinn's `HandshakeTokenKey` impl for *ring* `hkdf::Prk`) that derives a
 * per-token AES-256-GCM key from the token's random nonce.
 */
class HkdfSha256TokenKey private constructor(private val prk: ByteArray) : HandshakeTokenKey {

    /** `prk.expand(&[random_bytes], HKDF_SHA256)` into a 32-byte AES-256-GCM key (ring_like.rs:22). */
    override fun aeadFromHkdf(randomBytes: ByteArray): AeadKey {
        val key = ByteArray(32)
        Crypto.hkdfExpand(DigestAlgorithm.SHA256, prk, randomBytes, key)
        try {
            return Aes256GcmZeroNonceKey(key)
        } finally {
            Crypto.wipe(key)
        }
    }

    companion object {
        /** `hkdf::Salt::new(HKDF_SHA256, &[]).extract(master_key)`, as quinn's `ServerConfig::new` does. */
        fun fromMasterKey(masterKey: ByteArray): HkdfSha256TokenKey {
            val prk = ByteArray(32)
            Crypto.hkdfExtract(DigestAlgorithm.SHA256, ByteArray(0), masterKey, prk)
            return HkdfSha256TokenKey(prk)
        }

        /** A key from a 64-byte random master key (quinn `ServerConfig::new`, config/mod.rs:404). */
        fun random(): HkdfSha256TokenKey {
            val master = ByteArray(64)
            secureRandom(master)
            return fromMasterKey(master).also { Crypto.wipe(master) }
        }
    }
}

/**
 * AES-256-GCM with an all-zero nonce (quinn's `AeadKey` impl for *ring* `aead::LessSafeKey`, ring_like.rs:36). Safe
 * only because every key is derived for a single token from that token's random nonce.
 */
internal class Aes256GcmZeroNonceKey(key: ByteArray) : AeadKey {
    private val aead = OpenSslAeadKey(AeadAlgorithm.AES_256_GCM, key)
    private val resource = NativeKeyResource(aead)

    // Only a backstop: token keys are single-use and closed by their caller.
    @Suppress("unused")
    private val cleaner = createCleaner(resource) { it.release() }

    override fun close() = resource.release()

    override fun seal(data: ByteArray, additionalData: ByteArray): ByteArray {
        val out = data.copyOf(data.size + TAG_LEN)
        aead.seal(out, 0, data.size, ZERO_NONCE, additionalData)
        return out
    }

    override fun open(data: ByteArray, additionalData: ByteArray): ByteArray {
        if (data.size < TAG_LEN) throw CryptoError()
        val buf = data.copyOf()
        if (!aead.open(buf, 0, buf.size, ZERO_NONCE, additionalData)) throw CryptoError()
        return buf.copyOf(buf.size - TAG_LEN)
    }

    private companion object {
        const val TAG_LEN = 16
        val ZERO_NONCE = ByteArray(12)
    }
}

private fun region(a: ByteArray, offset: Int, length: Int): ByteArray =
    if (offset == 0 && length == a.size) a else a.copyOfRange(offset, offset + length)
