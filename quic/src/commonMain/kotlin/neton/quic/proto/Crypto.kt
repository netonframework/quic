package neton.quic.proto

// The crypto seams the encoding layer needs (quinn-proto `crypto.rs:97-223`). Nothing here implements
// cryptography: the implementations on openssl-kotlin primitives are in nativeMain (`PacketProtection.kt`,
// `TokenKeys.kt`); the TLS handshake will supply the Handshake / 1-RTT secrets (SPEC §4). The packet
// layout rules around them (where the sample is taken, which header bits and packet number bytes the mask
// covers) are protocol, not crypto, and live here in [HeaderProtection].

/** Generic crypto error (quinn `CryptoError`). */
class CryptoError(message: String = "crypto error") : Exception(message)

/** The QUIC version is not supported by the crypto layer (quinn `crypto::UnsupportedVersion`, crypto.rs:218). */
class UnsupportedVersion(val version: Int) : Exception("unsupported QUIC version 0x${version.toUInt().toString(16)}")

/** A pair of keys for bidirectional communication (quinn `crypto::KeyPair`, crypto.rs:97). */
class KeyPair<T : AutoCloseable>(
    /** Key for encrypting data. */
    val local: T,
    /** Key for decrypting data. */
    val remote: T,
) {
    /** Release both keys (each exactly once; see [HeaderKey.close]). */
    fun close() { local.close(); remote.close() }
}

/** A complete set of keys for a certain packet space (quinn `crypto::Keys`, crypto.rs:105). */
class Keys(
    /** Header protection keys. */
    val header: KeyPair<HeaderKey>,
    /** Packet protection keys. */
    val packet: KeyPair<PacketKey>,
) {
    /** Release all four keys. Only for keys this set owns alone: 1-RTT header keys outlive a key update. */
    fun close() { header.close(); packet.close() }
}

/**
 * Keys used to protect packet headers (quinn `crypto::HeaderKey`, crypto.rs:168; RFC 9001 §5.4).
 *
 * Packet regions are `packet[start, end)`; [pnOffset] is relative to `start`, as in quinn where the slice
 * starts at the packet's first byte.
 */
/**
 * Keys own native cipher contexts. ⚖️ quinn frees them on drop; here the owner calls [close] when the key is retired
 * (a packet space discarded, a key phase ended, the connection drained). Closing is idempotent; a GC cleaner only
 * backs it up and never releases twice.
 */
interface HeaderKey : AutoCloseable {
    override fun close() {}

    /** Remove header protection in place. */
    fun decrypt(pnOffset: Int, packet: ByteArray, start: Int, end: Int)

    /** Apply header protection in place. */
    fun encrypt(pnOffset: Int, packet: ByteArray, start: Int, end: Int)

    /** The sample size used for this key's algorithm (16 for AES and ChaCha20). */
    val sampleSize: Int
}

/** Keys used to protect packet payloads (quinn `crypto::PacketKey`, crypto.rs:148; RFC 9001 §5.3). */
interface PacketKey : AutoCloseable {
    /** Release the native context (idempotent); see [HeaderKey]. */
    override fun close() {}

    /**
     * Encrypt `packet[start + headerLen, end - tagLen)` in place with the header `packet[start, start + headerLen)`
     * as associated data, writing the tag into the last [tagLen] bytes.
     */
    fun encrypt(packetNumber: Long, packet: ByteArray, start: Int, end: Int, headerLen: Int)

    /**
     * Decrypt `payload[payloadStart, payloadEnd)` in place, authenticating `header[headerStart, headerEnd)`.
     * Returns the plaintext length (the ciphertext length minus [tagLen]); throws [CryptoError] on failure.
     */
    fun decrypt(
        packetNumber: Long,
        header: ByteArray, headerStart: Int, headerEnd: Int,
        payload: ByteArray, payloadStart: Int, payloadEnd: Int,
    ): Int

    /** The length of the AEAD tag appended to packets on encryption. */
    val tagLen: Int

    /** Maximum number of packets that may be sent using a single key. */
    val confidentialityLimit: Long

    /** Maximum number of incoming packets that may fail decryption before the connection must be abandoned. */
    val integrityLimit: Long
}

/** A key for signing with HMAC-based algorithms (quinn `crypto::HmacKey`, crypto.rs:178). */
interface HmacKey {
    fun sign(data: ByteArray, offset: Int, length: Int, signatureOut: ByteArray, outOffset: Int)
    val signatureLen: Int

    /** Throws [CryptoError] when the signature does not verify. */
    fun verify(data: ByteArray, offset: Int, length: Int, signature: ByteArray, sigOffset: Int, sigLength: Int)
}

/** A key that derives per-token AEAD keys with HKDF (quinn `crypto::HandshakeTokenKey`, crypto.rs:194). */
interface HandshakeTokenKey {
    fun aeadFromHkdf(randomBytes: ByteArray): AeadKey
}

/** A key for sealing data with AEAD-based algorithms (quinn `crypto::AeadKey`, crypto.rs:200). */
/** A single-use token key: close it after the operation (idempotent). */
interface AeadKey : AutoCloseable {
    override fun close() {}

    /** Seal [data] and return ciphertext followed by the tag. */
    fun seal(data: ByteArray, additionalData: ByteArray): ByteArray

    /** Open sealed [data]; returns the plaintext or throws [CryptoError]. */
    fun open(data: ByteArray, additionalData: ByteArray): ByteArray
}

/**
 * The RFC 9001 §5.4 header protection layout, shared by every cipher suite: the crypto layer only supplies the
 * 5-byte mask for a sample (AES-ECB or ChaCha20, [mask]); this class takes the sample and applies the mask
 * exactly as rustls does for quinn (`crypto/rustls.rs:228-251`, rustls `quic.rs` `xor_in_place`):
 *
 * - the sample is [sampleSize] bytes starting 4 bytes after the start of the packet number field
 *   (the packet number is assumed to be 4 bytes long for sampling);
 * - the first byte's low 4 bits (long header) or 5 bits (short header) are masked;
 * - the packet number bytes are masked with `mask[1..]`, the packet number length being read from the first
 *   byte *after* unmasking (decrypt) or *before* masking (encrypt).
 */
abstract class HeaderProtection : HeaderKey {

    /** Write the 5-byte mask for `sample[sampleOffset, sampleOffset + sampleSize)` into [out]. */
    protected abstract fun mask(sample: ByteArray, sampleOffset: Int, out: ByteArray)

    override fun decrypt(pnOffset: Int, packet: ByteArray, start: Int, end: Int) = apply(pnOffset, packet, start, end, masked = true)

    override fun encrypt(pnOffset: Int, packet: ByteArray, start: Int, end: Int) = apply(pnOffset, packet, start, end, masked = false)

    // Scratch for the mask: header keys belong to one connection, which is driven by one thread at a time.
    private val m = ByteArray(5)

    private fun apply(pnOffset: Int, packet: ByteArray, start: Int, end: Int, masked: Boolean) {
        val sampleOffset = start + sampleOffset(pnOffset)
        require(sampleOffset + sampleSize <= end) { "packet too short to sample for header protection" }
        val m = m
        mask(packet, sampleOffset, m)
        val first = packet[start].toInt() and 0xFF
        val bits = if (first and 0x80 != 0) 0x0F else 0x1F
        val firstPlain = if (masked) first xor (m[0].toInt() and bits) else first
        val pnLen = (firstPlain and 0x03) + 1
        packet[start] = (first xor (m[0].toInt() and bits)).toByte()
        val pnStart = start + pnOffset
        for (i in 0 until pnLen) packet[pnStart + i] = (packet[pnStart + i].toInt() xor m[1 + i].toInt()).toByte()
    }

    companion object {
        /** Offset of the header protection sample relative to the packet start (RFC 9001 §5.4.2). */
        fun sampleOffset(pnOffset: Int): Int = pnOffset + 4
    }
}
