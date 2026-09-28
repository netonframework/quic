@file:OptIn(ExperimentalNativeApi::class)

package neton.quic.proto

import neton.openssl.AeadAlgorithm
import neton.openssl.Crypto
import neton.openssl.DigestAlgorithm
import neton.openssl.MaskAlgorithm
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner
import neton.openssl.AeadKey as OpenSslAeadKey
import neton.openssl.HeaderProtectionKey as OpenSslHeaderProtectionKey

// QUIC packet protection on OpenSSL primitives: what quinn gets from rustls's `quic` module and its *ring* provider
// (quinn-proto `crypto/rustls.rs`; rustls `quic.rs`, `crypto/ring/quic.rs`, `crypto/ring/tls13.rs`). Initial keys,
// the 1-RTT key schedule with key updates, packet and header protection keys for the three TLS 1.3 cipher suites,
// and the Retry integrity tag. The TLS handshake itself (which yields the Handshake / 1-RTT / 0-RTT secrets fed to
// [Secrets]) is not here.
//
// ⚖️ quinn's keys free their native state on drop; OpenSSL handles here are released by a Cleaner when the key
// object becomes unreachable (the openssl-kotlin handles have no finalizer of their own).

/** AEAD tag length of every suite (rustls `quic::TAG_LEN`). */
private const val TAG_LEN = 16

/** AEAD nonce / packet IV length. */
private const val NONCE_LEN = 12

/** Header protection sample length, AES and ChaCha20 alike (RFC 9001 §5.4.2). */
private const val SAMPLE_LEN = 16

/**
 * A TLS 1.3 cipher suite usable with QUIC, with the parameters rustls's *ring* provider gives it
 * (rustls `crypto/ring/tls13.rs` `quic: KeyBuilder`; limits from RFC 9001 §6.6 and Appendix B).
 */
enum class CipherSuite(
    val aead: AeadAlgorithm,
    val mask: MaskAlgorithm,
    /** The suite's hash, used for HKDF (secrets are this long). */
    val hash: DigestAlgorithm,
    /** Length of packet and header protection keys. */
    val keyLen: Int,
    /** Maximum number of packets that may be sent using a single key. */
    val confidentialityLimit: Long,
    /** Maximum number of incoming packets that may fail decryption before the connection must be abandoned. */
    val integrityLimit: Long,
) {
    TLS13_AES_128_GCM_SHA256(AeadAlgorithm.AES_128_GCM, MaskAlgorithm.AES_128, DigestAlgorithm.SHA256, 16, 1L shl 23, 1L shl 52),
    TLS13_AES_256_GCM_SHA384(AeadAlgorithm.AES_256_GCM, MaskAlgorithm.AES_256, DigestAlgorithm.SHA384, 32, 1L shl 23, 1L shl 52),

    // ⚖️ rustls: confidentiality limit u64::MAX; Long.MAX_VALUE (2^63 - 1 packets) is just as unreachable.
    TLS13_CHACHA20_POLY1305_SHA256(AeadAlgorithm.CHACHA20_POLY1305, MaskAlgorithm.CHACHA20, DigestAlgorithm.SHA256, 32, Long.MAX_VALUE, 1L shl 36),
}

/**
 * The suite Initial packets are protected with (RFC 9001 §5.2; quinn `initial_suite_from_provider`, which requires
 * TLS13_AES_128_GCM_SHA256).
 */
val INITIAL_SUITE: CipherSuite = CipherSuite.TLS13_AES_128_GCM_SHA256

/**
 * The QUIC version as far as key derivation is concerned (rustls `quic::Version`; quinn only maps to `V1Draft` and
 * `V1`, rustls's `V2` is not reachable from quinn and is left out).
 */
enum class TlsQuicVersion(internal val initialSalt: ByteArray) {
    /** Draft versions 29 to 32 (draft-ietf-quic-tls-32 §5.2 salt). */
    V1Draft(hexBytes("afbfec289993d24c9e9786f19c6111e04390a899")),

    /** RFC 9001 (also used by quinn for drafts 33 and 34). */
    V1(hexBytes("38762cf7f55934b34d179ae6a4c80cadccbb7f0a"));

    companion object {
        /** quinn `interpret_version` (crypto/rustls.rs:650); throws [UnsupportedVersion]. */
        fun of(version: Int): TlsQuicVersion {
            val v = version.toUInt()
            return when {
                v in 0xff00_001du..0xff00_0020u -> V1Draft
                v == 1u || v in 0xff00_0021u..0xff00_0022u -> V1
                else -> throw UnsupportedVersion(version)
            }
        }
    }
}

// Labels are identical for V1Draft and V1 (rustls `Version::packet_key_label` etc.; only V2 differs).
private const val LABEL_KEY = "quic key"
private const val LABEL_IV = "quic iv"
private const val LABEL_HP = "quic hp"
private const val LABEL_KU = "quic ku"

/** HKDF-Expand-Label with an empty context (RFC 8446 §7.1). */
internal fun expandLabel(hash: DigestAlgorithm, secret: ByteArray, label: String, length: Int): ByteArray {
    val out = ByteArray(length)
    Crypto.hkdfExpandLabel(hash, secret, label, EMPTY, out)
    return out
}

private val EMPTY = ByteArray(0)

/**
 * The traffic secrets of one packet space, for both directions (rustls `quic::Secrets`). The TLS layer creates it
 * from the secrets it derived (the client's and the server's, [CipherSuite.hash] long each; they are copied); the
 * Initial secrets come from [initialSecrets].
 *
 * Only packet keys change on a key update; header protection keys stay those of the first generation.
 */
class Secrets(
    client: ByteArray,
    server: ByteArray,
    val suite: CipherSuite,
    val side: Side,
    val version: TlsQuicVersion,
) {
    /** Secret used to encrypt packets transmitted by the client. */
    internal var client: ByteArray = client.copyOf()
        private set

    /** Secret used to encrypt packets transmitted by the server. */
    internal var server: ByteArray = server.copyOf()
        private set

    init {
        require(client.size == suite.hash.outputSize && server.size == suite.hash.outputSize) {
            "a ${suite.name} secret has ${suite.hash.outputSize} bytes"
        }
    }

    private val local: ByteArray get() = if (side == Side.Client) client else server
    private val remote: ByteArray get() = if (side == Side.Client) server else client

    /** Header and packet keys for both directions from the current secrets (rustls `Keys::new`). */
    fun keys(): Keys = Keys(
        KeyPair(headerKey(suite, local), headerKey(suite, remote)),
        KeyPair(packetKey(suite, local), packetKey(suite, remote)),
    )

    /**
     * The first 1-RTT keys, leaving these secrets one generation ahead for [nextPacketKeys] (rustls `write_hs`
     * returning `KeyChange::OneRtt { keys, next }`: `Keys::new(&secrets)` then `secrets.update()`).
     */
    fun oneRttKeys(): Keys = keys().also { update() }

    /**
     * Packet keys for the next key update, then advance to the generation after it (rustls
     * `Secrets::next_packet_keys`, used by quinn `next_1rtt_keys`): keys are always one generation ahead, so a
     * peer-initiated update can be decrypted without deriving on the receive path.
     */
    fun nextPacketKeys(): KeyPair<PacketKey> =
        KeyPair(packetKey(suite, local), packetKey(suite, remote)).also { update() }

    /** Derive the next generation of secrets with "quic ku" (rustls `Secrets::update`; RFC 9001 §6.1). */
    fun update() {
        val nextClient = expandLabel(suite.hash, client, LABEL_KU, client.size)
        val nextServer = expandLabel(suite.hash, server, LABEL_KU, server.size)
        Crypto.wipe(client)
        Crypto.wipe(server)
        client = nextClient
        server = nextServer
    }
}

/**
 * The Initial secrets for the client's first destination connection ID (rustls `Keys::initial`; RFC 9001 §5.2):
 * `HKDF-Extract(initial_salt, cid)`, then "client in" / "server in".
 */
fun initialSecrets(version: TlsQuicVersion, dstCid: ConnectionId, side: Side): Secrets {
    val suite = INITIAL_SUITE
    val initialSecret = ByteArray(suite.hash.outputSize)
    Crypto.hkdfExtract(suite.hash, version.initialSalt, dstCid.toByteArray(), initialSecret)
    val client = expandLabel(suite.hash, initialSecret, "client in", suite.hash.outputSize)
    val server = expandLabel(suite.hash, initialSecret, "server in", suite.hash.outputSize)
    Crypto.wipe(initialSecret)
    return Secrets(client, server, suite, side, version).also {
        Crypto.wipe(client)
        Crypto.wipe(server)
    }
}

/**
 * Initial keys for [side] from the client's first destination connection ID (quinn `initial_keys`,
 * crypto/rustls.rs:596, and `ServerConfig::initial_keys`). Throws [UnsupportedVersion] for versions quinn does not
 * support.
 *
 * ⚖️ quinn takes the initial `Suite` from the TLS configuration, which it requires to be TLS13_AES_128_GCM_SHA256;
 * here it is always [INITIAL_SUITE].
 */
fun initialKeys(version: Int, dstCid: ConnectionId, side: Side): Keys =
    initialSecrets(TlsQuicVersion.of(version), dstCid, side).keys()

/** Packet protection key for one direction (rustls `KeyBuilder::packet_key`: "quic key" and "quic iv"). */
internal fun packetKey(suite: CipherSuite, secret: ByteArray): PacketKey {
    val key = expandLabel(suite.hash, secret, LABEL_KEY, suite.keyLen)
    val iv = expandLabel(suite.hash, secret, LABEL_IV, NONCE_LEN)
    try {
        return OpenSslPacketKey(suite, key, iv)
    } finally {
        Crypto.wipe(key)
    }
}

/** Header protection key for one direction (rustls `KeyBuilder::header_protection_key`: "quic hp"). */
internal fun headerKey(suite: CipherSuite, secret: ByteArray): HeaderKey {
    val key = expandLabel(suite.hash, secret, LABEL_HP, suite.keyLen)
    try {
        return OpenSslHeaderKey(suite, key)
    } finally {
        Crypto.wipe(key)
    }
}

/**
 * Packet payload protection (rustls `crypto/ring/quic.rs` `PacketKey`, through quinn's `crypto::PacketKey` impl at
 * crypto/rustls.rs:616): AEAD in place with nonce = IV XOR packet number and the header as associated data.
 *
 * Allocation-free per packet: the nonce buffer is reused, and so are the associated-data buffers.
 * ⚖️ openssl-kotlin takes the associated data as a whole array, not a region, so the header is copied into a
 * scratch array of exactly its length. Header lengths on one key vary only with the packet number length (1 to 4
 * bytes), so four slots indexed by `length mod 4` keep one buffer per length in steady state.
 *
 * One operation at a time: a key belongs to one connection, which is driven by one thread at a time.
 */
internal class OpenSslPacketKey(suite: CipherSuite, key: ByteArray, private val iv: ByteArray) : PacketKey {
    private val aead = OpenSslAeadKey(suite.aead, key)

    @Suppress("unused")
    private val cleaner = createCleaner(aead) { it.close() }

    private val nonce = ByteArray(NONCE_LEN)
    private val aadSlots = arrayOfNulls<ByteArray>(4)

    override val tagLen: Int get() = TAG_LEN
    override val confidentialityLimit: Long = suite.confidentialityLimit
    override val integrityLimit: Long = suite.integrityLimit

    override fun encrypt(packetNumber: Long, packet: ByteArray, start: Int, end: Int, headerLen: Int) {
        val aad = aad(packet, start, headerLen)
        aead.seal(packet, start + headerLen, end - start - headerLen - TAG_LEN, nonce(packetNumber), aad)
    }

    override fun decrypt(
        packetNumber: Long,
        header: ByteArray, headerStart: Int, headerEnd: Int,
        payload: ByteArray, payloadStart: Int, payloadEnd: Int,
    ): Int {
        val len = payloadEnd - payloadStart
        if (len < TAG_LEN) throw DECRYPTION_FAILED
        val aad = aad(header, headerStart, headerEnd - headerStart)
        if (!aead.open(payload, payloadStart, len, nonce(packetNumber), aad)) throw DECRYPTION_FAILED
        return len - TAG_LEN
    }

    /** rustls `Nonce::new`: the IV with the packet number XORed into its last 8 bytes, big-endian. */
    private fun nonce(packetNumber: Long): ByteArray {
        val n = nonce
        iv.copyInto(n)
        for (i in 0 until 8) {
            val at = NONCE_LEN - 1 - i
            n[at] = (n[at].toInt() xor (packetNumber ushr (8 * i)).toInt()).toByte()
        }
        return n
    }

    private fun aad(src: ByteArray, start: Int, len: Int): ByteArray {
        val slot = len and 3
        var a = aadSlots[slot]
        if (a == null || a.size != len) {
            a = ByteArray(len)
            aadSlots[slot] = a
        }
        src.copyInto(a, 0, start, start + len)
        return a
    }

    private companion object {
        // Decryption failures are ordinary on the receive path (forged or corrupted packets): throwing a shared
        // instance keeps them allocation-free, like [UnexpectedEnd].
        val DECRYPTION_FAILED = CryptoError("packet decryption failed")
    }
}

/**
 * Header protection (rustls `crypto/ring/quic.rs` `HeaderProtectionKey`): the 5-byte mask from AES-ECB or ChaCha20
 * over the sample; the packet layout is [HeaderProtection]'s.
 */
internal class OpenSslHeaderKey(suite: CipherSuite, key: ByteArray) : HeaderProtection() {
    private val hp = OpenSslHeaderProtectionKey(suite.mask, key)

    @Suppress("unused")
    private val cleaner = createCleaner(hp) { it.close() }

    override val sampleSize: Int get() = SAMPLE_LEN

    override fun mask(sample: ByteArray, sampleOffset: Int, out: ByteArray) = hp.mask(sample, sampleOffset, out, 0)
}

// ---- Retry integrity (RFC 9001 §5.8; quinn crypto/rustls.rs:209-224) ----

private val RETRY_INTEGRITY_KEY_DRAFT = hexBytes("ccce187ed09a09d05728155a6cb96be1")
private val RETRY_INTEGRITY_NONCE_DRAFT = hexBytes("e54930f97f2136f0530a8c1c")
private val RETRY_INTEGRITY_KEY_V1 = hexBytes("be0c690b9f66575a1d766b54e368c84e")
private val RETRY_INTEGRITY_NONCE_V1 = hexBytes("461599d35d632bf2239825bb")

private fun retryNonce(v: TlsQuicVersion): ByteArray = if (v == TlsQuicVersion.V1) RETRY_INTEGRITY_NONCE_V1 else RETRY_INTEGRITY_NONCE_DRAFT

private fun retryKey(v: TlsQuicVersion): OpenSslAeadKey =
    OpenSslAeadKey(AeadAlgorithm.AES_128_GCM, if (v == TlsQuicVersion.V1) RETRY_INTEGRITY_KEY_V1 else RETRY_INTEGRITY_KEY_DRAFT)

/** The Retry pseudo-packet prefix: ODCID length, ODCID (RFC 9001 §5.8). [extra] bytes are left for the caller. */
private fun retryPseudoPacket(origDstCid: ConnectionId, extra: Int): ByteArray {
    val p = ByteArray(1 + origDstCid.size + extra)
    p[0] = origDstCid.size.toByte()
    origDstCid.copyInto(p, 1)
    return p
}

/**
 * The integrity tag of the Retry packet `packet[offset, offset + length)` (everything before the tag), sent in
 * response to a client whose first destination CID was [origDstCid] (quinn `ServerConfig::retry_tag`). Throws
 * [UnsupportedVersion].
 */
fun retryTag(version: Int, origDstCid: ConnectionId, packet: ByteArray, offset: Int = 0, length: Int = packet.size - offset): ByteArray {
    val v = TlsQuicVersion.of(version)
    val pseudo = retryPseudoPacket(origDstCid, length)
    packet.copyInto(pseudo, 1 + origDstCid.size, offset, offset + length)
    val tag = ByteArray(TAG_LEN)
    retryKey(v).use { it.seal(tag, 0, 0, retryNonce(v), pseudo) }
    return tag
}

/**
 * Whether a Retry packet is authentic (quinn `Session::is_valid_retry`, crypto/rustls.rs:174): its header
 * `header[headerStart, headerStart + headerLen)` and payload `payload[payloadStart, payloadStart + payloadLen)`
 * (the token followed by the 16-byte tag), for the destination CID the client first used. Throws
 * [UnsupportedVersion] (quinn's session already holds a supported version).
 */
fun isValidRetry(
    version: Int,
    origDstCid: ConnectionId,
    header: ByteArray, headerStart: Int, headerLen: Int,
    payload: ByteArray, payloadStart: Int, payloadLen: Int,
): Boolean {
    val v = TlsQuicVersion.of(version)
    val tokenLen = payloadLen - TAG_LEN
    if (tokenLen < 0) return false
    val pseudo = retryPseudoPacket(origDstCid, headerLen + tokenLen)
    var at = 1 + origDstCid.size
    header.copyInto(pseudo, at, headerStart, headerStart + headerLen)
    at += headerLen
    payload.copyInto(pseudo, at, payloadStart, payloadStart + tokenLen)
    val tag = payload.copyOfRange(payloadStart + tokenLen, payloadStart + payloadLen)
    return retryKey(v).use { it.open(tag, 0, TAG_LEN, retryNonce(v), pseudo) }
}

/** [isValidRetry] over whole arrays. */
fun isValidRetry(version: Int, origDstCid: ConnectionId, header: ByteArray, payload: ByteArray): Boolean =
    isValidRetry(version, origDstCid, header, 0, header.size, payload, 0, payload.size)

internal fun hexBytes(s: String): ByteArray = ByteArray(s.length / 2) { s.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
