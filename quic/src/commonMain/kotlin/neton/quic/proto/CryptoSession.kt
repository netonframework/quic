package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes

// The cryptographic session abstraction the connection drives (quinn-proto `crypto.rs:27-150`): what TLS 1.3 must
// provide to QUIC (SPEC §4). The implementation on openssl-kotlin's QUIC TLS interface comes later; until then only
// a test double exists, and only in the test source set.
//
// ⚖️ quinn's `crypto::Session`, `crypto::ClientConfig` and `crypto::ServerConfig` are `CryptoSession`,
// `CryptoClientConfig` and `CryptoServerConfig`: one Kotlin package holds both these and the endpoint's
// `ClientConfig` / `ServerConfig`. Rust's `Result`s are thrown exceptions ([TransportError], [UnsupportedVersion],
// [ConnectError], [ExportKeyingMaterialError]).

/**
 * A cryptographic session, commonly TLS (quinn `crypto::Session`, crypto.rs:28).
 *
 * **Release contract** (⚖️ quinn drops the session with the connection; SPEC §11.6 / §11.9): an implementation may
 * hold native resources (the real TLS session holds an OpenSSL SSL, the StableRef its callbacks get, native buffers
 * and secrets). The connection owns its session exclusively and calls [close] exactly when it no longer drives it:
 * when it drains (every path to the Drained state), and when the endpoint discards it without draining (a server
 * connection whose first packet failed). The endpoint closes a session it started but could not hand to a
 * connection. [close] must be idempotent and must free the native resources at once (a GC cleaner may back it up,
 * never replace it); afterwards no callback may run into Kotlin. After [close], [handshakeData], [peerIdentity] and
 * [transportParameters] keep answering what was known; [readHandshake] throws, [writeHandshake] and [next1rttKeys]
 * return `null`, and [exportKeyingMaterial] may throw [ExportKeyingMaterialError]. Keys already handed out are owned
 * by the connection and are not affected.
 */
interface CryptoSession : AutoCloseable {
    /** Release the session's native resources (see the release contract above). Idempotent. */
    override fun close() {}

    /** Create the initial set of keys given the client's initial destination connection ID. */
    fun initialKeys(dstCid: ConnectionId, side: Side): Keys

    /** Data negotiated during the handshake, if available: `null` until the connection emits `HandshakeDataReady`. */
    fun handshakeData(): Any?

    /** The peer's identity, if available. */
    fun peerIdentity(): Any?

    /**
     * The 0-RTT keys if available (clients only; on servers once 0-RTT was accepted). `null` when the key material is
     * not available, e.g. because this server was not connected to before.
     */
    fun earlyCrypto(): EarlyKeys?

    /** Whether the 0-RTT-encrypted data has been accepted by the peer; `null` on servers. */
    fun earlyDataAccepted(): Boolean?

    /** `true` until the connection is fully established. */
    val isHandshaking: Boolean

    /**
     * Read bytes of handshake data, the contents of CRYPTO frames in order. The caller then calls [writeHandshake] to
     * see whether the crypto protocol has anything to send. Returns `true` only the first time [handshakeData] became
     * available. Throws [TransportError].
     */
    fun readHandshake(buf: Bytes): Boolean

    /**
     * The peer's QUIC transport parameters, available once the first flight from the peer has been received (on a
     * client resuming a session, the ones remembered with the ticket). Throws [TransportError] when malformed.
     */
    fun transportParameters(): TransportParameters?

    /**
     * Write handshake bytes into [buf] and return the keys of the next packet space when the handshake moves on to it.
     * The bytes written belong to the current space; bytes after a key change are written by the next call.
     */
    fun writeHandshake(buf: Buffer): Keys?

    /** Compute keys for the next key update. */
    fun next1rttKeys(): KeyPair<PacketKey>?

    /** Verify the integrity of a Retry packet (its header, and its payload: the token followed by the tag). */
    fun isValidRetry(origDstCid: ConnectionId, header: ByteArray, payload: ByteArray): Boolean

    /**
     * Fill [output] with keying material derived from the session's secrets, using [label] and [context] for domain
     * separation. Throws [ExportKeyingMaterialError] if the requested output length is too large.
     */
    fun exportKeyingMaterial(output: ByteArray, label: ByteArray, context: ByteArray)
}

/** 0-RTT keys (quinn's `(Box<dyn HeaderKey>, Box<dyn PacketKey>)` from `early_crypto`). */
class EarlyKeys(val header: HeaderKey, val packet: PacketKey)

/** Client-side configuration for the crypto protocol (quinn `crypto::ClientConfig`, crypto.rs:112). */
interface CryptoClientConfig {
    /** Start a client session with this configuration. Throws [ConnectError]. */
    fun startSession(version: Int, serverName: String, params: TransportParameters): CryptoSession
}

/** Server-side configuration for the crypto protocol (quinn `crypto::ServerConfig`, crypto.rs:123). */
interface CryptoServerConfig {
    /** Create the initial set of keys given the client's initial destination connection ID. Throws [UnsupportedVersion]. */
    fun initialKeys(version: Int, dstCid: ConnectionId): Keys

    /**
     * Generate the integrity tag for the Retry packet `packet[offset, offset + length)`. Never called if [initialKeys]
     * rejected [version].
     */
    fun retryTag(version: Int, origDstCid: ConnectionId, packet: ByteArray, offset: Int, length: Int): ByteArray

    /** Start a server session with this configuration. Never called if [initialKeys] rejected [version]. */
    fun startSession(version: Int, params: TransportParameters): CryptoSession
}

/** The requested keying material is too long (quinn `ExportKeyingMaterialError`, crypto.rs:188). */
class ExportKeyingMaterialError : Exception("export keying material error") {
    override fun equals(other: Any?): Boolean = other is ExportKeyingMaterialError
    override fun hashCode(): Int = 0
}
