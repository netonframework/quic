package neton.quic

import neton.io.net.SocketAddress
import neton.quic.proto.ConnectionError
import neton.quic.proto.ConnectionId
import neton.quic.proto.ServerConfig
import neton.quic.proto.Incoming as ProtoIncoming
import neton.quic.proto.RetryError as ProtoRetryError

/**
 * An incoming connection for which the server has not yet begun its part of the handshake (incoming.rs:18).
 *
 * Exactly one of [accept], [refuse], [retry] or [ignore] disposes of it. ⚖️ quinn refuses an `Incoming` dropped
 * unhandled; here [close] does that, and the endpoint refuses the ones still unhandled when it stops.
 */
class Incoming internal constructor(
    internal val inner: ProtoIncoming,
    private val endpoint: Endpoint,
) : AutoCloseable {
    private var consumed = false

    private fun consume() {
        check(!consumed) { "this Incoming was already accepted, refused, retried or ignored" }
        consumed = true
    }

    /** Attempt to accept this incoming connection (an error may still occur). Throws [ConnectionError]. */
    fun accept(): Connecting {
        consume()
        return endpoint.acceptIncoming(this, null)
    }

    /** Accept this incoming connection using a custom configuration. Throws [ConnectionError]. */
    fun acceptWith(serverConfig: ServerConfig): Connecting {
        consume()
        return endpoint.acceptIncoming(this, serverConfig)
    }

    /** Accept, then wait for the handshake to complete (quinn's `IntoFuture` for `Incoming`). Throws [ConnectionError]. */
    suspend fun await(): Connection = accept().await()

    /** Reject this incoming connection attempt. */
    fun refuse() {
        consume()
        endpoint.refuseIncoming(this)
    }

    /**
     * Respond with a retry packet, requiring the client to retry with address validation. Throws [RetryError] if
     * [mayRetry] is false; this [Incoming] then remains to be disposed of ([RetryError.intoIncoming]).
     */
    fun retry() {
        consume()
        try {
            endpoint.retryIncoming(this)
        } catch (e: ProtoRetryError) {
            consumed = false
            throw RetryError(this)
        }
    }

    /** Ignore this incoming connection attempt, not sending any packet in response. */
    fun ignore() {
        consume()
        endpoint.ignoreIncoming(this)
    }

    /** ⚖️ quinn's `Drop`: an implicit [refuse] if this was not otherwise disposed of. Idempotent. */
    override fun close() {
        if (!consumed) refuse()
    }

    /** The local IP address which was used when the peer established the connection (port 0), if known. */
    fun localIp(): SocketAddress? = inner.localIp()

    /** The peer's UDP address. */
    fun remoteAddress(): SocketAddress = inner.remoteAddress()

    /**
     * Whether the socket address that is initiating this connection has been validated: the sender of the initial
     * packet has proved that they can receive traffic sent to [remoteAddress]. If false, [mayRetry] is guaranteed to
     * be true; the inverse is not guaranteed.
     */
    fun remoteAddressValidated(): Boolean = inner.remoteAddressValidated()

    /** Whether it is legal to respond with a retry packet. */
    fun mayRetry(): Boolean = inner.mayRetry()

    /** The original destination CID when initiating the connection. */
    fun origDstCid(): ConnectionId = inner.origDstCid()

    override fun toString(): String = "Incoming(remote=${remoteAddress()})"
}

/** Error for attempting to retry an [Incoming] which already bears a token from a previous retry (incoming.rs:125). */
class RetryError internal constructor(private val incoming: Incoming) : Exception("retry() with validated Incoming") {
    /** The [Incoming]. */
    fun intoIncoming(): Incoming = incoming
}
