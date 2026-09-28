package neton.quic.proto

import neton.io.net.EcnCodepoint
import neton.io.net.SocketAddress

// Events between an endpoint and its connections (quinn-proto `shared.rs`) and the outgoing datagram description
// (`lib.rs` `Transmit`).

/**
 * Events sent from an [Endpoint] to a [Connection] (shared.rs:8). Opaque to the application, which only hands them
 * from [Endpoint.handle] / [Endpoint.handleEvent] to [Connection.handleEvent].
 */
sealed class ConnectionEvent {
    /**
     * A datagram has been received for the connection (quinn `DatagramConnectionEvent`). The coalesced packets that
     * follow the first one are `firstDecode.data[restStart, restEnd)` (quinn's `remaining`).
     */
    internal class Datagram(
        val now: Instant,
        val remote: SocketAddress,
        val ecn: EcnCodepoint?,
        val firstDecode: PartialDecode,
    ) : ConnectionEvent()

    /** New connection identifiers have been issued for the connection. */
    internal class NewIdentifiers(val ids: List<IssuedCid>, val now: Instant) : ConnectionEvent()
}

/** Events sent from a [Connection] to an [Endpoint] (shared.rs:30). */
sealed class EndpointEvent {
    /** The connection has been drained. */
    internal data object Drained : EndpointEvent()

    /** The reset token and/or address eligible for generating resets has been updated. */
    internal class ResetTokenChanged(val remote: SocketAddress, val token: ResetToken) : EndpointEvent()

    /** The connection needs [n] connection identifiers. */
    internal class NeedIdentifiers(val now: Instant, val n: Long) : EndpointEvent()

    /**
     * Stop routing the connection ID with [sequence] to the connection; when [allowMoreCids] is set, a new connection
     * ID will be issued to the peer.
     */
    internal class RetireConnectionId(val now: Instant, val sequence: Long, val allowMoreCids: Boolean) : EndpointEvent()

    /** Whether this is the last event a connection will emit; its state in the event loop can then be freed. */
    val isDrained: Boolean get() = this === Drained

    companion object {
        /**
         * An event indicating that a connection will no longer emit events: useful for telling an [Endpoint] that a
         * connection has been destroyed outside of the usual state machine flow.
         */
        fun drained(): EndpointEvent = Drained
    }
}

/**
 * An outgoing datagram, or a batch of equal-sized datagrams for segmentation offload (quinn `Transmit`, lib.rs:282):
 * the first [size] readable bytes of the buffer passed to the call that produced it.
 */
class Transmit(
    /** The socket this datagram should be sent to. */
    val destination: SocketAddress,
    /** Explicit congestion notification bits to set on the packet. */
    val ecn: EcnCodepoint?,
    /** Amount of data written to the caller-supplied buffer. */
    val size: Int,
    /** The segment size if this transmission contains multiple datagrams; `null` for a single datagram. */
    val segmentSize: Int?,
    /**
     * Optional source IP address for the datagram. ⚖️ quinn's `IpAddr`: neton-io has no IP address type, so this is a
     * [SocketAddress] whose port is 0 (as neton-io reports a datagram's local destination).
     */
    val srcIp: SocketAddress?,
) {
    override fun toString(): String =
        "Transmit(destination=$destination, ecn=$ecn, size=$size, segmentSize=$segmentSize, srcIp=$srcIp)"
}
