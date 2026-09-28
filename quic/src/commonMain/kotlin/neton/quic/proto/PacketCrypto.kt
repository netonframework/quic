package neton.quic.proto

// Packet decryption for a connection (quinn-proto `connection/packet_crypto.rs`).
//
// ⚖️ quinn returns `Option<UnprotectHeaderResult>` and `Result<Option<DecryptPacketResult>, Option<TransportError>>`;
// here header unprotection is inline in `Connection.handleDecode`, and [decryptPacketBody] returns the packet number
// or a negative sentinel ([NO_PACKET_NUMBER], [DECRYPT_FAILED]), throws the `Some(TransportError)` case, and reports
// the key update flags through a reused [DecryptPacketResult]: one packet decrypts without allocating.

/** [decryptPacketBody] result for unprotected packets, which have no packet number (quinn `Ok(None)`). */
internal const val NO_PACKET_NUMBER: Long = -1

/** [decryptPacketBody] result when the packet failed authentication (quinn `Err(None)`). */
internal const val DECRYPT_FAILED: Long = -2

/** Flags from the last [decryptPacketBody] call (quinn `DecryptPacketResult` without its packet number). */
internal class DecryptPacketResult {
    /** Whether a locally initiated key update has been acknowledged by the peer. */
    var outgoingKeyUpdateAcked = false

    /** Whether the peer has initiated a key update. */
    var incomingKeyUpdate = false
}

/** packet_crypto.rs:148 */
internal class PrevCrypto(
    /**
     * The keys used for the previous key phase, temporarily retained to decrypt packets sent by the peer prior to its
     * own key update.
     */
    val crypto: KeyPair<PacketKey>,
    /**
     * The incoming packet that ends the interval for which these keys are applicable (-1 for none), and the time of
     * its receipt. Incoming packets should be decrypted using these keys iff this is none or their packet number is
     * lower. None indicates that we have not yet received a packet using newer keys, which implies that the update was
     * locally initiated.
     */
    var endPacket: Long,
    var endPacketTime: Instant,
    /** Whether the following key phase is from a remotely initiated update that we haven't acked. */
    var updateUnacked: Boolean,
)

/** packet_crypto.rs:165 */
internal class ZeroRttCrypto(val header: HeaderKey, val packet: PacketKey) {
    fun close() { header.close(); packet.close() }
}

/**
 * Decrypts a packet's body in place (packet_crypto.rs:74). Returns the full packet number, [NO_PACKET_NUMBER] for
 * unprotected packets or [DECRYPT_FAILED]; throws [TransportError] for protocol violations.
 */
internal fun decryptPacketBody(
    packet: Packet,
    spaces: Array<PacketSpace>,
    zeroRttCrypto: ZeroRttCrypto?,
    connKeyPhase: Boolean,
    prevCrypto: PrevCrypto?,
    nextCrypto: KeyPair<PacketKey>?,
    result: DecryptPacketResult,
): Long {
    val header = packet.header
    if (!header.isProtected) {
        // Unprotected packets also don't have packet numbers
        return NO_PACKET_NUMBER
    }
    val space = header.space
    val rxPacket = spaces[space].rxPacket
    // The subtypes' non-null `number` (the nullable `Header.number` would box the packet number)
    val number = when (header) {
        is Header.Short -> header.number.expand(rxPacket + 1)
        is Header.Long -> header.number.expand(rxPacket + 1)
        is InitialHeader -> header.number.expand(rxPacket + 1)
        else -> return DECRYPT_FAILED
    }
    val packetKeyPhase = header.keyPhase

    var cryptoUpdate = false
    val crypto: PacketKey = if (header.is0rtt) {
        zeroRttCrypto!!.packet
    } else if (packetKeyPhase == connKeyPhase || space != SpaceId.Data) {
        spaces[space].crypto!!.packet.remote
    } else if (prevCrypto != null && (prevCrypto.endPacket < 0 || number < prevCrypto.endPacket)) {
        // Use the previous keys if this packet comes prior to acknowledgment of the key update by the peer;
        // otherwise, this must be a remotely-initiated key update, so fall through to the final case.
        prevCrypto.crypto.remote
    } else {
        // We're in the Data space with a key phase mismatch and either there is no locally initiated key update or
        // the locally initiated key update was acknowledged by a lower-numbered packet. The key phase mismatch must
        // therefore represent a new remotely-initiated key update.
        cryptoUpdate = true
        nextCrypto!!.remote
    }

    try {
        val headerEnd = packet.headerStart + packet.headerLen
        packet.payloadLen = crypto.decrypt(
            number,
            packet.data, packet.headerStart, headerEnd,
            packet.data, packet.payloadStart, packet.payloadStart + packet.payloadLen,
        )
    } catch (e: CryptoError) {
        return DECRYPT_FAILED
    }

    if (!packet.reservedBitsValid()) throw TransportError.PROTOCOL_VIOLATION("reserved bits set")

    result.outgoingKeyUpdateAcked = prevCrypto != null && prevCrypto.endPacket < 0 && packetKeyPhase == connKeyPhase
    result.incomingKeyUpdate = cryptoUpdate

    if (cryptoUpdate) {
        // Validate incoming key update
        if (number <= rxPacket || prevCrypto?.updateUnacked == true) throw TransportError.KEY_UPDATE_ERROR("")
    }

    return number
}
