package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.net.SocketAddress
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNotEquals
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

class TransportParametersTest {

    private val localhostV4 = SocketAddress.ipv4(127, 0, 0, 1, 42)
    private val localhostV6 = SocketAddress.of(ByteArray(16).also { it[15] = 1 }, 24)

    private fun read(side: Side, bytes: ByteArray) = TransportParameters.read(side, Reader(bytes))

    private fun written(p: TransportParameters): ByteArray = encoded { p.write(it) }

    // ---- transport_parameters.rs tests ----

    @Test
    fun coding() {
        val params = TransportParameters.default().apply {
            initialSrcCid = ConnectionId.of(ByteArray(0))
            originalDstCid = ConnectionId.of(ByteArray(0))
            initialMaxStreamsBidi = VarInt(16)
            initialMaxStreamsUni = VarInt(16)
            ackDelayExponent = VarInt(2)
            maxUdpPayloadSize = VarInt(1200)
            preferredAddress = PreferredAddress(localhostV4, localhostV6, ConnectionId.of(byteArrayOf(0x42)), ResetToken(ByteArray(16) { 0xab.toByte() }))
            greaseQuicBit = true
            minAckDelay = VarInt(2_000)
        }
        assertEquals(params, read(Side.Client, written(params)))
    }

    /** rand's `StepRng`: returns successive values from [state], wrapping. */
    private class StepRandom(private var state: Long) : Random() {
        override fun nextLong(): Long = state.also { state += 1 }
        override fun nextInt(): Int = nextLong().toInt()
        override fun nextBits(bitCount: Int): Int = if (bitCount == 0) 0 else (nextLong() ushr (64 - bitCount)).toInt()
    }

    @Test
    fun reservedTransportParameterGenerateReservedId() {
        val u32Max = 0xFFFF_FFFFL
        val seeds = longArrayOf(
            0, 1, 27, 31,
            u32Max, u32Max - 1, u32Max + 1, u32Max - 27, u32Max + 27, u32Max - 31, u32Max + 31,
            -1L, -2L, -1L - 27, -1L - 31, // u64::MAX, u64::MAX - 1, - 27, - 31
            1L shl 62, (1L shl 62) - 1, (1L shl 62) + 1, (1L shl 62) - 27, (1L shl 62) + 27, (1L shl 62) - 31, (1L shl 62) + 31,
        )
        for (seed in seeds) {
            val id = ReservedTransportParameter.generateReservedId(StepRandom(seed))
            assertEquals(27L, id.value % 31, "seed $seed")
            assertTrue(id.value < (1L shl 62))
        }
    }

    @Test
    fun reservedTransportParameterIgnoredWhenRead() {
        val reserved = ReservedTransportParameter.random(Random.Default)
        assertTrue(reserved.payloadLen < ReservedTransportParameter.MAX_PAYLOAD_LEN)
        assertEquals(27L, reserved.id.value % 31)
        val buf = Buffer(64)
        reserved.write(buf)
        assertFalse(buf.isEmpty)
        assertEquals(TransportParameters.default(), read(Side.Server, buf.bytes()))
    }

    @Test
    fun readSemanticValidation() {
        val illegalParamsBuilders: List<(TransportParameters) -> Unit> = listOf(
            { t ->
                // This min_ack_delay is bigger than max_ack_delay!
                t.minAckDelay = VarInt.fromLong(t.maxAckDelay.value * 1_000 + 1)
            },
            { t ->
                // Preferred address can only be sent by servers (and we are reading the transport params as a
                // server, i.e. params sent by a client).
                t.preferredAddress = PreferredAddress(localhostV4, null, ConnectionId.of(ByteArray(0)), ResetToken(ByteArray(16) { 0xab.toByte() }))
            },
        )
        for (builder in illegalParamsBuilders) {
            val params = TransportParameters.default()
            builder(params)
            assertSame(TransportParameterError.IllegalValue, assertFailsWith<TransportParameterError> { read(Side.Server, written(params)) })
        }
    }

    @Test
    fun readLengthMismatch() {
        // `max_datagram_frame_size` claims three bytes of value but encodes a one-byte VarInt, so a whole
        // `disable_active_migration` parameter fits inside its declared length.
        val buf = encoded {
            it.writeVar(TransportParameterId.MaxDatagramFrameSize)
            it.writeVar(3)
            it.writeVar(0)
            it.writeVar(TransportParameterId.DisableActiveMigration)
            it.writeVar(0)
        }
        assertSame(TransportParameterError.Malformed, assertFailsWith<TransportParameterError> { read(Side.Server, buf) })
    }

    @Test
    fun readMinAckDelayLengthMismatch() {
        // `min_ack_delay` claims no value at all, so its VarInt starts on the parameter that follows it.
        val buf = encoded {
            it.writeVar(TransportParameterId.MinAckDelayDraft07)
            it.writeVar(0)
            it.writeVar(TransportParameterId.InitialMaxData)
            it.writeVar(1)
            it.writeVar(7)
        }
        assertSame(TransportParameterError.Malformed, assertFailsWith<TransportParameterError> { read(Side.Server, buf) })
    }

    @Test
    fun readPreferredAddressLengthMismatch() {
        // `preferred_address` has a fixed size for a given connection ID length, so bytes past that size are
        // read as a parameter of their own.
        val address = PreferredAddress(localhostV4, null, ConnectionId.of(byteArrayOf(0x42)), ResetToken(ByteArray(16) { 0xab.toByte() }))
        val value = encoded {
            address.write(it)
            it.writeVar(TransportParameterId.DisableActiveMigration)
            it.writeVar(0)
        }
        val buf = encoded {
            it.writeVar(TransportParameterId.PreferredAddress)
            it.writeVar(value.size.toLong())
            it.writeBytes(value)
        }
        assertSame(TransportParameterError.Malformed, assertFailsWith<TransportParameterError> { read(Side.Client, buf) })
    }

    @Test
    fun resumptionParamsValidation() {
        val highLimit = TransportParameters.default().apply { initialMaxStreamsUni = VarInt(32) }
        val lowLimit = TransportParameters.default().apply { initialMaxStreamsUni = VarInt(16) }
        highLimit.validateResumptionFrom(lowLimit)
        assertFailsWith<TransportError> { lowLimit.validateResumptionFrom(highLimit) }
    }

    // ---- beyond the reference tests ----

    private fun sent(rng: Random, cidLen: Int = 8, server: Boolean? = null) = TransportParameters.new(
        initialSrcCid = ConnectionId.of(hex("0102030405060708")),
        maxConcurrentBidiStreams = VarInt(100),
        maxConcurrentUniStreams = VarInt(100),
        receiveWindow = VarInt(1_000_000),
        streamReceiveWindow = VarInt(125_000),
        maxUdpPayloadSize = VarInt(1472),
        maxIdleTimeout = VarInt(30_000),
        serverMigration = server,
        localCidLen = cidLen,
        datagramReceiveBufferSize = 1_000_000,
        greaseQuicBit = true,
        rng = rng,
    )

    @Test
    fun sentParametersRoundTripAndShuffle() {
        val a = sent(Random(1))
        val bytes = written(a)
        val back = read(Side.Client, bytes)
        // The receiver ignores the reserved parameter and has no write order; everything else survives.
        assertNull(back.greaseTransportParameter)
        assertNull(back.writeOrder)
        a.greaseTransportParameter = null
        a.writeOrder = null
        assertEquals(a, back)

        assertEquals(VarInt(5), back.activeConnectionIdLimit) // CidQueue::LEN
        assertEquals(VarInt(65535), back.maxDatagramFrameSize)  // min(receive buffer, 65535)
        assertEquals(VarInt(1000), back.minAckDelay)             // TIMER_GRANULARITY in microseconds
        assertTrue(back.greaseQuicBit)
        assertFalse(back.disableActiveMigration)
        assertEquals(5L, back.issueCidsLimit())

        // Seeded: the same seed gives the same bytes, different seeds a different order.
        assertContentEquals(written(sent(Random(7))), written(sent(Random(7))))
        val orders = (1..8).map { sent(Random(it)).writeOrder!!.toList() }.toSet()
        assertTrue(orders.size > 1, "write order is shuffled")
        for (o in orders) assertEquals((0 until 21).toList(), o.map { it.toInt() }.sorted())
    }

    @Test
    fun zeroLengthCidsAndServerMigration() {
        val p = sent(Random(3), cidLen = 0, server = false)
        assertEquals(VarInt(2), p.activeConnectionIdLimit)
        assertTrue(p.disableActiveMigration)
        val back = read(Side.Client, written(p))
        assertEquals(VarInt(2), back.activeConnectionIdLimit)
        assertTrue(back.disableActiveMigration)
        assertFalse(sent(Random(3), server = true).disableActiveMigration)
    }

    @Test
    fun serverOnlyParametersFromClientAreIllegal() {
        for (set in listOf<(TransportParameters) -> Unit>(
            { it.originalDstCid = ConnectionId.of(byteArrayOf(1)) },
            { it.retrySrcCid = ConnectionId.of(byteArrayOf(1)) },
            { it.statelessResetToken = ResetToken(ByteArray(16)) },
        )) {
            val p = TransportParameters.default().also(set)
            val bytes = written(p)
            assertSame(TransportParameterError.IllegalValue, assertFailsWith<TransportParameterError> { read(Side.Server, bytes) })
            assertEquals(p, read(Side.Client, bytes))
        }
    }

    @Test
    fun rangeValidation() {
        val cases = listOf<(TransportParameters) -> Unit>(
            { it.ackDelayExponent = VarInt(21) },
            { it.maxAckDelay = VarInt(1L shl 14) },
            { it.maxUdpPayloadSize = VarInt(1199) },
            { it.initialMaxStreamsBidi = VarInt(MAX_STREAM_COUNT + 1) },
            { it.initialMaxStreamsUni = VarInt(MAX_STREAM_COUNT + 1) },
        )
        for (c in cases) {
            val p = TransportParameters.default().also(c)
            assertSame(TransportParameterError.IllegalValue, assertFailsWith<TransportParameterError> { read(Side.Client, written(p)) })
        }
        // active_connection_id_limit < 2 (the default is not written, so encode it by hand)
        val low = encoded { it.writeVar(TransportParameterId.ActiveConnectionIdLimit); it.writeVar(1); it.writeVar(1) }
        assertSame(TransportParameterError.IllegalValue, assertFailsWith<TransportParameterError> { read(Side.Client, low) })
    }

    @Test
    fun duplicatesAndUnknownParameters() {
        val dup = encoded {
            it.writeVar(TransportParameterId.InitialMaxData); it.writeVar(1); it.writeVar(5)
            it.writeVar(TransportParameterId.InitialMaxData); it.writeVar(1); it.writeVar(6)
        }
        assertSame(TransportParameterError.Malformed, assertFailsWith<TransportParameterError> { read(Side.Client, dup) })
        val dupFlag = encoded { repeat(2) { _ -> it.writeVar(TransportParameterId.DisableActiveMigration); it.writeVar(0) } }
        assertSame(TransportParameterError.Malformed, assertFailsWith<TransportParameterError> { read(Side.Client, dupFlag) })
        val unknown = encoded {
            it.writeVar(0x4242); it.writeVar(3); it.writeBytes(byteArrayOf(1, 2, 3))
            it.writeVar(TransportParameterId.InitialMaxData); it.writeVar(2); it.writeVar(100)
        }
        assertEquals(VarInt(100), read(Side.Client, unknown).initialMaxData)
        val truncated = encoded { it.writeVar(TransportParameterId.InitialMaxData); it.writeVar(4); it.writeVar(1) }
        assertSame(TransportParameterError.Malformed, assertFailsWith<TransportParameterError> { read(Side.Client, truncated) })
        assertEquals(TransportErrorCode.TRANSPORT_PARAMETER_ERROR, TransportParameterError.Malformed.toTransportError().code)
    }

    @Test
    fun preferredAddressRules() {
        val token = ResetToken(ByteArray(16) { 7 })
        // Both addresses unspecified: illegal.
        val none = encoded {
            it.writeVar(TransportParameterId.PreferredAddress); it.writeVar(4 + 2 + 16 + 2 + 1 + 1 + 16)
            it.writeBytes(ByteArray(4 + 2 + 16 + 2)); it.writeByte(1); it.writeByte(9); token.encode(it)
        }
        assertSame(TransportParameterError.IllegalValue, assertFailsWith<TransportParameterError> { read(Side.Client, none) })
        // IPv6 only round-trips, with the IPv4 half absent.
        val p = TransportParameters.default().apply { preferredAddress = PreferredAddress(null, localhostV6, ConnectionId.of(byteArrayOf(1, 2)), token) }
        val back = read(Side.Client, written(p))
        assertEquals(p.preferredAddress, back.preferredAddress)
        assertNull(back.preferredAddress!!.addressV4)
    }

    @Test
    fun defaultsAreNotWritten() {
        assertEquals(0, written(TransportParameters.default()).size)
        assertNotEquals(TransportParameters.default(), TransportParameters.default().apply { greaseQuicBit = true })
    }
}
