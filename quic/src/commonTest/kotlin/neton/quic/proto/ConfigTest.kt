package neton.quic.proto

import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertNull
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.days
import kotlin.time.Duration.Companion.milliseconds
import kotlin.time.Duration.Companion.seconds

// Not in quinn (config/ has no tests): quinn's defaults (SPEC §2.6) and the setters' validation; timers; stats.
class ConfigTest {

    @Test
    fun transportConfigDefaults() {
        val c = TransportConfig()
        assertEquals(VarInt(100), c.maxConcurrentBidiStreams)
        assertEquals(VarInt(100), c.maxConcurrentUniStreams)
        assertEquals(VarInt(30_000), c.maxIdleTimeout)
        assertEquals(VarInt(1_250_000), c.streamReceiveWindow)
        assertEquals(VarInt.MAX, c.receiveWindow)
        assertEquals(10_000_000L, c.sendWindow)
        assertTrue(c.sendFairness)
        assertEquals(3, c.packetThreshold)
        assertEquals(1.125f, c.timeThreshold)
        assertEquals(333.milliseconds, c.initialRtt)
        assertEquals(1200, c.initialMtu)
        assertEquals(1200, c.minMtu)
        assertEquals(1200, c.getInitialMtu())
        assertTrue(c.mtuDiscoveryConfig != null)
        assertFalse(c.padToMtu)
        assertNull(c.ackFrequencyConfig)
        assertEquals(3, c.persistentCongestionThreshold)
        assertNull(c.keepAliveInterval)
        assertEquals(16L * 1024, c.cryptoBufferSize)
        assertTrue(c.allowSpin)
        assertEquals(1_250_000L, c.datagramReceiveBufferSize)
        assertEquals(1024L * 1024, c.datagramSendBufferSize)
        assertTrue(c.congestionControllerFactory is CubicConfig)
        assertTrue(c.enableSegmentationOffload)
        assertFalse(c.deterministicPacketNumbers)

        val m = MtuDiscoveryConfig()
        assertEquals(600.seconds, m.interval)
        assertEquals(1452, m.upperBound)
        assertEquals(60.seconds, m.blackHoleCooldown)
        assertEquals(20, m.minimumChange)

        val a = AckFrequencyConfig()
        assertEquals(VarInt(1), a.ackElicitingThreshold)
        assertNull(a.maxAckDelay)
        assertEquals(VarInt(2), a.reorderingThreshold)
    }

    @Test
    fun transportConfigSetters() {
        val c = TransportConfig()
            .initialMtu(1000) // raised to 1200
            .minMtu(1300)
            .maxIdleTimeout(IdleTimeout.of(10.seconds))
            .congestionControllerFactory(NewRenoConfig())
        assertEquals(1200, c.initialMtu)
        assertEquals(1300, c.minMtu)
        assertEquals(1300, c.getInitialMtu())
        assertEquals(VarInt(10_000), c.maxIdleTimeout)
        c.maxIdleTimeout(null)
        assertNull(c.maxIdleTimeout)
        assertTrue(c.congestionControllerFactory is NewRenoConfig)
        assertFailsWith<IllegalArgumentException> { c.initialMtu(70_000) }
        assertFailsWith<IllegalArgumentException> { c.packetThreshold(-1) }
        assertEquals(MAX_UDP_PAYLOAD, MtuDiscoveryConfig().upperBound(65_535).upperBound)
        assertFailsWith<VarIntBoundsExceeded> { IdleTimeout.of((1L shl 62).milliseconds) }
        assertEquals(IdleTimeout(VarInt(5)), IdleTimeout.of(5.milliseconds))
    }

    @Test
    fun endpointAndValidationTokenConfig() {
        val e = EndpointConfig(object : HmacKey {
            override val signatureLen: Int get() = 32
            override fun sign(data: ByteArray, offset: Int, length: Int, signatureOut: ByteArray, outOffset: Int) {}
            override fun verify(data: ByteArray, offset: Int, length: Int, signature: ByteArray, sigOffset: Int, sigLength: Int) {}
        })
        assertEquals(1472L, e.getMaxUdpPayloadSize())
        assertContentEquals(DEFAULT_SUPPORTED_VERSIONS, e.supportedVersions)
        assertTrue(e.greaseQuicBit)
        assertEquals(20.milliseconds, e.minResetInterval)
        assertNull(e.rngSeed)
        assertTrue(e.connectionIdGeneratorFactory() is HashedConnectionIdGenerator)
        assertFailsWith<ConfigError.OutOfBounds> { e.maxUdpPayloadSize(1199) }
        assertFailsWith<ConfigError.OutOfBounds> { e.maxUdpPayloadSize(65_528) }
        assertEquals(65_527L, e.maxUdpPayloadSize(65_527).getMaxUdpPayloadSize())
        assertFailsWith<IllegalArgumentException> { e.rngSeed(ByteArray(31)) }

        val v = ValidationTokenConfig()
        assertEquals(14.days, v.lifetime)
        assertTrue(v.log is BloomTokenLog)
        assertEquals(2, v.sent)
        assertTrue(v.log(NoneTokenLog).log === NoneTokenLog)

        // Wall clock after 2020-01-01
        assertTrue(StdSystemTime.now() > (50 * 365).days)
    }

    @Test
    fun timerTable() {
        val t = TimerTable()
        assertEquals(Instant.NONE, t.nextTimeout())
        assertEquals(9, Timer.VALUES.size)
        t.set(Timer.Idle, Instant(50))
        t.set(Timer.MaxAckDelay, Instant(20))
        t.set(Timer.Pacing, Instant(30))
        assertEquals(Instant(20), t.nextTimeout())
        assertEquals(Instant(50), t.get(Timer.Idle))
        assertTrue(t.get(Timer.Close).isNone)
        assertTrue(t.isExpired(Timer.MaxAckDelay, Instant(20)))
        assertFalse(t.isExpired(Timer.Idle, Instant(20)))
        assertFalse(t.isExpired(Timer.Close, Instant(1000)))
        t.stop(Timer.MaxAckDelay)
        assertEquals(Instant(30), t.nextTimeout())
        val copy = t.copy()
        t.stop(Timer.Pacing)
        assertEquals(Instant(30), copy.nextTimeout())
        assertEquals(Instant(50), t.nextTimeout())
    }

    @Test
    fun stats() {
        val s = ConnectionStats()
        s.udpTx.onSent(3, 3600)
        s.frameTx.record(Frame.Ping)
        s.path.cwnd = 12000
        val copy = s.copy()
        s.udpTx.onSent(1, 1200)
        assertEquals(3L, copy.udpTx.datagrams)
        assertEquals(3600L, copy.udpTx.bytes)
        assertEquals(1L, copy.udpTx.ios)
        assertEquals(1L, copy.frameTx.ping)
        assertEquals(12000L, copy.path.cwnd)
        assertEquals(4L, s.udpTx.datagrams)
        assertTrue(s.toString().startsWith("ConnectionStats { udp_tx: UdpStats { datagrams: 4"))
    }
}
