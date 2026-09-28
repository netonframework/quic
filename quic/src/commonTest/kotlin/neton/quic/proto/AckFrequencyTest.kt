package neton.quic.proto

import neton.io.bytes.Buffer
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertTrue
import kotlin.time.Duration.Companion.microseconds
import kotlin.time.Duration.Companion.milliseconds

// connection/ack_frequency.rs tests (2), then state transitions not tested in quinn.
class AckFrequencyTest {

    private fun roundTrip(params: TransportParameters): TransportParameters {
        val buf = Buffer(64)
        params.write(buf)
        val bytes = buf.bytes()
        // peer parameters must pass wire-level validation
        return TransportParameters.read(Side.Client, Reader(bytes))
    }

    @Test
    fun peerMinAckDelayCanExceedRtt() {
        val params = TransportParameters.default().apply {
            minAckDelay = VarInt(100_000)
            maxAckDelay = VarInt(100)
        }
        val decoded = roundTrip(params)
        val state = AckFrequencyState(100.milliseconds)
        val delay = state.candidateMaxAckDelay(5.milliseconds, AckFrequencyConfig(), decoded)
        assertEquals(100.milliseconds, delay)
    }

    @Test
    fun peerMinAckDelayCanExceedRttWithLargeMax() {
        val params = TransportParameters.default().apply {
            minAckDelay = VarInt(100_000)
            maxAckDelay = VarInt(200)
        }
        val decoded = roundTrip(params)
        val state = AckFrequencyState(100.milliseconds)
        val delay = state.candidateMaxAckDelay(5.milliseconds, AckFrequencyConfig(), decoded)
        assertEquals(100.milliseconds, delay)
    }

    @Test
    fun sendingAndReceiving() {
        val peer = TransportParameters.default().apply { minAckDelay = VarInt(1000) }
        val config = AckFrequencyConfig()
        val state = AckFrequencyState(25.milliseconds)

        // Always send at startup
        assertTrue(state.shouldSendAckFrequency(100.milliseconds, config, peer))
        assertEquals(VarInt(0), state.nextSequenceNumber())
        // rtt 100 ms: the candidate is the peer's 25 ms, the current value; no error
        assertFalse(state.shouldSendAckFrequency(100.milliseconds, config, peer))
        // an explicit 10 ms request differs by more than 20%
        val tenMs = AckFrequencyConfig().maxAckDelay(10.milliseconds)
        assertTrue(state.shouldSendAckFrequency(100.milliseconds, tenMs, peer))
        // capped by max(rtt, 25 ms)
        assertEquals(25.milliseconds, state.candidateMaxAckDelay(1.milliseconds, AckFrequencyConfig().maxAckDelay(40.milliseconds), peer))

        state.ackFrequencySent(7, 40.milliseconds)
        assertEquals(40.milliseconds, state.maxAckDelayForPto())
        state.onAcked(6)
        assertEquals(25.milliseconds, state.peerMaxAckDelay)
        state.onAcked(7)
        assertEquals(40.milliseconds, state.peerMaxAckDelay)
        assertEquals(40.milliseconds, state.maxAckDelayForPto())
        assertEquals(VarInt(1), state.nextSequenceNumber())

        // Receiving
        val acks = PendingAcks()
        assertTrue(state.ackFrequencyReceived(Frame.AckFrequency(VarInt(3), VarInt(5), VarInt(10_000), VarInt(0)), acks))
        assertEquals(10_000.microseconds, state.maxAckDelay)
        // stale
        assertFalse(state.ackFrequencyReceived(Frame.AckFrequency(VarInt(3), VarInt(5), VarInt(20_000), VarInt(0)), acks))
        assertEquals(10_000.microseconds, state.maxAckDelay)
        // below the timer granularity
        assertFailsWith<TransportError> {
            state.ackFrequencyReceived(Frame.AckFrequency(VarInt(4), VarInt(5), VarInt(999), VarInt(0)), acks)
        }
    }
}
