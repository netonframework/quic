package neton.quic.proto

// Connection timers (quinn-proto `connection/timer.rs`).

private const val NONE_NANOS: Long = Long.MIN_VALUE // Instant.NONE

/** Kinds of connection timer (timer.rs:4); the ordinal is quinn's discriminant. */
internal enum class Timer {
    /** When to send an ack-eliciting probe packet or declare unacked packets lost. */
    LossDetection,

    /** When to close the connection after no activity. */
    Idle,

    /** When the close timer expires, the connection has been gracefully terminated. */
    Close,

    /** When keys are discarded because they should not be needed anymore. */
    KeyDiscard,

    /** When to give up on validating a new path to the peer. */
    PathValidation,

    /** When to send a `PING` frame to keep the connection alive. */
    KeepAlive,

    /** When pacing will allow us to send a packet. */
    Pacing,

    /** When to invalidate old CID and proactively push new one via NEW_CONNECTION_ID frame. */
    PushNewCid,

    /** When to send an immediate ACK if there are unacked ack-eliciting packets of the peer. */
    MaxAckDelay;

    companion object {
        val VALUES: List<Timer> = entries
    }
}

/**
 * A table of data associated with each distinct kind of [Timer] (timer.rs:47). ⚖️ quinn's `[Option<Instant>; 10]`
 * is a `LongArray` of nanoseconds and [get] / [nextTimeout] return [Instant.NONE] for `None`, so reading timers
 * allocates nothing.
 */
internal class TimerTable {
    private val data = LongArray(10).also { it.fill(NONE_NANOS) }

    fun set(timer: Timer, time: Instant) {
        data[timer.ordinal] = time.nanos
    }

    /** The expiry of [timer], or [Instant.NONE] when it is stopped. */
    fun get(timer: Timer): Instant = Instant(data[timer.ordinal])

    fun stop(timer: Timer) {
        data[timer.ordinal] = NONE_NANOS
    }

    /** The earliest expiry, or [Instant.NONE] when no timer is set. */
    fun nextTimeout(): Instant {
        var min = NONE_NANOS
        for (x in data) {
            if (x != NONE_NANOS && (min == NONE_NANOS || x < min)) min = x
        }
        return Instant(min)
    }

    fun isExpired(timer: Timer, after: Instant): Boolean {
        val x = data[timer.ordinal]
        return x != NONE_NANOS && x <= after.nanos
    }

    /** quinn's `Copy`. */
    fun copy(): TimerTable = TimerTable().also { data.copyInto(it.data) }
}
