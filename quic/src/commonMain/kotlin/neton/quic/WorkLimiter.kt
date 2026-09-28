package neton.quic

// quinn `work_limiter.rs`: limits the amount of time spent on a certain type of work in a cycle.
//
// ⚖️ Time is a `Long` of nanoseconds from a caller-supplied [NanoClock] (quinn passes `impl Fn() -> Instant`; a Kotlin
// `() -> Long` would box every reading): the receive loop feeds it a clock that excludes the time spent parked on an
// empty socket, because a coroutine cannot poll the socket without suspending (see `Endpoint`).

/** A monotonic clock in nanoseconds. */
internal fun interface NanoClock {
    fun nanos(): Long
}

/**
 * Limits the amount of time spent on a certain type of work in a cycle (work_limiter.rs:19).
 *
 * The limiter works dynamically: for a sampled subset of cycles it measures the time that is approximately required
 * for fulfilling 1 work item, and calculates the amount of allowed work items per cycle. The estimates are smoothed
 * over all cycles where the exact duration is measured. In cycles where no measurement is performed the previously
 * determined work limit is used.
 *
 * For the limiter the exact definition of a work item does not matter: it could for example track the amount of
 * transmitted bytes per cycle, or the amount of transmitted datagrams per cycle. It will however work best if the
 * required time to complete a work item is constant.
 */
internal class WorkLimiter(
    /** The desired cycle time, in nanoseconds. */
    private val desiredCycleTimeNanos: Long,
) {
    /** Whether to measure the required work time, or to use the previous estimates. */
    private var measuring = true

    /** The current cycle number (a `u16` in quinn). */
    private var cycle = 0

    /** The time the cycle started; only used in measurement mode. */
    private var startTime = 0L

    /** How many work items have been completed in the cycle. */
    private var completed = 0L

    /** The amount of work items which are allowed for a cycle. */
    internal var allowed = 0L
        private set

    /** The estimated and smoothed time per work item in nanoseconds. */
    internal var smoothedTimePerWorkItemNanos = 0.0
        private set

    /** Starts one work cycle. */
    fun startCycle(now: NanoClock) {
        completed = 0
        if (measuring) startTime = now.nanos()
    }

    /** Returns whether more work can be performed inside the desired cycle time. */
    fun allowWork(now: NanoClock): Boolean =
        if (measuring) now.nanos() - startTime < desiredCycleTimeNanos else completed < allowed

    /** Records that [work] additional work items have been completed inside the cycle. */
    fun recordWork(work: Int) {
        completed += work
    }

    /**
     * Finishes one work cycle. For cycles where the exact duration is measured this updates the estimates for the
     * time per work item and the limit of allowed work items per cycle, with the same exponential smoothing as QUIC
     * path RTTs: the last value is weighted by 1/8, the previous average by 7/8.
     */
    fun finishCycle(now: NanoClock) {
        // If no work was done in the cycle drop the measurement, it won't be useful
        if (completed == 0L) return

        if (measuring) {
            val elapsed = now.nanos() - startTime
            val timePerWorkItemNanos = elapsed.toDouble() / completed.toDouble()

            // Calculate the time per work item. We set this to at least 1ns to avoid dividing by 0 when calculating
            // the allowed amount of work items.
            smoothedTimePerWorkItemNanos = (
                if (allowed == 0L) {
                    timePerWorkItemNanos // Initial estimate
                } else {
                    (7.0 * smoothedTimePerWorkItemNanos + timePerWorkItemNanos) / 8.0 // Smoothed estimate
                }
                ).coerceAtLeast(1.0)

            // Allow at least 1 work item in order to make progress
            allowed = (desiredCycleTimeNanos.toDouble() / smoothedTimePerWorkItemNanos).toLong().coerceAtLeast(1)
        }

        cycle = (cycle + 1) and 0xFFFF
        measuring = cycle % SAMPLING_INTERVAL == 0
    }

    internal companion object {
        /** We take a measurement sample once every `SAMPLING_INTERVAL` cycles. */
        const val SAMPLING_INTERVAL = 256
    }
}
