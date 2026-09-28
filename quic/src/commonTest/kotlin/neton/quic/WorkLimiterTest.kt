package neton.quic

import kotlin.test.Test
import kotlin.test.assertEquals

/** quinn `work_limiter.rs` tests. */
class WorkLimiterTest {
    /** Mocked time, in nanoseconds. */
    private var time = 0L
    private val getTime = NanoClock { time }

    private fun advanceTime(nanos: Long) {
        time += nanos
    }

    @Test
    fun limitWork() {
        val cycleTime = 500_000_000L
        val batchWorkItems = 12
        val batchTime = 100_000_000L

        val expectedInitialBatches = (cycleTime / batchTime).toInt()
        val expectedAllowedWorkItems = expectedInitialBatches * batchWorkItems

        val limiter = WorkLimiter(cycleTime)
        time = 1_000_000_000L

        // The initial cycle is measuring
        limiter.startCycle(getTime)
        var initialBatches = 0
        while (limiter.allowWork(getTime)) {
            limiter.recordWork(batchWorkItems)
            advanceTime(batchTime)
            initialBatches += 1
        }
        limiter.finishCycle(getTime)

        assertEquals(expectedInitialBatches, initialBatches)
        assertEquals(expectedAllowedWorkItems.toLong(), limiter.allowed)
        val initialTimePerWorkItem = limiter.smoothedTimePerWorkItemNanos

        // The next cycles are using historic data
        val batchSizes = intArrayOf(1, 2, 3, 5)
        for (batchSize in batchSizes) {
            limiter.startCycle(getTime)
            var allowedWork = 0
            while (limiter.allowWork(getTime)) {
                limiter.recordWork(batchSize)
                allowedWork += batchSize
            }
            limiter.finishCycle(getTime)

            assertEquals(expectedAllowedWorkItems, allowedWork)
        }

        // After `SAMPLING_INTERVAL`, we get into measurement mode again
        repeat(WorkLimiter.SAMPLING_INTERVAL - batchSizes.size - 1) {
            limiter.startCycle(getTime)
            limiter.recordWork(1)
            limiter.finishCycle(getTime)
        }

        // We now do more work per cycle, and expect the estimate of allowed work items to go up
        val batchWorkItems2 = 96
        val timePerWorkItems2Nanos = cycleTime.toDouble() / (expectedInitialBatches * batchWorkItems2).toDouble()

        val expectedUpdatedTimePerWorkItem = (initialTimePerWorkItem * 7.0 + timePerWorkItems2Nanos) / 8.0
        val expectedUpdatedAllowedWorkItems = (cycleTime.toDouble() / expectedUpdatedTimePerWorkItem).toLong()

        limiter.startCycle(getTime)
        initialBatches = 0
        while (limiter.allowWork(getTime)) {
            limiter.recordWork(batchWorkItems2)
            advanceTime(batchTime)
            initialBatches += 1
        }
        limiter.finishCycle(getTime)

        assertEquals(expectedInitialBatches, initialBatches)
        assertEquals(expectedUpdatedAllowedWorkItems, limiter.allowed)
    }
}
