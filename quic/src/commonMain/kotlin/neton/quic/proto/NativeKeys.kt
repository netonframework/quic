@file:OptIn(kotlin.concurrent.atomics.ExperimentalAtomicApi::class)

package neton.quic.proto

import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.incrementAndFetch
import kotlin.concurrent.atomics.decrementAndFetch
import kotlin.concurrent.atomics.AtomicLong

/**
 * Accounting of the native cipher contexts QUIC keys hold, so tests can check that retiring keys (discarded spaces,
 * ended key phases, drained connections, finished tokens) really frees them rather than waiting for the GC.
 */
internal object NativeKeys {
    private val liveCount = AtomicLong(0)

    /** Contexts created and not yet released. */
    val live: Long get() = liveCount.load()

    fun opened() { liveCount.incrementAndFetch() }
    fun released() { liveCount.decrementAndFetch() }
}

/**
 * One native context with exactly-once release: the owner's [release] and the GC cleaner that backs it up both go
 * through the same compare-and-set, so whichever comes first frees it and the other does nothing.
 */
internal class NativeKeyResource(private val handle: AutoCloseable) {
    private val released = AtomicInt(0)

    init { NativeKeys.opened() }

    fun release() {
        if (!released.compareAndSet(0, 1)) return
        handle.close()
        NativeKeys.released()
    }
}
