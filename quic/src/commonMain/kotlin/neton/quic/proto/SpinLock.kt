@file:OptIn(ExperimentalAtomicApi::class)

package neton.quic.proto

import kotlin.concurrent.atomics.AtomicInt
import kotlin.concurrent.atomics.ExperimentalAtomicApi

/**
 * ⚖️ A minimal spin lock standing in for quinn's `std::sync::Mutex` around endpoint-shared state (the token log and
 * token cache, which a server or client configuration may share between endpoints on different threads). Kotlin
 * common has no blocking mutex; the critical sections are a few hash operations.
 */
internal class SpinLock {
    private val state = AtomicInt(0)

    inline fun <T> withLock(block: () -> T): T {
        lock()
        try {
            return block()
        } finally {
            unlock()
        }
    }

    fun lock() {
        while (!state.compareAndSet(0, 1)) {
            // spin
        }
    }

    fun unlock() {
        state.store(0)
    }
}
