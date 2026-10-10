package neton.quic.proto

import neton.openssl.OpenSsl
import kotlin.concurrent.AtomicInt
import kotlin.concurrent.AtomicLong

/**
 * Accounting of the native TLS objects (sessions and contexts of the QUIC TLS facade; StableRefs no longer exist since its
 * callbacks moved into C, so that count stays 0), so tests
 * can check that closing sessions and configurations — on success, on every failure path, and through the cleaner
 * backstop — really frees them (SPEC §11.6 standard, applied to the TLS layer).
 */
internal object NativeTls {
    private val sessions = AtomicLong(0)
    private val contexts = AtomicLong(0)
    private val stableRefs = AtomicLong(0)

    /** SSL objects created and not yet freed. */
    val liveSessions: Long get() = sessions.value

    /** SSL_CTX references held by configurations and not yet released. */
    val liveContexts: Long get() = contexts.value

    /** Callback StableRefs created and not yet disposed. */
    val liveStableRefs: Long get() = stableRefs.value

    fun sessionOpened() { sessions.incrementAndGet() }
    fun sessionFreed() { sessions.decrementAndGet() }
    fun contextOpened() { contexts.incrementAndGet() }
    fun contextFreed() { contexts.decrementAndGet() }
    fun refCreated() { stableRefs.incrementAndGet() }
    fun refDisposed() { stableRefs.decrementAndGet() }
}

/**
 * The OpenSSL error queue is per thread and shared by every connection driven on it. Each OpenSSL call of the TLS layer
 * starts from an empty queue ([OpenSsl.clearErrors]) and drains what the call left ([drainOpenSslErrors]), so no error of
 * one connection's call is reported by — or changes the outcome of — another's.
 */
internal fun drainOpenSslErrors(): String = OpenSsl.takeErrors().split("; ").take(8).joinToString("; ")

/**
 * Exactly-once release shared by an owner's explicit `close()` and the GC cleaner backing it up (the pattern of
 * [NativeKeyResource]): whichever comes first runs [free], the other does nothing.
 */
internal class OnceRelease(private val free: () -> Unit) {
    private val released = AtomicInt(0)

    val isReleased: Boolean get() = released.value != 0

    fun release() {
        if (!released.compareAndSet(0, 1)) return
        free()
    }
}
