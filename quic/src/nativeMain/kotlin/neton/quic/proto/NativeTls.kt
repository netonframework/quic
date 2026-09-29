@file:OptIn(ExperimentalForeignApi::class)

package neton.quic.proto

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.toKString
import neton.openssl.c.ERR_clear_error
import neton.openssl.c.neton_openssl_next_error
import kotlin.concurrent.AtomicInt
import kotlin.concurrent.AtomicLong

/**
 * Accounting of the native TLS objects (SSL, SSL_CTX, the StableRefs handed to OpenSSL as callback arguments), so tests
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
 * starts from an empty queue ([ERR_clear_error]) and drains what the call left ([drainOpenSslErrors]), so no error of
 * one connection's call is reported by — or changes the outcome of — another's.
 */
internal fun drainOpenSslErrors(): String = memScoped {
    val buffer = allocArray<ByteVar>(256)
    val messages = ArrayList<String>(2)
    while (neton_openssl_next_error(buffer, 256u) != 0) {
        if (messages.size < 8) messages += buffer.toKString()
    }
    ERR_clear_error()
    messages.joinToString("; ")
}

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
