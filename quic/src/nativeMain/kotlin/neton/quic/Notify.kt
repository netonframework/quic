package neton.quic

import kotlinx.coroutines.CancellableContinuation
import kotlinx.coroutines.suspendCancellableCoroutine
import kotlin.coroutines.resume

/**
 * A wake-all signal for coroutines of one reactor (quinn uses `tokio::sync::Notify::notify_waiters`).
 *
 * ⚖️ Everything of an endpoint runs on its reactor thread, so there is no lock and no race between checking a
 * condition and starting to wait: a caller checks its condition, then calls [await], with no suspension in between.
 * A waiter that is cancelled leaves the list.
 */
internal class Notify {
    private var waiters: ArrayList<CancellableContinuation<Unit>>? = null

    /** Suspend until the next [notifyWaiters]. */
    suspend fun await() {
        suspendCancellableCoroutine { cont ->
            val list = waiters ?: ArrayList<CancellableContinuation<Unit>>(2).also { waiters = it }
            list.add(cont)
            cont.invokeOnCancellation { waiters?.remove(cont) }
        }
    }

    /** Wake every coroutine currently waiting. */
    fun notifyWaiters() {
        val list = waiters ?: return
        if (list.isEmpty()) return
        waiters = null
        for (cont in list) cont.resume(Unit)
    }
}
