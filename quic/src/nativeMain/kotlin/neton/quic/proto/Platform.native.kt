@file:OptIn(ExperimentalForeignApi::class, ExperimentalNativeApi::class)

package neton.quic.proto

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.toKString
import kotlin.experimental.ExperimentalNativeApi
import kotlin.native.ref.createCleaner
import platform.posix.FILE
import platform.posix.fclose
import platform.posix.fflush
import platform.posix.fopen
import platform.posix.fputs
import platform.posix.fread
import platform.posix.getenv

/** The resource and its release, so that the cleaner's own function captures nothing (createCleaner requires it). */
private class CleanupTask<T>(private val resource: T, private val release: (T) -> Unit) {
    fun run() = release(resource)
}

internal actual fun <T> backstopCleaner(resource: T, release: (T) -> Unit): Any? =
    createCleaner(CleanupTask(resource, release)) { it.run() }

internal actual fun environmentVariable(name: String): String? = getenv(name)?.toKString()

internal actual fun openAppendFile(path: String): ((String) -> Unit)? {
    val f: CPointer<FILE> = fopen(path, "ab") ?: return null // binary: no CRLF on Windows
    return { text -> fputs(text, f); fflush(f) }
}

internal actual fun readFileOrNull(path: String): ByteArray? {
    val f = fopen(path, "rb") ?: return null
    try {
        val chunks = ArrayList<ByteArray>()
        memScoped {
            val buf = allocArray<ByteVar>(CHUNK)
            while (true) {
                val n = fread(buf, 1u, CHUNK.toULong(), f).toInt()
                if (n <= 0) break
                chunks += buf.readBytes(n)
            }
        }
        val all = ByteArray(chunks.sumOf { it.size })
        var at = 0
        for (c in chunks) { c.copyInto(all, at); at += c.size }
        return all
    } finally {
        fclose(f)
    }
}

private const val CHUNK = 64 * 1024
