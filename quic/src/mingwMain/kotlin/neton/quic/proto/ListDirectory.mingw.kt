@file:OptIn(ExperimentalForeignApi::class)

package neton.quic.proto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.pointed
import kotlinx.cinterop.toKString
import platform.posix.closedir
import platform.posix.opendir
import platform.posix.readdir

internal actual fun listDirectory(dir: String): List<String>? {
    val d = opendir(dir) ?: return null
    try {
        val out = ArrayList<String>()
        while (true) {
            val name = readdir(d)?.pointed?.d_name?.toKString() ?: break
            if (name != "." && name != "..") out += name
        }
        return out
    } finally {
        closedir(d)
    }
}
