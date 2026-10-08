@file:OptIn(ExperimentalForeignApi::class)

package neton.quic.proto

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.toKString
import platform.posix.FILE
import platform.posix.fflush
import platform.posix.fopen
import platform.posix.fputs
import platform.posix.getenv

/**
 * Receives the TLS secrets of each session, for debugging and for tools that decrypt captured traffic (rustls `KeyLog`).
 * Given to [TlsClientConfig] / [TlsServerConfig]; no configuration logs secrets unless one is set. Called on the
 * connection's thread during the handshake; an exception thrown here is dropped.
 */
interface KeyLog {
    /**
     * One secret: [label] is the NSS key log label (`CLIENT_HANDSHAKE_TRAFFIC_SECRET`, `SERVER_TRAFFIC_SECRET_0`,
     * `EXPORTER_SECRET`, `CLIENT_EARLY_TRAFFIC_SECRET`, ...), [clientRandom] the 32-byte ClientHello random that names
     * the session.
     */
    fun log(label: String, clientRandom: ByteArray, secret: ByteArray)
}

/**
 * Appends the secrets to a file in the NSS key log format that Wireshark reads (rustls `KeyLogFile`). The file is
 * [path], by default the `SSLKEYLOGFILE` environment variable; with no path, or one that cannot be opened, nothing is
 * logged (as rustls). Shared by any number of configurations and threads.
 */
class KeyLogFile(path: String? = getenv("SSLKEYLOGFILE")?.toKString()?.ifEmpty { null }) : KeyLog {
    private val lock = SpinLock()
    private val file: CPointer<FILE>? = path?.let { fopen(it, "ab") } // binary: no CRLF on Windows

    /** Whether lines are written (a path was given and the file opened). */
    val isOpen: Boolean get() = file != null

    override fun log(label: String, clientRandom: ByteArray, secret: ByteArray) {
        val f = file ?: return
        val line = "$label ${clientRandom.toHex()} ${secret.toHex()}\n"
        lock.withLock {
            fputs(line, f)
            fflush(f)
        }
    }

    private fun ByteArray.toHex(): String {
        val out = StringBuilder(size * 2)
        for (b in this) {
            val v = b.toInt() and 0xff
            out.append(HEX[v shr 4]).append(HEX[v and 0xf])
        }
        return out.toString()
    }

    private companion object {
        const val HEX = "0123456789abcdef"
    }
}

/** Split an OpenSSL key log line (`LABEL <client random hex> <secret hex>`) and pass it on; malformed lines are dropped. */
internal fun logKeyLine(log: KeyLog, line: String) {
    val parts = line.split(' ')
    if (parts.size != 3) return
    val random = hexOrNull(parts[1]) ?: return
    val secret = hexOrNull(parts[2]) ?: return
    log.log(parts[0], random, secret)
}

private fun hexOrNull(s: String): ByteArray? {
    if (s.length % 2 != 0) return null
    val out = ByteArray(s.length / 2)
    for (i in out.indices) {
        val hi = s[2 * i].digitToIntOrNull(16) ?: return null
        val lo = s[2 * i + 1].digitToIntOrNull(16) ?: return null
        out[i] = ((hi shl 4) or lo).toByte()
    }
    return out
}
