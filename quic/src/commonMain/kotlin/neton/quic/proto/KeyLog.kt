package neton.quic.proto

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
class KeyLogFile(path: String? = environmentVariable("SSLKEYLOGFILE")?.ifEmpty { null }) : KeyLog {
    private val lock = SpinLock()
    private val file: ((String) -> Unit)? = path?.let { openAppendFile(it) }

    /** Whether lines are written (a path was given and the file opened). */
    val isOpen: Boolean get() = file != null

    override fun log(label: String, clientRandom: ByteArray, secret: ByteArray) {
        val f = file ?: return
        val line = "$label ${clientRandom.toHex()} ${secret.toHex()}\n"
        lock.withLock { f(line) }
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

/** An appender for the file at [path] (created if missing, written in binary, flushed per call), or null. */
internal expect fun openAppendFile(path: String): ((String) -> Unit)?

/**
 * Runs [release] on [resource] once the object holding the result becomes unreachable (Kotlin/Native's createCleaner):
 * a backstop only, explicit close is the release path. Null where there is none (the JVM: bytecode 1.8 has no
 * java.lang.ref.Cleaner).
 */
internal expect fun <T> backstopCleaner(resource: T, release: (T) -> Unit): Any?
