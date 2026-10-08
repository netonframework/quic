@file:OptIn(ExperimentalForeignApi::class)

package neton.quic.proto

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.toKString
import neton.openssl.c.ERR_clear_error
import neton.openssl.c.PEM_read_bio_X509
import neton.openssl.c.X509_free
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread
import platform.posix.getenv

// The operating system's trusted root certificates (rustls-native-certs `load_native_certs`), for clients that verify
// servers on the public Internet. As rustls-native-certs: `SSL_CERT_FILE` (a PEM bundle) and `SSL_CERT_DIR` (directories
// of PEM files, separated by ':') replace the platform's store when set; otherwise the platform's own (systemRootsDer).

/** The platform's trusted roots as DER, in no particular order; may contain duplicates. */
internal expect fun platformRootsDer(): List<ByteArray>

internal fun systemRootsDer(): List<ByteArray> {
    val file = getenv("SSL_CERT_FILE")?.toKString()?.ifEmpty { null }
    val dirs = getenv("SSL_CERT_DIR")?.toKString()?.ifEmpty { null }
    val found = if (file != null || dirs != null) {
        val out = ArrayList<ByteArray>()
        if (file != null) readFileOrNull(file)?.let { out += pemCertificates(it) }
        dirs?.split(':')?.filter { it.isNotEmpty() }?.forEach { out += pemDirectory(it) }
        out
    } else {
        platformRootsDer()
    }
    // Duplicates (hashed links in certificate directories, the same root in several stores) are kept once
    val seen = HashSet<String>()
    return found.filter { seen.add(it.contentHashCode().toString() + ":" + it.size) && parsesAsCertificate(it) }
}

private fun parsesAsCertificate(der: ByteArray): Boolean = try {
    X509_free(parseDer(der))
    true
} catch (e: Exception) {
    ERR_clear_error()
    false
}

/** Every CERTIFICATE block of a PEM document; anything else (text, other blocks) is skipped. */
internal fun pemCertificates(pem: ByteArray): List<ByteArray> {
    val out = ArrayList<ByteArray>()
    if (pem.isEmpty()) return out
    withMemBio(pem) { bio ->
        while (true) {
            val x = PEM_read_bio_X509(bio, null, null, null) ?: break
            try { out += toDer(x) } finally { X509_free(x) }
        }
    }
    ERR_clear_error() // the "no start line" that ends the loop
    return out
}

/** The certificates of every PEM file in [dir] (no recursion); an unreadable directory gives none. */
internal fun pemDirectory(dir: String): List<ByteArray> =
    listDirectory(dir)?.flatMap { name -> readFileOrNull("$dir/$name")?.let { pemCertificates(it) } ?: emptyList() } ?: emptyList()

/** The names in [dir] other than `.` and `..`, or null when it cannot be opened (opendir differs per platform). */
internal expect fun listDirectory(dir: String): List<String>?

/** The whole file, or null when it cannot be opened (missing, a directory on some systems, no permission). */
internal fun readFileOrNull(path: String): ByteArray? {
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
