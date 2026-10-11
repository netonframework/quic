package neton.quic.proto

import neton.openssl.QuicTlsCredentials

// The operating system's trusted root certificates (rustls-native-certs `load_native_certs`), for clients that verify
// servers on the public Internet. As rustls-native-certs: `SSL_CERT_FILE` (a PEM bundle) and `SSL_CERT_DIR` (directories
// of PEM files, separated by ':') replace the platform's store when set; otherwise the platform's own (systemRootsDer).

/** The platform's trusted roots as DER, in no particular order; may contain duplicates. */
internal expect fun platformRootsDer(): List<ByteArray>

internal fun systemRootsDer(): List<ByteArray> {
    val file = environmentVariable("SSL_CERT_FILE")?.ifEmpty { null }
    val dirs = environmentVariable("SSL_CERT_DIR")?.ifEmpty { null }
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

private fun parsesAsCertificate(der: ByteArray): Boolean = QuicTlsCredentials.isCertificate(der)

/** Every CERTIFICATE block of a PEM document; anything else (text, other blocks) is skipped. */
internal fun pemCertificates(pem: ByteArray): List<ByteArray> =
    if (pem.isEmpty()) emptyList() else QuicTlsCredentials.pemCertificates(pem)

/** The certificates of every PEM file in [dir] (no recursion); an unreadable directory gives none. */
internal fun pemDirectory(dir: String): List<ByteArray> =
    listDirectory(dir)?.flatMap { name -> readFileOrNull("$dir/$name")?.let { pemCertificates(it) } ?: emptyList() } ?: emptyList()

/** The names in [dir] other than `.` and `..`, or null when it cannot be opened (opendir differs per platform). */
internal expect fun listDirectory(dir: String): List<String>?

/** The whole file, or null when it cannot be opened (missing, a directory on some systems, no permission). */

/** The environment variable [name], or null. */
internal expect fun environmentVariable(name: String): String?

/** The contents of the file at [path], or null when it cannot be read. */
internal expect fun readFileOrNull(path: String): ByteArray?
