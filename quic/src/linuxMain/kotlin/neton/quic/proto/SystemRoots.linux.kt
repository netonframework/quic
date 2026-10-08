package neton.quic.proto

// The distributions' CA bundles (openssl-probe's list, which rustls-native-certs uses): the first one present wins;
// without any, the hashed certificate directory.
private val BUNDLES = listOf(
    "/etc/ssl/certs/ca-certificates.crt", // Debian, Ubuntu, Gentoo, Arch
    "/etc/pki/tls/certs/ca-bundle.crt", // Fedora, RHEL 6
    "/etc/pki/ca-trust/extracted/pem/tls-ca-bundle.pem", // RHEL 7+, Rocky, Alma
    "/etc/ssl/ca-bundle.pem", // openSUSE
    "/etc/pki/tls/cacert.pem", // OpenELEC
    "/etc/ssl/cert.pem", // Alpine
    "/opt/etc/ssl/certs/ca-certificates.crt", // Entware
)

private val DIRECTORIES = listOf("/etc/ssl/certs", "/etc/pki/tls/certs")

internal actual fun platformRootsDer(): List<ByteArray> {
    for (path in BUNDLES) {
        val certs = readFileOrNull(path)?.let { pemCertificates(it) }
        if (!certs.isNullOrEmpty()) return certs
    }
    return DIRECTORIES.flatMap { pemDirectory(it) }
}
