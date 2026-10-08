package neton.quic.proto

// Android's system CA store: one PEM file per root (with a text dump before the block). Since Android 14 the roots
// are updatable through the Conscrypt APEX, which takes precedence over the system image's copy. User-added CAs are
// not trusted, as for apps that target API 24 and above.
private val DIRECTORIES = listOf("/apex/com.android.conscrypt/cacerts", "/system/etc/security/cacerts")

internal actual fun platformRootsDer(): List<ByteArray> {
    for (dir in DIRECTORIES) {
        val certs = pemDirectory(dir)
        if (certs.isNotEmpty()) return certs
    }
    return emptyList()
}
