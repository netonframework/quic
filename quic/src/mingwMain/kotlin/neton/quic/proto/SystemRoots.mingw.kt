@file:OptIn(ExperimentalForeignApi::class)

package neton.quic.proto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.pointed
import kotlinx.cinterop.readBytes
import platform.windows.CertCloseStore
import platform.windows.CertEnumCertificatesInStore
import platform.windows.CertOpenSystemStoreW

// Windows: the certificates of the system "ROOT" store (CertOpenSystemStore), as rustls-native-certs reads it. Roots
// Windows would fetch on demand (automatic root update) are not there until something has used them.
internal actual fun platformRootsDer(): List<ByteArray> {
    val store = CertOpenSystemStoreW(0u, "ROOT") ?: return emptyList()
    try {
        val out = ArrayList<ByteArray>()
        var ctx = CertEnumCertificatesInStore(store, null)
        while (ctx != null) {
            val c = ctx.pointed
            val bytes = c.pbCertEncoded
            if (bytes != null && c.cbCertEncoded > 0u) out += bytes.readBytes(c.cbCertEncoded.toInt())
            ctx = CertEnumCertificatesInStore(store, ctx) // frees the previous context
        }
        return out
    } finally {
        CertCloseStore(store, 0u)
    }
}
