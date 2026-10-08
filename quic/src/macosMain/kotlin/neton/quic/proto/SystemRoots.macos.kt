@file:OptIn(ExperimentalForeignApi::class)

package neton.quic.proto

import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.alloc
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.value
import platform.CoreFoundation.CFArrayGetCount
import platform.CoreFoundation.CFArrayGetValueAtIndex
import platform.CoreFoundation.CFArrayRefVar
import platform.CoreFoundation.CFDataGetBytePtr
import platform.CoreFoundation.CFDataGetLength
import platform.CoreFoundation.CFRelease
import platform.Security.SecCertificateCopyData
import platform.Security.SecCertificateRef
import platform.Security.SecTrustCopyAnchorCertificates
import platform.Security.errSecSuccess

// macOS: the system's anchor certificates (SecTrustCopyAnchorCertificates), the roots the Security framework trusts by
// default. Trust settings an administrator or user changed in the keychain are not applied (rustls-native-certs reads
// them; a later addition if needed).
internal actual fun platformRootsDer(): List<ByteArray> = memScoped {
    val anchors = alloc<CFArrayRefVar>()
    if (SecTrustCopyAnchorCertificates(anchors.ptr) != errSecSuccess) return@memScoped emptyList()
    val array = anchors.value ?: return@memScoped emptyList()
    try {
        val out = ArrayList<ByteArray>()
        for (i in 0 until CFArrayGetCount(array)) {
            @Suppress("UNCHECKED_CAST")
            val cert = CFArrayGetValueAtIndex(array, i) as SecCertificateRef? ?: continue
            val data = SecCertificateCopyData(cert) ?: continue
            try {
                val len = CFDataGetLength(data).toInt()
                val bytes = CFDataGetBytePtr(data)
                if (bytes != null && len > 0) out += bytes.readBytes(len)
            } finally {
                CFRelease(data)
            }
        }
        out
    } finally {
        CFRelease(array)
    }
}
