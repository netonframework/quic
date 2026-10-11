package neton.quic.proto

import java.io.File
import java.io.FileOutputStream
import java.io.IOException
import java.security.KeyStore
import java.security.cert.X509Certificate
import javax.net.ssl.TrustManagerFactory
import javax.net.ssl.X509TrustManager

/** Assertions follow the JVM's `-ea` (enabled for tests by Gradle), as debug binaries do on native. */
internal actual val DEBUG_ASSERTIONS: Boolean = Platform::class.java.desiredAssertionStatus()

private object Platform

/** No backstop on the JVM: bytecode 1.8 (and older Android) has no java.lang.ref.Cleaner; close() is the release path. */
internal actual fun <T> backstopCleaner(resource: T, release: (T) -> Unit): Any? = null

internal actual fun environmentVariable(name: String): String? = System.getenv(name)

internal actual fun readFileOrNull(path: String): ByteArray? = try {
    File(path).readBytes()
} catch (_: IOException) {
    null
} catch (_: SecurityException) {
    null
}

internal actual fun listDirectory(dir: String): List<String>? = File(dir).list()?.toList()

internal actual fun openAppendFile(path: String): ((String) -> Unit)? {
    val out = try { FileOutputStream(path, true) } catch (_: IOException) { return null }
    return { text ->
        out.write(text.toByteArray(Charsets.UTF_8))
        out.flush()
    }
}

/**
 * The JVM's default trust anchors (the platform's on Android: the system CA store, through the default
 * TrustManagerFactory; the JDK's cacerts elsewhere), as DER.
 */
internal actual fun platformRootsDer(): List<ByteArray> {
    val factory = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm())
    factory.init(null as KeyStore?)
    return factory.trustManagers.filterIsInstance<X509TrustManager>()
        .flatMap { it.acceptedIssuers.toList() }
        .map(X509Certificate::getEncoded)
}
