@file:OptIn(kotlin.experimental.ExperimentalNativeApi::class)

package neton.quic.proto

import neton.quic.testkit.TestCa
import kotlin.native.OsFamily
import kotlin.native.Platform
import kotlin.test.Test
import kotlin.test.assertContentEquals
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertTrue

/** `Certificates.system()` (SPEC §11.19) and the PEM file / directory readers behind it. */
class SystemRootsTest {
    @Test
    fun theSystemHasRoots() {
        if (Platform.osFamily == OsFamily.IOS) {
            assertFailsWith<UnsupportedOperationException> { Certificates.system() }
            return
        }
        val roots = Certificates.system()
        println("system roots: ${roots.size}")
        // Every desktop and server system ships well over a hundred; a handful would mean a reader stopped early
        assertTrue(roots.size > 20, "only ${roots.size} system roots")
        // Each one is a certificate, each once
        assertEquals(roots.size, roots.toDer().map { it.toList() }.toSet().size)
        // And they make a client configuration
        TlsClientConfig(roots, listOf("h3".encodeToByteArray())).close()
    }

    @Test
    fun pemReadersSkipWhatIsNotACertificate() {
        val ca = TestCa.create("system roots test")
        val pem = ca.identity.certificates.toDer().single()
        val block = "-----BEGIN CERTIFICATE-----\n" +
            kotlin.io.encoding.Base64.Default.encode(pem).chunked(64).joinToString("\n") + "\n-----END CERTIFICATE-----\n"
        // Android's files put a text dump before the block; other blocks are skipped
        val text = "Certificate:\n    Data: ...\n" + block + "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n"
        val found = pemCertificates(text.encodeToByteArray())
        assertEquals(1, found.size)
        assertContentEquals(pem, found[0])
        assertEquals(0, pemCertificates(ByteArray(0)).size)
        assertEquals(0, pemCertificates("no certificates here".encodeToByteArray()).size)
        assertEquals(0, pemDirectory("/no/such/directory").size)
        assertEquals(null, readFileOrNull("/no/such/file"))
    }
}
