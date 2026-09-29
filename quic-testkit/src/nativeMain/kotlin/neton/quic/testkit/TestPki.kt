@file:OptIn(ExperimentalForeignApi::class)

package neton.quic.testkit

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointer
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.UByteVar
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.toCValues
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import neton.openssl.c.ASN1_INTEGER_set_int64
import neton.openssl.c.BIO
import neton.openssl.c.BIO_free
import neton.openssl.c.BIO_new
import neton.openssl.c.BIO_new_mem_buf
import neton.openssl.c.PEM_read_bio_PrivateKey
import neton.openssl.c.d2i_X509_bio
import neton.openssl.c.BIO_read
import neton.openssl.c.BIO_s_mem
import neton.openssl.c.ERR_clear_error
import neton.openssl.c.EVP_PKEY
import neton.openssl.c.EVP_PKEY_CTX_free
import neton.openssl.c.EVP_PKEY_CTX_new_from_name
import neton.openssl.c.EVP_PKEY_CTX_set_group_name
import neton.openssl.c.EVP_PKEY_free
import neton.openssl.c.EVP_PKEY_generate
import neton.openssl.c.EVP_PKEY_keygen_init
import neton.openssl.c.EVP_sha256
import neton.openssl.c.MBSTRING_ASC
import neton.openssl.c.NID_authority_key_identifier
import neton.openssl.c.NID_basic_constraints
import neton.openssl.c.NID_ext_key_usage
import neton.openssl.c.NID_key_usage
import neton.openssl.c.NID_subject_alt_name
import neton.openssl.c.NID_subject_key_identifier
import neton.openssl.c.PEM_write_bio_PrivateKey
import neton.openssl.c.PEM_write_bio_X509
import neton.openssl.c.X509
import neton.openssl.c.X509V3_CTX
import neton.openssl.c.X509V3_EXT_conf_nid
import neton.openssl.c.X509V3_set_ctx
import neton.openssl.c.X509_EXTENSION_free
import neton.openssl.c.X509_NAME_add_entry_by_txt
import neton.openssl.c.X509_add_ext
import neton.openssl.c.X509_free
import neton.openssl.c.X509_get_serialNumber
import neton.openssl.c.X509_get_subject_name
import neton.openssl.c.X509_getm_notAfter
import neton.openssl.c.X509_getm_notBefore
import neton.openssl.c.X509_new
import neton.openssl.c.X509_set_issuer_name
import neton.openssl.c.X509_set_pubkey
import neton.openssl.c.X509_set_version
import neton.openssl.c.X509_sign
import neton.openssl.c.X509_time_adj_ex
import neton.openssl.c.i2d_X509
import neton.quic.proto.Certificates
import neton.quic.proto.PrivateKey
import kotlin.random.Random

// Test certificates generated at test time with OpenSSL's X509 API (quinn's tests use rcgen): a CA, leaf certificates
// it issues (server and client), self-signed certificates, expired ones, and big ones. Test-only (this artifact is
// never a production dependency); keys are ECDSA P-256, like rcgen's default.

/** A certificate with its private key, as DER and PEM. */
class TestIdentity internal constructor(
    val certDer: ByteArray,
    val certPem: String,
    val keyPem: String,
) {
    /** The certificate as a one-element chain. */
    val certificates: Certificates get() = Certificates.der(certDer)

    /** The private key. */
    val privateKey: PrivateKey get() = PrivateKey.pem(keyPem)

    /** This certificate followed by [issuer]'s (a chain for a leaf issued by a CA). */
    fun chainWith(issuer: TestIdentity): Certificates = Certificates.der(certDer, issuer.certDer)
}

/** A test certificate authority. */
class TestCa private constructor(val identity: TestIdentity, private val name: String) {
    /** The CA certificate, as trust anchors. */
    val trustAnchors: Certificates get() = identity.certificates

    /**
     * Issue a leaf certificate for [dnsNames] and [ipAddresses], valid from [validFromDays] to [validUntilDays] relative
     * to now, for both server and client authentication.
     */
    fun issue(
        commonName: String,
        dnsNames: List<String> = emptyList(),
        ipAddresses: List<String> = emptyList(),
        validFromDays: Int = -1,
        validUntilDays: Int = 30,
    ): TestIdentity = TestPki.generate(
        commonName, dnsNames, ipAddresses, validFromDays, validUntilDays, ca = false, issuer = this,
    )

    companion object {
        fun create(name: String = "neton quic test CA"): TestCa =
            TestCa(TestPki.generate(name, emptyList(), emptyList(), -1, 365, ca = true, issuer = null), name)
    }
}

object TestPki {
    /** A self-signed certificate (its own trust anchor), like rcgen's `generate_simple_self_signed`. */
    fun selfSigned(
        dnsNames: List<String> = listOf("localhost"),
        ipAddresses: List<String> = emptyList(),
        commonName: String = "neton quic self-signed",
        validFromDays: Int = -1,
        validUntilDays: Int = 30,
    ): TestIdentity = generate(commonName, dnsNames, ipAddresses, validFromDays, validUntilDays, ca = false, issuer = null)

    internal fun generate(
        commonName: String,
        dnsNames: List<String>,
        ipAddresses: List<String>,
        validFromDays: Int,
        validUntilDays: Int,
        ca: Boolean,
        issuer: TestCa?,
    ): TestIdentity {
        ERR_clear_error()
        val key = newP256Key()
        val issuerKey = issuer?.let { loadKey(it.identity.keyPem) }
        val issuerCert = issuer?.let { parseCert(it.identity.certDer) }
        val x = X509_new() ?: error("X509_new")
        try {
            check(X509_set_version(x, 2) == 1)
            check(ASN1_INTEGER_set_int64(X509_get_serialNumber(x), Random.nextLong(1, Long.MAX_VALUE)) == 1)
            check(X509_time_adj_ex(X509_getm_notBefore(x), validFromDays, 0, null) != null)
            check(X509_time_adj_ex(X509_getm_notAfter(x), validUntilDays, 0, null) != null)
            check(X509_set_pubkey(x, key) == 1)
            val subject = X509_get_subject_name(x)
            check(X509_NAME_add_entry_by_txt(subject, "O", MBSTRING_ASC, "neton quic tests".encodeToByteArray().asUBytes().toCValues(), -1, -1, 0) == 1)
            check(X509_NAME_add_entry_by_txt(subject, "CN", MBSTRING_ASC, commonName.encodeToByteArray().asUBytes().toCValues(), -1, -1, 0) == 1)
            check(X509_set_issuer_name(x, if (issuerCert != null) X509_get_subject_name(issuerCert) else subject) == 1)
            memScoped {
                val ctx = alloc<X509V3_CTX>()
                X509V3_set_ctx(ctx.ptr, issuerCert ?: x, x, null, null, 0)
                fun ext(nid: Int, value: String) {
                    val e = X509V3_EXT_conf_nid(null, ctx.ptr, nid, value) ?: error("extension $nid=$value")
                    try { check(X509_add_ext(x, e, -1) == 1) } finally { X509_EXTENSION_free(e) }
                }
                if (ca) {
                    ext(NID_basic_constraints, "critical,CA:TRUE")
                    ext(NID_key_usage, "critical,keyCertSign,cRLSign")
                    ext(NID_subject_key_identifier, "hash")
                } else {
                    ext(NID_basic_constraints, "critical,CA:FALSE")
                    ext(NID_key_usage, "critical,digitalSignature")
                    ext(NID_ext_key_usage, "serverAuth,clientAuth")
                    ext(NID_subject_key_identifier, "hash")
                    if (issuerCert != null) ext(NID_authority_key_identifier, "keyid")
                    val sans = dnsNames.map { "DNS:$it" } + ipAddresses.map { "IP:$it" }
                    if (sans.isNotEmpty()) ext(NID_subject_alt_name, sans.joinToString(","))
                }
            }
            check(X509_sign(x, issuerKey ?: key, EVP_sha256()) > 0) { "X509_sign" }
            return TestIdentity(der(x), pem { PEM_write_bio_X509(it, x) }, pem { PEM_write_bio_PrivateKey(it, key, null, null, 0, null, null) })
        } finally {
            X509_free(x)
            EVP_PKEY_free(key)
            issuerKey?.let { EVP_PKEY_free(it) }
            issuerCert?.let { X509_free(it) }
            ERR_clear_error()
        }
    }

    private fun ByteArray.asUBytes(): UByteArray = UByteArray(size) { this[it].toUByte() }

    private fun newP256Key(): CPointer<EVP_PKEY> {
        val ctx = EVP_PKEY_CTX_new_from_name(null, "EC", null) ?: error("EVP_PKEY_CTX_new_from_name")
        try {
            check(EVP_PKEY_keygen_init(ctx) == 1)
            check(EVP_PKEY_CTX_set_group_name(ctx, "P-256") == 1)
            return memScoped {
                val out = alloc<CPointerVar<EVP_PKEY>>()
                check(EVP_PKEY_generate(ctx, out.ptr) == 1)
                out.value!!
            }
        } finally {
            EVP_PKEY_CTX_free(ctx)
        }
    }

    private fun loadKey(pem: String): CPointer<EVP_PKEY> =
        withMemBio(pem.encodeToByteArray()) { PEM_read_bio_PrivateKey(it, null, null, null) } ?: error("issuer key")

    private fun parseCert(der: ByteArray): CPointer<X509> = withMemBio(der) { d2i_X509_bio(it, null) } ?: error("issuer certificate")

    private inline fun <T> withMemBio(bytes: ByteArray, block: (CPointer<BIO>) -> T): T = bytes.usePinned { pinned ->
        val bio = BIO_new_mem_buf(pinned.addressOf(0), bytes.size) ?: error("BIO_new_mem_buf")
        try { block(bio) } finally { BIO_free(bio) }
    }

    private fun der(x: CPointer<X509>): ByteArray {
        val len = i2d_X509(x, null)
        check(len > 0)
        val out = ByteArray(len)
        out.usePinned { pinned ->
            memScoped {
                val p = alloc<CPointerVar<UByteVar>>()
                p.value = pinned.addressOf(0).reinterpret()
                check(i2d_X509(x, p.ptr) == len)
            }
        }
        return out
    }

    private inline fun pem(write: (CPointer<BIO>) -> Int): String {
        val bio = BIO_new(BIO_s_mem()) ?: error("BIO_new")
        try {
            check(write(bio) == 1) { "PEM write" }
            val out = StringBuilder()
            memScoped {
                val buf = allocArray<ByteVar>(4096)
                while (true) {
                    val n = BIO_read(bio, buf, 4096)
                    if (n <= 0) break
                    out.append(buf.readBytes(n).decodeToString())
                }
            }
            return out.toString()
        } finally {
            BIO_free(bio)
        }
    }
}
