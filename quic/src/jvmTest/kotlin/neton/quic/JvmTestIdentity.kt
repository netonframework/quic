package neton.quic

/**
 * A fixed self-signed P-256 certificate for CN=localhost (SAN DNS:localhost, IP:127.0.0.1), valid until 2125, generated
 * once with the OpenSSL command line (2026-10-11). Tests only: the JVM cannot generate certificates as the native tests'
 * TestPki does.
 */
internal object JvmTestIdentity {
    const val CERTIFICATE_PEM = """
-----BEGIN CERTIFICATE-----
MIIBmzCCAUGgAwIBAgIULG2s9UnTRxtCMyvJpHmJ9RJOlIUwCgYIKoZIzj0EAwIw
FDESMBAGA1UEAwwJbG9jYWxob3N0MCAXDTI2MDEwMTAwMDAwMFoYDzIxMjUxMjMx
MDAwMDAwWjAUMRIwEAYDVQQDDAlsb2NhbGhvc3QwWTATBgcqhkjOPQIBBggqhkjO
PQMBBwNCAAREcrIqlX250aqRcnA9L6zTi87ChZ1byp0B/vPgn6zsikmM2QkMmFfz
Di3OOv1/uQogxqjp3MAYhNyfGx+uWorOo28wbTAdBgNVHQ4EFgQUeqT0AcLE56Vs
T6miR1Tsn452PJUwHwYDVR0jBBgwFoAUeqT0AcLE56VsT6miR1Tsn452PJUwDwYD
VR0TAQH/BAUwAwEB/zAaBgNVHREEEzARgglsb2NhbGhvc3SHBH8AAAEwCgYIKoZI
zj0EAwIDSAAwRQIgE8UptQolcbP+rsJvP2Ip2M4D6g31ddqnoXD+eHHzxJECIQCo
BPvyRrFNxICEsrPluRCn72kLejlWCI0CfWjrTYZ9JA==
-----END CERTIFICATE-----
"""

    const val PRIVATE_KEY_PEM = """
-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgxdQDKpOe7dh4VzxW
5QgRwZxaCqB0Hmjg5DLTv4YFZ6ihRANCAAREcrIqlX250aqRcnA9L6zTi87ChZ1b
yp0B/vPgn6zsikmM2QkMmFfzDi3OOv1/uQogxqjp3MAYhNyfGx+uWorO
-----END PRIVATE KEY-----
"""
}
