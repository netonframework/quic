@file:OptIn(ExperimentalForeignApi::class)

package neton.quic.proto

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.cstr
import neton.openssl.c.SSL
import neton.openssl.c.SSL_ctrl

// C `long` is 32 bits on Windows.
internal actual fun sslSetTlsextHostName(ssl: CPointer<SSL>, name: String): Boolean =
    SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_HOST_NAME, name.cstr) == 1
