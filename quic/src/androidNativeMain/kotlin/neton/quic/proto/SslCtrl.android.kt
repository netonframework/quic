@file:OptIn(ExperimentalForeignApi::class)

package neton.quic.proto

import kotlinx.cinterop.CPointer
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.cstr
import neton.openssl.c.SSL_CTX_ctrl
import neton.openssl.c.SSL_CTX
import neton.openssl.c.SSL
import neton.openssl.c.SSL_ctrl

internal actual fun sslSetTlsextHostName(ssl: CPointer<SSL>, name: String): Boolean =
    SSL_ctrl(ssl, SSL_CTRL_SET_TLSEXT_HOSTNAME, TLSEXT_NAMETYPE_HOST_NAME.toLong(), name.cstr) == 1L

/** SSL_CTX_set_session_cache_mode (a macro over SSL_CTX_ctrl). */
internal actual fun sslCtxSetSessionCacheMode(ctx: CPointer<SSL_CTX>, mode: Int) {
    SSL_CTX_ctrl(ctx, SSL_CTRL_SET_SESS_CACHE_MODE, mode.toLong(), null)
}
