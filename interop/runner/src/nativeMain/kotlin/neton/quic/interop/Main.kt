@file:OptIn(ExperimentalForeignApi::class)

package neton.quic.interop

import kotlinx.cinterop.ByteVar
import kotlinx.cinterop.CPointerVar
import kotlinx.cinterop.ExperimentalForeignApi
import kotlinx.cinterop.addressOf
import kotlinx.cinterop.alloc
import kotlinx.cinterop.allocArray
import kotlinx.cinterop.memScoped
import kotlinx.cinterop.pointed
import kotlinx.cinterop.ptr
import kotlinx.cinterop.readBytes
import kotlinx.cinterop.reinterpret
import kotlinx.cinterop.toKString
import kotlinx.cinterop.usePinned
import kotlinx.cinterop.value
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.delay
import kotlinx.coroutines.launch
import neton.io.net.SocketAddress
import neton.io.net.bindUdp
import neton.io.net.runReactor
import neton.quic.Connection
import neton.quic.Endpoint
import neton.quic.Incoming
import neton.quic.proto.Certificates
import neton.quic.proto.CipherSuite
import neton.quic.proto.ClientConfig
import neton.quic.proto.ConnectionError
import neton.quic.proto.EndpointConfig
import neton.quic.proto.KeyLogFile
import neton.quic.proto.PrivateKey
import neton.quic.proto.ServerConfig
import neton.quic.proto.TlsClientConfig
import neton.quic.proto.TlsServerConfig
import neton.quic.proto.VarInt
import neton.quic.proto.default
import neton.quic.proto.withCrypto
import platform.posix.AF_INET
import platform.posix.AF_INET6
import platform.posix.AF_UNSPEC
import platform.posix.SOCK_DGRAM
import platform.posix.addrinfo
import platform.posix.fclose
import platform.posix.fopen
import platform.posix.fread
import platform.posix.freeaddrinfo
import platform.posix.fwrite
import platform.posix.getaddrinfo
import platform.posix.getenv
import platform.posix.sockaddr_in
import platform.posix.sockaddr_in6
import kotlin.system.exitProcess

// An endpoint for the QUIC Interop Runner (https://github.com/quic-interop/quic-interop-runner, quic.md): HTTP/0.9 over
// QUIC v1 with ALPN hq-interop. The runner passes ROLE, TESTCASE, REQUESTS and SSLKEYLOGFILE; the server serves /www on
// port 443 with /certs/cert.pem and /certs/priv.key, the client saves what it downloads to /downloads. Exit status: 0
// done, 1 failed, 127 test case not supported.

private val ALPN = listOf("hq-interop".encodeToByteArray())
private const val UNSUPPORTED = 127
private const val CHUNK = 64 * 1024

// The runner's fixed locations; overridable to try the endpoint outside Docker.
private val WWW = env("NETON_INTEROP_WWW") ?: "/www"
private val DOWNLOADS = env("NETON_INTEROP_DOWNLOADS") ?: "/downloads"
private val CERTS = env("NETON_INTEROP_CERTS") ?: "/certs"
private val PORT = env("NETON_INTEROP_PORT")?.toInt() ?: 443

private val SERVER_CASES = setOf("handshake", "transfer", "chacha20", "retry", "resumption", "zerortt", "multiconnect", "ecn")
private val CLIENT_CASES = SERVER_CASES + "keyupdate"

private fun env(name: String): String? = getenv(name)?.toKString()?.ifEmpty { null }

private fun log(msg: String) = println("[neton-quic] $msg")

fun main() {
    val role = env("ROLE")
    val testcase = env("TESTCASE") ?: ""
    val supported = when (role) {
        "server" -> testcase in SERVER_CASES
        "client" -> testcase in CLIENT_CASES
        else -> { log("ROLE must be server or client, not $role"); exitProcess(1) }
    }
    if (!supported) {
        log("test case '$testcase' not supported as $role")
        exitProcess(UNSUPPORTED)
    }
    log("$role, test case $testcase")
    val ok = try {
        if (role == "server") runServer(testcase) else runClient(testcase, env("REQUESTS") ?: "")
        true
    } catch (t: Throwable) {
        log("failed: $t")
        t.printStackTrace()
        false
    }
    exitProcess(if (ok) 0 else 1)
}

private fun cipherSuites(testcase: String): List<CipherSuite> =
    if (testcase == "chacha20") listOf(CipherSuite.TLS13_CHACHA20_POLY1305_SHA256) else CipherSuite.entries

// ---- server ----

private fun runServer(testcase: String) = runReactor {
    val tls = TlsServerConfig(
        Certificates.pem(readFile("$CERTS/cert.pem")),
        PrivateKey.pem(readFile("$CERTS/priv.key")),
        ALPN,
        cipherSuites = cipherSuites(testcase),
        keyLog = KeyLogFile(),
    )
    val endpoint = Endpoint.create(EndpointConfig.default(), ServerConfig.withCrypto(tls), bindUdp(SocketAddress.of(ByteArray(16), PORT)))
    log("listening on ${endpoint.localAddr()}")
    while (true) {
        val incoming = endpoint.accept() ?: break
        if (testcase == "retry" && !incoming.remoteAddressValidated()) {
            incoming.retry()
            continue
        }
        launch { serveConnection(incoming) }
    }
}

private suspend fun CoroutineScope.serveConnection(incoming: Incoming) {
    val conn = try {
        incoming.await()
    } catch (e: ConnectionError) {
        log("handshake failed: $e")
        return
    }
    log("connection from ${conn.remoteAddress()}")
    while (true) {
        val (send, recv) = try { conn.acceptBi() } catch (e: ConnectionError) { break }
        launch {
            try {
                val request = recv.readToEnd(4096).decodeToString()
                val path = parseRequest(request)
                if (path == null) {
                    log("bad request '${request.trim()}'")
                    send.reset(VarInt(0x10))
                    return@launch
                }
                val f = fopen("$WWW$path", "rb")
                if (f == null) {
                    log("not found: $path")
                    send.reset(VarInt(0x11))
                    return@launch
                }
                try {
                    val buf = ByteArray(CHUNK)
                    while (true) {
                        val n = buf.usePinned { fread(it.addressOf(0), 1u, CHUNK.toULong(), f).toInt() }
                        if (n <= 0) break
                        send.writeAll(buf, 0, n)
                    }
                } finally {
                    fclose(f)
                }
                send.finish()
            } catch (e: Exception) {
                log("stream ${send.id}: $e")
            }
        }
    }
    log("connection from ${conn.remoteAddress()} ended: ${conn.closeReason()}")
}

/** The path of an HTTP/0.9 request (`GET /path`), or null; no `..` segments. */
private fun parseRequest(request: String): String? {
    val line = request.trim()
    if (!line.startsWith("GET /")) return null
    val path = line.removePrefix("GET ").substringBefore(' ')
    if (path.split('/').any { it == ".." }) return null
    return path
}

// ---- client ----

private class Request(val host: String, val port: Int, val path: String) {
    val fileName: String get() = path.substringAfterLast('/')
}

private fun parseUrl(url: String): Request {
    require(url.startsWith("https://")) { "not an https URL: $url" }
    val rest = url.removePrefix("https://")
    val authority = rest.substringBefore('/')
    val path = "/" + rest.substringAfter('/', "")
    val host: String
    val port: Int
    if (authority.startsWith("[")) {
        host = authority.substring(1, authority.indexOf(']'))
        port = authority.substringAfter("]:", "443").toInt()
    } else {
        host = authority.substringBefore(':')
        port = authority.substringAfter(':', "443").toInt()
    }
    return Request(host, port, path)
}

private fun runClient(testcase: String, requestList: String) {
    val requests = requestList.split(' ').filter { it.isNotEmpty() }.map(::parseUrl)
    require(requests.isNotEmpty()) { "no REQUESTS" }
    val first = requests.first()
    val server = resolve(first.host, first.port)
    log("server ${first.host} is $server; ${requests.size} request(s)")
    runReactor {
        val tls = TlsClientConfig.dangerousNoServerVerificationForTestsOnly(
            ALPN,
            cipherSuites = cipherSuites(testcase),
            enableEarlyData = testcase == "zerortt",
            keyLog = KeyLogFile(),
        )
        val local = if (server.family == 6) SocketAddress.IPV6_UNSPECIFIED_ANY_PORT else SocketAddress.IPV4_UNSPECIFIED_ANY_PORT
        val endpoint = Endpoint.create(EndpointConfig.default(), null, bindUdp(local))
        endpoint.setDefaultClientConfig(ClientConfig(tls))
        when (testcase) {
            "multiconnect" -> for (r in requests) {
                val conn = endpoint.connect(server, r.host).await()
                download(conn, listOf(r))
                closeAndWait(conn)
            }
            "resumption", "zerortt" -> {
                val conn = endpoint.connect(server, first.host).await()
                download(conn, listOf(first))
                // The session tickets come right after the handshake; one more round trip makes sure they are in.
                delay(conn.rtt())
                closeAndWait(conn)
                val rest = requests.drop(1)
                val connecting = endpoint.connect(server, first.host)
                val again = if (testcase == "zerortt") {
                    val early = connecting.into0Rtt()
                    if (early == null) {
                        log("no 0-RTT: no usable ticket")
                        connecting.await()
                    } else {
                        val (c, accepted) = early
                        launch { log("0-RTT accepted: ${accepted.await()}") }
                        c
                    }
                } else {
                    connecting.await()
                }
                download(again, rest)
                closeAndWait(again)
            }
            else -> {
                val conn = endpoint.connect(server, first.host).await()
                if (testcase == "keyupdate") updateKeysEarly(conn)
                download(conn, requests)
                closeAndWait(conn)
            }
        }
        endpoint.waitIdle()
        endpoint.close()
    }
    log("done")
}

/**
 * Start a key update early in the transfer (the keyupdate test wants packets in key phase 1 from both sides). One is
 * allowed only after a packet sent with the current keys was acknowledged (RFC 9001 §6.1), so ask a few times; each
 * granted request is a separate, legal update.
 */
private fun CoroutineScope.updateKeysEarly(conn: Connection) = launch {
    repeat(10) {
        delay(50)
        conn.forceKeyUpdate()
    }
}

/** Request every file on its own stream, all at once (stream limits make later ones wait), saving each to /downloads. */
private suspend fun download(conn: Connection, requests: List<Request>) = kotlinx.coroutines.coroutineScope {
    for (r in requests) launch { fetch(conn, r) }
}

private suspend fun fetch(conn: Connection, r: Request) {
    val (send, recv) = conn.openBi()
    send.writeAll("GET ${r.path}\r\n".encodeToByteArray())
    send.finish()
    val out = fopen("$DOWNLOADS/${r.fileName}", "wb") ?: error("cannot create $DOWNLOADS/${r.fileName}")
    var total = 0L
    try {
        val buf = ByteArray(CHUNK)
        while (true) {
            val n = recv.read(buf)
            if (n < 0) break
            if (n > 0) buf.usePinned { fwrite(it.addressOf(0), 1u, n.toULong(), out) }
            total += n
        }
    } finally {
        fclose(out)
    }
    log("${r.path}: $total bytes")
}

private suspend fun closeAndWait(conn: Connection) {
    conn.close(VarInt(0), ByteArray(0))
    conn.closed()
}

// ---- helpers ----

/** The first address of [host] (getaddrinfo, as the runner's names are in /etc/hosts). */
private fun resolve(host: String, port: Int): SocketAddress = memScoped {
    val hints = alloc<addrinfo>()
    hints.ai_family = AF_UNSPEC
    hints.ai_socktype = SOCK_DGRAM
    val res = alloc<CPointerVar<addrinfo>>()
    val rc = getaddrinfo(host, port.toString(), hints.ptr, res.ptr)
    check(rc == 0 && res.value != null) { "cannot resolve $host: $rc" }
    try {
        val ai = res.value!!.pointed
        when (ai.ai_family) {
            AF_INET -> {
                val sin = ai.ai_addr!!.reinterpret<sockaddr_in>().pointed
                SocketAddress.of(sin.sin_addr.ptr.reinterpret<ByteVar>().readBytes(4), port)
            }
            AF_INET6 -> {
                val sin6 = ai.ai_addr!!.reinterpret<sockaddr_in6>().pointed
                SocketAddress.of(sin6.sin6_addr.ptr.reinterpret<ByteVar>().readBytes(16), port)
            }
            else -> error("$host: address family ${ai.ai_family}")
        }
    } finally {
        freeaddrinfo(res.value)
    }
}

private fun readFile(path: String): ByteArray {
    val f = fopen(path, "rb") ?: error("cannot open $path")
    try {
        val out = ArrayList<ByteArray>()
        memScoped {
            val buf = allocArray<ByteVar>(CHUNK)
            while (true) {
                val n = fread(buf, 1u, CHUNK.toULong(), f).toInt()
                if (n <= 0) break
                out += buf.readBytes(n)
            }
        }
        val all = ByteArray(out.sumOf { it.size })
        var at = 0
        for (b in out) { b.copyInto(all, at); at += b.size }
        return all
    } finally {
        fclose(f)
    }
}
