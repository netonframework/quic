package neton.quic.proto

import neton.io.bytes.Buffer

/** Bytes from a hex string; whitespace is ignored (the reference tests' `hex!`). */
fun hex(s: String): ByteArray {
    val clean = s.filter { !it.isWhitespace() }
    require(clean.length % 2 == 0)
    return ByteArray(clean.length / 2) { clean.substring(2 * it, 2 * it + 2).toInt(16).toByte() }
}

fun ByteArray.hexString(): String = toHex()

/** The readable bytes of a buffer, as a new array, without consuming them. */
fun Buffer.bytes(): ByteArray = peekAll()

/** Encode with [block] into a fresh buffer and return the bytes. */
inline fun encoded(block: (Buffer) -> Unit): ByteArray {
    val b = Buffer(64)
    block(b)
    return b.peekAll()
}

/** A header key that leaves the header unchanged (tests only: the layout, not the cryptography, is under test). */
class NoHeaderProtection(override val sampleSize: Int = 16) : HeaderKey {
    override fun decrypt(pnOffset: Int, packet: ByteArray, start: Int, end: Int) {}
    override fun encrypt(pnOffset: Int, packet: ByteArray, start: Int, end: Int) {}
}
