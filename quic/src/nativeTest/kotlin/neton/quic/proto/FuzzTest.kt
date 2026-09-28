package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import neton.io.net.SocketAddress
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertTrue
import kotlin.test.fail

/**
 * Deterministic robustness tests for the decoders, after quinn's `fuzz/fuzz_targets` (packet, params, streamid; the
 * `streams` target needs the stream state machine, not ported yet, so frames take its place). Instead of libFuzzer,
 * each target runs a fixed number of seeded inputs: random bytes, and valid encodings mutated byte-wise (flips,
 * overwrites with boundary values, insertions, deletions, truncation, duplication). Every decoder may only fail with
 * its declared error types, and whatever decodes must survive decode -> encode -> decode unchanged.
 */
class FuzzTest {

    // ---- fuzz_targets/packet.rs ----

    @Test
    fun packet() {
        val rng = Random(0x9001)
        val seeds = packetSeeds()
        val initial = initialKeys(v1, ConnectionId.of(hex("8394c8f03e515708")), Side.Server)
        var decoded = 0
        repeat(ITERATIONS) { i ->
            val data = if (i % 4 == 0) randomBytes(rng, rng.nextInt(0, 1400)) else mutate(rng, seeds[rng.nextInt(seeds.size)])
            val localCidLen = rng.nextInt(0, MAX_CID_SIZE + 1)
            val grease = rng.nextBoolean()
            val len = data.size
            var start = 0
            // Walk the coalesced packets as the endpoint does.
            while (start < len) {
                val partial = expecting<PacketDecodeError, PartialDecode>("PartialDecode.decode") {
                    PartialDecode.decode(data, start, len, FixedLengthConnectionIdParser(localCidLen), DEFAULT_SUPPORTED_VERSIONS, grease)
                } ?: break
                // The target's assertion: this packet and the rest partition the datagram.
                if (partial.hasRest) assertEquals(len - start, partial.len + (partial.restEnd - partial.restStart))
                else assertEquals(len - start, partial.len)
                decoded++
                expecting<PacketDecodeError, Packet>("PartialDecode.finish") { partial.finish(initial.header.remote) }
                    ?.let { p ->
                        assertTrue(p.headerLen > 0 && p.payloadLen >= 0 && p.payloadStart + p.payloadLen == partial.end)
                        // Decrypting garbage fails with CryptoError only.
                        val number = p.header.number
                        if (number != null) {
                            expecting<CryptoError, Int>("PacketKey.decrypt") {
                                initial.packet.remote.decrypt(
                                    number.expand(0), p.data, p.headerStart, p.headerStart + p.headerLen,
                                    p.data, p.payloadStart, p.payloadStart + p.payloadLen,
                                )
                            }
                        }
                    }
                if (!partial.hasRest) break
                start = partial.restStart
            }
        }
        assertTrue(decoded > ITERATIONS / 4, "too few inputs got past the header ($decoded)")
    }

    // ---- fuzz_targets/params.rs ----

    @Test
    fun params() {
        val rng = Random(0x7a7a)
        val seeds = paramSeeds()
        var accepted = 0
        repeat(ITERATIONS) { i ->
            val data = if (i % 4 == 0) randomBytes(rng, rng.nextInt(0, 200)) else mutate(rng, seeds[rng.nextInt(seeds.size)])
            val side = if (rng.nextBoolean()) Side.Client else Side.Server
            val params = expecting<TransportParameterError, TransportParameters>("TransportParameters.read") {
                TransportParameters.read(side, Reader(data))
            } ?: return@repeat
            accepted++
            val again = TransportParameters.read(side, Reader(encoded { params.write(it) }))
            assertEquals(params, again, "parameters changed through write / read")
        }
        assertTrue(accepted > ITERATIONS / 20, "too few inputs decoded ($accepted)")
    }

    // ---- fuzz_targets/streamid.rs ----

    @Test
    fun streamid() {
        val rng = Random(0x5151)
        repeat(ITERATIONS * 5) {
            val side = if (rng.nextBoolean()) Side.Client else Side.Server
            val dir = if (rng.nextBoolean()) Dir.Bi else Dir.Uni
            val index = rng.nextLong()
            val s = StreamId.of(side, dir, index)
            assertEquals(side, s.initiator)
            assertEquals(dir, s.dir)
            // Indices that fit (62 bits of stream ID) also come back.
            if (index ushr 60 == 0L) assertEquals(index, s.index)
        }
    }

    // ---- frames (in place of fuzz_targets/streams.rs) ----

    @Test
    fun frames() {
        val rng = Random(0xf4a3)
        val seeds = frameSeeds()
        var parsed = 0
        repeat(ITERATIONS) { i ->
            val data = if (i % 4 == 0) randomBytes(rng, rng.nextInt(0, 300)) else mutate(rng, seeds[rng.nextInt(seeds.size)])
            val iter = expecting<TransportError, FrameIter>("FrameIter") { FrameIter(data) } ?: run {
                assertEquals(0, data.size, "only an empty payload is refused up front")
                return@repeat
            }
            while (iter.hasNext()) {
                val frame = expecting<InvalidFrame, Frame>("FrameIter.next") { iter.next() } ?: break
                parsed++
                val again = FrameIter(encoded { frame.encode(it) }).asSequence().toList()
                assertEquals(listOf(frame), again, "frame changed through encode / decode")
            }
        }
        assertTrue(parsed > ITERATIONS / 2, "too few frames parsed ($parsed)")
    }

    // ---- inputs ----

    private val v1 = DEFAULT_SUPPORTED_VERSIONS[0]

    private fun packetSeeds(): List<ByteArray> {
        val dcid = ConnectionId.of(hex("8394c8f03e515708"))
        val scid = ConnectionId.of(hex("f067a5502a4262b5"))
        val keys = initialKeys(v1, dcid, Side.Client)
        fun protect(header: Header, payloadLen: Int, pn: Long): ByteArray {
            val buf = Buffer(1500)
            val enc = header.encode(buf)
            buf.writeBytes(ByteArray(payloadLen) { (it % 7).toByte() })
            if (header.number != null) buf.writeBytes(ByteArray(16))
            enc.finish(buf, keys.header.local, if (header.number != null) keys.packet.local else null, pn)
            return buf.bytes()
        }
        val initial = protect(InitialHeader(dcid, scid, Bytes.wrap(ByteArray(40) { it.toByte() }), PacketNumber.U32(2), v1), 60, 2)
        val handshake = protect(Header.Long(LongType.Handshake, dcid, scid, PacketNumber.U16(0x102), v1), 40, 0x102)
        val zeroRtt = protect(Header.Long(LongType.ZeroRtt, dcid, scid, PacketNumber.U8(1), DEFAULT_SUPPORTED_VERSIONS[3]), 30, 1)
        val short = protect(Header.Short(true, true, dcid, PacketNumber.U24(0x10203)), 30, 0x10203)
        val retry = encoded { Header.Retry(dcid, scid, v1).encode(it); it.writeBytes(ByteArray(32) { 9 }) }
        val vn = encoded { Header.VersionNegotiate(0x3a, scid, dcid).encode(it); it.writeInt(1); it.writeInt(0x0a0a0a0a) }
        return listOf(initial, handshake, zeroRtt, short, retry, vn, initial + handshake + short, handshake + zeroRtt)
    }

    private fun paramSeeds(): List<ByteArray> {
        val cid = ConnectionId.of(hex("0102030405060708"))
        fun params(server: Boolean?, cidLen: Int, rng: Random) = TransportParameters.new(
            initialSrcCid = cid,
            maxConcurrentBidiStreams = VarInt(100),
            maxConcurrentUniStreams = VarInt(3),
            receiveWindow = VarInt(1_000_000),
            streamReceiveWindow = VarInt(125_000),
            maxUdpPayloadSize = VarInt(1472),
            maxIdleTimeout = VarInt(30_000),
            serverMigration = server,
            localCidLen = cidLen,
            datagramReceiveBufferSize = 1_000_000,
            greaseQuicBit = true,
            rng = rng,
        )
        val rng = Random(1)
        val client = params(null, 8, rng)
        val server = params(false, 0, rng).apply {
            originalDstCid = ConnectionId.of(hex("aabbccdd"))
            retrySrcCid = ConnectionId.of(hex("11"))
            statelessResetToken = ResetToken(ByteArray(16) { it.toByte() })
            preferredAddress = PreferredAddress(
                SocketAddress.ipv4(192, 0, 2, 1, 443),
                SocketAddress.of(ByteArray(16).also { it[15] = 1 }, 8443),
                ConnectionId.of(hex("0908070605040302")),
                ResetToken(ByteArray(16) { (0xf0 + it).toByte() }),
            )
        }
        return listOf(encoded { client.write(it) }, encoded { server.write(it) }, ByteArray(0))
    }

    private fun frameSeeds(): List<ByteArray> {
        fun b(s: String) = Bytes.wrap(s.encodeToByteArray())
        val ranges = ArrayRangeSet().apply { insert(0, 3); insert(10, 20); insert(1000, 1001) }
        val all = listOf(
            Frame.Padding, Frame.Ping,
            Frame.ResetStream(StreamId(4), VarInt(7), VarInt(1_000_000)),
            Frame.StopSending(StreamId(3), VarInt(0x1234)),
            Frame.Crypto(0, b("client hello")),
            Frame.NewToken(b("opaque token")),
            Frame.Stream(StreamId(0), 0, false, b("hello")),
            Frame.Stream(StreamId(2), 99, true, b("offset")),
            Frame.MaxData(VarInt(1L shl 40)),
            Frame.MaxStreamData(StreamId(8), 65536),
            Frame.MaxStreams(Dir.Bi, 100),
            Frame.DataBlocked(12345),
            Frame.StreamDataBlocked(StreamId(9), 777),
            Frame.StreamsBlocked(Dir.Uni, 11),
            Frame.NewConnectionId(5, 2, ConnectionId.of(hex("0102030405060708")), ResetToken(ByteArray(16) { it.toByte() })),
            Frame.RetireConnectionId(3),
            Frame.PathChallenge(0x0123456789abcdefL),
            Frame.PathResponse(-1L),
            Frame.ConnectionClose(TransportErrorCode.PROTOCOL_VIOLATION, FrameType.STREAM_DATA_BLOCKED, b("bad")),
            Frame.ApplicationClose(VarInt(0x100), b("bye")),
            Frame.HandshakeDone,
            Frame.AckFrequency(VarInt(1), VarInt(2), VarInt(3), VarInt(4)),
            Frame.ImmediateAck,
            Frame.Datagram(b("unreliable")),
        )
        val single = all.map { f -> encoded { f.encode(it) } }
        val acks = listOf(null, EcnCounts(1, 2, 3)).map { ecn -> encoded { Frame.Ack.encode(25, ranges, ecn, it) } }
        return single + acks + listOf(encoded { out -> all.forEach { it.encode(out) } })
    }

    private fun randomBytes(rng: Random, n: Int) = ByteArray(n).also { rng.nextBytes(it) }

    /** One to four byte-level mutations of [seed]. */
    private fun mutate(rng: Random, seed: ByteArray): ByteArray {
        var d = seed.copyOf()
        repeat(rng.nextInt(1, 5)) {
            when (rng.nextInt(7)) {
                0 -> if (d.isNotEmpty()) { // flip a bit
                    val i = rng.nextInt(d.size)
                    d[i] = (d[i].toInt() xor (1 shl rng.nextInt(8))).toByte()
                }
                1 -> if (d.isNotEmpty()) d[rng.nextInt(d.size)] = INTERESTING[rng.nextInt(INTERESTING.size)]
                2 -> if (d.isNotEmpty()) d[rng.nextInt(d.size)] = rng.nextInt(256).toByte()
                3 -> { // insert bytes
                    val at = rng.nextInt(d.size + 1)
                    d = d.copyOfRange(0, at) + randomBytes(rng, rng.nextInt(1, 9)) + d.copyOfRange(at, d.size)
                }
                4 -> if (d.isNotEmpty()) { // delete a range
                    val at = rng.nextInt(d.size)
                    val n = rng.nextInt(1, minOf(8, d.size - at) + 1)
                    d = d.copyOfRange(0, at) + d.copyOfRange(at + n, d.size)
                }
                5 -> d = d.copyOf(rng.nextInt(d.size + 1)) // truncate
                else -> if (d.isNotEmpty()) { // duplicate a chunk
                    val at = rng.nextInt(d.size)
                    val n = rng.nextInt(1, minOf(16, d.size - at) + 1)
                    d = d.copyOfRange(0, at + n) + d.copyOfRange(at, d.size)
                }
            }
        }
        return d
    }

    /** Run [block]; `null` when it throws the declared error [E], a test failure for any other exception. */
    private inline fun <reified E : Throwable, T> expecting(what: String, block: () -> T): T? =
        try {
            block()
        } catch (e: Throwable) {
            if (e is E) null else fail("$what threw an undeclared ${e::class.simpleName}: ${e.message}", e)
        }

    private companion object {
        const val ITERATIONS = 20_000
        val INTERESTING = byteArrayOf(0x00, 0x01, 0x3f, 0x40, 0x7f, 0x80.toByte(), 0xbf.toByte(), 0xc0.toByte(), 0xff.toByte())
    }
}
