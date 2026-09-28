package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import kotlin.random.Random
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertTrue

// Beyond the reference: frames written by `StreamsState` decode as intended, and the primitive collections and
// the pending-stream heap behave like straightforward reference models.
class StreamsFramesTest {

    private fun make(side: Side): StreamsState =
        StreamsState(side, VarInt(128), VarInt(128), 1024 * 1024, VarInt(1024 * 1024), VarInt(1024 * 1024))

    private fun decode(buf: Buffer): List<Frame> = FrameIter(buf.bytes()).asSequence().toList()

    @Test
    fun writeControlFramesEncodesEveryQueuedFrame() {
        val client = make(Side.Client)
        client.setParams(params {
            initialMaxStreamsBidi = VarInt(4)
            initialMaxData = VarInt(10)
            initialMaxStreamDataBidiRemote = VarInt(5)
        })
        val pending = Retransmits()
        val streams = Streams(client, false)
        val a = streams.open(Dir.Bi)!!
        val b = streams.open(Dir.Bi)!!

        // STREAM_DATA_BLOCKED on a: its stream window (5) is exhausted
        val sa = SendStream(a, client, pending, false)
        assertEquals(5, sa.write(ByteArray(8)).bytes())
        assertEquals(WriteError.Blocked, sa.write(ByteArray(1)))
        assertTrue(a.value in pending.streamDataBlocked)
        // DATA_BLOCKED: the connection window (10) is exhausted by b
        val sb = SendStream(b, client, pending, false)
        assertEquals(5, sb.write(ByteArray(5)).bytes())
        assertEquals(WriteError.Blocked, sb.write(ByteArray(1)))
        assertTrue(pending.dataBlocked)
        // RESET_STREAM on b
        sb.reset(VarInt(7))
        // Incoming data on a server stream, then read and stop it: MAX_DATA, MAX_STREAMS and STOP_SENDING
        val sid = StreamId.of(Side.Server, Dir.Uni, 0)
        client.received(Frame.Stream(sid, 0, true, zeros(300_000)), 300_000)
        RecvStream(sid, client, pending).read(true).use { c ->
            assertIs<Chunk>(c.next(Int.MAX_VALUE))
            assertEquals(ReadResult.Finished, c.next(Int.MAX_VALUE))
        }
        assertTrue(pending.maxData)
        // MAX_STREAM_DATA for a: read half a window of a's receive side
        client.received(Frame.Stream(a, 0, false, zeros(200_000)), 200_000)
        RecvStream(a, client, pending).read(true).use { c -> assertIs<Chunk>(c.next(Int.MAX_VALUE)) }
        assertTrue(a.value in pending.maxStreamData)
        // MAX_STREAMS: queue explicitly (the threshold is 1/8 of 128 streams)
        pending.maxStreamId[Dir.Uni.ordinal] = true
        // STOP_SENDING
        val sid2 = StreamId.of(Side.Server, Dir.Uni, 1)
        client.received(Frame.Stream(sid2, 0, false, zeros(1)), 1)
        RecvStream(sid2, client, pending).stop(VarInt(9))

        val buf = Buffer(1200)
        val retransmits = ThinRetransmits()
        val stats = FrameStats()
        client.writeControlFrames(buf, pending, retransmits, stats, 1200)
        val frames = decode(buf)

        assertEquals(
            listOf(
                Frame.ResetStream(b, VarInt(7), VarInt(5)),
                Frame.StopSending(sid2, VarInt(9)),
                Frame.MaxData(VarInt(1024 * 1024 + 300_000 + 200_000 + 1)),
                Frame.MaxStreamData(a, 200_000L + 1024 * 1024),
                Frame.MaxStreams(Dir.Uni, 129),
                Frame.DataBlocked(10),
                Frame.StreamDataBlocked(a, 5),
            ),
            frames,
        )
        assertTrue(pending.isEmpty(client), "everything was written")
        val r = retransmits.get()!!
        assertEquals(listOf(StreamReset(b, VarInt(7))), r.resetStream)
        assertEquals(1, r.stopSending.size)
        assertTrue(r.maxData && r.dataBlocked && r.maxStreamId[Dir.Uni.ordinal])
        assertEquals(setOf(a.value), r.maxStreamData.toSet())
        assertEquals(setOf(a.value), r.streamDataBlocked.toSet())
        assertEquals(1L, stats.resetStream)
        assertEquals(1L, stats.stopSending)
        assertEquals(1L, stats.maxData)
        assertEquals(1L, stats.maxStreamData)
        assertEquals(1L, stats.maxStreamsUni)
        assertEquals(1L, stats.dataBlocked)
        assertEquals(1L, stats.streamDataBlocked)

        // Retransmitting the lost control frames re-queues them
        val again = Retransmits()
        again.orAssign(retransmits)
        assertFalse(again.isEmpty(client))
    }

    @Test
    fun writeControlFramesRespectsMaxSize() {
        val client = make(Side.Client)
        val pending = Retransmits()
        repeat(3) { pending.stopSending.add(Frame.StopSending(StreamId.of(Side.Server, Dir.Uni, it.toLong()), VarInt(1))) }
        val buf = Buffer(64)
        // STOP_SENDING needs `len + 17 < max`: room for exactly one at 18..34
        client.writeControlFrames(buf, pending, ThinRetransmits(), FrameStats(), 20)
        assertEquals(1, decode(buf).size)
        assertEquals(2, pending.stopSending.size)
        // quinn pops from the end of the Vec
        assertEquals(Frame.StopSending(StreamId.of(Side.Server, Dir.Uni, 2), VarInt(1)), decode(buf)[0])
    }

    /** STREAM frames carry the right bytes, including ranges that span several application writes and FIN. */
    @Test
    fun writeStreamFramesEncodesDataAcrossSegments() {
        val server = make(Side.Server)
        server.setParams(params {
            initialMaxStreamsUni = VarInt(1)
            initialMaxData = VarInt(10_000)
            initialMaxStreamDataUni = VarInt(10_000)
        })
        val pending = Retransmits()
        val id = Streams(server, false).open(Dir.Uni)!!
        val stream = SendStream(id, server, pending, false)
        val content = Random(3).nextBytes(3000)
        val parts = arrayOf(
            Bytes.wrap(content).slice(0, 700),
            Bytes.wrap(content).slice(700, 701),
            Bytes.wrap(content).slice(701, 3000),
        )
        assertEquals(Written(3000, 3), stream.writeChunks(parts))
        stream.finish()

        val received = ByteArray(3000)
        var fin = false
        var total = 0
        while (true) {
            val buf = Buffer(1200)
            val metas = server.writeStreamFrames(buf, 1200, true)
            if (metas.isEmpty()) break
            val frames = decode(buf)
            assertEquals(metas.size, frames.size)
            for ((i, f) in frames.withIndex()) {
                val s = assertIs<Frame.Stream>(f)
                assertEquals(metas.id(i), s.id)
                assertEquals(metas.start(i), s.offset)
                assertEquals(metas.end(i) - metas.start(i), s.data.size.toLong())
                assertEquals(metas.fin(i), s.fin)
                s.data.copyInto(received, s.offset.toInt())
                total += s.data.size
                fin = fin || s.fin
            }
            assertTrue(buf.len <= 1200)
        }
        assertEquals(3000, total)
        assertTrue(fin)
        assertEquals(content.toList(), received.toList())

        // Acknowledging everything finishes the stream
        server.receivedAckOf(id, 0, 3000, true)
        assertEquals(StreamEvent.Finished(id), server.poll())
        assertFalse(server.send.containsKey(id.value))
    }

    /** A lost frame is retransmitted before new data, with its FIN. */
    @Test
    fun retransmitResendsLostRange() {
        val server = make(Side.Server)
        server.setParams(params {
            initialMaxStreamsUni = VarInt(1)
            initialMaxData = VarInt(10_000)
            initialMaxStreamDataUni = VarInt(10_000)
        })
        val id = Streams(server, false).open(Dir.Uni)!!
        val stream = SendStream(id, server, Retransmits(), false)
        stream.write("hello world".encodeToByteArray()).bytes()
        stream.finish()
        val first = server.writeStreamFrames(Buffer(100), 100, true)
        assertEquals(StreamMeta(id, 0, 11, true), first[0])
        server.retransmit(first[0])
        val buf = Buffer(100)
        val again = server.writeStreamFrames(buf, 100, true)
        assertEquals(StreamMeta(id, 0, 11, true), again[0])
        assertEquals(Frame.Stream(id, 0, true, Bytes.wrap("hello world".encodeToByteArray())), decode(buf)[0])
    }

    /** [PendingStreamsQueue] against a sorted-list model of quinn's `(priority, recency, id)` ordering. */
    @Test
    fun pendingStreamsQueueMatchesReferenceModel() {
        val rnd = Random(5)
        repeat(100) {
            val q = PendingStreamsQueue()
            data class E(val priority: Int, val recency: ULong, val id: Long)
            val model = ArrayList<E>()
            var recency = ULong.MAX_VALUE
            var next: Long? = null
            repeat(500) {
                when (rnd.nextInt(10)) {
                    in 0..5 -> {
                        val id = rnd.nextLong(0, 1000)
                        val p = rnd.nextInt(-3, 4)
                        recency -= 1u
                        q.pushPending(id, p)
                        model.add(E(p, recency, id))
                    }
                    in 6..8 -> {
                        val expected = next?.also { next = null } ?: model
                            .maxWithOrNull(compareBy<E> { it.priority }.thenBy { it.recency }.thenBy { it.id })
                            ?.also { model.remove(it) }?.id ?: -1L
                        assertEquals(expected, q.pop())
                    }
                    else -> if (next == null) {
                        val id = rnd.nextLong(0, 1000)
                        q.reinsertPending(id, rnd.nextInt(-3, 4))
                        next = id
                    }
                }
                assertEquals(model.size + (if (next != null) 1 else 0), q.len)
            }
        }
    }

    /** [LongMap] against `HashMap`, including `null` values, removals and growth. */
    @Test
    fun longMapMatchesHashMap() {
        val rnd = Random(9)
        repeat(50) { round ->
            val m = LongMap<String>(if (round % 2 == 0) 1 else 64)
            val ref = HashMap<Long, String?>()
            val keyRange = if (round % 3 == 0) 20L else 1L shl 40
            repeat(2000) {
                val k = rnd.nextLong(0, keyRange)
                when (rnd.nextInt(6)) {
                    0, 1 -> {
                        val v = if (rnd.nextInt(4) == 0) null else "v$it"
                        assertEquals(!ref.containsKey(k), m.put(k, v))
                        ref[k] = v
                    }
                    2, 3 -> {
                        val had = ref.containsKey(k)
                        assertEquals(had, m.remove(k))
                        ref.remove(k)
                    }
                    else -> {
                        assertEquals(ref.containsKey(k), m.containsKey(k))
                        assertEquals(ref[k], m.get(k))
                    }
                }
                assertEquals(ref.size, m.size)
            }
            for ((k, v) in ref) {
                val slot = m.find(k)
                assertTrue(slot >= 0)
                assertEquals(v, m.valueAt(slot))
            }
        }
    }

    /** [LongHashSet] against `HashSet`. */
    @Test
    fun longHashSetMatchesHashSet() {
        val rnd = Random(10)
        repeat(50) { round ->
            val s = LongHashSet()
            val ref = HashSet<Long>()
            val keyRange = if (round % 2 == 0) 30L else 1L shl 50
            repeat(2000) {
                val k = rnd.nextLong(0, keyRange)
                when (rnd.nextInt(4)) {
                    0 -> assertEquals(ref.add(k), s.add(k))
                    1 -> assertEquals(ref.remove(k), s.remove(k))
                    2 -> assertEquals(ref.contains(k), k in s)
                    else -> {
                        val f = s.first()
                        if (ref.isEmpty()) assertEquals(-1L, f) else assertTrue(f in ref)
                    }
                }
                assertEquals(ref.size, s.size)
            }
            assertEquals(ref, s.toSet())
            assertEquals(ref, s.copy().toSet())
        }
    }
}
