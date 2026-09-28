package neton.quic.proto

import neton.io.bytes.Buffer
import neton.io.bytes.Bytes
import kotlin.test.Test
import kotlin.test.assertEquals
import kotlin.test.assertFailsWith
import kotlin.test.assertFalse
import kotlin.test.assertIs
import kotlin.test.assertNull
import kotlin.test.assertSame
import kotlin.test.assertTrue

internal fun params(block: TransportParameters.() -> Unit): TransportParameters = TransportParameters().apply(block)

internal fun zeros(n: Int): Bytes = Bytes.wrap(ByteArray(n))

/** The byte count of a successful write (quinn's `write(..).unwrap()`). */
internal fun WriteResult.bytes(): Int = (this as Written).bytes

// streams/state.rs tests (quinn's `ConnState::Established` is `connClosed = false`)
class StreamsStateTest {

    private fun make(side: Side): StreamsState =
        StreamsState(side, VarInt(128), VarInt(128), 1024 * 1024, VarInt(1024 * 1024), VarInt(1024 * 1024))

    private fun streams(s: StreamsState) = Streams(s, false)
    private fun send(id: StreamId, s: StreamsState, pending: Retransmits) = SendStream(id, s, pending, false)
    private fun recv(id: StreamId, s: StreamsState, pending: Retransmits) = RecvStream(id, s, pending)

    @Test
    fun sendWindowRetainsSelectivelyAckedData() {
        val server = make(Side.Server)
        server.sendWindow = 24
        server.setParams(params {
            initialMaxStreamsUni = VarInt(1)
            initialMaxData = VarInt(1000)
            initialMaxStreamDataUni = VarInt(1000)
        })
        val pending = Retransmits()
        val id = streams(server).open(Dir.Uni)!!
        send(id, server, pending).write(ByteArray(24) { 42 }).bytes()
        val send = server.send.get(id.value)!!
        assertEquals(0L to 16L, send.pending.poll(16).let { it.first to it.second })
        assertEquals(16L to 23L, send.pending.poll(16).let { it.first to it.second })
        assertEquals(23L to 24L, send.pending.poll(16).let { it.first to it.second })

        server.receivedAckOf(StreamMeta(id, 16, 23, false))
        assertEquals(0L, server.writeLimit(), "acknowledged suffix still occupies storage")
        server.receivedAckOf(StreamMeta(id, 0, 16, false))
        assertEquals(0L, server.writeLimit(), "partial prefix keeps the original Bytes allocation")
        server.receivedAckOf(StreamMeta(id, 23, 24, false))
        assertEquals(24L, server.writeLimit())
        send(id, server, pending).write(ByteArray(24) { 7 }).bytes()
        assertEquals(0L, server.writeLimit())
    }

    @Test
    fun resetReleasesRetainedSendStorage() {
        val server = make(Side.Server)
        server.sendWindow = 24
        server.setParams(params {
            initialMaxStreamsUni = VarInt(1)
            initialMaxData = VarInt(1000)
            initialMaxStreamDataUni = VarInt(1000)
        })
        val pending = Retransmits()
        val id = streams(server).open(Dir.Uni)!!
        send(id, server, pending).write(ByteArray(24) { 42 }).bytes()
        var send = server.send.get(id.value)!!
        send.pending.pollTransmit(16)
        send.pending.pollTransmit(16)
        server.receivedAckOf(StreamMeta(id, 16, 23, false))
        send(id, server, pending).reset(VarInt(0))

        send = server.send.get(id.value)!!
        assertTrue(send.pending.isFullyAcked, "reset must release the abandoned allocation")
        assertEquals(24L, send.offset, "RESET_STREAM must retain its final offset")
        assertEquals(24L, server.writeLimit())
        server.retransmit(StreamMeta(id, 0, 16, false))
        server.receivedAckOf(StreamMeta(id, 0, 16, false))
        assertFalse(server.send.get(id.value)!!.isPending)
        assertEquals(24L, server.writeLimit())
    }

    @Test
    fun trivialFlowControl() {
        val client = StreamsState(Side.Client, VarInt(1), VarInt(1), 1024 * 1024, VarInt(1024 * 1024), VarInt(1024 * 1024))
        val id = StreamId.of(Side.Server, Dir.Uni, 0)
        val initialMax = client.localMaxData
        val messageSize = 2048
        assertEquals(ShouldTransmit(false), client.received(Frame.Stream(id, 0, true, zeros(messageSize)), 2048))
        assertEquals(2048L, client.dataRecvd)
        assertEquals(0L, client.localMaxData - initialMax)

        val pending = Retransmits()
        val recv = recv(id, client, pending)

        val chunks = recv.read(true)
        assertEquals(messageSize, assertIs<Chunk>(chunks.next(messageSize)).bytes.size)
        assertSame(ReadResult.Finished, chunks.next(0))
        val shouldTransmit = chunks.finalize()
        assertTrue(shouldTransmit.shouldTransmit)
        assertTrue(pending.maxStreamId[Dir.Uni.ordinal])
        assertEquals(messageSize.toLong(), client.localMaxData - initialMax)
    }

    @Test
    fun resetFlowControl() {
        val client = make(Side.Client)
        val id = StreamId.of(Side.Server, Dir.Uni, 0)
        val initialMax = client.localMaxData
        assertEquals(ShouldTransmit(false), client.received(Frame.Stream(id, 0, false, zeros(2048)), 2048))
        assertEquals(2048L, client.dataRecvd)
        assertEquals(0L, client.localMaxData - initialMax)

        val pending = Retransmits()
        var chunks = recv(id, client, pending).read(true)
        chunks.next(1024)
        chunks.finalize()
        assertEquals(1024L, client.localMaxData - initialMax)
        assertEquals(ShouldTransmit(false), client.receivedReset(Frame.ResetStream(id, VarInt(0), VarInt(4096))))

        assertEquals(4096L, client.dataRecvd)
        assertEquals(4096L, client.localMaxData - initialMax)

        // Ensure reading after a reset doesn't issue redundant credit
        chunks = recv(id, client, pending).read(true)
        assertEquals(ReadError.Reset(VarInt(0)), chunks.next(1024))
        chunks.finalize()
        assertEquals(4096L, client.dataRecvd)
        assertEquals(4096L, client.localMaxData - initialMax)
    }

    @Test
    fun resetAfterEmptyFrameFlowControl() {
        val client = make(Side.Client)
        val id = StreamId.of(Side.Server, Dir.Uni, 0)
        val initialMax = client.localMaxData
        assertEquals(ShouldTransmit(false), client.received(Frame.Stream(id, 4096, false, zeros(0)), 0))
        assertEquals(4096L, client.dataRecvd)
        assertEquals(0L, client.localMaxData - initialMax)
        assertEquals(ShouldTransmit(false), client.receivedReset(Frame.ResetStream(id, VarInt(0), VarInt(4096))))
        assertEquals(4096L, client.dataRecvd)
        assertEquals(4096L, client.localMaxData - initialMax)
    }

    @Test
    fun duplicateResetFlowControl() {
        val client = make(Side.Client)
        val id = StreamId.of(Side.Server, Dir.Uni, 0)
        assertEquals(ShouldTransmit(false), client.receivedReset(Frame.ResetStream(id, VarInt(0), VarInt(4096))))
        assertEquals(4096L, client.dataRecvd)
        assertEquals(ShouldTransmit(false), client.receivedReset(Frame.ResetStream(id, VarInt(0), VarInt(4096))))
        assertEquals(4096L, client.dataRecvd)
    }

    @Test
    fun recvStopped() {
        val client = make(Side.Client)
        val id = StreamId.of(Side.Server, Dir.Uni, 0)
        val initialMax = client.localMaxData
        assertEquals(ShouldTransmit(false), client.received(Frame.Stream(id, 0, false, zeros(32)), 32))
        assertEquals(initialMax, client.localMaxData)

        val pending = Retransmits()
        val recv = recv(id, client, pending)

        recv.stop(VarInt(0))
        assertEquals(1, recv.pending.stopSending.size)
        assertFalse(recv.pending.maxData)

        assertFailsWith<ClosedStream> { recv.stop(VarInt(0)) }
        assertSame(ReadableError.ClosedStream, assertFailsWith<ReadableError> { recv.read(true) })
        assertSame(ReadableError.ClosedStream, assertFailsWith<ReadableError> { recv.read(false) })

        assertEquals(32L, client.localMaxData - initialMax)
        assertEquals(ShouldTransmit(false), client.received(Frame.Stream(id, 32, true, zeros(16)), 16))
        assertEquals(48L, client.localMaxData - initialMax)
        assertFalse(client.recv.containsKey(id.value))
    }

    @Test
    fun stoppedReset() {
        for (finalOffset in listOf(32L, 48L)) {
            val client = make(Side.Client)
            val initialMaxData = client.localMaxData
            val id = StreamId.of(Side.Server, Dir.Uni, 0)
            // Server opens stream
            assertEquals(ShouldTransmit(false), client.received(Frame.Stream(id, 0, false, zeros(32)), 32))

            val pending = Retransmits()
            val recv = recv(id, client, pending)

            recv.stop(VarInt(0))
            assertEquals(1, pending.stopSending.size)
            assertFalse(pending.maxData)
            assertEquals(initialMaxData + 32, client.localMaxData)

            // Server complies
            val prevMax = client.maxRemote[Dir.Uni.ordinal]
            assertEquals(ShouldTransmit(false), client.receivedReset(Frame.ResetStream(id, VarInt(0), VarInt(finalOffset))))
            assertFalse(client.recv.containsKey(id.value), "stream state is freed")
            assertEquals(prevMax + 1, client.maxRemote[Dir.Uni.ordinal])
            assertEquals(finalOffset, client.dataRecvd)
            assertEquals(initialMaxData + finalOffset, client.localMaxData)
        }
    }

    @Test
    fun sendStopped() {
        val server = make(Side.Server)
        server.setParams(params {
            initialMaxStreamsUni = VarInt(1)
            initialMaxData = VarInt(42)
            initialMaxStreamDataUni = VarInt(42)
        })

        val pending = Retransmits()
        val id = streams(server).open(Dir.Uni)!!

        val stream = send(id, server, pending)

        val errorCode = VarInt(0)
        stream.state.receivedStopSending(id, errorCode)
        assertTrue(stream.state.events.contains(StreamEvent.Stopped(id, errorCode)))
        stream.state.events.clear()

        assertEquals(WriteError.Stopped(errorCode), stream.write(ByteArray(0)))

        stream.reset(VarInt(0))
        assertEquals(WriteError.ClosedStream, stream.write(ByteArray(0)))

        // A duplicate frame is a no-op
        stream.state.receivedStopSending(id, errorCode)
        assertTrue(stream.state.events.isEmpty())
    }

    @Test
    fun finalOffsetFlowControl() {
        val client = make(Side.Client)
        val e = assertFailsWith<TransportError> {
            client.receivedReset(Frame.ResetStream(StreamId.of(Side.Server, Dir.Uni, 0), VarInt(0), VarInt.MAX))
        }
        assertEquals(TransportErrorCode.FLOW_CONTROL_ERROR, e.code)
    }

    @Test
    fun streamPriority() {
        val server = make(Side.Server)
        server.setParams(params {
            initialMaxStreamsBidi = VarInt(3)
            initialMaxData = VarInt(10)
            initialMaxStreamDataBidiRemote = VarInt(10)
        })

        val pending = Retransmits()
        val streams = streams(server)

        val idHigh = streams.open(Dir.Bi)!!
        val idMid = streams.open(Dir.Bi)!!
        val idLow = streams.open(Dir.Bi)!!

        val mid = send(idMid, server, pending)
        mid.write("mid".encodeToByteArray()).bytes()

        val low = send(idLow, server, pending)
        low.setPriority(-1)
        low.write("low".encodeToByteArray()).bytes()

        val high = send(idHigh, server, pending)
        high.setPriority(1)
        high.write("high".encodeToByteArray()).bytes()

        val buf = Buffer(40)
        val meta = server.writeStreamFrames(buf, 40, true)
        assertEquals(idHigh, meta.id(0))
        assertEquals(idMid, meta.id(1))
        assertEquals(idLow, meta.id(2))

        assertFalse(server.canSendStreamData())
        assertEquals(0, server.pending.len)
    }

    @Test
    fun requeueStreamPriority() {
        val server = make(Side.Server)
        server.setParams(params {
            initialMaxStreamsBidi = VarInt(3)
            initialMaxData = VarInt(1000)
            initialMaxStreamDataBidiRemote = VarInt(1000)
        })

        val pending = Retransmits()
        val streams = streams(server)

        val idHigh = streams.open(Dir.Bi)!!
        val idMid = streams.open(Dir.Bi)!!

        val mid = send(idMid, server, pending)
        assertEquals(3, mid.write("mid".encodeToByteArray()).bytes())
        assertEquals(1, server.pending.len)

        var high = send(idHigh, server, pending)
        high.setPriority(1)
        assertEquals(200, high.write(ByteArray(200)).bytes())
        assertEquals(2, server.pending.len)

        // Requeue the high priority stream to lowest priority. The initial send still uses high priority since it's
        // queued that way. After that it will switch to low priority
        high = send(idHigh, server, pending)
        high.setPriority(-1)

        val buf = Buffer(1000)
        var meta = server.writeStreamFrames(buf, 40, true)
        assertEquals(1, meta.size)
        assertEquals(idHigh, meta.id(0))

        // After requeuing we should end up with 2 priorities - not 3
        assertEquals(2, server.pending.len)

        // Send the remaining data. The initial mid priority one should go first now
        meta = server.writeStreamFrames(buf, 1000, true)
        assertEquals(2, meta.size)
        assertEquals(idMid, meta.id(0))
        assertEquals(idHigh, meta.id(1))

        assertFalse(server.canSendStreamData())
        assertEquals(0, server.pending.len)
    }

    @Test
    fun sameStreamPriority() {
        for (fair in listOf(true, false)) {
            val server = make(Side.Server)
            server.setParams(params {
                initialMaxStreamsBidi = VarInt(3)
                initialMaxData = VarInt(300)
                initialMaxStreamDataBidiRemote = VarInt(300)
            })

            val pending = Retransmits()
            val streams = streams(server)

            // a, b and c all have the same priority
            val idA = streams.open(Dir.Bi)!!
            val idB = streams.open(Dir.Bi)!!
            val idC = streams.open(Dir.Bi)!!

            send(idA, server, pending).write(ByteArray(100) { 'a'.code.toByte() }).bytes()
            send(idB, server, pending).write(ByteArray(100) { 'b'.code.toByte() }).bytes()
            send(idC, server, pending).write(ByteArray(100) { 'c'.code.toByte() }).bytes()

            val metas = ArrayList<StreamMeta>()
            val buf = Buffer(1024)

            // loop until all the streams are written
            while (true) {
                val bufLen = buf.len
                val meta = server.writeStreamFrames(buf, bufLen + 40, fair)
                if (meta.isEmpty()) break
                metas.addAll(meta.toList())
            }

            assertFalse(server.canSendStreamData())
            assertEquals(0, server.pending.len)

            val streamIds = metas.map { it.id }
            if (fair) {
                // When fairness is enabled, if we run out of buffer space to write out a stream, the stream is
                // re-queued after all the streams with the same priority.
                assertEquals(listOf(idA, idB, idC, idA, idB, idC, idA, idB, idC), streamIds)
            } else {
                // When fairness is disabled the stream is re-queued before all the other streams with the same
                // priority.
                assertEquals(listOf(idA, idA, idA, idB, idB, idB, idC, idC, idC), streamIds)
            }
        }
    }

    @Test
    fun unfairPriorityBump() {
        val server = make(Side.Server)
        server.setParams(params {
            initialMaxStreamsBidi = VarInt(3)
            initialMaxData = VarInt(300)
            initialMaxStreamDataBidiRemote = VarInt(300)
        })

        val pending = Retransmits()
        val streams = streams(server)

        // a, and b have the same priority, c has higher priority
        val idA = streams.open(Dir.Bi)!!
        val idB = streams.open(Dir.Bi)!!
        val idC = streams.open(Dir.Bi)!!

        send(idA, server, pending).write(ByteArray(100) { 'a'.code.toByte() }).bytes()
        send(idB, server, pending).write(ByteArray(100) { 'b'.code.toByte() }).bytes()

        val metas = ArrayList<StreamMeta>()
        val buf = Buffer(1024)

        // Write the first chunk of stream_a
        val meta = server.writeStreamFrames(buf, buf.len + 40, false)
        assertFalse(meta.isEmpty())
        metas.addAll(meta.toList())

        // Queue stream_c which has higher priority
        val streamC = send(idC, server, pending)
        streamC.setPriority(1)
        streamC.write(ByteArray(100) { 'b'.code.toByte() }).bytes()

        // loop until all the streams are written
        while (true) {
            val m = server.writeStreamFrames(buf, buf.len + 40, false)
            if (m.isEmpty()) break
            metas.addAll(m.toList())
        }

        assertFalse(server.canSendStreamData())
        assertEquals(0, server.pending.len)

        // stream_c bumps stream_b but doesn't bump stream_a which had already been partly written out
        assertEquals(listOf(idA, idA, idA, idC, idC, idC, idB, idB, idB), metas.map { it.id })
    }

    @Test
    fun stopFinished() {
        val client = make(Side.Client)
        val id = StreamId.of(Side.Server, Dir.Uni, 0)
        // Server finishes stream
        client.received(Frame.Stream(id, 0, true, zeros(32)), 32)
        val pending = Retransmits()
        recv(id, client, pending).stop(VarInt(0))
        assertNull(client.recv.get(id.value), "stream is freed")
        assertFalse(client.recv.containsKey(id.value), "stream is freed")
    }

    // Verify that a stream that's been reset doesn't cause the appearance of pending data
    @Test
    fun resetStreamCannotSend() {
        val server = make(Side.Server)
        server.setParams(params {
            initialMaxStreamsUni = VarInt(1)
            initialMaxData = VarInt(42)
            initialMaxStreamDataUni = VarInt(42)
        })
        val pending = Retransmits()
        val streams = streams(server)

        val id = streams.open(Dir.Uni)!!
        val stream = send(id, server, pending)
        stream.write("hello".encodeToByteArray()).bytes()
        stream.reset(VarInt(0))

        assertEquals(listOf(StreamReset(id, VarInt(0))), pending.resetStream)
        assertFalse(server.canSendStreamData())
    }

    @Test
    fun streamLimitFixed() {
        val client = make(Side.Client)
        // Open streams 0-127
        assertEquals(ShouldTransmit(false), client.received(Frame.Stream(StreamId.of(Side.Server, Dir.Uni, 127), 0, true, zeros(0)), 0))
        // Try to open stream 128, exceeding limit
        assertEquals(
            TransportErrorCode.STREAM_LIMIT_ERROR,
            assertFailsWith<TransportError> {
                client.received(Frame.Stream(StreamId.of(Side.Server, Dir.Uni, 128), 0, true, zeros(0)), 0)
            }.code,
        )

        // Free stream 127
        val pending = Retransmits()
        recv(StreamId.of(Side.Server, Dir.Uni, 127), client, pending).stop(VarInt(0))

        // Open stream 128
        assertEquals(ShouldTransmit(false), client.received(Frame.Stream(StreamId.of(Side.Server, Dir.Uni, 128), 0, true, zeros(0)), 0))
    }

    @Test
    fun streamLimitGrows() {
        val client = make(Side.Client)
        // Open streams 0-127
        assertEquals(ShouldTransmit(false), client.received(Frame.Stream(StreamId.of(Side.Server, Dir.Uni, 127), 0, true, zeros(0)), 0))
        // Try to open stream 128, exceeding limit
        assertEquals(
            TransportErrorCode.STREAM_LIMIT_ERROR,
            assertFailsWith<TransportError> {
                client.received(Frame.Stream(StreamId.of(Side.Server, Dir.Uni, 128), 0, true, zeros(0)), 0)
            }.code,
        )

        // Relax limit by one
        client.setMaxConcurrent(Dir.Uni, VarInt(129))

        // Open stream 128
        assertEquals(ShouldTransmit(false), client.received(Frame.Stream(StreamId.of(Side.Server, Dir.Uni, 128), 0, true, zeros(0)), 0))
    }

    @Test
    fun streamLimitShrinks() {
        val client = make(Side.Client)
        // Open streams 0-127
        assertEquals(ShouldTransmit(false), client.received(Frame.Stream(StreamId.of(Side.Server, Dir.Uni, 127), 0, true, zeros(0)), 0))

        // Tighten limit by one
        client.setMaxConcurrent(Dir.Uni, VarInt(127))

        // Free stream 127
        var pending = Retransmits()
        recv(StreamId.of(Side.Server, Dir.Uni, 127), client, pending).stop(VarInt(0))

        // Try to open stream 128, still exceeding limit
        assertEquals(
            TransportErrorCode.STREAM_LIMIT_ERROR,
            assertFailsWith<TransportError> {
                client.received(Frame.Stream(StreamId.of(Side.Server, Dir.Uni, 128), 0, true, zeros(0)), 0)
            }.code,
        )

        // Free stream 126
        assertEquals(
            ShouldTransmit(false),
            client.receivedReset(Frame.ResetStream(StreamId.of(Side.Server, Dir.Uni, 126), VarInt(0), VarInt(0))),
        )
        pending = Retransmits()
        recv(StreamId.of(Side.Server, Dir.Uni, 126), client, pending).stop(VarInt(0))

        // Open stream 128
        assertEquals(ShouldTransmit(false), client.received(Frame.Stream(StreamId.of(Side.Server, Dir.Uni, 128), 0, true, zeros(0)), 0))
    }

    @Test
    fun remoteStreamCapacity() {
        val client = make(Side.Client)
        repeat(2) {
            client.setMaxConcurrent(Dir.Uni, VarInt(200))
            client.setMaxConcurrent(Dir.Bi, VarInt(201))
            assertEquals(200 + 201, client.recv.size)
            assertEquals(200L, client.maxRemote[Dir.Uni.ordinal])
            assertEquals(201L, client.maxRemote[Dir.Bi.ordinal])
        }
    }

    @Test
    fun expandReceiveWindow() {
        val server = make(Side.Server)
        val newReceiveWindow = 2 * server.receiveWindow
        val expanded = server.setReceiveWindow(VarInt(newReceiveWindow))
        assertTrue(expanded)
        assertEquals(newReceiveWindow, server.receiveWindow)
        assertEquals(newReceiveWindow, server.localMaxData)
        assertEquals(0L, server.receiveWindowShrinkDebt)
        val prevLocalMaxData = server.localMaxData

        // credit, expecting all of them added to local_max_data
        val credits = 1024L
        val shouldTransmit = server.addReadCredits(credits)
        assertEquals(0L, server.receiveWindowShrinkDebt)
        assertEquals(prevLocalMaxData + credits, server.localMaxData)
        assertTrue(shouldTransmit.shouldTransmit)
    }

    @Test
    fun shrinkReceiveWindow() {
        val server = make(Side.Server)
        val newReceiveWindow = server.receiveWindow / 2
        var prevLocalMaxData = server.localMaxData

        // shrink the receive_window, local_max_data is not expected to be changed
        val shrinkDiff = server.receiveWindow - newReceiveWindow
        val expanded = server.setReceiveWindow(VarInt(newReceiveWindow))
        assertFalse(expanded)
        assertEquals(newReceiveWindow, server.receiveWindow)
        assertEquals(prevLocalMaxData, server.localMaxData)
        assertEquals(shrinkDiff, server.receiveWindowShrinkDebt)
        prevLocalMaxData = server.localMaxData

        // credit twice, local_max_data does not change as it is absorbed by receive_window_shrink_debt
        var credits = 1024L
        repeat(2) {
            val expectedReceiveWindowShrinkDebt = server.receiveWindowShrinkDebt - credits
            val shouldTransmit = server.addReadCredits(credits)
            assertEquals(expectedReceiveWindowShrinkDebt, server.receiveWindowShrinkDebt)
            assertEquals(prevLocalMaxData, server.localMaxData)
            assertFalse(shouldTransmit.shouldTransmit)
        }

        // credit again which exceeds all remaining expected_receive_window_shrink_debt
        credits = 1024L * 512
        prevLocalMaxData = server.localMaxData
        var expectedLocalMaxData = server.localMaxData + (credits - server.receiveWindowShrinkDebt)
        server.addReadCredits(credits)
        assertEquals(0L, server.receiveWindowShrinkDebt)
        assertEquals(expectedLocalMaxData, server.localMaxData)
        assertTrue(server.localMaxData > prevLocalMaxData)

        // credit again, all should be added to local_max_data
        credits = 1024L * 512
        expectedLocalMaxData = server.localMaxData + credits
        val shouldTransmit = server.addReadCredits(credits)
        assertEquals(0L, server.receiveWindowShrinkDebt)
        assertEquals(expectedLocalMaxData, server.localMaxData)
        assertTrue(shouldTransmit.shouldTransmit)
    }

    @Test
    fun expandSendWindow() {
        val server = make(Side.Server)

        val initialSendWindow = server.sendWindow
        val largerSendWindow = initialSendWindow * 2

        // Set `initial_max_data` larger than `send_window` so we're limited by local flow control
        server.setParams(params {
            initialMaxData = VarInt.MAX
            initialMaxStreamDataUni = VarInt.MAX
            initialMaxStreamsUni = VarInt(100)
        })

        assertEquals(initialSendWindow, server.writeLimit())
        assertNull(server.poll())

        val retransmits = Retransmits()

        val streamId = streams(server).open(Dir.Uni) ?: error("should be able to open a stream")

        val stream = send(streamId, server, retransmits)

        // Check that the stream accepts `initial_send_window` bytes
        val initialSendLen = initialSendWindow.toInt()
        val data = ByteArray(initialSendLen) { 0xFF.toByte() }

        assertEquals(initialSendLen, stream.write(data).bytes())

        // Try to write the same data again, observe that it's blocked
        assertEquals(WriteError.Blocked, stream.write(data))

        // Check that we get a `Writable` event after increasing the send window
        stream.state.setSendWindow(largerSendWindow)
        assertEquals(StreamEvent.Writable(streamId), stream.state.poll())

        // Check that the stream accepts the exact same amount of data again
        assertEquals(initialSendLen, stream.write(data).bytes())
        assertEquals(WriteError.Blocked, stream.write(data))

        assertNull(stream.state.poll())

        // Ack the data
        stream.state.receivedAckOf(StreamMeta(streamId, 0, largerSendWindow, false))

        assertEquals(StreamEvent.Writable(streamId), stream.state.poll())

        // Check that our full send window is available again
        assertEquals(initialSendLen, stream.write(data).bytes())
        assertEquals(initialSendLen, stream.write(data).bytes())
        assertEquals(WriteError.Blocked, stream.write(data))
    }

    @Test
    fun shrinkSendWindow() {
        val server = make(Side.Server)

        val initialSendWindow = server.sendWindow
        val smallerSendWindow = server.sendWindow / 2

        // Set `initial_max_data` larger than `send_window` so we're limited by local flow control
        server.setParams(params {
            initialMaxData = VarInt.MAX
            initialMaxStreamDataUni = VarInt.MAX
            initialMaxStreamsUni = VarInt(100)
        })

        assertEquals(initialSendWindow, server.writeLimit())
        assertNull(server.poll())

        val retransmits = Retransmits()

        val streamId = streams(server).open(Dir.Uni) ?: error("should be able to open a stream")

        val stream = send(streamId, server, retransmits)

        val initialSendLen = initialSendWindow.toInt()

        val data = ByteArray(initialSendLen) { 0xFF.toByte() }

        // Assert that the full send window is accepted
        assertEquals(initialSendLen, stream.write(data).bytes())
        assertEquals(WriteError.Blocked, stream.write(data))

        assertEquals(0L, stream.state.writeLimit())
        assertNull(stream.state.poll())

        // Shrink our send window, assert that it's still not writable
        stream.state.setSendWindow(smallerSendWindow)
        assertEquals(0L, stream.state.writeLimit())
        assertNull(stream.state.poll())

        // Assert that data is still not accepted
        assertEquals(WriteError.Blocked, stream.write(data))

        // Ack some data, assert that writes are still not accepted due to outstanding sends
        stream.state.receivedAckOf(StreamMeta(streamId, 0, smallerSendWindow, false))

        assertEquals(WriteError.Blocked, stream.write(data))

        // Ack the rest of the data
        stream.state.receivedAckOf(StreamMeta(streamId, smallerSendWindow, initialSendWindow, false))

        // This should generate a `Writable` event
        assertEquals(StreamEvent.Writable(streamId), stream.state.poll())
        assertEquals(smallerSendWindow, stream.state.writeLimit())

        // Assert that only `smaller_send_window` bytes are accepted
        assertEquals(smallerSendWindow.toInt(), stream.write(data).bytes())
        assertEquals(WriteError.Blocked, stream.write(data))
    }
}
