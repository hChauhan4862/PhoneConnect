package com.phoneconnect.agent

import com.phoneconnect.agent.wire.Envelope
import com.phoneconnect.agent.wire.StreamKind
import kotlinx.coroutines.test.runTest
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentTransportTest {
    // Fixtures produced by the Rust codec (crates/protocol) with FrameLimits::control_only().
    private val rustControlFrame =
        "00000044080110011a0c726571756573742d30303432220b6465766963652d376633612a0c736573" +
            "73696f6e2d393163323007388080b3c19c33420c6c6973742d64657669636573"
    private val rustEventsFrame = "0000001708011002220b6465766963652d376633614204deadbeef"

    @Test
    fun `decodes a frame produced by the Rust codec`() {
        val decoded = decode(rustControlFrame.hex())

        assertEquals(EnvelopeCodec.PROTOCOL_VERSION, decoded.envelope.protocolVersion)
        assertEquals(StreamKind.STREAM_KIND_CONTROL, decoded.envelope.streamKind)
        assertEquals("device-7f3a", decoded.envelope.deviceId)
        assertEquals("session-91c2", decoded.envelope.sessionId)
        assertEquals("request-0042", decoded.envelope.requestId)
        assertEquals(7, decoded.envelope.sequence)
        assertEquals(1_760_000_000_000L, decoded.envelope.deadlineUnixMs)
        assertArrayEquals("list-devices".toByteArray(), decoded.envelope.payload.toByteArray())
        assertEquals(rustControlFrame.length / 2, decoded.consumed)
    }

    @Test
    fun `re-encodes the Rust frame byte for byte`() {
        val decoded = decode(rustControlFrame.hex())

        assertEquals(rustControlFrame, encode(decoded.envelope).toHex())
    }

    @Test
    fun `decodes a frame whose optional fields the Rust codec left unset`() {
        val decoded = decode(rustEventsFrame.hex())

        assertEquals(StreamKind.STREAM_KIND_EVENTS, decoded.envelope.streamKind)
        assertEquals("", decoded.envelope.requestId)
        assertEquals("", decoded.envelope.sessionId)
        assertEquals(0, decoded.envelope.sequence)
        assertEquals(0L, decoded.envelope.deadlineUnixMs)
        assertArrayEquals(byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte()), decoded.envelope.payload.toByteArray())
        assertEquals(rustEventsFrame, encode(decoded.envelope).toHex())
    }

    @Test
    fun `consumed bytes leave trailing frames for the next decode`() {
        val first = encode(controlEnvelope(sequence = 1))
        val second = encode(controlEnvelope(sequence = 2))
        val buffer = first + second

        val decoded = decode(buffer)
        assertEquals(first.size, decoded.consumed)
        assertEquals(1, decoded.envelope.sequence)

        val next = decode(buffer.copyOfRange(decoded.consumed, buffer.size))
        assertEquals(2, next.envelope.sequence)
        assertEquals(second.size, next.consumed)
    }

    @Test
    fun `refuses a frame above one mebibyte at the length prefix`() {
        val oversized = ByteArray(4) { (EnvelopeCodec.CONTROL_FRAME_LIMIT + 1).ushr(24 - it * 8).toByte() } + ByteArray(16)

        val error = EnvelopeCodec.decode(oversized).exceptionOrNull()

        assertTrue("expected FrameTooLarge, got $error", error is WireError.FrameTooLarge)
        assertEquals(EnvelopeCodec.CONTROL_FRAME_LIMIT + 1, (error as WireError.FrameTooLarge).declared)
        assertEquals(EnvelopeCodec.CONTROL_FRAME_LIMIT, error.limit)
        assertEquals("the stream kind must not be needed to refuse the prefix", null, error.streamKind)
    }

    @Test
    fun `refuses truncated frames instead of reading past the buffer`() {
        val frame = encode(controlEnvelope(sequence = 1))

        assertTrue(EnvelopeCodec.decode(ByteArray(0)).exceptionOrNull() is WireError.TruncatedPrefix)
        assertTrue(EnvelopeCodec.decode(frame.copyOfRange(0, 2)).exceptionOrNull() is WireError.TruncatedPrefix)
        val error = EnvelopeCodec.decode(frame.copyOfRange(0, frame.size - 3)).exceptionOrNull()
        assertTrue("expected TruncatedFrame, got $error", error is WireError.TruncatedFrame)
        assertEquals(frame.size - 4, (error as WireError.TruncatedFrame).declared)
    }

    @Test
    fun `refuses unknown stream kinds and malformed identifiers`() {
        val unknownKind = controlEnvelope(sequence = 1).toBuilder().setStreamKindValue(99).build()
        val error = EnvelopeCodec.encode(unknownKind).exceptionOrNull()
        assertTrue("expected UnknownStreamKind, got $error", error is WireError.UnknownStreamKind)

        val emptyKind = controlEnvelope(sequence = 1).toBuilder().setStreamKindValue(0).build()
        assertTrue(EnvelopeCodec.encode(emptyKind).exceptionOrNull() is WireError.MissingStreamKind)

        val badId = controlEnvelope(sequence = 1).toBuilder().setDeviceId("device\nforged").build()
        val idError = EnvelopeCodec.encode(badId).exceptionOrNull()
        assertTrue("expected InvalidIdentifier, got $idError", idError is WireError.InvalidIdentifier)
        assertEquals("device_id", (idError as WireError.InvalidIdentifier).kind)
    }

    @Test
    fun `refuses a frame from a future protocol version`() {
        val future = controlEnvelope(sequence = 1).toBuilder()
            .setProtocolVersion(EnvelopeCodec.PROTOCOL_VERSION + 1)
            .build()

        val error = EnvelopeCodec.encode(future).exceptionOrNull()

        assertTrue("expected UnsupportedVersion, got $error", error is WireError.UnsupportedVersion)
    }

    @Test
    fun `sequence counters advance per stream and never repeat`() = runTest {
        val channel = FakeFrameChannel()
        val transport = AgentTransport(channel, "device-7f3a", "session-91c2")

        transport.sendControl("request-1", "a".toByteArray())
        transport.sendControl("request-2", "b".toByteArray())
        transport.sendEvent("c".toByteArray())
        transport.sendControl("request-3", "d".toByteArray())

        val sent = channel.sent.map { decode(it).envelope }
        assertEquals(listOf(1, 2, 3), sent.filter { it.streamKind == StreamKind.STREAM_KIND_CONTROL }.map { it.sequence })
        assertEquals(listOf(1), sent.filter { it.streamKind == StreamKind.STREAM_KIND_EVENTS }.map { it.sequence })
        assertEquals("device-7f3a", sent.map { it.deviceId }.toSet().single())
        assertEquals("session-91c2", sent.map { it.sessionId }.toSet().single())
    }

    @Test
    fun `a revoked device closes the stream and reports a terminal failure`() = runTest {
        val channel = FakeFrameChannel(events = listOf(ChannelEvent.Closed("device_revoked")))
        val transport = AgentTransport(channel, "device-7f3a", "session-91c2")

        val inbound = transport.receive()

        assertEquals(Inbound.End(ConnectionFailure.DeviceRevoked), inbound)
        assertTrue("a terminal stream must be closed immediately", channel.closed)
    }

    @Test
    fun `revoked, expired, and closed sessions are terminal for the session`() = runTest {
        for (reason in listOf("session_revoked", "session_expired", "session_closed", "session_unknown")) {
            assertEquals(
                "close reason $reason must end the session",
                Inbound.End(ConnectionFailure.SessionEnded),
                transportFor(reason).receive(),
            )
        }
    }

    @Test
    fun `a peer close is retryable and an unknown reason is a protocol failure`() = runTest {
        assertEquals(
            Inbound.End(ConnectionFailure.Retryable(ReconnectReason.TRANSPORT_CLOSED)),
            transportFor("peer_closed").receive(),
        )
        assertEquals(
            Inbound.End(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)),
            transportFor("something_new").receive(),
        )
    }

    @Test
    fun `an oversized inbound frame ends the transport instead of buffering it`() = runTest {
        val oversized = ByteArray(4) { (EnvelopeCodec.CONTROL_FRAME_LIMIT + 1).ushr(24 - it * 8).toByte() } + ByteArray(8)
        val channel = FakeFrameChannel(events = listOf(ChannelEvent.Frame(oversized)))
        val transport = AgentTransport(channel, "device-7f3a", "session-91c2")

        val inbound = transport.receive()

        assertEquals(Inbound.End(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)), inbound)
        assertTrue("a protocol violation must close the channel", channel.closed)
    }

    @Test
    fun `an inbound frame is decoded and surfaced to the agent`() = runTest {
        val channel = FakeFrameChannel(events = listOf(ChannelEvent.Frame(rustControlFrame.hex())))
        val transport = AgentTransport(channel, "device-7f3a", "session-91c2")

        val inbound = transport.receive()

        assertTrue("expected a frame, got $inbound", inbound is Inbound.Frame)
        assertEquals(StreamKind.STREAM_KIND_CONTROL, (inbound as Inbound.Frame).envelope.streamKind)
        assertTrue(!channel.closed)
    }

    @Test
    fun `an invalid identifier is refused before any frame is sent`() = runTest {
        val channel = FakeFrameChannel()
        val error = runCatching { AgentTransport(channel, "bad id", "session-91c2") }.exceptionOrNull()

        assertTrue("expected an InvalidIdentifier, got $error", error is WireError.InvalidIdentifier)
        assertTrue(channel.sent.isEmpty())
    }

    private fun transportFor(closeReason: String) = AgentTransport(
        FakeFrameChannel(events = listOf(ChannelEvent.Closed(closeReason))),
        "device-7f3a",
        "session-91c2",
    )

    private fun controlEnvelope(sequence: Int) = EnvelopeCodec.newEnvelope(
        streamKind = StreamKind.STREAM_KIND_CONTROL,
        deviceId = "device-7f3a",
        sessionId = "session-91c2",
        requestId = "request-0042",
    ).toBuilder().setSequence(sequence).build()

    private fun decode(frame: ByteArray) = EnvelopeCodec.decode(frame).getOrThrow()

    private fun encode(envelope: Envelope): ByteArray = EnvelopeCodec.encode(envelope).getOrThrow()

    private fun String.hex(): ByteArray {
        require(length % 2 == 0)
        return ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private fun <T> Result<T>.exceptionOrNull(): Throwable? = exceptionOrNull()

    private class FakeFrameChannel(
        private val events: List<ChannelEvent> = emptyList(),
    ) : FrameChannel {
        private val queue = ArrayDeque(events)
        val sent = mutableListOf<ByteArray>()
        var closed = false
            private set

        override suspend fun send(frame: ByteArray) {
            check(!closed) { "send on a closed channel" }
            sent += frame
        }

        override suspend fun receive(): ChannelEvent =
            queue.removeFirstOrNull() ?: ChannelEvent.Closed("peer_closed")

        override fun close() {
            closed = true
        }
    }
}
