package com.phoneconnect.agent

import com.phoneconnect.agent.crypto.Epoch
import com.phoneconnect.agent.crypto.EpochClaims
import com.phoneconnect.agent.crypto.IdentityKey
import com.phoneconnect.agent.crypto.SessionCipher
import com.phoneconnect.agent.crypto.SessionRole
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
        val decoded = EnvelopeCodec.decode(rustControlFrame.hex()).getOrThrow()

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
        val decoded = EnvelopeCodec.decode(rustControlFrame.hex()).getOrThrow()

        assertEquals(rustControlFrame, EnvelopeCodec.encode(decoded.envelope).getOrThrow().toHex())
    }

    @Test
    fun `decodes a frame whose optional fields the Rust codec left unset`() {
        val decoded = EnvelopeCodec.decode(rustEventsFrame.hex()).getOrThrow()

        assertEquals(StreamKind.STREAM_KIND_EVENTS, decoded.envelope.streamKind)
        assertEquals("", decoded.envelope.requestId)
        assertEquals("", decoded.envelope.sessionId)
        assertEquals(0, decoded.envelope.sequence)
        assertEquals(0L, decoded.envelope.deadlineUnixMs)
        assertArrayEquals(
            byteArrayOf(0xDE.toByte(), 0xAD.toByte(), 0xBE.toByte(), 0xEF.toByte()),
            decoded.envelope.payload.toByteArray(),
        )
        assertEquals(rustEventsFrame, EnvelopeCodec.encode(decoded.envelope).getOrThrow().toHex())
    }

    @Test
    fun `consumed bytes leave trailing frames for the next decode`() {
        val first = EnvelopeCodec.encode(controlEnvelope(sequence = 1)).getOrThrow()
        val second = EnvelopeCodec.encode(controlEnvelope(sequence = 2)).getOrThrow()
        val buffer = first + second

        val decoded = EnvelopeCodec.decode(buffer).getOrThrow()
        assertEquals(first.size, decoded.consumed)
        assertEquals(1, decoded.envelope.sequence)

        val next = EnvelopeCodec.decode(buffer.copyOfRange(decoded.consumed, buffer.size)).getOrThrow()
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
        val frame = EnvelopeCodec.encode(controlEnvelope(sequence = 1)).getOrThrow()

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
    fun `sent frames are sealed and every stream advances its own sequence`() = runTest {
        val peer = clientCipher()
        val channel = FakeFrameChannel()
        val transport = AgentTransport(channel, DEVICE_ID, SESSION_ID, deviceCipher())

        transport.sendControl("request-1", "a".toByteArray())
        transport.sendControl("request-2", "b".toByteArray())
        transport.sendEvent("c".toByteArray())
        transport.sendControl("request-3", "d".toByteArray())

        val opened = channel.sent.map { peer.open(it).getOrThrow() }
        assertEquals(listOf(1, 2, 3), opened.filter { it.streamKind == StreamKind.STREAM_KIND_CONTROL }.map { it.sequence })
        assertEquals(listOf(1), opened.filter { it.streamKind == StreamKind.STREAM_KIND_EVENTS }.map { it.sequence })
        assertEquals(DEVICE_ID, opened.map { it.deviceId }.toSet().single())
        assertEquals(SESSION_ID, opened.map { it.sessionId }.toSet().single())
        assertArrayEquals("d".toByteArray(), opened.last().payload.toByteArray())
    }

    @Test
    fun `a failed send does not consume a sequence number`() = runTest {
        val peer = clientCipher()
        val channel = FakeFrameChannel(failSends = 1)
        val transport = AgentTransport(channel, DEVICE_ID, SESSION_ID, deviceCipher())

        val failure = runCatching { transport.sendControl("request-1", "a".toByteArray()) }
        assertTrue("the channel failure must surface", failure.exceptionOrNull() is IllegalStateException)

        transport.sendControl("request-2", "b".toByteArray())
        assertEquals(1, peer.open(channel.sent.single()).getOrThrow().sequence)
    }

    @Test
    fun `a revoked device closes the stream and reports a terminal failure`() = runTest {
        val channel = FakeFrameChannel(events = listOf(ChannelEvent.Closed("device_revoked")))
        val transport = AgentTransport(channel, DEVICE_ID, SESSION_ID, deviceCipher())

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
    fun `an unopenable inbound frame ends the transport instead of surfacing bytes`() = runTest {
        val channel = FakeFrameChannel(events = listOf(ChannelEvent.Frame(ByteArray(64) { 0x7F })))
        val transport = AgentTransport(channel, DEVICE_ID, SESSION_ID, deviceCipher())

        val inbound = transport.receive()

        assertEquals(Inbound.End(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)), inbound)
        assertTrue("a protocol violation must close the channel", channel.closed)
    }

    @Test
    fun `a frame for another session is rejected`() = runTest {
        val peer = clientCipher()
        val foreign = controlEnvelope(sequence = 1).toBuilder()
            .setSessionId("sess_someone_else")
            .setDeviceId(DEVICE_ID)
            .build()
        val channel = FakeFrameChannel(events = listOf(ChannelEvent.Frame(peer.seal(foreign).getOrThrow())))
        val transport = AgentTransport(channel, DEVICE_ID, SESSION_ID, deviceCipher())

        val inbound = transport.receive()

        assertEquals(Inbound.End(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)), inbound)
        assertTrue(channel.closed)
    }

    @Test
    fun `a frame for another device is rejected`() = runTest {
        val peer = clientCipher()
        val foreign = controlEnvelope(sequence = 1).toBuilder()
            .setSessionId(SESSION_ID)
            .setDeviceId("dev_someone_else")
            .build()
        val channel = FakeFrameChannel(events = listOf(ChannelEvent.Frame(peer.seal(foreign).getOrThrow())))
        val transport = AgentTransport(channel, DEVICE_ID, SESSION_ID, deviceCipher())

        val inbound = transport.receive()

        assertEquals(Inbound.End(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)), inbound)
        assertTrue(channel.closed)
    }

    @Test
    fun `an inbound frame is opened and surfaced to the agent`() = runTest {
        val peer = clientCipher()
        val expected = controlEnvelope(sequence = 7)
        val channel = FakeFrameChannel(events = listOf(ChannelEvent.Frame(peer.seal(expected).getOrThrow())))
        val transport = AgentTransport(channel, DEVICE_ID, SESSION_ID, deviceCipher())

        val inbound = transport.receive()

        assertTrue("expected a frame, got $inbound", inbound is Inbound.Frame)
        assertEquals(expected, (inbound as Inbound.Frame).envelope)
        assertTrue(!channel.closed)
    }

    @Test
    fun `keepalive pings the relay while the session is open and stops afterwards`() = runTest {
        val channel = FakeFrameChannel(events = listOf(ChannelEvent.Closed("peer_closed")))
        val transport = AgentTransport(channel, DEVICE_ID, SESSION_ID, deviceCipher())

        transport.keepalive()
        assertEquals(1, channel.keepalives)

        transport.receive()
        transport.keepalive()
        assertEquals("a closed session must not ping", 1, channel.keepalives)
    }

    @Test
    fun `an invalid identifier is refused before any frame is sent`() = runTest {
        val channel = FakeFrameChannel()
        val error = runCatching { AgentTransport(channel, "bad id", SESSION_ID, deviceCipher()) }.exceptionOrNull()

        assertTrue("expected an InvalidIdentifier, got $error", error is WireError.InvalidIdentifier)
        assertTrue(channel.sent.isEmpty())
    }

    private fun transportFor(closeReason: String) = AgentTransport(
        FakeFrameChannel(events = listOf(ChannelEvent.Closed(closeReason))),
        DEVICE_ID,
        SESSION_ID,
        deviceCipher(),
    )

    private fun controlEnvelope(sequence: Int) = EnvelopeCodec.newEnvelope(
        streamKind = StreamKind.STREAM_KIND_CONTROL,
        deviceId = DEVICE_ID,
        sessionId = SESSION_ID,
        requestId = "request-0042",
    ).toBuilder().setSequence(sequence).build()

    private fun deviceCipher(): SessionCipher {
        EpochClaims.clear()
        return SessionCipher.agree(
            IdentityKey.fromBytes(ByteArray(32) { 0x33 }).getOrThrow(),
            clientPublic(),
            SESSION_ID,
            SessionRole.DEVICE,
            epoch(),
        ).getOrThrow()
    }

    private fun clientCipher(): SessionCipher {
        EpochClaims.clear()
        return SessionCipher.agree(
            IdentityKey.fromBytes(ByteArray(32) { 0x44 }).getOrThrow(),
            devicePublic(),
            SESSION_ID,
            SessionRole.CLIENT,
            epoch(),
        ).getOrThrow()
    }

    private fun epoch() = Epoch.of("client-nonce", "device-nonce").getOrThrow()

    private fun devicePublic() = IdentityKey.fromBytes(ByteArray(32) { 0x33 }).getOrThrow().publicKey()

    private fun clientPublic() = IdentityKey.fromBytes(ByteArray(32) { 0x44 }).getOrThrow().publicKey()

    private fun String.hex(): ByteArray {
        require(length % 2 == 0)
        return ByteArray(length / 2) { index -> substring(index * 2, index * 2 + 2).toInt(16).toByte() }
    }

    private fun ByteArray.toHex(): String = joinToString("") { "%02x".format(it) }

    private class FakeFrameChannel(
        private val events: List<ChannelEvent> = emptyList(),
        private var failSends: Int = 0,
    ) : FrameChannel {
        private val queue = ArrayDeque(events)
        val sent = mutableListOf<ByteArray>()
        var closed = false
            private set
        var keepalives = 0
            private set

        override suspend fun send(frame: ByteArray) {
            if (failSends > 0) {
                failSends -= 1
                throw IllegalStateException("channel is not writable")
            }
            check(!closed) { "send on a closed channel" }
            sent += frame
        }

        override suspend fun receive(): ChannelEvent =
            queue.removeFirstOrNull() ?: ChannelEvent.Closed("peer_closed")

        override suspend fun keepalive() {
            keepalives += 1
        }

        override fun close() {
            closed = true
        }
    }

    private companion object {
        const val DEVICE_ID = "dev_transport"
        const val SESSION_ID = "sess_transport"
    }
}
