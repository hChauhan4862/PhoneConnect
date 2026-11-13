package com.phoneconnect.agent

import com.google.protobuf.ByteString
import com.phoneconnect.agent.crypto.SealedFrame
import com.phoneconnect.agent.crypto.SessionCipher
import com.phoneconnect.agent.wire.Envelope
import com.phoneconnect.agent.wire.StreamKind

/**
 * One message delivered by a [FrameChannel]: a whole routing frame, or the end of the stream.
 *
 * A routing frame is a length-prefixed PhoneConnect envelope whose payload is the sealed
 * frame, exactly what `ConnectedPath::relay_envelope` puts on the relay. The relay validates
 * and bounds that envelope without reading its payload.
 */
sealed interface ChannelEvent {
    data class Frame(val bytes: ByteArray) : ChannelEvent

    /** The peer or relay closed the stream; [reason] is the server's stable close code. */
    data class Closed(val reason: String?) : ChannelEvent
}

/**
 * The authenticated byte channel one session runs on: exactly one routing frame per message.
 *
 * A channel moves bytes and reports the server's close code; it never sees plaintext and never
 * unwraps the sealed payload. The relay lease (`409 relay_unavailable`) never produces a
 * channel, so a session that cannot relay ends before this interface is reached.
 */
interface FrameChannel : AutoCloseable {
    suspend fun send(frame: ByteArray)

    suspend fun receive(): ChannelEvent

    /**
     * Writes a WebSocket ping on transports that need one. The server closes a relay
     * direction that has carried nothing for 30 seconds, so a channel says it is still there
     * without consuming a frame slot, a sequence number, or a queue entry.
     */
    suspend fun keepalive() {}

    override fun close()
}

/** What a receive produced. */
sealed interface Inbound {
    data class Frame(val envelope: Envelope) : Inbound

    /** The stream is over; [failure] decides whether it is retried. */
    data class End(val failure: ConnectionFailure) : Inbound
}

/**
 * Speaks the shared envelope contract on one session: control and event streams only,
 * monotonic per-stream sequence numbers, the 1 MiB control-only frame profile, sealing every
 * frame through [SessionCipher], binding inbound frames to this session and device, and
 * turning server revocation into an immediate stream close.
 */
class AgentTransport(
    private val channel: FrameChannel,
    private val deviceId: String,
    private val sessionId: String,
    private val cipher: SessionCipher,
) : AutoCloseable {
    private val sequences = mutableMapOf<StreamKind, Long>()
    private var ended: ConnectionFailure? = null

    init {
        // Fail at construction, not on the first send: a bad identity can never produce a
        // frame a peer would have to reject.
        EnvelopeCodec.validate(EnvelopeCodec.newEnvelope(StreamKind.STREAM_KIND_CONTROL, deviceId, sessionId))
    }

    suspend fun sendControl(requestId: String, payload: ByteArray, deadlineUnixMs: Long = 0) {
        send(StreamKind.STREAM_KIND_CONTROL, requestId, payload, deadlineUnixMs)
    }

    suspend fun sendEvent(payload: ByteArray, deadlineUnixMs: Long = 0) {
        send(StreamKind.STREAM_KIND_EVENTS, "", payload, deadlineUnixMs)
    }

    suspend fun receive(): Inbound {
        ended?.let { return Inbound.End(it) }
        return when (val event = channel.receive()) {
            is ChannelEvent.Frame -> {
                val sealed = routingPayload(event.bytes).getOrElse { error ->
                    return end(error.asProtocolFailure())
                }
                val envelope = cipher.open(sealed).getOrElse { error ->
                    return end(error.asProtocolFailure())
                }
                // A frame sealed by this session can still be addressed elsewhere if a peer
                // is confused; never surface another session's or device's traffic.
                if (envelope.sessionId != sessionId || envelope.deviceId != deviceId) {
                    return end(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR))
                }
                Inbound.Frame(envelope)
            }

            is ChannelEvent.Closed -> end(failureFor(event.reason))
        }
    }

    /** Pings the relay so a quiet direction is not reaped while the session is healthy. */
    suspend fun keepalive() {
        if (ended == null) channel.keepalive()
    }

    override fun close() {
        channel.close()
    }

    private suspend fun send(kind: StreamKind, requestId: String, payload: ByteArray, deadlineUnixMs: Long) {
        check(ended == null) { "the session is already over: $ended" }
        val sequence = sequences[kind] ?: FIRST_SEQUENCE
        if (sequence > MAX_SEQUENCE) {
            throw WireError.SequenceExhausted(MAX_SEQUENCE.toUInt())
        }
        val envelope = EnvelopeCodec.newEnvelope(kind, deviceId, sessionId, requestId).toBuilder()
            .setSequence(sequence.toInt())
            .setDeadlineUnixMs(deadlineUnixMs)
            .setPayload(ByteString.copyFrom(payload))
            .build()
        // The sequence number is consumed only once the frame is actually sealed and handed
        // to the channel: a failed send must not leave a hole in a monotonic stream.
        val sealed = cipher.seal(envelope).getOrThrow()
        channel.send(routingFrame(sealed))
        sequences[kind] = sequence + 1
    }

    /**
     * Wraps a sealed frame in the routing envelope the relay validates and bounds. Mirrors
     * `ConnectedPath::relay_envelope`: the stream kind comes from the sealed header, the ids
     * are this session's, and the request id and sequence are unset.
     */
    private fun routingFrame(sealed: ByteArray): ByteArray {
        val number = SealedFrame.streamKind(sealed)
            ?: throw WireError.MalformedBody("sealed frame has no readable stream kind")
        val kind = EnvelopeCodec.streamKindOf(number)
            ?: throw WireError.UnknownStreamKind(number)
        val outer = EnvelopeCodec.newEnvelope(kind, deviceId, sessionId).toBuilder()
            .setPayload(ByteString.copyFrom(sealed))
            .build()
        return EnvelopeCodec.encode(outer).getOrThrow()
    }

    /** Decodes one routing frame and returns its sealed payload. */
    private fun routingPayload(frame: ByteArray): Result<ByteArray> = runCatching {
        val decoded = EnvelopeCodec.decode(frame).getOrElse { throw it }
        if (decoded.consumed != frame.size) {
            throw WireError.MalformedBody("routing frame carries ${frame.size - decoded.consumed} trailing bytes")
        }
        if (decoded.envelope.deviceId != deviceId || decoded.envelope.sessionId != sessionId) {
            throw WireError.MalformedBody("routing frame is for another session or device")
        }
        decoded.envelope.payload.toByteArray()
    }

    private fun end(failure: ConnectionFailure): Inbound.End {
        ended = failure
        channel.close()
        return Inbound.End(failure)
    }

    /**
     * Every sealing, framing, or validation failure ends the stream as a protocol failure.
     * A bad tag and a bad envelope are equally fatal to this session and equally retryable on
     * a fresh one; none of them is ever dropped silently or surfaced as data.
     */
    private fun Throwable.asProtocolFailure(): ConnectionFailure =
        ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)

    private fun failureFor(closeReason: String?): ConnectionFailure = when (closeReason) {
        // The device is revoked: retrying cannot authenticate again.
        "device_revoked" -> ConnectionFailure.DeviceRevoked
        // The session is gone. The enrollment is still valid, but this session id is done.
        // `lease_revoked` is the same outcome for the stream: the control lease that
        // authorized it ended, so this capability must not be reused.
        "session_revoked", "session_expired", "session_closed", "session_unknown",
        "lease_revoked",
        -> ConnectionFailure.SessionEnded
        // A relay lease refused for this session id is terminal for that id only.
        "relay_unavailable" -> ConnectionFailure.RelayUnavailable
        // Ordinary transport faults: retry with backoff.
        null, "peer_closed", "idle_timeout", "backpressure", "byte_budget_exhausted", "store_unavailable" ->
            ConnectionFailure.Retryable(ReconnectReason.TRANSPORT_CLOSED)
        // The peer broke framing or announced a reason this build cannot classify.
        else -> ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)
    }

    private companion object {
        const val FIRST_SEQUENCE = 1L

        /** `uint32::MAX` as an unsigned count; sequences never wrap. */
        const val MAX_SEQUENCE = 0xFFFF_FFFFL
    }
}
