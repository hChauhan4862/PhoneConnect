package com.phoneconnect.agent

import com.google.protobuf.ByteString
import com.phoneconnect.agent.wire.Envelope
import com.phoneconnect.agent.wire.StreamKind

/** One message delivered by a [FrameChannel]: a whole frame, or the end of the stream. */
sealed interface ChannelEvent {
    data class Frame(val bytes: ByteArray) : ChannelEvent

    /** The peer or relay closed the stream; [reason] is the server's stable close code. */
    data class Closed(val reason: String?) : ChannelEvent
}

/**
 * The authenticated byte channel one session runs on: exactly one PhoneConnect frame per
 * message, sealed end to end before it reaches the relay.
 *
 * Sealing is the implementation's contract: a channel hands [AgentTransport] plaintext
 * frames only after the session is authenticated and closes with the server's close code.
 * The relay lease (`409 relay_unavailable`) never produces a channel, so a session that
 * cannot relay ends before this interface is reached.
 */
interface FrameChannel : AutoCloseable {
    suspend fun send(frame: ByteArray)

    suspend fun receive(): ChannelEvent

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
 * monotonic per-stream sequence numbers, the 1 MiB control-only frame profile, and
 * server revocation as an immediate stream close.
 *
 * It owns framing and stream lifecycle, not the sealed transport: a [FrameChannel] arrives
 * already authenticated and sealed.
 */
class AgentTransport(
    private val channel: FrameChannel,
    deviceId: String,
    sessionId: String,
) : AutoCloseable {
    private val deviceId: String = deviceId
    private val sessionId: String = sessionId
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
                val decoded = EnvelopeCodec.decode(event.bytes).getOrElse { error ->
                    return end(error.asProtocolFailure())
                }
                if (decoded.consumed != event.bytes.size) {
                    // A channel message carries exactly one frame; anything else means the
                    // two sides disagree about framing.
                    return end(ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR))
                }
                Inbound.Frame(decoded.envelope)
            }

            is ChannelEvent.Closed -> end(failureFor(event.reason))
        }
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
        sequences[kind] = sequence + 1

        val envelope = EnvelopeCodec.newEnvelope(kind, deviceId, sessionId, requestId).toBuilder()
            .setSequence(sequence.toInt())
            .setDeadlineUnixMs(deadlineUnixMs)
            .setPayload(ByteString.copyFrom(payload))
            .build()
        channel.send(EnvelopeCodec.encode(envelope).getOrThrow())
    }

    private fun end(failure: ConnectionFailure): Inbound.End {
        ended = failure
        channel.close()
        return Inbound.End(failure)
    }

    /** Every framing or validation failure is a protocol failure, never a silent drop. */
    private fun Throwable.asProtocolFailure(): ConnectionFailure =
        ConnectionFailure.Retryable(ReconnectReason.PROTOCOL_ERROR)

    private fun failureFor(closeReason: String?): ConnectionFailure = when (closeReason) {
        // The device is revoked: retrying cannot authenticate again.
        "device_revoked" -> ConnectionFailure.DeviceRevoked
        // The session is gone. The enrollment is still valid, but this session id is done.
        "session_revoked", "session_expired", "session_closed", "session_unknown" ->
            ConnectionFailure.SessionEnded
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
