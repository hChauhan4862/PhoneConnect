package com.phoneconnect.agent

import com.google.protobuf.InvalidProtocolBufferException
import com.phoneconnect.agent.wire.Envelope
import com.phoneconnect.agent.wire.StreamKind

/**
 * Explicit wire failures. Nothing is repaired or defaulted: a frame either survives
 * validation or the stream learns exactly why it did not.
 */
sealed class WireError(message: String) : Exception(message) {
    data class TruncatedPrefix(val available: Int) :
        WireError("truncated frame prefix: $available of $EnvelopeCodec.LENGTH_PREFIX_LEN bytes")

    data class TruncatedFrame(val declared: Int, val available: Int) :
        WireError("truncated frame: $declared bytes declared, $available buffered")

    data class FrameTooLarge(
        val streamKind: StreamKind?,
        val declared: Int,
        val limit: Int,
    ) : WireError("frame of $declared bytes exceeds the $limit-byte limit for $streamKind")

    data class UnknownStreamKind(val value: Int) : WireError("unknown stream kind $value")

    data object MissingStreamKind : WireError("envelope is missing a stream kind")

    data class UnsupportedVersion(val found: Int, val supported: Int) :
        WireError("protocol version $found is not supported; this build speaks $supported")

    data class InvalidIdentifier(val kind: String, val reason: String) :
        WireError("invalid $kind: $reason")

    data class SequenceExhausted(val sequence: UInt) :
        WireError("sequence $sequence cannot be advanced; the stream must be re-established")

    data class MalformedBody(val detail: String) : WireError("malformed protobuf frame: $detail")
}

/** A decoded envelope plus the bytes it occupied, so callers can drain a buffer. */
data class DecodedEnvelope(val envelope: Envelope, val consumed: Int)

/**
 * The agent side of the shared envelope contract (`proto/phoneconnect/v1/envelope.proto`).
 *
 * Frames are a four-byte big-endian length prefix followed by an encoded [Envelope]. The
 * agent only ever carries control and event streams, so it applies the control-only
 * profile: the prefix itself is capped at 1 MiB before any body is buffered, exactly as
 * `FrameLimits::control_only()` does in the Rust crates.
 */
object EnvelopeCodec {
    const val PROTOCOL_VERSION: Int = 1
    const val LENGTH_PREFIX_LEN: Int = 4
    const val CONTROL_FRAME_LIMIT: Int = 1024 * 1024
    const val MAX_IDENTIFIER_LEN: Int = 128

    private val identifierChars = "-_.:=".toSet()

    fun newEnvelope(
        streamKind: StreamKind,
        deviceId: String,
        sessionId: String,
        requestId: String = "",
    ): Envelope = Envelope.newBuilder()
        .setProtocolVersion(PROTOCOL_VERSION)
        .setStreamKind(streamKind)
        .setDeviceId(deviceId)
        .setSessionId(sessionId)
        .setRequestId(requestId)
        .setSequence(0)
        .setDeadlineUnixMs(0)
        .build()

    /** Validates [envelope] and returns its length-delimited frame. */
    fun encode(envelope: Envelope): Result<ByteArray> = runCatching {
        val streamKind = validate(envelope)
        val body = envelope.toByteArray()
        if (body.size > CONTROL_FRAME_LIMIT) {
            throw WireError.FrameTooLarge(streamKind, body.size, CONTROL_FRAME_LIMIT)
        }
        val frame = ByteArray(LENGTH_PREFIX_LEN + body.size)
        writeLengthPrefix(frame, body.size)
        body.copyInto(frame, LENGTH_PREFIX_LEN)
        frame
    }

    /**
     * Decodes the first frame in [buffer]. Trailing bytes are left alone so a buffered
     * stream of frames can be drained in order.
     */
    fun decode(buffer: ByteArray): Result<DecodedEnvelope> = runCatching {
        if (buffer.size < LENGTH_PREFIX_LEN) {
            throw WireError.TruncatedPrefix(buffer.size)
        }
        val announced = readLengthPrefix(buffer)
        // Refuse from the prefix alone: the stream kind is not known yet, so the profile's
        // 1 MiB ceiling is what protects the buffer. Compare before narrowing, or a prefix
        // like 0xFFFFFFFF would wrap into a negative length.
        if (announced > CONTROL_FRAME_LIMIT.toLong()) {
            throw WireError.FrameTooLarge(
                streamKind = null,
                declared = announced.coerceAtMost(Int.MAX_VALUE.toLong()).toInt(),
                limit = CONTROL_FRAME_LIMIT,
            )
        }
        val declared = announced.toInt()
        val available = buffer.size - LENGTH_PREFIX_LEN
        if (available < declared) {
            throw WireError.TruncatedFrame(declared = declared, available = available)
        }
        val envelope = try {
            Envelope.parseFrom(buffer.copyOfRange(LENGTH_PREFIX_LEN, LENGTH_PREFIX_LEN + declared))
        } catch (error: InvalidProtocolBufferException) {
            throw WireError.MalformedBody(error.message ?: "invalid protobuf")
        }
        validate(envelope)
        DecodedEnvelope(envelope, LENGTH_PREFIX_LEN + declared)
    }

    /** Advances the per-stream counter, refusing to wrap. */
    fun advanceSequence(envelope: Envelope): Result<Envelope> = runCatching {
        val current = envelope.sequence.toUInt()
        if (current == UInt.MAX_VALUE) {
            throw WireError.SequenceExhausted(current)
        }
        envelope.toBuilder().setSequence((current + 1u).toInt()).build()
    }

    /** Checks what a relay or peer must not be trusted about; returns the decoded kind. */
    fun validate(envelope: Envelope): StreamKind {
        if (envelope.protocolVersion != PROTOCOL_VERSION) {
            throw WireError.UnsupportedVersion(envelope.protocolVersion, PROTOCOL_VERSION)
        }
        val streamKind = when (val value = envelope.streamKindValue) {
            0 -> throw WireError.MissingStreamKind
            1 -> StreamKind.STREAM_KIND_CONTROL
            2 -> StreamKind.STREAM_KIND_EVENTS
            3 -> StreamKind.STREAM_KIND_FILE
            4 -> StreamKind.STREAM_KIND_MEDIA
            5 -> StreamKind.STREAM_KIND_PROXY
            else -> throw WireError.UnknownStreamKind(value)
        }
        validateIdentifier("device_id", envelope.deviceId)
        if (envelope.sessionId.isNotEmpty()) {
            validateIdentifier("session_id", envelope.sessionId)
        }
        if (envelope.requestId.isNotEmpty()) {
            validateIdentifier("request_id", envelope.requestId)
        }
        return streamKind
    }

    private fun validateIdentifier(kind: String, value: String) {
        if (value.isEmpty()) {
            throw WireError.InvalidIdentifier(kind, "must not be empty")
        }
        if (value.length > MAX_IDENTIFIER_LEN) {
            throw WireError.InvalidIdentifier(kind, "must be at most $MAX_IDENTIFIER_LEN bytes")
        }
        val valid = value.all { character ->
            character in 'a'..'z' || character in 'A'..'Z' || character in '0'..'9' || character in identifierChars
        }
        if (!valid) {
            throw WireError.InvalidIdentifier(
                kind,
                "may only contain ASCII letters, digits, and '-', '_', '.', ':', '='",
            )
        }
    }

    private fun readLengthPrefix(buffer: ByteArray): Long =
        ((buffer[0].toLong() and 0xFF) shl 24) or
            ((buffer[1].toLong() and 0xFF) shl 16) or
            ((buffer[2].toLong() and 0xFF) shl 8) or
            (buffer[3].toLong() and 0xFF)

    private fun writeLengthPrefix(frame: ByteArray, length: Int) {
        frame[0] = (length ushr 24).toByte()
        frame[1] = (length ushr 16).toByte()
        frame[2] = (length ushr 8).toByte()
        frame[3] = length.toByte()
    }
}
