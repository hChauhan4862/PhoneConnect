//! Codec contract for PhoneConnect envelopes.
//!
//! These tests are written against `phoneconnect::v1` because every later component
//! (server, native transport, relay) compiles against that path.

use phoneconnect::v1::{
    CONTROL_FRAME_LIMIT, DeviceId, Envelope, FrameLimits, LENGTH_PREFIX_LEN, PROTOCOL_VERSION,
    ProtocolError, RequestId, STREAM_FRAME_LIMIT, SessionId, StreamKind, decode_frame,
    encode_frame, read_frame_length,
};
use prost::Message;

fn device() -> DeviceId {
    DeviceId::new("device-7f3a").expect("valid device id")
}

fn session() -> SessionId {
    SessionId::new("session-91c2").expect("valid session id")
}

fn request() -> RequestId {
    RequestId::new("request-0042").expect("valid request id")
}

fn sample_envelope() -> Envelope {
    let mut envelope = Envelope::new(StreamKind::Control, &device(), &session(), &request());
    envelope.sequence = 7;
    envelope.deadline_unix_ms = 1_760_000_000_000;
    envelope.payload = b"list-devices".to_vec();
    envelope
}

/// Encodes `envelope` into a frame without any protocol validation, so tests can
/// hand the decoder input a real peer could send.
fn raw_frame(envelope: &Envelope) -> Vec<u8> {
    let body = envelope.encode_to_vec();
    let mut frame = (body.len() as u32).to_be_bytes().to_vec();
    frame.extend_from_slice(&body);
    frame
}

#[test]
fn round_trips_every_envelope_field() {
    let limits = FrameLimits::default();
    let envelope = sample_envelope();

    let frame = encode_frame(&envelope, &limits).expect("encode succeeds");
    assert_eq!(
        u32::from_be_bytes(frame[..4].try_into().unwrap()) as usize,
        frame.len() - 4,
        "length prefix must describe the body exactly"
    );

    let decoded = decode_frame(&frame, &limits).expect("decode succeeds");
    assert_eq!(decoded.consumed, frame.len());
    assert_eq!(decoded.envelope, envelope);
    assert_eq!(decoded.envelope.protocol_version, PROTOCOL_VERSION);
    assert_eq!(
        StreamKind::try_from(decoded.envelope.stream_kind).unwrap(),
        StreamKind::Control
    );
    assert_eq!(decoded.envelope.device_id, "device-7f3a");
    assert_eq!(decoded.envelope.session_id, "session-91c2");
    assert_eq!(decoded.envelope.request_id, "request-0042");
    assert_eq!(decoded.envelope.sequence, 7);
    assert_eq!(decoded.envelope.deadline_unix_ms, 1_760_000_000_000);
    assert_eq!(decoded.envelope.payload, b"list-devices");
}

#[test]
fn reports_consumed_bytes_for_buffered_frames() {
    let limits = FrameLimits::default();
    let first = encode_frame(&sample_envelope(), &limits).expect("encode succeeds");
    let mut second_envelope = sample_envelope();
    second_envelope.sequence = 8;
    let second = encode_frame(&second_envelope, &limits).expect("encode succeeds");

    let mut buffer = first.clone();
    buffer.extend_from_slice(&second);

    let decoded = decode_frame(&buffer, &limits).expect("decode succeeds");
    assert_eq!(decoded.consumed, first.len());
    assert_eq!(decoded.envelope.sequence, 7);

    let decoded = decode_frame(&buffer[decoded.consumed..], &limits).expect("decode succeeds");
    assert_eq!(decoded.consumed, second.len());
    assert_eq!(decoded.envelope.sequence, 8);
}

#[test]
fn rejects_unknown_stream_kinds() {
    let limits = FrameLimits::default();

    let mut envelope = sample_envelope();
    envelope.stream_kind = 99;
    let error = encode_frame(&envelope, &limits).expect_err("unknown kind must not encode");
    assert!(
        matches!(error, ProtocolError::UnknownStreamKind { value: 99 }),
        "expected UnknownStreamKind(99), got {error:?}"
    );

    let error =
        decode_frame(&raw_frame(&envelope), &limits).expect_err("unknown kind must not decode");
    assert!(
        matches!(error, ProtocolError::UnknownStreamKind { value: 99 }),
        "expected UnknownStreamKind(99), got {error:?}"
    );

    envelope.set_kind(StreamKind::Unspecified);
    let error = encode_frame(&envelope, &limits).expect_err("an unset kind must not encode");
    assert!(
        matches!(error, ProtocolError::MissingStreamKind),
        "expected MissingStreamKind, got {error:?}"
    );
}

#[test]
fn rejects_malformed_identifiers_from_the_wire() {
    let limits = FrameLimits::default();

    let mut envelope = sample_envelope();
    envelope.device_id = "device\nforged-log-line".to_owned();
    let error = decode_frame(&raw_frame(&envelope), &limits).expect_err("junk ids must not decode");
    assert!(
        matches!(
            error,
            ProtocolError::InvalidIdentifier {
                kind: "device_id",
                ..
            }
        ),
        "expected InvalidIdentifier(device_id), got {error:?}"
    );

    let mut envelope = sample_envelope();
    envelope.device_id = String::new();
    let error = encode_frame(&envelope, &limits).expect_err("an empty device id must not encode");
    assert!(
        matches!(
            error,
            ProtocolError::InvalidIdentifier {
                kind: "device_id",
                ..
            }
        ),
        "expected InvalidIdentifier(device_id), got {error:?}"
    );
}

#[test]
fn rejects_unsupported_protocol_versions() {
    let limits = FrameLimits::default();

    let mut envelope = sample_envelope();
    envelope.protocol_version = PROTOCOL_VERSION + 1;
    let error = encode_frame(&envelope, &limits).expect_err("future version must not encode");
    assert!(
        matches!(
            error,
            ProtocolError::UnsupportedVersion { found, supported }
                if found == PROTOCOL_VERSION + 1 && supported == PROTOCOL_VERSION
        ),
        "expected UnsupportedVersion, got {error:?}"
    );

    let error =
        decode_frame(&raw_frame(&envelope), &limits).expect_err("future version must not decode");
    assert!(
        matches!(error, ProtocolError::UnsupportedVersion { .. }),
        "expected UnsupportedVersion, got {error:?}"
    );
}

#[test]
fn rejects_truncated_frames() {
    let limits = FrameLimits::default();
    let frame = encode_frame(&sample_envelope(), &limits).expect("encode succeeds");

    let error = decode_frame(&[], &limits).expect_err("empty input is truncated");
    assert!(
        matches!(error, ProtocolError::TruncatedPrefix { available: 0 }),
        "expected TruncatedPrefix, got {error:?}"
    );

    let error = decode_frame(&frame[..2], &limits).expect_err("short prefix is truncated");
    assert!(
        matches!(error, ProtocolError::TruncatedPrefix { available: 2 }),
        "expected TruncatedPrefix, got {error:?}"
    );

    let error =
        decode_frame(&frame[..frame.len() - 3], &limits).expect_err("short body is truncated");
    assert!(
        matches!(
            error,
            ProtocolError::TruncatedFrame { declared, available }
                if declared == frame.len() - 4 && available == frame.len() - 4 - 3
        ),
        "expected TruncatedFrame with the declared length, got {error:?}"
    );
}

#[test]
fn rejects_empty_bodies_instead_of_defaulting() {
    let limits = FrameLimits::default();
    let frame = 0u32.to_be_bytes();

    let error = decode_frame(&frame, &limits).expect_err("an empty body carries no version");
    assert!(
        matches!(error, ProtocolError::UnsupportedVersion { found: 0, .. }),
        "expected UnsupportedVersion(0), got {error:?}"
    );
}

#[test]
fn sequence_never_wraps_silently() {
    let mut envelope = sample_envelope();
    envelope.sequence = 41;
    assert_eq!(envelope.advance_sequence().expect("increment"), 42);
    assert_eq!(envelope.sequence, 42);

    envelope.sequence = u32::MAX;
    let error = envelope
        .advance_sequence()
        .expect_err("overflow must be explicit");
    assert!(
        matches!(
            error,
            ProtocolError::SequenceExhausted { sequence: u32::MAX }
        ),
        "expected SequenceExhausted, got {error:?}"
    );
    assert_eq!(
        envelope.sequence,
        u32::MAX,
        "a failed advance must not mutate"
    );
}

#[test]
fn enforces_the_one_mib_control_frame_limit() {
    assert_eq!(CONTROL_FRAME_LIMIT, 1024 * 1024);
    let limits = FrameLimits::default();

    let mut envelope = sample_envelope();
    envelope.payload = vec![0u8; CONTROL_FRAME_LIMIT as usize];
    let error =
        encode_frame(&envelope, &limits).expect_err("oversized control frame must not encode");
    assert!(
        matches!(
            error,
            ProtocolError::FrameTooLarge { stream_kind: Some(StreamKind::Control), limit, .. }
                if limit == CONTROL_FRAME_LIMIT as usize
        ),
        "expected FrameTooLarge(Control), got {error:?}"
    );

    // A peer only has to send a length prefix claiming more than the largest configured
    // limit: the decoder must fail closed from the prefix alone, before buffering the body.
    let mut frame = (STREAM_FRAME_LIMIT + 1).to_be_bytes().to_vec();
    frame.extend_from_slice(&[0u8; 16]);
    let error = decode_frame(&frame, &limits).expect_err("oversized prefix must be rejected");
    assert!(
        matches!(error, ProtocolError::FrameTooLarge { length, limit, .. }
            if length == STREAM_FRAME_LIMIT as usize + 1 && limit == STREAM_FRAME_LIMIT as usize),
        "expected FrameTooLarge from the prefix alone, got {error:?}"
    );

    // A control-only connection uses the dedicated profile, so the 1 MiB cap applies to
    // the prefix before the stream kind can be inspected.
    let control_only = FrameLimits::control_only();
    assert_eq!(control_only.max_limit(), CONTROL_FRAME_LIMIT);
    let mut frame = (CONTROL_FRAME_LIMIT + 1).to_be_bytes().to_vec();
    frame.extend_from_slice(&[0u8; 16]);
    let error = decode_frame(&frame, &control_only)
        .expect_err("control-only prefix above 1 MiB must be rejected");
    assert!(
        matches!(error, ProtocolError::FrameTooLarge { length, limit, .. }
            if length == CONTROL_FRAME_LIMIT as usize + 1 && limit == CONTROL_FRAME_LIMIT as usize),
        "expected FrameTooLarge from the 1 MiB prefix cap, got {error:?}"
    );

    let mut envelope = sample_envelope();
    envelope.payload = vec![0u8; CONTROL_FRAME_LIMIT as usize - 32];
    let error =
        encode_frame(&envelope, &limits).expect_err("near-limit payload still overflows the frame");
    assert!(
        matches!(
            error,
            ProtocolError::FrameTooLarge {
                stream_kind: Some(StreamKind::Control),
                ..
            }
        ),
        "expected FrameTooLarge(Control), got {error:?}"
    );
}

#[test]
fn stream_limits_are_configurable_per_stream_kind() {
    let defaults = FrameLimits::default();
    let mut envelope = sample_envelope();
    envelope.set_kind(StreamKind::File);
    envelope.payload = vec![7u8; 2 * 1024 * 1024];

    let frame = encode_frame(&envelope, &defaults).expect("file streams allow more than 1 MiB");
    let decoded = decode_frame(&frame, &defaults).expect("file streams decode");
    assert_eq!(decoded.envelope.payload.len(), 2 * 1024 * 1024);

    let tight = FrameLimits::default()
        .with_stream_limit(StreamKind::File, 1024 * 1024)
        .expect("non-zero limit");
    let error = encode_frame(&envelope, &tight).expect_err("tightened file limit must reject");
    assert!(
        matches!(
            error,
            ProtocolError::FrameTooLarge { stream_kind: Some(StreamKind::File), limit, .. }
                if limit == 1024 * 1024
        ),
        "expected FrameTooLarge(File) with the configured limit, got {error:?}"
    );
    let error =
        decode_frame(&frame, &tight).expect_err("tightened file limit must reject decoded frames");
    assert!(
        matches!(
            error,
            ProtocolError::FrameTooLarge {
                stream_kind: Some(StreamKind::File),
                ..
            }
        ),
        "expected FrameTooLarge(File), got {error:?}"
    );

    assert_eq!(
        FrameLimits::default().limit_for(StreamKind::Control),
        CONTROL_FRAME_LIMIT
    );
    assert_eq!(
        FrameLimits::default().limit_for(StreamKind::Events),
        CONTROL_FRAME_LIMIT
    );
    assert!(FrameLimits::default().limit_for(StreamKind::Proxy) > CONTROL_FRAME_LIMIT);
    assert!(
        FrameLimits::default()
            .with_stream_limit(StreamKind::Media, 0)
            .is_err(),
        "a zero limit would reject every frame, which is a configuration error"
    );
}

#[test]
fn control_only_profile_rejects_oversized_frames_at_the_prefix() {
    let control_only = FrameLimits::control_only();
    assert_eq!(control_only.max_limit(), CONTROL_FRAME_LIMIT);
    for kind in [
        StreamKind::Control,
        StreamKind::Events,
        StreamKind::File,
        StreamKind::Media,
        StreamKind::Proxy,
    ] {
        assert_eq!(
            control_only.limit_for(kind),
            CONTROL_FRAME_LIMIT,
            "control-only caps {kind:?} at the control limit"
        );
    }

    // A file frame that the default profile accepts is refused at the prefix, before the
    // body is inspected: the per-kind limit cannot be known yet, so the profile's 1 MiB
    // cap must do the rejecting.
    let mut file_envelope = sample_envelope();
    file_envelope.set_kind(StreamKind::File);
    file_envelope.payload = vec![7u8; 2 * 1024 * 1024];
    let file_frame = raw_frame(&file_envelope);
    assert!(
        file_frame.len() > CONTROL_FRAME_LIMIT as usize,
        "the fixture must exceed the control limit"
    );
    let error = decode_frame(&file_frame, &control_only)
        .expect_err("a control-only peer must not buffer a 2 MiB frame");
    assert!(
        matches!(
            error,
            ProtocolError::FrameTooLarge {
                stream_kind: None,
                length,
                limit
            } if length == file_frame.len() - LENGTH_PREFIX_LEN && limit == CONTROL_FRAME_LIMIT as usize
        ),
        "expected a prefix-level FrameTooLarge for a 2 MiB frame, got {error:?}"
    );

    // Only the prefix is buffered: a peer announcing an oversized control frame and then
    // sending no body must be refused for size, not reported as truncated.
    let truncated_body = (CONTROL_FRAME_LIMIT + 1).to_be_bytes().to_vec();
    assert_eq!(truncated_body.len(), LENGTH_PREFIX_LEN);
    let error = decode_frame(&truncated_body, &control_only)
        .expect_err("an oversized announcement is rejected before any body read");
    assert!(
        matches!(
            error,
            ProtocolError::FrameTooLarge {
                stream_kind: None,
                length,
                limit
            } if length == CONTROL_FRAME_LIMIT as usize + 1 && limit == CONTROL_FRAME_LIMIT as usize
        ),
        "expected a prefix-level FrameTooLarge with no body buffered, got {error:?}"
    );

    // Legal control frames still decode under the profile.
    let mut envelope = sample_envelope();
    envelope.payload = vec![0u8; CONTROL_FRAME_LIMIT as usize - 256];
    let frame = encode_frame(&envelope, &control_only).expect("control frame within 1 MiB encodes");
    let decoded = decode_frame(&frame, &control_only).expect("control frame within 1 MiB decodes");
    assert_eq!(decoded.envelope, envelope);
}

#[test]
fn refuses_limits_for_the_unspecified_stream_kind() {
    let error = FrameLimits::default()
        .with_stream_limit(StreamKind::Unspecified, 8 * 1024 * 1024)
        .expect_err("Unspecified must not alias the control limit");
    assert!(
        matches!(
            error,
            ProtocolError::UnspecifiedStreamKindLimit { limit } if limit == 8 * 1024 * 1024
        ),
        "expected UnspecifiedStreamKindLimit, got {error:?}"
    );

    let limits = FrameLimits::default();
    assert_eq!(
        limits.limit_for(StreamKind::Control),
        CONTROL_FRAME_LIMIT,
        "a refused configuration must not change the control limit"
    );
    assert_eq!(limits.max_limit(), STREAM_FRAME_LIMIT);
}

#[test]
fn length_prefixes_are_bounded_before_any_body_is_read() {
    let limits = FrameLimits::default();
    assert_eq!(LENGTH_PREFIX_LEN, 4);
    assert_eq!(limits.max_limit(), STREAM_FRAME_LIMIT);

    let declared = read_frame_length(512u32.to_be_bytes(), &limits).expect("within limits");
    assert_eq!(declared, 512);

    let error = read_frame_length((STREAM_FRAME_LIMIT + 1).to_be_bytes(), &limits)
        .expect_err("a prefix above every configured limit must be refused");
    assert!(
        matches!(
            error,
            ProtocolError::FrameTooLarge {
                stream_kind: None,
                length,
                limit
            } if length == STREAM_FRAME_LIMIT as usize + 1 && limit == STREAM_FRAME_LIMIT as usize
        ),
        "expected FrameTooLarge from the prefix, got {error:?}"
    );

    // u32::MAX is a legal prefix value but never a legal frame.
    let error =
        read_frame_length(u32::MAX.to_be_bytes(), &limits).expect_err("u32::MAX is too large");
    assert!(
        matches!(error, ProtocolError::FrameTooLarge { length, .. } if length == u32::MAX as usize),
        "expected FrameTooLarge(u32::MAX), got {error:?}"
    );
}

#[test]
fn identifiers_are_validated_not_trusted() {
    assert_eq!(DeviceId::new("dev-1").unwrap().as_str(), "dev-1");
    assert_eq!(SessionId::new("sess-1").unwrap().to_string(), "sess-1");
    assert_eq!(RequestId::new("req-1").unwrap().as_str(), "req-1");
    assert!("req-1".parse::<RequestId>().is_ok());

    for bad in ["", "with space", "semi;colon", "new\nline"] {
        let error = DeviceId::new(bad).expect_err("invalid id must be rejected");
        assert!(
            matches!(error, ProtocolError::InvalidIdentifier { .. }),
            "expected InvalidIdentifier for {bad:?}, got {error:?}"
        );
    }
    let too_long = "d".repeat(129);
    assert!(
        SessionId::new(too_long).is_err(),
        "ids are bounded to 128 bytes"
    );
    assert!("".parse::<SessionId>().is_err(), "empty ids are invalid");
}
