//! End-to-end frame confidentiality and path authentication.
//!
//! These tests are written against the transport's public AEAD surface. They prove the
//! properties the design claims: the relay only forwards ciphertext, only the two identity
//! keys that agreed on a session can read a frame, and every tamper, replay, direction
//! confusion, and unknown key is refused explicitly.

use phoneconnect::v1::{DeviceId, Envelope, RequestId, SessionId, StreamKind};
use phoneconnect_transport::{
    AeadError, Epoch, IdentityKey, IdentityPublicKey, SealedHeader, SessionCipher, TicketRole,
};

const SESSION: &str = "sess_aead";

/// A fresh epoch, the way two freshly minted tickets provide one.
fn epoch() -> Epoch {
    Epoch::new(identity().to_secret_string(), identity().to_secret_string()).expect("epoch")
}
const PAYLOAD_MARKER: &[u8] = b"PC-AEAD-PLAINTEXT-MARKER";

fn envelope(request: &str, sequence: u32) -> Envelope {
    let device = DeviceId::new("dev_aead").expect("device id");
    let session = SessionId::new(SESSION).expect("session id");
    let request = RequestId::new(request).expect("request id");
    let mut envelope = Envelope::new(StreamKind::Control, &device, &session, &request);
    envelope.sequence = sequence;
    envelope.payload = PAYLOAD_MARKER.to_vec();
    envelope
}

fn identity() -> IdentityKey {
    IdentityKey::generate().expect("identity key")
}

struct Pair {
    client: SessionCipher,
    device: SessionCipher,
    client_identity: IdentityKey,
    device_identity: IdentityKey,
}

impl Pair {
    fn new() -> Self {
        let client_identity = identity();
        let device_identity = identity();
        let epoch = epoch();
        let client = SessionCipher::new(
            &client_identity,
            device_identity.public_key(),
            SESSION,
            TicketRole::Client,
            &epoch,
        )
        .expect("client cipher");
        let device = SessionCipher::new(
            &device_identity,
            client_identity.public_key(),
            SESSION,
            TicketRole::Device,
            &epoch,
        )
        .expect("device cipher");
        Self {
            client,
            device,
            client_identity,
            device_identity,
        }
    }
}

#[test]
fn sealed_frames_carry_no_plaintext_envelope() {
    let pair = Pair::new();
    let plain = envelope("req-secret", 7);
    let sealed = pair.client.seal(&plain).expect("seal");

    assert!(
        !sealed
            .windows(PAYLOAD_MARKER.len())
            .any(|w| w == PAYLOAD_MARKER),
        "the payload must not appear on the wire"
    );
    for secret in ["req-secret", SESSION, "dev_aead"] {
        assert!(
            !sealed
                .windows(secret.len())
                .any(|window| window == secret.as_bytes()),
            "{secret} must be inside the ciphertext, not the header"
        );
    }
    assert_eq!(
        pair.device.open(&sealed).expect("the peer decrypts"),
        plain,
        "the receiver gets the exact envelope back"
    );
}

#[test]
fn each_direction_uses_its_own_key() {
    let pair = Pair::new();
    let from_client = pair
        .client
        .seal(&envelope("req-from-client", 1))
        .expect("seal");
    let from_device = pair
        .device
        .seal(&envelope("req-from-device", 1))
        .expect("seal");

    assert_ne!(
        from_client[SealedHeader::DIRECTION_OFFSET],
        from_device[SealedHeader::DIRECTION_OFFSET],
        "the direction byte is part of the authenticated header"
    );
    assert_eq!(
        pair.device.open(&from_client).expect("client to device"),
        envelope("req-from-client", 1)
    );
    assert_eq!(
        pair.client.open(&from_device).expect("device to client"),
        envelope("req-from-device", 1)
    );

    // A frame reflected back to its sender never authenticates.
    assert_eq!(
        pair.client.open(&from_client),
        Err(AeadError::WrongDirection)
    );
    assert_eq!(
        pair.device.open(&from_device),
        Err(AeadError::WrongDirection)
    );
}

#[test]
fn only_the_pinned_peer_identity_can_decrypt() {
    let pair = Pair::new();
    let sealed = pair
        .client
        .seal(&envelope("req-only-for-b", 1))
        .expect("seal");

    // An impostor that knows the session id but not the peer identity private key derives a
    // different traffic key.
    let impostor_identity = identity();
    let impostor = SessionCipher::new(
        &impostor_identity,
        pair.device_identity.public_key(),
        SESSION,
        TicketRole::Client,
        &epoch(),
    )
    .expect("impostor cipher");
    let frame_key_id = pair.client.key_id();
    assert_eq!(
        impostor.open(&sealed),
        Err(AeadError::UnknownKeyId {
            found: frame_key_id.clone(),
            expected: impostor.key_id().to_owned(),
        }),
        "a different identity pair is a different key id"
    );

    // A cipher built with the wrong peer identity cannot open the frame either.
    let mismatched = SessionCipher::new(
        &pair.device_identity,
        impostor_identity.public_key(),
        SESSION,
        TicketRole::Device,
        &epoch(),
    )
    .expect("mismatched cipher");
    assert_eq!(
        mismatched.open(&sealed),
        Err(AeadError::UnknownKeyId {
            found: frame_key_id,
            expected: mismatched.key_id().to_owned(),
        })
    );

    // The legitimate peer is unaffected.
    pair.device.open(&sealed).expect("the pinned peer decrypts");
    let _ = pair.client_identity;
}

#[test]
fn a_flipped_ciphertext_byte_fails_authentication() {
    let pair = Pair::new();
    let sealed = pair.client.seal(&envelope("req-tamper", 1)).expect("seal");

    let mut flipped_tag = sealed.clone();
    *flipped_tag.last_mut().expect("tag byte") ^= 0x01;
    assert_eq!(
        pair.device.open(&flipped_tag),
        Err(AeadError::Authentication)
    );

    let mut flipped_body = sealed.clone();
    let body = sealed.len() - 8;
    flipped_body[body] ^= 0x80;
    assert_eq!(
        pair.device.open(&flipped_body),
        Err(AeadError::Authentication)
    );
}

#[test]
fn a_tampered_authenticated_header_fails() {
    let pair = Pair::new();
    let sealed = pair.client.seal(&envelope("req-header", 3)).expect("seal");

    // The header binds the sequence number and stream kind as associated data, so a changed
    // header is not a new frame: it is a failed tag.
    let mut changed_sequence = sealed.clone();
    changed_sequence[SealedHeader::SEQUENCE_OFFSET] ^= 0x01;
    assert_eq!(
        pair.device.open(&changed_sequence),
        Err(AeadError::Authentication)
    );

    let mut changed_kind = sealed.clone();
    changed_kind[SealedHeader::STREAM_KIND_OFFSET] = 5;
    assert_eq!(
        pair.device.open(&changed_kind),
        Err(AeadError::Authentication)
    );
}

#[test]
fn a_replayed_counter_is_refused() {
    let pair = Pair::new();
    let first = pair.client.seal(&envelope("req-one", 1)).expect("seal");
    let second = pair.client.seal(&envelope("req-two", 2)).expect("seal");

    pair.device.open(&first).expect("first frame");
    assert_eq!(
        pair.device.open(&first),
        Err(AeadError::Replayed { counter: 1 }),
        "a captured frame cannot be delivered twice"
    );
    pair.device.open(&second).expect("second frame");
    assert_eq!(
        pair.device.open(&first),
        Err(AeadError::Replayed { counter: 1 }),
        "a replayed frame is still a replay after a newer one arrives"
    );
}

#[test]
fn a_reordered_frame_is_accepted_but_a_regression_is_fatal() {
    let pair = Pair::new();
    let first = pair.client.seal(&envelope("req-one", 1)).expect("seal");
    let second = pair.client.seal(&envelope("req-two", 2)).expect("seal");

    // UDP reorders: a frame inside the window that has not been seen is delivered, so the
    // caller can tell a reorder apart from a fatal regression.
    pair.device.open(&second).expect("newer frame first");
    assert_eq!(
        pair.device.open(&first).expect("reordered frame delivered"),
        envelope("req-one", 1)
    );

    // Once the counter is far outside the window it is a regression, not a reorder.
    let mut frames = Vec::new();
    for _ in 0..80 {
        frames.push(pair.client.seal(&envelope("req-bulk", 3)).expect("seal"));
    }
    let last = frames.pop().expect("a frame");
    pair.device.open(&last).expect("jump ahead");
    assert_eq!(
        pair.device.open(&frames[0]),
        Err(AeadError::CounterRegression {
            counter: 3,
            highest: 82
        }),
        "a counter outside the window is a fatal regression"
    );
}

#[test]
fn an_unknown_key_id_is_refused_before_decryption() {
    let first = Pair::new();
    let second = Pair::new();
    let foreign = second
        .client
        .seal(&envelope("req-other-session", 1))
        .expect("seal");

    assert_eq!(
        first.device.open(&foreign),
        Err(AeadError::UnknownKeyId {
            found: second.client.key_id().to_owned(),
            expected: first.client.key_id().to_owned(),
        })
    );
    assert_ne!(
        first.client.key_id(),
        second.client.key_id(),
        "different identity pairs derive different key ids"
    );
}

#[test]
fn identity_public_keys_round_trip_as_base64url() {
    let key = identity();
    let encoded = key.public_key().as_str();
    assert_eq!(encoded.len(), 43, "32 bytes, unpadded base64url");
    let parsed = IdentityPublicKey::parse(&encoded).expect("parse");
    assert_eq!(parsed, key.public_key());
    assert!(IdentityPublicKey::parse("not-a-key").is_err());
    assert!(
        IdentityPublicKey::parse("AAAA").is_err(),
        "must be 32 bytes"
    );
}

#[test]
fn a_malformed_sealed_record_is_refused() {
    let pair = Pair::new();
    assert!(matches!(
        pair.device.open(&[]),
        Err(AeadError::Malformed { .. })
    ));
    assert!(matches!(
        pair.device.open(&[1, 2, 3]),
        Err(AeadError::Malformed { .. })
    ));
    let sealed = pair.client.seal(&envelope("req-short", 1)).expect("seal");
    let truncated = &sealed[..sealed.len() - 4];
    assert_eq!(pair.device.open(truncated), Err(AeadError::Authentication));
}

#[test]
fn a_second_connection_on_one_session_derives_fresh_keys() {
    let client_identity = identity();
    let device_identity = identity();
    let first_epoch = Epoch::new("first-client-nonce", "first-device-nonce").expect("epoch");
    let second_epoch = Epoch::new("second-client-nonce", "second-device-nonce").expect("epoch");

    let first_client = SessionCipher::new(
        &client_identity,
        device_identity.public_key(),
        SESSION,
        TicketRole::Client,
        &first_epoch,
    )
    .expect("first client cipher");
    let second_client = SessionCipher::new(
        &client_identity,
        device_identity.public_key(),
        SESSION,
        TicketRole::Client,
        &second_epoch,
    )
    .expect("second client cipher");
    let first_device = SessionCipher::new(
        &device_identity,
        client_identity.public_key(),
        SESSION,
        TicketRole::Device,
        &first_epoch,
    )
    .expect("first device cipher");
    let second_device = SessionCipher::new(
        &device_identity,
        client_identity.public_key(),
        SESSION,
        TicketRole::Device,
        &second_epoch,
    )
    .expect("second device cipher");

    assert_ne!(
        first_client.key_id(),
        second_client.key_id(),
        "a new connection epoch means new keys"
    );

    // The first connection's frame opens only on the first device cipher: a reconnect never
    // reuses a key, so it can never reuse a ChaCha20-Poly1305 nonce.
    let frame = first_client.seal(&envelope("req-first", 1)).expect("seal");
    first_device.open(&frame).expect("same epoch decrypts");
    assert_eq!(
        second_device.open(&frame),
        Err(AeadError::UnknownKeyId {
            found: first_client.key_id(),
            expected: second_client.key_id(),
        })
    );

    // `Epoch::split` orders the nonces by role, so both peers derive the same salt.
    let theirs = Epoch::split("client-nonce", "device-nonce", TicketRole::Device).expect("epoch");
    let ours = Epoch::split("device-nonce", "client-nonce", TicketRole::Client).expect("epoch");
    assert_eq!(theirs, ours);
}

#[test]
fn reusing_one_epoch_for_two_paths_is_refused() {
    let client_identity = identity();
    let device_identity = identity();
    let epoch = Epoch::new("reused-client-nonce", "reused-device-nonce").expect("epoch");

    SessionCipher::new(
        &client_identity,
        device_identity.public_key(),
        "sess_reuse",
        TicketRole::Client,
        &epoch,
    )
    .expect("first path");
    // The peer half of the same connection is not a reuse.
    SessionCipher::new(
        &device_identity,
        client_identity.public_key(),
        "sess_reuse",
        TicketRole::Device,
        &epoch,
    )
    .expect("peer half");

    assert_eq!(
        SessionCipher::new(
            &client_identity,
            device_identity.public_key(),
            "sess_reuse",
            TicketRole::Client,
            &epoch,
        )
        .err(),
        Some(AeadError::EpochReused),
        "a second path on one session must bring a fresh epoch"
    );

    // A fresh epoch is accepted.
    let fresh = Epoch::new("fresh-client-nonce", "fresh-device-nonce").expect("epoch");
    SessionCipher::new(
        &client_identity,
        device_identity.public_key(),
        "sess_reuse",
        TicketRole::Client,
        &fresh,
    )
    .expect("fresh epoch");
}
