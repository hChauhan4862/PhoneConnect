//! End-to-end frame confidentiality and path authentication.
//!
//! These tests are written against the transport's public AEAD surface. They prove the
//! properties the design claims: the relay only forwards ciphertext, only the two identity
//! keys that agreed on a session can read a frame, and every tamper, replay, direction
//! confusion, and unknown key is refused explicitly.

use phoneconnect::v1::{DeviceId, Envelope, RequestId, SessionId, StreamKind};
use phoneconnect_transport::{
    AeadError, IdentityKey, IdentityPublicKey, SealedHeader, SessionCipher, TicketRole,
};

const SESSION: &str = "sess_aead";
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
        let client = SessionCipher::new(
            &client_identity,
            device_identity.public_key(),
            SESSION,
            TicketRole::Client,
        )
        .expect("client cipher");
        let device = SessionCipher::new(
            &device_identity,
            client_identity.public_key(),
            SESSION,
            TicketRole::Device,
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
fn a_replayed_or_regressed_counter_fails() {
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
        Err(AeadError::CounterRegression {
            counter: 1,
            highest: 2
        }),
        "an older counter is a regression, never a fresh frame"
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
