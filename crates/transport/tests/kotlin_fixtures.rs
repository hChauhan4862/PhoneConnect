//! The Kotlin agent's sealed-frame fixtures, pinned from the Rust side too.
//!
//! `android/app/src/test/.../crypto/SealedSessionTest.kt` asserts that the Kotlin port
//! reproduces these exact bytes. This test asserts that the Rust implementation still
//! produces them, so a change to the AEAD label, key-id derivation, salt order, counter start,
//! header layout, or nonce construction fails on both sides instead of only on a device.

use phoneconnect::v1::{DeviceId, Envelope, RequestId, SessionId, StreamKind};
use phoneconnect_transport::{Epoch, IdentityKey, SessionCipher, TicketRole};

const CLIENT_SECRET: [u8; 32] = [0x11; 32];
const DEVICE_SECRET: [u8; 32] = [0x22; 32];
const SESSION: &str = "sess_aead_vector";
const CLIENT_NONCE: &str = "client-nonce-vector";
const DEVICE_NONCE: &str = "device-nonce-vector";

/// The base64url public keys the Kotlin test pins for these two secrets.
const CLIENT_PUBLIC: &str = "e06Qm75__kTEZaIgA31gjuNYl9Me-XLwf3SJLLD3PxM";
const DEVICE_PUBLIC: &str = "D6poTtKIZ7l_Smot7l34zpdOdrcBjj8iocTPJnhXDyA";

const KEY_ID: &str = "504ecf1f0e255804";
const CLIENT_SEAL_1: &str = concat!(
    "01504ecf1f0e2558040100000000000000010100000007b59b0e9fb8996ab7f56fcc7464ccc7f7",
    "f770d9326ac4028b1fca418387e2085c9dae59bb6a66ad9d87d7ca2c858cadbaaa9d852f7ed409c",
    "2f4440ae2886c071183732fe62ef36e5d89567ce815d19252cfa1d56080d24f",
);
const DEVICE_SEAL_1: &str = concat!(
    "01504ecf1f0e2558040200000000000000010100000007b35320ed79c8000e92ecca095bc94dea45",
    "7c5699279a3c92c093cf2dde8b38c8b7167486ac4bc8a9a4a056e33b2b79c7c2e9f617cf94951f4c",
    "d0a24a66c657b2245b189f19df2fa6149d389b76a47d525fd3d763c07e7b",
);
const CLIENT_SEAL_2: &str = concat!(
    "01504ecf1f0e25580401000000000000000201000000081766d373197ace7bbbcb6d38864a2bf2c4",
    "c2154a6a1b28e27e94bc674740c80df5e2a56c7c61a9a8c27ada73343e909b3b8db62fac696aff2",
    "899cf05080f8ee5af9878e185d324fa728142ec6c63e8",
);

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn vector_envelope(sequence: u32, payload: &[u8]) -> Envelope {
    let device = DeviceId::new("dev_vector").expect("device id");
    let session = SessionId::new(SESSION).expect("session id");
    let request = RequestId::new("req-vector").expect("request id");
    let mut envelope = Envelope::new(StreamKind::Control, &device, &session, &request);
    envelope.sequence = sequence;
    envelope.deadline_unix_ms = 1_760_000_000_000;
    envelope.payload = payload.to_vec();
    envelope
}

/// One test on purpose: the transport claims an epoch per session and role for the life of
/// the process, so two tests sharing these fixed nonces would see `EpochReused`.
#[test]
fn the_kotlin_fixtures_match_the_rust_implementation_in_both_directions() {
    let client_identity = IdentityKey::from_bytes(CLIENT_SECRET);
    let device_identity = IdentityKey::from_bytes(DEVICE_SECRET);
    assert_eq!(
        client_identity.public_key().as_str(),
        CLIENT_PUBLIC,
        "the X25519 public key the Kotlin test pins changed"
    );
    assert_eq!(
        device_identity.public_key().as_str(),
        DEVICE_PUBLIC,
        "the X25519 public key the Kotlin test pins changed"
    );

    let epoch = Epoch::new(CLIENT_NONCE, DEVICE_NONCE).expect("epoch");
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

    assert_eq!(client.key_id(), KEY_ID, "the key id the Kotlin test pins changed");
    assert_eq!(device.key_id(), KEY_ID);

    let first = vector_envelope(7, b"PC-AEAD-VECTOR");
    assert_eq!(
        hex(&client.seal(&first).expect("client seal")),
        CLIENT_SEAL_1,
        "the client ciphertext the Kotlin test pins changed"
    );
    assert_eq!(
        hex(&device.seal(&first).expect("device seal")),
        DEVICE_SEAL_1,
        "the device ciphertext the Kotlin test pins changed"
    );

    let second = vector_envelope(8, b"second");
    assert_eq!(
        hex(&client.seal(&second).expect("second seal")),
        CLIENT_SEAL_2,
        "the counter start or nonce the Kotlin test pins changed"
    );

    // And the same bytes open on the peer side, so the fixture is not merely a checksum.
    let sealed = decode_hex(CLIENT_SEAL_1);
    let envelope = device.open(&sealed).expect("device opens the Kotlin fixture");
    assert_eq!(envelope, vector_envelope(7, b"PC-AEAD-VECTOR"));

    let sealed = decode_hex(DEVICE_SEAL_1);
    let envelope = client.open(&sealed).expect("client opens the Kotlin fixture");
    assert_eq!(envelope, vector_envelope(7, b"PC-AEAD-VECTOR"));
}

fn decode_hex(value: &str) -> Vec<u8> {
    value
        .as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|chunk| u8::from_str_radix(std::str::from_utf8(chunk).unwrap(), 16).unwrap())
        .collect()
}
