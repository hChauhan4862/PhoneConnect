//! The device↔client epoch across nonce-only rendezvous, end to end.
//!
//! Both peers publish only a redemption nonce (no endpoint), read each other's nonce from
//! the candidates route, derive the same per-connection keys, and exchange one sealed frame
//! over the real bounded relay. A nonce-only peer must never appear as a `server_observed`
//! probe target.

use std::sync::Arc;

use phoneconnect::v1::{DeviceId, Envelope, RequestId, SessionId, StreamKind};
use phoneconnect_server::PeerRole;
use phoneconnect_server::relay::{Relay, RelayLimits};
use phoneconnect_server::rendezvous::{CandidateKind, Rendezvous, TicketAuthority};
use phoneconnect_server::store::{
    DeviceStore, EnrollmentTokenRecord, ManualClock, NewDevice, SessionRecord, SqliteStore,
};
use phoneconnect_transport::{Epoch, IdentityKey, SessionCipher, TicketRole};

const NOW_MS: i64 = 1_760_000_000_000;
const DEVICE_ID: &str = "dev_nonce";
const RELAY_ENDPOINT: &str = "http://relay.test/api/sessions";
const SESSION_ID: &str = "sess_nonce";

fn role(role: PeerRole) -> TicketRole {
    match role {
        PeerRole::Client => TicketRole::Client,
        PeerRole::Device => TicketRole::Device,
    }
}

async fn harness() -> (
    Arc<SqliteStore>,
    Arc<ManualClock>,
    SessionRecord,
    Rendezvous,
    IdentityKey,
    IdentityKey,
) {
    let store = Arc::new(SqliteStore::in_memory().expect("in-memory store"));
    let clock = Arc::new(ManualClock::new(NOW_MS));
    let client_identity = IdentityKey::generate().expect("client identity");
    let device_identity = IdentityKey::generate().expect("device identity");
    let record = SessionRecord {
        session_id: SESSION_ID.to_owned(),
        device_id: DEVICE_ID.to_owned(),
        owner_id: "owner-1".to_owned(),
        capability_hash: "capability-hash".to_owned(),
        client_identity_key: client_identity.public_key().as_str(),
        device_identity_key: device_identity.public_key().as_str(),
        created_at_ms: NOW_MS,
        expires_at_ms: NOW_MS + 300_000,
        revoked_at_ms: None,
        control: true,
    };
    store
        .insert_enrollment_token(EnrollmentTokenRecord {
            token_hash: "nonce-enrollment".to_owned(),
            owner_id: "owner-1".to_owned(),
            created_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + 900_000,
        })
        .await
        .expect("enrollment token persists");
    store
        .consume_enrollment_token(
            "nonce-enrollment",
            NOW_MS,
            NewDevice {
                device_id: DEVICE_ID.to_owned(),
                credential_hash: "nonce-credential".to_owned(),
                identity_public_key: device_identity.public_key().as_str(),
                enrolled_at_ms: NOW_MS,
            },
        )
        .await
        .expect("device persists");
    store
        .insert_session(record.clone())
        .await
        .expect("session persists");

    let authority = Arc::new(TicketAuthority::new().expect("ticket authority"));
    let rendezvous = Rendezvous::new(RELAY_ENDPOINT, authority);
    (store, clock, record, rendezvous, client_identity, device_identity)
}

#[tokio::test]
async fn nonce_only_peers_derive_the_same_keys_and_cross_the_relay() {
    let (store, clock, session, rendezvous, client_identity, device_identity) = harness().await;

    let device_ticket = rendezvous
        .ticket(&session, PeerRole::Device, NOW_MS)
        .expect("device ticket");
    let client_ticket = rendezvous
        .ticket(&session, PeerRole::Client, NOW_MS)
        .expect("client ticket");

    // Neither peer advertises an endpoint: only the epoch nonce is published.
    let device_view = rendezvous
        .observe(&session, PeerRole::Device, &device_ticket, None, NOW_MS)
        .expect("device nonce registration");
    assert!(
        device_view.peer_nonce.is_none(),
        "the client has not registered yet: {device_view:?}"
    );
    rendezvous
        .observe(&session, PeerRole::Client, &client_ticket, None, NOW_MS)
        .expect("client nonce registration");

    let client_view = rendezvous.candidates(&session, PeerRole::Client, NOW_MS);
    let device_view = rendezvous.candidates(&session, PeerRole::Device, NOW_MS);

    assert_eq!(
        client_view.peer_nonce.as_deref(),
        Some(device_ticket.nonce.as_str()),
        "the client must receive the device's nonce"
    );
    assert_eq!(
        device_view.peer_nonce.as_deref(),
        Some(client_ticket.nonce.as_str()),
        "the device must receive the client's nonce"
    );
    for view in [&client_view, &device_view] {
        assert!(
            view.candidates
                .iter()
                .all(|candidate| candidate.kind == CandidateKind::Relay),
            "a nonce-only peer must not become a probe target: {view:?}"
        );
        assert_eq!(view.candidates.len(), 1, "only the relay candidate: {view:?}");
    }

    // Both sides derive the epoch from the same two nonces, in role order.
    let device_epoch = Epoch::split(
        &device_ticket.nonce,
        &client_ticket.nonce,
        role(PeerRole::Device),
    )
    .expect("device epoch");
    let client_epoch = Epoch::split(
        &client_ticket.nonce,
        &device_ticket.nonce,
        role(PeerRole::Client),
    )
    .expect("client epoch");
    let device_cipher = SessionCipher::new(
        &device_identity,
        client_identity.public_key(),
        SESSION_ID,
        TicketRole::Device,
        &device_epoch,
    )
    .expect("device cipher");
    let client_cipher = SessionCipher::new(
        &client_identity,
        device_identity.public_key(),
        SESSION_ID,
        TicketRole::Client,
        &client_epoch,
    )
    .expect("client cipher");
    assert_eq!(
        device_cipher.key_id(),
        client_cipher.key_id(),
        "both peers must agree on the session key id"
    );

    // One sealed frame crosses the server's bounded relay and only the device can read it.
    let relay = Arc::new(Relay::new(
        RELAY_ENDPOINT,
        RelayLimits::default(),
        store,
        clock,
    ));
    relay.open(&session, NOW_MS).expect("relay authorizes the session");
    let client_peer = relay
        .attach(SESSION_ID, PeerRole::Client)
        .await
        .expect("client attaches");
    let device_peer = relay
        .attach(SESSION_ID, PeerRole::Device)
        .await
        .expect("device attaches");

    let envelope = {
        let device = DeviceId::new(DEVICE_ID).expect("device id");
        let session_id = SessionId::new(SESSION_ID).expect("session id");
        let request = RequestId::new("req-nonce").expect("request id");
        let mut envelope = Envelope::new(StreamKind::Control, &device, &session_id, &request);
        envelope.sequence = 1;
        envelope.payload = b"clock-sync".to_vec();
        envelope
    };
    let sealed = client_cipher.seal(&envelope).expect("client seals");

    // The relay forwards a length-prefixed routing envelope whose payload is the sealed
    // frame, never the sealed bytes on their own (this is `ConnectedPath::relay_envelope`).
    let outer = {
        let device = DeviceId::new(DEVICE_ID).expect("device id");
        let session_id = SessionId::new(SESSION_ID).expect("session id");
        let request = RequestId::new("relay").expect("request id");
        let mut outer = Envelope::new(StreamKind::Control, &device, &session_id, &request);
        outer.request_id.clear();
        outer.payload = sealed.clone();
        phoneconnect::encode_frame(&outer, &phoneconnect::FrameLimits::control_only())
            .expect("routing envelope encodes")
    };
    client_peer.send_bytes(&outer).await.expect("relay accepts the frame");
    let forwarded = device_peer.recv_bytes().await.expect("device receives the frame");

    assert_eq!(forwarded, outer, "the relay forwards the routing frame unchanged");
    let decoded = phoneconnect::decode_frame(&forwarded, &phoneconnect::FrameLimits::control_only())
        .expect("routing envelope decodes");
    let opened = device_cipher.open(&decoded.envelope.payload).expect("device opens the frame");
    assert_eq!(opened, envelope);
}

#[tokio::test]
async fn a_nonce_only_registration_is_still_single_use() {
    let (_store, _clock, session, rendezvous, _client, _device) = harness().await;
    let ticket = rendezvous
        .ticket(&session, PeerRole::Device, NOW_MS)
        .expect("device ticket");

    rendezvous
        .observe(&session, PeerRole::Device, &ticket, None, NOW_MS)
        .expect("first registration");
    let error = rendezvous
        .observe(&session, PeerRole::Device, &ticket, None, NOW_MS)
        .expect_err("a replayed nonce must be refused");

    assert!(
        matches!(error, phoneconnect_server::rendezvous::TicketError::Replayed),
        "expected Replayed, got {error:?}"
    );
}
