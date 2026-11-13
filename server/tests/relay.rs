//! Relay contract: authenticated peers only, bounded buffering, explicit close reasons.

mod common;

use std::time::{Duration, Instant};

use axum::http::StatusCode;
use common::TestApp;
use phoneconnect::v1::{
    DeviceId, Envelope, FrameLimits, RequestId, SessionId, StreamKind, encode_frame,
};
use phoneconnect_server::relay::{PeerRole, RelayClose, RelayLimits, authorize_relay};
use phoneconnect_server::store::{DeviceStore, SessionRecord, StoreError};

const PAYLOAD_MARKER: &[u8] = b"PC-RELAY-PAYLOAD-MUST-NOT-PERSIST";

fn envelope(session_id: &str, payload: &[u8]) -> Envelope {
    let device_id = DeviceId::new("dev_relay_test").expect("device id");
    let session = SessionId::new(session_id).expect("session id");
    let request = RequestId::new("req_1").expect("request id");
    let mut envelope = Envelope::new(StreamKind::Control, &device_id, &session, &request);
    envelope.payload = payload.to_vec();
    envelope
}

async fn opened_session(app: &TestApp) -> (String, String) {
    let (device_id, credential) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"]
        .as_str()
        .expect("session_id")
        .to_owned();
    let capability = session["capability"]
        .as_str()
        .expect("capability")
        .to_owned();
    let (status, body) = app.relay_upgrade(&session_id, Some(&capability)).await;
    assert_eq!(status, StatusCode::OK, "relay upgrade failed: {body}");
    drop(credential);
    (session_id, capability)
}

#[tokio::test]
async fn relay_upgrade_requires_an_authorized_session() {
    let app = TestApp::new();
    let (device_id, _) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"].as_str().expect("session_id");
    let capability = session["capability"].as_str().expect("capability");

    let (status, body) = app.relay_upgrade(session_id, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "missing_credentials");

    let (status, body) = app.relay_upgrade(session_id, Some("pcsess_forged")).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_credential");

    app.clock.advance_ms(300_000);
    let (status, body) = app.relay_upgrade(session_id, Some(capability)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "session_expired");

    // An unauthorized session never becomes attachable.
    assert_eq!(
        app.state.relay.attach(session_id, PeerRole::Device).err(),
        Some(RelayClose::UnknownSession)
    );
}

#[tokio::test]
async fn relay_upgrade_accepts_only_the_session_peers() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (other_device, other_credential) = app.enroll_new("user-b").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"].as_str().expect("session_id");

    // The owning device may open the relay with the credential it already holds.
    let (status, body) = app.relay_upgrade(session_id, Some(&credential)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    // A different device's credential is not a peer of this session.
    let other_session = app.create_session(&other_device).await;
    let other_session_id = other_session["session_id"].as_str().expect("session_id");
    let (status, body) = app.relay_upgrade(session_id, Some(&other_credential)).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "session_scope_mismatch");
    assert_eq!(
        app.state
            .relay
            .attach(other_session_id, PeerRole::Device)
            .err(),
        Some(RelayClose::UnknownSession)
    );
}

#[tokio::test]
async fn relay_upgrade_describes_bounded_limits() {
    let app = TestApp::new();
    let (device_id, _) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"].as_str().expect("session_id");
    let capability = session["capability"].as_str().expect("capability");

    let (status, body) = app.relay_upgrade(session_id, Some(capability)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["session_id"], session_id);
    assert_eq!(body["endpoint"], common::RELAY_ENDPOINT);
    assert_eq!(
        body["expires_at"].as_i64(),
        session["expires_at"].as_i64(),
        "the relay lease never outlives the session"
    );

    let limits = RelayLimits::default();
    assert_eq!(
        body["limits"]["max_frame_bytes"].as_u64(),
        Some(limits.max_frame_bytes as u64)
    );
    assert_eq!(
        body["limits"]["max_queued_frames"].as_u64(),
        Some(limits.max_queued_frames as u64)
    );
    assert_eq!(
        body["limits"]["idle_timeout_ms"].as_u64(),
        Some(limits.idle_timeout_ms)
    );
}

#[tokio::test]
async fn relay_rejects_expired_and_revoked_sessions_before_attach() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;
    let record = app
        .store
        .session(&session_id)
        .await
        .expect("session record");

    let mut expired = record.clone();
    expired.expires_at_ms = app.now();
    assert_eq!(
        authorize_relay(&expired, app.now()),
        Err(RelayClose::SessionExpired)
    );

    let mut revoked = record.clone();
    revoked.revoked_at_ms = Some(app.now());
    assert_eq!(
        authorize_relay(&revoked, app.now()),
        Err(RelayClose::SessionRevoked)
    );
    assert_eq!(authorize_relay(&record, app.now()), Ok(()));
}

#[tokio::test]
async fn relay_forwards_opaque_frames_between_authenticated_peers() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;

    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .expect("client attaches");

    let frame = envelope(&session_id, PAYLOAD_MARKER);
    device
        .send_frame(&frame)
        .await
        .expect("device frame accepted");

    let received = client.recv_frame().await.expect("client receives frame");
    assert_eq!(received, frame, "the relay forwards the envelope unchanged");

    // The same bytes travel in both directions and stay byte-identical.
    let client_frame = envelope(&session_id, b"reply");
    client
        .send_frame(&client_frame)
        .await
        .expect("client frame accepted");
    assert_eq!(
        device.recv_frame().await.expect("device receives"),
        client_frame
    );
}

#[tokio::test]
async fn relay_rejects_malformed_frames_without_forwarding_them() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .expect("client attaches");

    // Declared 3-byte body that is not a valid envelope.
    let malformed = [0u8, 0, 0, 3, 0xff, 0xff, 0xff];
    match device.send_bytes(&malformed).await {
        Err(RelayClose::MalformedFrame { .. }) => {}
        other => panic!("expected MalformedFrame, got {other:?}"),
    }

    // Unsupported protocol version: field 1 varint 2.
    let wrong_version = [0u8, 0, 0, 2, 0x08, 0x02];
    match device.send_bytes(&wrong_version).await {
        Err(RelayClose::MalformedFrame { .. }) => {}
        other => panic!("expected MalformedFrame for version, got {other:?}"),
    }

    // Unknown stream kind: field 2 varint 99, no payload.
    let unknown_kind = [0u8, 0, 0, 4, 0x08, 0x01, 0x10, 0x63];
    match device.send_bytes(&unknown_kind).await {
        Err(RelayClose::MalformedFrame { .. }) => {}
        other => panic!("expected MalformedFrame for stream kind, got {other:?}"),
    }

    let nothing = tokio::time::timeout(Duration::from_millis(50), client.recv_bytes()).await;
    assert!(
        nothing.is_err(),
        "malformed frames must never reach the peer"
    );
}

#[tokio::test]
async fn relay_rejects_oversized_frames_at_the_length_prefix() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .expect("client attaches");

    let limit = FrameLimits::default().max_limit() as usize;
    let oversized = ((limit + 1) as u32).to_be_bytes();
    match device.send_bytes(&oversized).await {
        Err(RelayClose::OversizedFrame {
            length,
            limit: reported,
        }) => {
            assert_eq!(length, limit + 1);
            assert_eq!(reported, limit);
        }
        other => panic!("expected OversizedFrame, got {other:?}"),
    }

    let nothing = tokio::time::timeout(Duration::from_millis(50), client.recv_bytes()).await;
    assert!(
        nothing.is_err(),
        "oversized frames must never reach the peer"
    );
}

#[tokio::test]
async fn relay_applies_backpressure_instead_of_buffering() {
    let limits = RelayLimits {
        max_queued_frames: 2,
        ..RelayLimits::default()
    };
    let app = TestApp::with_relay(limits);
    let (session_id, _capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .expect("client attaches");

    device
        .send_frame(&envelope(&session_id, b"one"))
        .await
        .expect("first frame");
    device
        .send_frame(&envelope(&session_id, b"two"))
        .await
        .expect("second frame");

    match device.send_frame(&envelope(&session_id, b"three")).await {
        Err(RelayClose::Backpressure) => {}
        other => panic!("expected Backpressure, got {other:?}"),
    }

    // Draining restores capacity; no frames were lost or silently dropped.
    let first = client.recv_bytes().await.expect("first frame drains");
    assert!(!first.is_empty());
    let second = client.recv_bytes().await.expect("second frame drains");
    assert!(!second.is_empty());
    device
        .send_frame(&envelope(&session_id, b"four"))
        .await
        .expect("capacity restored");
}

#[tokio::test]
async fn relay_half_close_closes_one_direction_only() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .expect("client attaches");

    device
        .send_frame(&envelope(&session_id, b"last"))
        .await
        .expect("frame sent");
    device.close_send().expect("half close accepted");

    let drained = client
        .recv_frame()
        .await
        .expect("buffered frame still delivered");
    assert_eq!(drained.payload, b"last");
    assert_eq!(client.recv_frame().await, Err(RelayClose::PeerClosed));

    // The opposite direction stays usable.
    client
        .send_frame(&envelope(&session_id, b"still-open"))
        .await
        .expect("client can still send");
    let received = device.recv_frame().await.expect("device still receives");
    assert_eq!(received.payload, b"still-open");
}

#[tokio::test]
async fn relay_idle_timeout_is_bounded() {
    let limits = RelayLimits {
        idle_timeout_ms: 50,
        ..RelayLimits::default()
    };
    let app = TestApp::with_relay(limits);
    let (session_id, _capability) = opened_session(&app).await;
    let _device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .expect("client attaches");

    let started = Instant::now();
    assert_eq!(client.recv_frame().await, Err(RelayClose::IdleTimeout));
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "idle timeout must stay bounded"
    );
}

#[tokio::test]
async fn relay_enforces_a_session_byte_budget() {
    let limits = RelayLimits {
        max_session_bytes: 256,
        ..RelayLimits::default()
    };
    let app = TestApp::with_relay(limits);
    let (session_id, _capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .expect("device attaches");
    let _client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .expect("client attaches");

    let small = envelope(&session_id, &[0u8; 16]);
    assert!(
        encode_frame(&small, &FrameLimits::default())
            .expect("frame")
            .len()
            < 256,
        "the first frame must fit the budget"
    );
    device.send_frame(&small).await.expect("within budget");
    match device.send_frame(&envelope(&session_id, &[0u8; 512])).await {
        Err(RelayClose::ByteBudgetExhausted) => {}
        other => panic!("expected ByteBudgetExhausted, got {other:?}"),
    }
}

#[tokio::test]
async fn relay_close_interrupts_blocked_peers_immediately() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;
    let _device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .expect("client attaches");

    let waiting = tokio::spawn(async move { client.recv_frame().await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    app.state
        .relay
        .close_session(&session_id, RelayClose::SessionRevoked);

    let result = tokio::time::timeout(Duration::from_millis(500), waiting)
        .await
        .expect("blocked peer wakes on close")
        .expect("task completed");
    assert_eq!(result, Err(RelayClose::SessionRevoked));
}

#[tokio::test]
async fn relay_persists_no_stream_payloads() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .expect("client attaches");
    device
        .send_frame(&envelope(&session_id, PAYLOAD_MARKER))
        .await
        .expect("frame relayed");
    assert_eq!(
        client.recv_frame().await.expect("frame received").payload,
        PAYLOAD_MARKER
    );

    let tables = app.store.schema().expect("schema readable");
    assert_eq!(
        tables,
        vec![
            "devices".to_owned(),
            "enrollment_tokens".to_owned(),
            "sessions".to_owned()
        ],
        "the store holds credentials and session metadata only"
    );

    // Payload bytes live in bounded in-memory queues, never in the durable records.
    let device_record = app.store.device("dev_relay_test").await;
    assert!(
        matches!(device_record, Err(StoreError::UnknownDevice { .. })),
        "relay traffic must not create device records: {device_record:?}"
    );
    let record = app
        .store
        .session(&session_id)
        .await
        .expect("session record");
    assert!(!format!("{record:?}").contains(&String::from_utf8_lossy(PAYLOAD_MARKER).to_string()));
}

#[tokio::test]
async fn relay_does_not_carry_a_session_past_its_expiry() {
    let app = TestApp::new();
    let (session_id, capability) = opened_session(&app).await;

    app.clock.advance_ms(300_000);
    let (status, body) = app.relay_upgrade(&session_id, Some(&capability)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "session_expired");
}

#[tokio::test]
async fn relay_authorization_details_are_independently_checkable() {
    let record = SessionRecord {
        session_id: "sess_check".to_owned(),
        device_id: "dev_check".to_owned(),
        owner_id: "user-a".to_owned(),
        capability_hash: "hash".to_owned(),
        created_at_ms: 1_000,
        expires_at_ms: 2_000,
        revoked_at_ms: None,
    };
    assert_eq!(authorize_relay(&record, 1_999), Ok(()));
    assert_eq!(
        authorize_relay(&record, 2_000),
        Err(RelayClose::SessionExpired)
    );
}

#[tokio::test]
async fn relay_prunes_expired_sessions_when_a_new_session_opens() {
    let app = TestApp::new();
    let (expired_session, _capability) = opened_session(&app).await;

    app.clock.advance_ms(300_000);
    let (device, _) = app.enroll_new("user-b").await;
    let session = app.create_session(&device).await;
    let session_id = session["session_id"].as_str().expect("session_id");
    let capability = session["capability"].as_str().expect("capability");
    let (status, body) = app.relay_upgrade(session_id, Some(capability)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    assert_eq!(
        app.state
            .relay
            .attach(&expired_session, PeerRole::Device)
            .err(),
        Some(RelayClose::UnknownSession),
        "expired relay state is dropped rather than retained forever"
    );
}
