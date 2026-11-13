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
        app.state
            .relay
            .attach(session_id, PeerRole::Device)
            .await
            .err(),
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
            .await
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
    // The lease advertises the live per-session transport route.
    assert_eq!(body["endpoint"], common::relay_url(session_id));
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
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
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
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
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
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
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
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
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
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
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
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
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
        .await
        .expect("device attaches");
    let _client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
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
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
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
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
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
            "control_leases".to_owned(),
            "devices".to_owned(),
            "enrollment_tokens".to_owned(),
            "lease_sessions".to_owned(),
            "sessions".to_owned()
        ],
        "the store holds credentials, session metadata, and lease authorization only"
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
        client_identity_key: "client-identity".to_owned(),
        device_identity_key: "device-identity".to_owned(),
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
            .await
            .err(),
        Some(RelayClose::UnknownSession),
        "expired relay state is dropped rather than retained forever"
    );
}

#[tokio::test]
async fn attached_relay_stops_forwarding_when_the_session_expires() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
        .expect("client attaches");

    // Forwarding works while the session is live.
    device
        .send_frame(&envelope(&session_id, b"live"))
        .await
        .expect("live frame accepted");
    assert_eq!(
        client
            .recv_frame()
            .await
            .expect("live frame received")
            .payload,
        b"live"
    );

    // A receiver already blocked must be woken by expiry, not only by the next sender.
    let waiting = tokio::spawn(async move { client.recv_bytes().await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    app.clock.advance_ms(300_000);
    let reason = tokio::time::timeout(Duration::from_secs(2), waiting)
        .await
        .expect("blocked peer wakes when the session expires")
        .expect("task completed");
    assert_eq!(reason, Err(RelayClose::SessionExpired));

    match device.send_frame(&envelope(&session_id, b"late")).await {
        Err(RelayClose::SessionExpired) => {}
        other => panic!("expected SessionExpired, got {other:?}"),
    }
    assert_eq!(
        app.state
            .relay
            .attach(&session_id, PeerRole::Device)
            .await
            .err(),
        Some(RelayClose::SessionExpired),
        "an expired session is no longer attachable"
    );
}

#[tokio::test]
async fn attached_relay_stops_forwarding_when_the_session_is_revoked() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
        .expect("client attaches");

    let waiting = tokio::spawn(async move { client.recv_bytes().await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let revoked_at = Instant::now();
    let (status, body) = app
        .revoke("sessions", &session_id, Some(common::ADMIN_TOKEN))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let reason = tokio::time::timeout(Duration::from_secs(2), waiting)
        .await
        .expect("blocked peer wakes on revocation")
        .expect("task completed");
    assert!(
        revoked_at.elapsed() < Duration::from_millis(200),
        "revocation closes the relay now, not at the next liveness poll: {:?}",
        revoked_at.elapsed()
    );
    assert_eq!(reason, Err(RelayClose::SessionRevoked));
    // A synchronous check proves the handle was closed by the revocation request itself,
    // rather than discovered by a later store lookup.
    assert_eq!(
        device.close_send().err(),
        Some(RelayClose::SessionRevoked),
        "the relay is already closed when revocation returns"
    );
    assert_eq!(
        device
            .send_frame(&envelope(&session_id, b"after-revoke"))
            .await
            .err(),
        Some(RelayClose::SessionRevoked),
        "a revoked session forwards nothing"
    );
}

#[tokio::test]
async fn attached_relay_stops_when_the_owning_device_is_revoked() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"]
        .as_str()
        .expect("session_id")
        .to_owned();
    let capability = session["capability"].as_str().expect("capability");
    let (status, body) = app.relay_upgrade(&session_id, Some(capability)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
        .expect("client attaches");

    let waiting = tokio::spawn(async move { client.recv_bytes().await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let revoked_at = Instant::now();
    let (status, body) = app
        .revoke("devices", &device_id, Some(common::ADMIN_TOKEN))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let reason = tokio::time::timeout(Duration::from_secs(2), waiting)
        .await
        .expect("blocked peer wakes when the device is revoked")
        .expect("task completed");
    assert!(
        revoked_at.elapsed() < Duration::from_millis(200),
        "device revocation closes its relays now, not at the next poll: {:?}",
        revoked_at.elapsed()
    );
    // Synchronous proof that the revocation request itself closed the handle.
    assert!(
        matches!(device.close_send(), Err(RelayClose::DeviceRevoked { .. })),
        "the relay is already closed when device revocation returns"
    );
    assert!(
        matches!(reason, Err(RelayClose::DeviceRevoked { .. })),
        "expected DeviceRevoked, got {reason:?}"
    );
    let send = device
        .send_frame(&envelope(&session_id, b"after-device-revoke"))
        .await;
    assert!(
        matches!(send, Err(RelayClose::DeviceRevoked { .. })),
        "expected DeviceRevoked, got {send:?}"
    );
}

#[tokio::test]
async fn attach_re_reads_the_live_session_record() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;

    // The relay registered a snapshot at open; revocation after that must still be seen.
    app.store
        .revoke_session(&session_id, app.now())
        .await
        .expect("session revocation persists");

    assert_eq!(
        app.state
            .relay
            .attach(&session_id, PeerRole::Device)
            .await
            .err(),
        Some(RelayClose::SessionRevoked),
        "attach must consult the store, not the snapshot taken at open"
    );
}

#[tokio::test]
async fn relay_rejects_frames_with_trailing_bytes() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
        .expect("client attaches");

    let mut frame = encode_frame(
        &envelope(&session_id, b"declared-prefix"),
        &FrameLimits::default(),
    )
    .expect("frame encodes");
    let frame_len = frame.len();
    let trailing = b"bytes the prefix does not describe";
    frame.extend_from_slice(trailing);

    match device.send_bytes(&frame).await {
        Err(RelayClose::TrailingBytes { declared, extra }) => {
            assert_eq!(declared, frame_len, "the declared frame length is reported");
            assert_eq!(extra, trailing.len(), "the trailing bytes are counted");
        }
        other => panic!("expected TrailingBytes, got {other:?}"),
    }

    let nothing = tokio::time::timeout(Duration::from_millis(50), client.recv_bytes()).await;
    assert!(
        nothing.is_err(),
        "a frame with trailing bytes is never forwarded"
    );
}

#[tokio::test]
async fn send_after_close_reports_the_close_reason() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .await
        .expect("device attaches");
    app.state
        .relay
        .close_session(&session_id, RelayClose::SessionClosed);

    assert_eq!(
        device
            .send_frame(&envelope(&session_id, b"nobody-listens"))
            .await
            .err(),
        Some(RelayClose::SessionClosed),
        "a closed session never reports a successful send"
    );
    let frame = encode_frame(
        &envelope(&session_id, b"nobody-listens"),
        &FrameLimits::default(),
    )
    .expect("frame encodes");
    assert_eq!(
        device.send_bytes(&frame).await.err(),
        Some(RelayClose::SessionClosed)
    );
}

#[tokio::test]
async fn attached_relay_notices_out_of_band_session_revocation() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
        .expect("client attaches");

    // Revocation that never goes through this process's admin surface, as another
    // server instance or an operator tool would do it, must still stop the relay.
    let waiting = tokio::spawn(async move { client.recv_bytes().await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    app.store
        .revoke_session(&session_id, app.now())
        .await
        .expect("session revocation persists");

    let reason = tokio::time::timeout(Duration::from_secs(2), waiting)
        .await
        .expect("blocked peer wakes on out-of-band revocation")
        .expect("task completed");
    assert_eq!(reason, Err(RelayClose::SessionRevoked));
    assert_eq!(
        device
            .send_frame(&envelope(&session_id, b"after-revoke"))
            .await
            .err(),
        Some(RelayClose::SessionRevoked)
    );
}

#[tokio::test]
async fn attached_relay_notices_out_of_band_device_revocation() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"]
        .as_str()
        .expect("session_id")
        .to_owned();
    let capability = session["capability"].as_str().expect("capability");
    let (status, body) = app.relay_upgrade(&session_id, Some(capability)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
        .expect("client attaches");

    let waiting = tokio::spawn(async move { client.recv_bytes().await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    app.store
        .revoke_device(&device_id, app.now())
        .await
        .expect("device revocation persists");

    let reason = tokio::time::timeout(Duration::from_secs(2), waiting)
        .await
        .expect("blocked peer wakes on out-of-band device revocation")
        .expect("task completed");
    assert!(
        matches!(reason, Err(RelayClose::DeviceRevoked { .. })),
        "expected DeviceRevoked, got {reason:?}"
    );
    let send = device
        .send_frame(&envelope(&session_id, b"after-device-revoke"))
        .await;
    assert!(
        matches!(send, Err(RelayClose::DeviceRevoked { .. })),
        "expected DeviceRevoked, got {send:?}"
    );
    drop(credential);
}

#[tokio::test]
async fn relay_forwards_a_valid_frame_byte_for_byte() {
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
        .expect("client attaches");

    let frame = encode_frame(
        &envelope(&session_id, b"exact-length"),
        &FrameLimits::default(),
    )
    .expect("frame encodes");
    device
        .send_bytes(&frame)
        .await
        .expect("an exact-length frame is accepted");
    assert_eq!(
        client.recv_bytes().await.expect("frame received"),
        frame,
        "the relay forwards validated bytes unchanged"
    );
}

#[tokio::test]
async fn a_new_lease_does_not_reset_the_session_byte_budget() {
    let limits = RelayLimits {
        max_session_bytes: 256,
        ..RelayLimits::default()
    };
    let app = TestApp::with_relay(limits);
    let (session_id, capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
        .expect("client attaches");

    // One frame fits the budget, a second frame of the same size would not.
    let frame = encode_frame(&envelope(&session_id, &[0u8; 100]), &FrameLimits::default())
        .expect("frame encodes");
    assert!(
        frame.len() <= 256,
        "the test frame must fit the budget: {}",
        frame.len()
    );
    assert!(
        frame.len() * 2 > 256,
        "two test frames must exceed the budget: {}",
        frame.len()
    );
    device
        .send_bytes(&frame)
        .await
        .expect("first frame is within budget");
    client
        .recv_bytes()
        .await
        .expect("the peer drains the frame");

    // Spending the budget ends the relay for both directions, not just the sender.
    match device.send_frame(&envelope(&session_id, &[0u8; 512])).await {
        Err(RelayClose::ByteBudgetExhausted) => {}
        other => panic!("expected ByteBudgetExhausted, got {other:?}"),
    }
    assert_eq!(
        client.recv_bytes().await,
        Err(RelayClose::ByteBudgetExhausted),
        "the receiving peer learns the session is spent"
    );

    // A new lease for the same session must not hand out a fresh allowance.
    let (status, body) = app.relay_upgrade(&session_id, Some(&capability)).await;
    assert_eq!(
        status,
        StatusCode::CONFLICT,
        "a spent relay session cannot be leased again: {body}"
    );
    assert_eq!(body["error"], "relay_unavailable");

    match app.state.relay.attach(&session_id, PeerRole::Device).await {
        Err(RelayClose::ByteBudgetExhausted) => {}
        other => panic!("expected ByteBudgetExhausted on re-attach, got {other:?}"),
    }
    match device.send_bytes(&frame).await {
        Err(RelayClose::ByteBudgetExhausted) => {}
        other => panic!("a new lease must not reset the session byte budget, got {other:?}"),
    }
}

#[tokio::test]
async fn an_idle_timeout_does_not_reset_the_session_byte_budget() {
    let limits = RelayLimits {
        max_session_bytes: 256,
        idle_timeout_ms: 50,
        ..RelayLimits::default()
    };
    let app = TestApp::with_relay(limits);
    let (session_id, capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .await
        .expect("device attaches");
    let client = app
        .state
        .relay
        .attach(&session_id, PeerRole::Client)
        .await
        .expect("client attaches");

    let frame = encode_frame(&envelope(&session_id, &[0u8; 100]), &FrameLimits::default())
        .expect("frame encodes");
    assert!(frame.len() <= 256 && frame.len() * 2 > 256);
    device.send_bytes(&frame).await.expect("first frame");
    client.recv_bytes().await.expect("frame delivered");
    assert_eq!(client.recv_frame().await, Err(RelayClose::IdleTimeout));

    // An idle timeout is a per-receive deadline, not a budget reset: the bytes already
    // forwarded still count after a new lease.
    let (status, body) = app.relay_upgrade(&session_id, Some(&capability)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .await
        .expect("re-attach after an idle timeout");
    match device.send_bytes(&frame).await {
        Err(RelayClose::ByteBudgetExhausted) => {}
        other => panic!("an idle timeout must not reset the session byte budget, got {other:?}"),
    }
}

#[tokio::test]
async fn a_closed_relay_session_cannot_be_reopened_before_it_expires() {
    let app = TestApp::new();
    let (session_id, capability) = opened_session(&app).await;
    app.state
        .relay
        .close_session(&session_id, RelayClose::SessionClosed);

    // The close reason is part of the session's relay state, not a lease's, so a second
    // lease inside the session lifetime is refused with that reason.
    let (status, body) = app.relay_upgrade(&session_id, Some(&capability)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "relay_unavailable");
    assert!(matches!(
        app.state.relay.attach(&session_id, PeerRole::Device).await,
        Err(RelayClose::SessionClosed)
    ));
}

// --------------------------------------------------------------------------------------
// Framed relay transport: the route the lease advertises is actually served.
// --------------------------------------------------------------------------------------

mod transport {
    use std::net::SocketAddr;
    use std::time::Duration;

    use crate::common::TestApp;
    use axum::http::StatusCode;
    use futures_util::{SinkExt, StreamExt};
    use phoneconnect::v1::{Envelope, FrameLimits, encode_frame};
    use phoneconnect_server::relay::{RelayClose, RelayLimits};
    use phoneconnect_server::store::DeviceStore;
    use tokio::net::TcpListener;
    use tokio_tungstenite::MaybeTlsStream;
    use tokio_tungstenite::WebSocketStream;
    use tokio_tungstenite::tungstenite::Error;
    use tokio_tungstenite::tungstenite::Message;
    use tokio_tungstenite::tungstenite::client::IntoClientRequest;

    type Socket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

    /// Serves the router on a loopback port and returns the `ws://` base.
    async fn serve(app: &TestApp) -> (String, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address: SocketAddr = listener.local_addr().expect("address");
        let router = phoneconnect_server::build_router(app.state.clone());
        let handle = tokio::spawn(async move {
            let _ = axum::serve(listener, router).await;
        });
        (format!("ws://{address}"), handle)
    }

    /// Rewrites the advertised `https://host/path` route onto the loopback test server.
    fn loopback_route(base: &str, advertised: &str) -> String {
        let path = advertised
            .split_once("://")
            .expect("an advertised scheme")
            .1;
        let path = &path[path.find('/').expect("an advertised path")..];
        format!("{base}{path}")
    }

    async fn attach(url: &str, bearer: &str) -> Socket {
        let mut request = url.into_client_request().expect("websocket request");
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {bearer}").parse().expect("bearer header"),
        );
        tokio_tungstenite::connect_async(request)
            .await
            .expect("relay transport accepts an authorized peer")
            .0
    }

    fn frame(session_id: &str, payload: &[u8]) -> Vec<u8> {
        let device = phoneconnect::v1::DeviceId::new("dev_ws").expect("device id");
        let session = phoneconnect::v1::SessionId::new(session_id).expect("session id");
        let request = phoneconnect::v1::RequestId::new("req-ws").expect("request id");
        let mut envelope = Envelope::new(
            phoneconnect::v1::StreamKind::Control,
            &device,
            &session,
            &request,
        );
        envelope.payload = payload.to_vec();
        encode_frame(&envelope, &FrameLimits::control_only()).expect("frame")
    }

    async fn next_binary(socket: &mut Socket) -> Vec<u8> {
        let message = tokio::time::timeout(Duration::from_secs(2), socket.next())
            .await
            .expect("a message arrives within the deadline")
            .expect("the stream is open")
            .expect("a valid frame");
        match message {
            Message::Binary(bytes) => bytes.to_vec(),
            other => panic!("expected a binary frame, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn relay_transport_forwards_frames_over_the_advertised_lease_endpoint() {
        let app = TestApp::new();
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

        let (status, lease) = app.relay_upgrade(&session_id, Some(&capability)).await;
        assert_eq!(status, StatusCode::OK, "{lease}");
        let endpoint = lease["endpoint"].as_str().expect("endpoint");

        let (base, server) = serve(&app).await;
        let url = loopback_route(&base, endpoint);

        let mut client = attach(&url, &capability).await;
        let mut device = attach(&url, &credential).await;

        let outbound = frame(&session_id, b"over the websocket relay");
        client
            .send(Message::Binary(outbound.clone().into()))
            .await
            .expect("client frame sent");
        assert_eq!(
            next_binary(&mut device).await,
            outbound,
            "the advertised route forwards the frame byte for byte"
        );

        let reply = frame(&session_id, b"and back");
        device
            .send(Message::Binary(reply.clone().into()))
            .await
            .expect("device frame sent");
        assert_eq!(next_binary(&mut client).await, reply);

        server.abort();
    }

    #[tokio::test]
    async fn relay_transport_requires_session_credentials() {
        let app = TestApp::new();
        let (device_id, _) = app.enroll_new("user-a").await;
        let session = app.create_session(&device_id).await;
        let session_id = session["session_id"].as_str().expect("session_id");
        let capability = session["capability"].as_str().expect("capability");
        let (_, lease) = app.relay_upgrade(session_id, Some(capability)).await;
        let (base, server) = serve(&app).await;
        let url = loopback_route(&base, lease["endpoint"].as_str().expect("endpoint"));

        let request = url.into_client_request().expect("websocket request");
        let error = tokio_tungstenite::connect_async(request)
            .await
            .expect_err("an unauthenticated peer never reaches the relay");
        match error {
            Error::Http(response) => assert_eq!(response.status(), 401),
            other => panic!("expected an HTTP rejection, got {other:?}"),
        }

        server.abort();
    }

    #[tokio::test]
    async fn a_closed_relay_answers_relay_unavailable() {
        let app = TestApp::new();
        let (device_id, _) = app.enroll_new("user-a").await;
        let session = app.create_session(&device_id).await;
        let session_id = session["session_id"].as_str().expect("session_id");
        let capability = session["capability"].as_str().expect("capability");
        let (_, lease) = app.relay_upgrade(session_id, Some(capability)).await;
        app.state
            .relay
            .close_session(session_id, RelayClose::SessionClosed);

        let (base, server) = serve(&app).await;
        let url = loopback_route(&base, lease["endpoint"].as_str().expect("endpoint"));
        let mut request = url.into_client_request().expect("websocket request");
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {capability}").parse().expect("bearer"),
        );
        let error = tokio_tungstenite::connect_async(request)
            .await
            .expect_err("a closed relay is terminal for this session id");
        match error {
            Error::Http(response) => assert_eq!(
                response.status(),
                409,
                "409 relay_unavailable is the terminal answer"
            ),
            other => panic!("expected HTTP 409, got {other:?}"),
        }

        server.abort();
    }

    /// The transport keeps its relay attached with a WebSocket ping, which costs no frame
    /// slot, no queue entry, and no sequence number. That only works because the relay treats
    /// anything a peer sends — a ping included — as proof the socket is alive: without it, the
    /// idle deadline would close a relay that a healthy direct path never touches.
    #[tokio::test]
    async fn a_websocket_ping_keeps_the_relay_attached_past_the_idle_timeout() {
        async fn ping_and_await_pong(socket: &mut Socket) {
            socket
                .send(Message::Ping(b"pc-ka".to_vec().into()))
                .await
                .expect("ping sent");
            let message = tokio::time::timeout(Duration::from_secs(1), socket.next())
                .await
                .expect("the relay answers within the deadline")
                .expect("the stream stays open")
                .expect("a message");
            match message {
                Message::Pong(_) => {}
                other => panic!("the relay answered with {other:?} instead of a Pong"),
            }
        }

        let app = TestApp::with_relay(RelayLimits {
            idle_timeout_ms: 400,
            ..RelayLimits::default()
        });
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
        let (_, lease) = app.relay_upgrade(&session_id, Some(&capability)).await;
        let (base, server) = serve(&app).await;
        let url = loopback_route(&base, lease["endpoint"].as_str().expect("endpoint"));

        let mut client = attach(&url, &capability).await;
        let mut device = attach(&url, &credential).await;

        // Three idle timeouts of nothing but pings: a session whose traffic is all direct
        // sends no frames at all, so this is the only thing keeping the relay attached.
        for _ in 0..12 {
            ping_and_await_pong(&mut client).await;
            ping_and_await_pong(&mut device).await;
            tokio::time::sleep(Duration::from_millis(100)).await;
        }

        // The sockets survived the idle deadline, so a frame still crosses them.
        let forwarded = frame(&session_id, b"after three idle timeouts");
        device
            .send(Message::Binary(forwarded.clone().into()))
            .await
            .expect("the device socket is still attached");
        assert_eq!(next_binary(&mut client).await, forwarded);

        server.abort();
    }

    #[tokio::test]
    async fn relay_transport_reports_device_revocation_in_its_close_frame() {
        let app = TestApp::new();
        let (device_id, credential) = app.enroll_new("user-a").await;
        let session = app.create_session(&device_id).await;
        let session_id = session["session_id"].as_str().expect("session_id");
        let capability = session["capability"].as_str().expect("capability");
        let (_, lease) = app.relay_upgrade(session_id, Some(capability)).await;

        let (base, server) = serve(&app).await;
        let url = loopback_route(&base, lease["endpoint"].as_str().expect("endpoint"));
        let mut client = attach(&url, capability).await;
        let _device = attach(&url, &credential).await;

        app.store
            .revoke_device(&device_id, app.now())
            .await
            .expect("revocation persists");

        let message = tokio::time::timeout(Duration::from_secs(2), client.next())
            .await
            .expect("the close arrives without waiting for a frame")
            .expect("the stream stays readable")
            .expect("a close frame");
        match message {
            Message::Close(Some(frame)) => {
                assert_eq!(
                    u16::from(frame.code),
                    1008,
                    "policy close, not a generic drop"
                );
                assert_eq!(
                    frame.reason.as_str(),
                    "device_revoked",
                    "the stream error carries the revocation"
                );
            }
            other => panic!("expected a close frame, got {other:?}"),
        }

        server.abort();
    }
}

#[tokio::test]
async fn relay_authorization_is_cached_within_the_poll_bound() {
    // The data path must not serialize on the store mutex per frame, but revocation must
    // still take effect within the documented bound. An out-of-band revocation (as another
    // server instance or an operator tool would perform it) is the strictest case because
    // nothing local closes the relay.
    let app = TestApp::new();
    let (session_id, _capability) = opened_session(&app).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .await
        .expect("device attaches");

    device
        .send_frame(&envelope(&session_id, b"warms-the-cache"))
        .await
        .expect("first frame authorizes and caches");

    app.store
        .revoke_session(&session_id, app.now())
        .await
        .expect("session revocation persists");

    // Inside the cache window the frame is still accepted: the hot path did not read the
    // store again, which is the point of the cache.
    device
        .send_frame(&envelope(&session_id, b"inside-the-cache-window"))
        .await
        .expect("a cached authorization serves the hot path");

    // Past the bound the next frame re-reads the store and stops the relay.
    tokio::time::sleep(Duration::from_millis(
        phoneconnect_server::relay::RELAY_AUTHORIZATION_CACHE_MS + 120,
    ))
    .await;
    assert_eq!(
        device
            .send_frame(&envelope(&session_id, b"past-the-bound"))
            .await
            .err(),
        Some(RelayClose::SessionRevoked),
        "revocation takes effect within the poll bound"
    );
}
