//! Control leases: one holder per device, explicit grant and handoff, read-only secondary
//! access, expiry, and revocation that closes the streams the lease authorized.

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::{ADMIN_TOKEN, TestApp};
use phoneconnect_server::relay::{PeerRole, RelayClose};
use phoneconnect_server::store::DeviceStore;
use serde_json::{Value, json};

async fn enrolled(app: &TestApp) -> (String, String) {
    app.enroll_new("owner-1").await
}

fn lease_id(body: &Value) -> String {
    body["lease_id"]
        .as_str()
        .unwrap_or_else(|| panic!("lease_id missing from {body}"))
        .to_owned()
}

#[tokio::test]
async fn the_owner_grants_a_lease_to_themselves() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;

    let (status, body) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CREATED, "acquire failed: {body}");
    assert_eq!(body["device_id"], Value::from(device_id.clone()));
    assert_eq!(body["owner_id"], Value::from("owner-1"));
    assert_eq!(body["holder_id"], Value::from("owner-1"));
    assert_eq!(body["granted_by"], Value::from("owner-1"));
    assert_eq!(body["revoked_at_ms"], Value::Null);
    assert_eq!(
        body["expires_at_ms"].as_i64(),
        Some(app.now() + 600_000),
        "the lease carries the requested expiry"
    );
    assert!(
        !lease_id(&body).is_empty(),
        "a lease has a server-issued identifier"
    );

    let (status, body) = app.lease_status(&device_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "status failed: {body}");
    assert_eq!(body["lease"]["holder_id"], Value::from("owner-1"));
    assert_eq!(body["access"]["is_owner"], Value::from(true));
    assert_eq!(body["access"]["role"], Value::from("controller"));
    assert_eq!(body["access"]["can_control"], Value::from(true));
}

#[tokio::test]
async fn a_free_lease_is_granted_only_to_the_device_owner() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;

    let (status, body) = app.acquire_lease(&device_id, "someone-else", 600).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], Value::from("owner_required"));

    let (status, body) = app.lease_status(&device_id, "someone-else").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["lease"], Value::Null);
    assert_eq!(body["access"]["role"], Value::from("viewer"));
    assert_eq!(body["access"]["can_control"], Value::from(false));

    // Nothing was recorded: a refused grant is not a lease.
    assert!(
        app.store
            .active_lease(&device_id, app.now())
            .await
            .expect("lease lookup")
            .is_none()
    );
}

#[tokio::test]
async fn a_held_lease_is_not_displaced_without_an_explicit_handoff() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;
    app.acquire_lease(&device_id, "owner-1", 600).await;
    let (status, handed) = app
        .handoff_lease(&device_id, "owner-1", "user-b", 600)
        .await;
    assert_eq!(status, StatusCode::OK, "handoff failed: {handed}");

    // Even the owner cannot take control back silently; the holder is displaced only by
    // handoff or revocation.
    let (status, body) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], Value::from("lease_held"));

    let (status, body) = app.acquire_lease(&device_id, "user-c", 600).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], Value::from("owner_required"));

    let active = app
        .store
        .active_lease(&device_id, app.now())
        .await
        .expect("lease lookup")
        .expect("a lease stays active");
    assert_eq!(
        active.holder_id, "user-b",
        "the first grant is still the active one"
    );
}

#[tokio::test]
async fn the_owner_hands_off_control_explicitly() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;
    let (status, granted) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CREATED, "{granted}");
    let first_lease = lease_id(&granted);

    let (status, body) = app
        .handoff_lease(&device_id, "owner-1", "user-b", 120)
        .await;
    assert_eq!(status, StatusCode::OK, "handoff failed: {body}");
    assert_eq!(body["lease"]["holder_id"], Value::from("user-b"));
    assert_eq!(body["lease"]["granted_by"], Value::from("owner-1"));
    assert_eq!(
        body["lease"]["expires_at_ms"].as_i64(),
        Some(app.now() + 120_000)
    );
    assert_eq!(body["replaced"]["lease_id"], Value::from(first_lease));
    assert_eq!(body["replaced"]["reason"], Value::from("handoff"));
    assert!(
        body["replaced"]["revoked_at_ms"].as_i64().is_some(),
        "the replaced lease carries its revocation time"
    );

    // The new holder controls; the owner is now a viewer with no control commands.
    assert_eq!(
        app.state
            .leases
            .authorize_control(&device_id, "user-b")
            .await
            .expect("the new holder controls")
            .holder_id,
        "user-b"
    );
    assert_eq!(
        app.state
            .leases
            .authorize_control(&device_id, "owner-1")
            .await
            .err()
            .map(|error| error.code()),
        Some("lease_read_only")
    );

    let (status, body) = app.lease_status(&device_id, "user-b").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["access"]["role"], Value::from("controller"));
    assert_eq!(body["access"]["is_owner"], Value::from(false));
}

#[tokio::test]
async fn only_the_owner_or_the_holder_can_hand_off() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;
    app.acquire_lease(&device_id, "owner-1", 600).await;
    app.handoff_lease(&device_id, "owner-1", "user-b", 600)
        .await;

    let (status, body) = app.handoff_lease(&device_id, "user-c", "user-c", 600).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], Value::from("lease_actor_not_allowed"));

    // The holder may pass control on, and the owner may take it back.
    let (status, body) = app.handoff_lease(&device_id, "user-b", "user-d", 30).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["lease"]["holder_id"], Value::from("user-d"));

    let (status, body) = app
        .handoff_lease(&device_id, "owner-1", "owner-1", 30)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["lease"]["holder_id"], Value::from("owner-1"));
}

#[tokio::test]
async fn a_secondary_viewer_reads_but_cannot_control() {
    let app = TestApp::new();
    let (device_id, credential) = enrolled(&app).await;
    app.acquire_lease(&device_id, "owner-1", 600).await;

    // A secondary viewer can read the lease and the device, not command it.
    let (status, body) = app.lease_status(&device_id, "user-c").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["lease"]["holder_id"], Value::from("owner-1"));
    assert_eq!(body["access"]["role"], Value::from("viewer"));
    assert_eq!(body["access"]["can_control"], Value::from(false));

    assert_eq!(
        app.state
            .leases
            .authorize_control(&device_id, "user-c")
            .await
            .err()
            .map(|error| error.code()),
        Some("lease_read_only")
    );

    // Opening a control stream is a control command: it needs the lease.
    let (status, body) = app
        .create_control_session(&device_id, "user-c", &TestApp::identity_key())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], Value::from("lease_read_only"));

    // Read-only telemetry is still available to the viewer.
    let (status, body) = app.ingest_telemetry(&device_id, &credential, 42).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = app.device_status(&device_id, "user-c").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["telemetry"]["latest"]["battery_percent"],
        Value::from(42)
    );
}

#[tokio::test]
async fn a_expired_lease_grants_nothing_and_can_be_replaced() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;
    let (status, granted) = app.acquire_lease(&device_id, "owner-1", 30).await;
    assert_eq!(status, StatusCode::CREATED, "{granted}");

    app.clock.advance_ms(29_000);
    assert!(
        app.state
            .leases
            .authorize_control(&device_id, "owner-1")
            .await
            .is_ok(),
        "the lease is still live before its expiry"
    );

    app.clock.advance_ms(1_000);
    assert_eq!(
        app.state
            .leases
            .authorize_control(&device_id, "owner-1")
            .await
            .err()
            .map(|error| error.code()),
        Some("lease_expired")
    );

    let (status, body) = app.lease_status(&device_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["lease"], Value::Null, "an expired lease is not active");
    assert_eq!(body["access"]["role"], Value::from("viewer"));

    let (status, body) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CREATED, "{body}");
    assert_eq!(body["holder_id"], Value::from("owner-1"));
}

#[tokio::test]
async fn a_control_session_never_outlives_its_lease() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;
    let (status, granted) = app.acquire_lease(&device_id, "owner-1", 60).await;
    assert_eq!(status, StatusCode::CREATED, "{granted}");
    let lease_expires_at = granted["expires_at_ms"].as_i64().expect("expiry");

    let (status, body) = app
        .create_control_session(&device_id, "owner-1", &TestApp::identity_key())
        .await;
    assert_eq!(status, StatusCode::OK, "control session failed: {body}");
    let session_id = body["session_id"].as_str().expect("session id");

    let session = app.store.session(session_id).await.expect("session record");
    assert!(
        session.expires_at_ms <= lease_expires_at,
        "a control session must not outlive the lease that authorized it: {} > {}",
        session.expires_at_ms,
        lease_expires_at
    );
    assert_eq!(
        app.store
            .lease_for_session(session_id)
            .await
            .expect("lease link")
            .as_deref(),
        Some(lease_id(&granted).as_str()),
        "the session remembers which lease authorized it"
    );
}

#[tokio::test]
async fn a_control_session_requires_a_live_lease() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;

    let (status, body) = app
        .create_control_session(&device_id, "owner-1", &TestApp::identity_key())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], Value::from("lease_required"));

    // A read-only session does not need a lease: only control does.
    let (status, body) = app.create_session_raw(&device_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        app.store
            .lease_for_session(body["session_id"].as_str().expect("session id"))
            .await
            .expect("lease link"),
        None,
        "a read-only session is not a lease capability"
    );
}

#[tokio::test]
async fn revocation_is_immediate_and_invalidates_the_lease_streams() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;
    let (status, granted) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CREATED, "{granted}");
    let active_lease = lease_id(&granted);

    let (status, session_body) = app
        .create_control_session(&device_id, "owner-1", &TestApp::identity_key())
        .await;
    assert_eq!(status, StatusCode::OK, "{session_body}");
    let session_id = session_body["session_id"]
        .as_str()
        .expect("session id")
        .to_owned();
    let capability = session_body["capability"].as_str().expect("capability");
    let (status, body) = app.relay_upgrade(&session_id, Some(capability)).await;
    assert_eq!(status, StatusCode::OK, "relay upgrade failed: {body}");

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

    // An attached relay is closed by the revocation request itself, not by a later poll.
    let waiting = tokio::spawn(async move { client.recv_bytes().await });
    tokio::time::sleep(Duration::from_millis(20)).await;
    let revoked_at = std::time::Instant::now();
    let (status, body) = app.revoke_lease(&active_lease, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "revoke failed: {body}");
    assert_eq!(body["reason"], Value::from("revoked"));
    assert_eq!(
        body["invalidated_sessions"],
        json!([session_id.clone()]),
        "the revocation names every stream capability it invalidated"
    );

    let reason = tokio::time::timeout(Duration::from_secs(2), waiting)
        .await
        .expect("blocked peer wakes on lease revocation")
        .expect("task completed");
    assert!(
        revoked_at.elapsed() < Duration::from_millis(200),
        "lease revocation closes the relay now: {:?}",
        revoked_at.elapsed()
    );
    assert_eq!(
        reason,
        Err(RelayClose::LeaseRevoked {
            lease_id: active_lease.clone()
        })
    );
    assert_eq!(
        device.close_send().err(),
        Some(RelayClose::LeaseRevoked {
            lease_id: active_lease.clone()
        }),
        "the relay is already closed when the revocation response arrives"
    );

    let record = app
        .store
        .session(&session_id)
        .await
        .expect("session record");
    assert!(
        record.is_revoked(),
        "the stream capability is invalidated in the store too"
    );

    // After revocation no further control capability is issued for that lease, and the
    // holder's commands are refused explicitly.
    let (status, body) = app
        .create_control_session(&device_id, "owner-1", &TestApp::identity_key())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], Value::from("lease_required"));
    assert_eq!(
        app.state
            .leases
            .authorize_control(&device_id, "owner-1")
            .await
            .err()
            .map(|error| error.code()),
        Some("lease_required")
    );
    assert_eq!(
        app.revoke_lease(&active_lease, "owner-1").await.0,
        StatusCode::OK,
        "revocation is idempotent"
    );
}

#[tokio::test]
async fn a_handoff_invalidates_the_previous_holders_streams() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;
    let (status, granted) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CREATED, "{granted}");
    let (status, body) = app
        .create_control_session(&device_id, "owner-1", &TestApp::identity_key())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let session_id = body["session_id"].as_str().expect("session id").to_owned();
    let capability = body["capability"].as_str().expect("capability");
    app.relay_upgrade(&session_id, Some(capability)).await;
    let device = app
        .state
        .relay
        .attach(&session_id, PeerRole::Device)
        .await
        .expect("device attaches");

    let (status, body) = app
        .handoff_lease(&device_id, "owner-1", "user-b", 600)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["replaced"]["invalidated_sessions"],
        json!([session_id.clone()]),
        "handing control away closes the old holder's streams"
    );
    assert!(
        matches!(device.close_send(), Err(RelayClose::LeaseRevoked { .. })),
        "the relay observes the handoff as a lease revocation"
    );
}

#[tokio::test]
async fn a_repeat_revocation_keeps_the_original_reason_and_time() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;
    app.acquire_lease(&device_id, "owner-1", 600).await;
    let (status, handoff) = app
        .handoff_lease(&device_id, "owner-1", "user-b", 600)
        .await;
    assert_eq!(status, StatusCode::OK, "{handoff}");
    let replaced = &handoff["replaced"];
    let replaced_id = replaced["lease_id"].as_str().expect("replaced lease id");
    let replaced_at = replaced["revoked_at_ms"].clone();
    assert_eq!(replaced["reason"], Value::from("handoff"));

    // Revoking a lease that already ended by handoff is idempotent and does not relabel it
    // as an explicit revocation, nor does it claim to invalidate anything again.
    let (status, body) = app.revoke_lease(replaced_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["reason"], Value::from("handoff"));
    assert_eq!(body["revoked_at_ms"], replaced_at);
    assert_eq!(body["invalidated_sessions"], json!([]));
}

#[tokio::test]
async fn only_the_owner_or_the_holder_can_revoke() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;
    let (status, granted) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CREATED, "{granted}");

    let (status, body) = app.revoke_lease(&lease_id(&granted), "user-c").await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], Value::from("lease_actor_not_allowed"));
    assert!(
        app.state
            .leases
            .authorize_control(&device_id, "owner-1")
            .await
            .is_ok(),
        "a refused revocation leaves the lease live"
    );

    let (status, body) = app.revoke_lease("lease_missing", "owner-1").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], Value::from("lease_unknown"));
}

#[tokio::test]
async fn a_revoked_device_grants_no_lease() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;
    let (status, body) = app.revoke("devices", &device_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], Value::from("device_revoked"));

    let (status, body) = app.acquire_lease("dev_missing", "owner-1", 600).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], Value::from("device_unknown"));
}

#[tokio::test]
async fn lease_requests_reject_invalid_arguments() {
    let app = TestApp::new();
    let (device_id, _credential) = enrolled(&app).await;

    let (status, body) = app.acquire_lease(&device_id, "", 600).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], Value::from("invalid_request"));

    let (status, body) = app.acquire_lease(&device_id, "owner-1", 0).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    let (status, body) = app.handoff_lease(&device_id, "", "user-b", 600).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");

    // The lease routes are admin-authorized: no token, no answer.
    let (status, _) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/lease"),
            None,
            Some(json!({ "actor_id": "owner-1", "expires_in_seconds": 600 })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);
}
