//! Nonce-only rendezvous registration: publish the epoch without a probe target.
//!
//! A peer with no direct path still needs its redemption nonce to reach the opposite peer,
//! because the two nonces are the connection epoch. `POST /candidates` therefore accepts a
//! ticket with **no** endpoint: the nonce is recorded, no `server_observed` candidate is
//! emitted, and every authorization rule still applies.

mod common;

use axum::http::{Method, StatusCode};
use common::{ADMIN_TOKEN, TestApp};
use serde_json::{Value, json};

const RELAY: &str = "relay";

fn session_uri(session_id: &str, suffix: &str) -> String {
    format!("/api/sessions/{session_id}/{suffix}")
}

async fn device_and_client(app: &TestApp) -> (String, String, String, String, String) {
    let (device_id, credential, device_identity) = app.enroll_new_with_identity("owner-1").await;
    let client_identity = TestApp::identity_key();
    let (status, session) = app
        .create_session_with_identity(&device_id, Some(ADMIN_TOKEN), &client_identity)
        .await;
    assert_eq!(status, StatusCode::OK, "create session failed: {session}");
    let session_id = session["session_id"].as_str().expect("session id").to_owned();
    let capability = session["capability"].as_str().expect("capability").to_owned();
    (
        device_id,
        credential,
        capability,
        session_id,
        device_identity,
    )
}

#[tokio::test]
async fn a_nonce_only_registration_publishes_the_epoch_without_a_probe_target() {
    let app = TestApp::new();
    let (_device_id, credential, capability, session_id, _) = device_and_client(&app).await;

    let (status, device_ticket) = app.ticket(&session_id, &credential).await;
    assert_eq!(status, StatusCode::OK, "device ticket failed: {device_ticket}");
    let device_nonce = device_ticket["ticket"]["nonce"]
        .as_str()
        .expect("device nonce")
        .to_owned();

    let (status, device_view) = app
        .register_nonce_only(&session_id, &credential, &device_ticket["ticket"])
        .await;
    assert_eq!(status, StatusCode::OK, "nonce-only registration failed: {device_view}");
    assert!(
        device_view.get("peer_nonce").is_none(),
        "the client has not registered yet: {device_view}"
    );

    // The client now reads the device's half of the epoch, and no probe target appears.
    let (status, client_view) = app.candidates(&session_id, Some(&capability)).await;
    assert_eq!(status, StatusCode::OK, "client candidates failed: {client_view}");
    assert_eq!(
        client_view["peer_nonce"], Value::from(device_nonce),
        "the client must receive the device's redemption nonce"
    );
    let candidates = client_view["candidates"].as_array().expect("candidates");
    assert!(
        candidates.iter().all(|candidate| candidate["kind"] == RELAY),
        "a nonce-only peer must not be advertised as a probe target: {client_view}"
    );
    assert_eq!(candidates.len(), 1, "only the relay candidate remains: {client_view}");
    assert!(
        client_view.get("capability").is_none(),
        "the candidates response must never carry a capability: {client_view}"
    );
}

#[tokio::test]
async fn a_nonce_only_registration_still_redeems_the_ticket_exactly_once() {
    let app = TestApp::new();
    let (_device_id, credential, _capability, session_id, _) = device_and_client(&app).await;
    let (_, ticket) = app.ticket(&session_id, &credential).await;

    let (status, _) = app
        .register_nonce_only(&session_id, &credential, &ticket["ticket"])
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .register_nonce_only(&session_id, &credential, &ticket["ticket"])
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "a replayed nonce must be refused: {body}");
    assert_eq!(body["error"], Value::from("ticket_replayed"));
}

#[tokio::test]
async fn an_expired_ticket_cannot_publish_a_nonce() {
    let app = TestApp::new();
    let (_device_id, credential, capability, session_id, _) = device_and_client(&app).await;
    let (_, ticket) = app.ticket(&session_id, &credential).await;

    app.clock
        .advance_ms(phoneconnect_server::rendezvous::TICKET_TTL_MS + 1);

    let (status, body) = app
        .register_nonce_only(&session_id, &credential, &ticket["ticket"])
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "an expired ticket must fail: {body}");
    assert_eq!(body["error"], Value::from("ticket_expired"));

    let (_, client_view) = app.candidates(&session_id, Some(&capability)).await;
    assert!(
        client_view.get("peer_nonce").is_none(),
        "an expired registration must not publish a nonce: {client_view}"
    );
}

#[tokio::test]
async fn a_revoked_session_cannot_publish_a_nonce() {
    let app = TestApp::new();
    let (_device_id, credential, capability, session_id, _) = device_and_client(&app).await;
    let (_, ticket) = app.ticket(&session_id, &credential).await;

    let (status, _) = app.revoke("sessions", &session_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .register_nonce_only(&session_id, &credential, &ticket["ticket"])
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked session must refuse registration: {body}"
    );
    assert_eq!(body["error"], Value::from("session_revoked"));

    let (status, _) = app.candidates(&session_id, Some(&capability)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "the session stays closed");
}

#[tokio::test]
async fn a_revoked_device_cannot_publish_a_nonce() {
    let app = TestApp::new();
    let (device_id, credential, _capability, session_id, _) = device_and_client(&app).await;
    let (_, ticket) = app.ticket(&session_id, &credential).await;

    let (status, _) = app.revoke("devices", &device_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .register_nonce_only(&session_id, &credential, &ticket["ticket"])
        .await;
    assert_eq!(
        status,
        StatusCode::UNAUTHORIZED,
        "a revoked device must refuse registration: {body}"
    );
    assert_eq!(body["error"], Value::from("device_revoked"));
}

#[tokio::test]
async fn a_non_nonce_body_is_still_rejected() {
    let app = TestApp::new();
    let (_device_id, credential, _capability, session_id, _) = device_and_client(&app).await;
    let (_, ticket) = app.ticket(&session_id, &credential).await;

    // A body with no ticket at all is not a nonce-only registration.
    let (status, body) = app
        .request(
            Method::POST,
            &session_uri(&session_id, "candidates"),
            Some(&credential),
            Some(json!({ "endpoint": "203.0.113.9:5000" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "unexpected body: {body}");
    let _ = &ticket;
}
