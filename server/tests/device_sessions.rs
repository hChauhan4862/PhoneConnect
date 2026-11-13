//! Device-side session discovery: how an enrolled device learns which session to join.
//!
//! A session is authorized by a user or client, never by the device. The device credential
//! proves which device is asking, and the answer carries a device-role ticket, so the agent
//! never needs a client identifier or any client privilege.

mod common;

use axum::http::{Method, StatusCode};
use common::{ADMIN_TOKEN, TestApp};
use serde_json::Value;

fn device_session_uri(device_id: &str) -> String {
    format!("/api/devices/{device_id}/sessions/next")
}

#[tokio::test]
async fn a_device_learns_its_session_with_a_device_ticket() {
    let app = TestApp::new();
    let (device_id, credential, device_identity) = app.enroll_new_with_identity("owner-1").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"].as_str().expect("session id").to_owned();
    let client_identity = session["ticket"]["own_identity_key"]
        .as_str()
        .expect("client identity key")
        .to_owned();

    let (status, body) = app
        .request(
            Method::GET,
            &device_session_uri(&device_id),
            Some(&credential),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::OK, "discovery failed: {body}");
    assert_eq!(body["session_id"], Value::from(session_id.clone()));
    assert_eq!(body["expires_at"], session["expires_at"]);
    assert_eq!(body["verification_key"], session["verification_key"]);
    let ticket = &body["ticket"];
    assert_eq!(ticket["role"], Value::from("device"));
    assert_eq!(ticket["session_id"], Value::from(session_id));
    assert_eq!(ticket["device_id"], Value::from(device_id.clone()));
    assert_eq!(
        ticket["own_identity_key"],
        Value::from(device_identity),
        "the device must receive its own pinned identity key"
    );
    assert_eq!(
        ticket["peer_identity_key"],
        Value::from(client_identity),
        "the device must be pinned to the client that authorized the session"
    );
    assert!(
        !ticket["nonce"].as_str().unwrap_or_default().is_empty(),
        "a device ticket needs a redemption nonce"
    );
    assert!(
        !ticket["signature"].as_str().unwrap_or_default().is_empty(),
        "the ticket must be signed"
    );
}

#[tokio::test]
async fn a_device_without_a_session_gets_no_content() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("owner-1").await;

    let (status, body) = app
        .request(
            Method::GET,
            &device_session_uri(&device_id),
            Some(&credential),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::NO_CONTENT, "unexpected body: {body}");
}

#[tokio::test]
async fn a_device_cannot_discover_another_devices_session() {
    let app = TestApp::new();
    let (device_id, _) = app.enroll_new("owner-1").await;
    app.create_session(&device_id).await;
    let (_, other_credential) = app.enroll_new("owner-2").await;

    let (status, body) = app
        .request(
            Method::GET,
            &device_session_uri(&device_id),
            Some(&other_credential),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::FORBIDDEN, "unexpected body: {body}");
    assert_eq!(body["error"], Value::from("device_scope_mismatch"));
}

#[tokio::test]
async fn discovery_requires_a_device_credential() {
    let app = TestApp::new();
    let (device_id, _) = app.enroll_new("owner-1").await;

    let (status, body) = app
        .request(Method::GET, &device_session_uri(&device_id), None, None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "unexpected body: {body}");

    // An admin token is not a device credential: the route answers *this device's*
    // question, and an admin has no device identity to answer with.
    let (status, body) = app
        .request(
            Method::GET,
            &device_session_uri(&device_id),
            Some(ADMIN_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "unexpected body: {body}");
}

#[tokio::test]
async fn revoked_or_expired_sessions_are_not_offered() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("owner-1").await;
    let first = app.create_session(&device_id).await;
    let first_id = first["session_id"].as_str().expect("session id");

    let (status, _) = app
        .revoke("sessions", first_id, Some(ADMIN_TOKEN))
        .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request(
            Method::GET,
            &device_session_uri(&device_id),
            Some(&credential),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::NO_CONTENT, "unexpected body: {body}");

    let second = app.create_session(&device_id).await;
    let second_id = second["session_id"].as_str().expect("session id");
    // Past the session expiry: an expired session must not be offered either.
    app.clock.advance_ms(10 * 60 * 1_000);

    let (status, body) = app
        .request(
            Method::GET,
            &device_session_uri(&device_id),
            Some(&credential),
            None,
        )
        .await;
    assert_eq!(
        status,
        StatusCode::NO_CONTENT,
        "expired session {second_id} must not be offered: {body}"
    );
}

#[tokio::test]
async fn a_revoked_device_cannot_discover_sessions() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("owner-1").await;
    app.create_session(&device_id).await;
    let (status, _) = app.revoke("devices", &device_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = app
        .request(
            Method::GET,
            &device_session_uri(&device_id),
            Some(&credential),
            None,
        )
        .await;

    assert_eq!(status, StatusCode::UNAUTHORIZED, "unexpected body: {body}");
    assert_eq!(body["error"], Value::from("device_revoked"));
}
