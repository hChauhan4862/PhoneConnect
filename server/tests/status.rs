//! The status surface reports the state a client would actually join: a live session wins
//! over a newer ended one, and a revoked device never advertises control.

mod common;

use axum::http::StatusCode;
use common::{ADMIN_TOKEN, TestApp};
use serde_json::Value;

#[tokio::test]
async fn the_status_prefers_a_live_session_over_a_newer_ended_one() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    let live = app.create_session(&device_id).await;
    let live_id = live["session_id"].as_str().expect("session id").to_owned();
    let ended = app.create_session(&device_id).await;
    let ended_id = ended["session_id"].as_str().expect("session id").to_owned();
    let (status, body) = app.revoke("sessions", &ended_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = app.device_status(&device_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(
        body["session"]["session_id"],
        Value::from(live_id.clone()),
        "a newer revoked session must not hide the one a client can join: {body}"
    );
    assert_eq!(body["session"]["state"], Value::from("active"));

    // With no live session, the newest ended one explains the absence explicitly.
    app.revoke("sessions", live_id.as_str(), Some(ADMIN_TOKEN))
        .await;
    let (status, body) = app.device_status(&device_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["session"]["state"], Value::from("revoked"));
    assert_eq!(body["session"]["path"]["state"], Value::from("none"));
}

#[tokio::test]
async fn a_revoked_device_reports_no_control_and_no_lease() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    let (status, body) = app.revoke("devices", &device_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = app.device_status(&device_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["device"]["state"], Value::from("revoked"));
    assert_eq!(body["lease"]["lease"], Value::Null);
    assert_eq!(body["lease"]["access"]["is_owner"], Value::from(true));
    assert_eq!(body["lease"]["access"]["can_control"], Value::from(false));
}
