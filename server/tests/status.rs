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
async fn the_status_reports_how_many_control_frames_a_read_only_session_refused() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"]
        .as_str()
        .expect("session id")
        .to_owned();
    let capability = session["capability"].as_str().expect("capability");
    app.relay_upgrade(&session_id, Some(capability)).await;
    let client = app
        .state
        .relay
        .attach(&session_id, phoneconnect_server::relay::PeerRole::Client)
        .await
        .expect("client attaches");
    let frame = phoneconnect_control_frame(&session_id);
    assert!(
        client.send_frame(&frame).await.is_err(),
        "a read-only session cannot command"
    );

    let (status, body) = app.device_status(&device_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["session"]["control_refusals"], Value::from(1));
}

fn phoneconnect_control_frame(session_id: &str) -> phoneconnect::v1::Envelope {
    use phoneconnect::v1::{DeviceId, Envelope, RequestId, SessionId, StreamKind};
    let device = DeviceId::new("dev_status").expect("device id");
    let session = SessionId::new(session_id).expect("session id");
    let request = RequestId::new("req_status").expect("request id");
    Envelope::new(StreamKind::Control, &device, &session, &request)
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
