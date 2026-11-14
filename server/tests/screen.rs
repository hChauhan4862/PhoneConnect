//! The screen route: a typed front door for `screen.snapshot`, forwarded through the same
//! authorization, deadline, and audit path as every other command.
//!
//! The device is the authority on whether it can capture at all: without the consent the user
//! granted on the setup screen the answer is `consent_required`, and this route passes that
//! through. The server's own job is to refuse an answer it could not hold.

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use common::control;
use futures_util::StreamExt;
use phoneconnect_server::management::MAX_RESULT_BYTES;
use phoneconnect_server::store::DeviceStore;
use serde_json::{Value, json};

async fn snapshot(
    app: &TestApp,
    device_id: &str,
    user_id: &str,
    body: Value,
) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/devices/{device_id}/screen/snapshot?user_id={user_id}"),
        Some(common::ADMIN_TOKEN),
        Some(body),
    )
    .await
}

async fn dispatch(app: &TestApp, device_id: &str, body: Value) -> String {
    let (status, accepted) = snapshot(app, device_id, "user-a", body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    accepted["command_id"]
        .as_str()
        .expect("command_id")
        .to_owned()
}

#[tokio::test]
async fn a_snapshot_is_forwarded_with_no_arguments_and_its_answer_passes_through() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let command_id = dispatch(&app, &device_id, json!({})).await;

    let frame = control::next_json(&mut socket).await;
    assert_eq!(frame["type"], "command");
    assert_eq!(frame["name"], "screen.snapshot");
    assert_eq!(frame["request_id"], command_id);
    assert_eq!(
        frame["args"],
        json!({}),
        "a caller cannot smuggle an argument to the device for this command"
    );

    // Nothing is invented while the capture has not happened.
    let (status, record) = app.command(&command_id, "user-a").await;
    assert_eq!(status, StatusCode::OK, "{record}");
    assert_eq!(record["status"], "pending");

    control::send(
        &mut socket,
        control::result(
            &command_id,
            "ok",
            json!({ "png_base64": "iVBORw0KGgo=", "width": 1080, "height": 1920, "captured_at_ms": 1_760_000_000_000i64 }),
        ),
    )
    .await;

    let record = wait_for_completion(&app, &command_id).await;
    assert_eq!(record["status"], "ok");
    assert_eq!(record["output"]["png_base64"], "iVBORw0KGgo=");
    assert_eq!(record["output"]["width"], 1080);
    assert_eq!(record["output"]["height"], 1920);
    assert_eq!(
        record["output"]["captured_at_ms"],
        json!(1_760_000_000_000i64)
    );
    assert_eq!(record["error"], json!(null));

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_consent_refusal_keeps_the_devices_machine_code_and_message() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let command_id = dispatch(&app, &device_id, json!({})).await;
    control::next_json(&mut socket).await;

    let message = "screen capture needs the user's consent, granted from the PhoneConnect setup screen on the device; no projection is held";
    control::send(
        &mut socket,
        control::error_result(&command_id, "consent_required", message),
    )
    .await;

    let record = wait_for_completion(&app, &command_id).await;
    assert_eq!(record["status"], "error");
    assert_eq!(record["error"], "consent_required");
    assert_eq!(record["message"], message);
    assert_eq!(record["output"], json!(null));

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_capture_at_the_server_result_cap_is_refused_as_result_too_large() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let command_id = dispatch(&app, &device_id, json!({})).await;
    control::next_json(&mut socket).await;

    // One byte over the cap: the device must downscale below it, and a device that does not
    // gets an explicit refusal instead of a stored, oversized answer.
    control::send(
        &mut socket,
        control::result(
            &command_id,
            "ok",
            json!({ "png_base64": "A".repeat(MAX_RESULT_BYTES) }),
        ),
    )
    .await;

    let record = wait_for_completion(&app, &command_id).await;
    assert_eq!(record["status"], "error");
    assert_eq!(record["error"], "result_too_large");
    assert_eq!(record["output"], json!(null));

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_snapshot_requires_control_and_a_well_formed_body() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let (status, body) = snapshot(&app, &device_id, "user-b", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "lease_read_only");

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/screen/snapshot?user_id=user-a"),
            None,
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "missing_credentials");

    let (status, body) = snapshot(&app, &device_id, "user-a", json!(["not", "an", "object"])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), socket.next())
            .await
            .is_err(),
        "a refused snapshot must never reach the device"
    );

    server.abort();
}

#[tokio::test]
async fn a_snapshot_to_an_offline_device_is_device_offline_and_audited() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("user-a").await;

    let (status, body) = snapshot(&app, &device_id, "user-a", json!({})).await;

    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "device_offline");

    let rows = app
        .store
        .list_audit(Some(&device_id), 10)
        .await
        .expect("audit rows");
    assert_eq!(rows[0].outcome, "refused");
    assert_eq!(rows[0].error.as_deref(), Some("device_offline"));
}

async fn wait_for_completion(app: &TestApp, command_id: &str) -> Value {
    for _ in 0..200 {
        let (status, body) = app.command(command_id, "user-a").await;
        assert_eq!(status, StatusCode::OK, "{body}");
        if body["status"] != "pending" {
            return body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("command {command_id} never completed");
}
