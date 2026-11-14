//! The control routes: `POST /api/devices/{id}/control/{get,set,reboot}`.
//!
//! The device owns every capability decision — what it can read, what a grant gates, and what
//! Android removed or made signature-level. The server authorizes the caller, refuses a body
//! that is not a control request, and forwards through the same dispatch path (deadlines,
//! capacity, rate limit, audit row) as every other command. It never invents a reading and
//! never turns a refusal into a success.

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use common::control;
use futures_util::StreamExt;
use phoneconnect_server::store::DeviceStore;
use serde_json::{Value, json};

async fn control_request(
    app: &TestApp,
    device_id: &str,
    user_id: &str,
    operation: &str,
    body: Value,
) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/devices/{device_id}/control/{operation}?user_id={user_id}"),
        Some(common::ADMIN_TOKEN),
        Some(body),
    )
    .await
}

async fn dispatch(app: &TestApp, device_id: &str, operation: &str, body: Value) -> String {
    let (status, accepted) = control_request(app, device_id, "user-a", operation, body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    accepted["command_id"]
        .as_str()
        .expect("command_id")
        .to_owned()
}

#[tokio::test]
async fn a_get_is_forwarded_with_no_arguments_and_its_readings_pass_through() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let command_id = dispatch(&app, &device_id, "get", json!({})).await;

    let frame = control::next_json(&mut socket).await;
    assert_eq!(frame["type"], "command");
    assert_eq!(frame["name"], "control.get");
    assert_eq!(frame["request_id"], command_id);
    assert_eq!(
        frame["args"],
        json!({}),
        "a caller cannot smuggle an argument to the device for this command"
    );

    // Nothing is invented while the device has not answered.
    let (status, record) = app.command(&command_id, "user-a").await;
    assert_eq!(status, StatusCode::OK, "{record}");
    assert_eq!(record["status"], "pending");

    control::send(
        &mut socket,
        control::result(
            &command_id,
            "ok",
            json!({
                "brightness": 102,
                "brightness_mode": 1,
                "volume_music": 7,
                "volume_max": 15,
                "rotation": null,
                "dnd_filter": 2,
                "night_mode": 1,
                "wifi_enabled": true,
                "bluetooth_enabled": null,
                "mobile_data_enabled": true,
                "battery_saver": false,
                "battery_percent": 88,
                "unavailable": {
                    "rotation": "rotation_requires_system_ui",
                    "bluetooth_enabled": "no_bluetooth_adapter",
                    "brightness": "write_settings_required"
                }
            }),
        ),
    )
    .await;

    let record = wait_for_completion(&app, &command_id).await;
    assert_eq!(record["status"], "ok");
    assert_eq!(record["output"]["brightness"], 102);
    assert_eq!(record["output"]["volume_max"], 15);
    assert_eq!(
        record["output"]["rotation"],
        Value::Null,
        "an unreadable value stays null, never a fabricated zero"
    );
    assert_eq!(
        record["output"]["unavailable"]["rotation"],
        "rotation_requires_system_ui"
    );
    assert_eq!(
        record["output"]["unavailable"]["brightness"],
        "write_settings_required"
    );

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_set_forwards_the_key_and_value_and_keeps_the_devices_refusal() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let command_id = dispatch(
        &app,
        &device_id,
        "set",
        json!({ "key": "brightness", "value": 120 }),
    )
    .await;

    let frame = control::next_json(&mut socket).await;
    assert_eq!(frame["name"], "control.set");
    assert_eq!(
        frame["args"],
        json!({ "key": "brightness", "value": 120 }),
        "the server forwards the key and value verbatim; the device owns the ranges"
    );

    control::send(
        &mut socket,
        control::error_result(&command_id, "not_permitted", "write_settings_required"),
    )
    .await;

    let record = wait_for_completion(&app, &command_id).await;
    assert_eq!(record["status"], "error");
    assert_eq!(record["error"], "not_permitted");
    assert_eq!(
        record["message"], "write_settings_required",
        "the machine reason must survive the server"
    );
    assert_eq!(record["output"], Value::Null);

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_boolean_value_for_a_radio_is_forwarded_for_the_devices_refusal() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let command_id = dispatch(
        &app,
        &device_id,
        "set",
        json!({ "key": "wifi", "value": false }),
    )
    .await;

    let frame = control::next_json(&mut socket).await;
    assert_eq!(frame["args"], json!({ "key": "wifi", "value": false }));

    control::send(
        &mut socket,
        control::error_result(&command_id, "not_permitted", "wifi_setter_removed"),
    )
    .await;

    let record = wait_for_completion(&app, &command_id).await;
    assert_eq!(record["error"], "not_permitted");
    assert_eq!(record["message"], "wifi_setter_removed");

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_reboot_is_forwarded_and_the_devices_constant_refusal_passes_through() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let command_id = dispatch(&app, &device_id, "reboot", json!({})).await;

    let frame = control::next_json(&mut socket).await;
    assert_eq!(frame["name"], "control.reboot");
    assert_eq!(frame["args"], json!({}));

    control::send(
        &mut socket,
        control::error_result(&command_id, "not_permitted", "reboot_requires_privilege"),
    )
    .await;

    let record = wait_for_completion(&app, &command_id).await;
    assert_eq!(record["status"], "error");
    assert_eq!(record["error"], "not_permitted");
    assert_eq!(record["message"], "reboot_requires_privilege");

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_control_request_requires_control_and_a_well_formed_body() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    // A viewer never dispatches anything.
    let (status, body) = control_request(&app, &device_id, "user-b", "get", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "lease_read_only");

    // The admin token is required too.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/control/get?user_id=user-a"),
            None,
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "missing_credentials");

    // A non-object body is refused before it becomes a command.
    let (status, body) = control_request(
        &app,
        &device_id,
        "user-a",
        "get",
        json!(["not", "an", "object"]),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");

    // `set` needs a key and a value of a type the device can use.
    for body in [
        json!({}),
        json!({ "value": 1 }),
        json!({ "key": 7, "value": 1 }),
        json!({ "key": "   ", "value": 1 }),
        json!({ "key": "brightness" }),
        json!({ "key": "brightness", "value": "bright" }),
        json!({ "key": "brightness", "value": 1.5 }),
        json!({ "key": "brightness", "value": null }),
    ] {
        let (status, answer) = control_request(&app, &device_id, "user-a", "set", body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
        assert_eq!(answer["error"], "invalid_request", "{answer}");
    }

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), socket.next())
            .await
            .is_err(),
        "a refused control request must never reach the device"
    );

    server.abort();
}

#[tokio::test]
async fn a_control_request_to_an_offline_device_is_device_offline_and_audited() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("user-a").await;

    let (status, body) = control_request(&app, &device_id, "user-a", "get", json!({})).await;

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
