//! The console routes: `system.props` (the one console capability an ordinary app has) and
//! the two commands that always refuse.
//!
//! Shell access and logcat are here so a caller gets `not_permitted` with the device's reason
//! rather than `unknown_command`; the server forwards them like any command and never invents
//! output. System properties are forwarded with a structurally valid key list, and the device
//! remains the authority on what its allowlist permits.

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use common::control;
use futures_util::StreamExt;
use phoneconnect_server::store::DeviceStore;
use serde_json::{Value, json};

async fn console(
    app: &TestApp,
    device_id: &str,
    user_id: &str,
    operation: &str,
    body: Value,
) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/devices/{device_id}/console/{operation}?user_id={user_id}"),
        Some(common::ADMIN_TOKEN),
        Some(body),
    )
    .await
}

async fn dispatch(app: &TestApp, device_id: &str, operation: &str, body: Value) -> String {
    let (status, accepted) = console(app, device_id, "user-a", operation, body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    accepted["command_id"]
        .as_str()
        .expect("command_id")
        .to_owned()
}

#[tokio::test]
async fn each_console_operation_is_forwarded_with_its_own_command_name() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let cases = [
        ("props", json!({}), "system.props", json!({})),
        (
            "props",
            json!({ "keys": ["sdk", "security_patch"] }),
            "system.props",
            json!({ "keys": ["sdk", "security_patch"] }),
        ),
        ("shell", json!({}), "shell.exec", json!({})),
        ("logcat", json!({}), "logcat.tail", json!({})),
    ];

    for (operation, body, name, expected_args) in cases {
        let command_id = dispatch(&app, &device_id, operation, body).await;
        let frame = control::next_json(&mut socket).await;
        assert_eq!(frame["type"], "command");
        assert_eq!(frame["name"], name);
        assert_eq!(frame["request_id"], command_id);
        assert_eq!(frame["args"], expected_args);

        // The console has no streaming endpoint: one answer per accepted command.
        let (status, record) = app.command(&command_id, "user-a").await;
        assert_eq!(status, StatusCode::OK, "{record}");
        assert_eq!(record["status"], "pending");
    }

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn system_properties_pass_the_devices_answer_through() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let command_id = dispatch(&app, &device_id, "props", json!({})).await;
    control::next_json(&mut socket).await;

    control::send(
        &mut socket,
        control::result(
            &command_id,
            "ok",
            json!({ "selected": {
                "sdk": "35",
                "release": "15",
                "model": "Pixel 8",
                "manufacturer": "Google",
                "build_id": "AP4A.250105.002",
                "security_patch": "2025-01-05"
            } }),
        ),
    )
    .await;

    let record = wait_for_completion(&app, &command_id).await;
    assert_eq!(record["status"], "ok");
    assert_eq!(record["output"]["selected"]["sdk"], "35");
    assert_eq!(record["output"]["selected"]["security_patch"], "2025-01-05");
    assert_eq!(record["error"], json!(null));

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn the_two_console_refusals_keep_the_devices_code_and_message() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let cases = [
        (
            "shell",
            "an ordinary installed app cannot run a shell: executing commands on the device needs the privileged shell (ADB) or root user, which this app is not",
        ),
        (
            "logcat",
            "an ordinary installed app cannot read the system log: READ_LOGS is a signature-level permission, so only a system or privileged app can read logcat",
        ),
    ];

    for (operation, message) in cases {
        let command_id = dispatch(&app, &device_id, operation, json!({})).await;
        control::next_json(&mut socket).await;
        control::send(
            &mut socket,
            control::error_result(&command_id, "not_permitted", message),
        )
        .await;

        let record = wait_for_completion(&app, &command_id).await;
        assert_eq!(record["status"], "error");
        assert_eq!(record["error"], "not_permitted");
        assert_eq!(record["message"], message);
        assert_eq!(record["output"], json!(null));
    }

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_property_outside_the_allowlist_is_the_devices_not_permitted() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    // The server forwards a name it does not interpret; the device's allowlist refuses it.
    let command_id = dispatch(&app, &device_id, "props", json!({ "keys": ["serialno"] })).await;
    let frame = control::next_json(&mut socket).await;
    assert_eq!(frame["args"], json!({ "keys": ["serialno"] }));

    control::send(
        &mut socket,
        control::error_result(
            &command_id,
            "not_permitted",
            "only the documented system properties may be read: sdk, release, model, manufacturer, build_id, security_patch",
        ),
    )
    .await;

    let record = wait_for_completion(&app, &command_id).await;
    assert_eq!(record["status"], "error");
    assert_eq!(record["error"], "not_permitted");

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_malformed_key_list_never_reaches_the_device() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    for body in [
        json!({ "keys": "sdk" }),
        json!({ "keys": [] }),
        json!({ "keys": [" "] }),
        json!({ "keys": [7] }),
        json!({ "keys": ["sd\u{0}k"] }),
    ] {
        let (status, answer) = console(&app, &device_id, "user-a", "props", body.clone()).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "body {body}: {answer}");
        assert_eq!(answer["error"], "invalid_request");
    }

    let (status, answer) = console(&app, &device_id, "user-a", "shell", json!([1, 2])).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{answer}");
    assert_eq!(answer["error"], "invalid_request");

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), socket.next())
            .await
            .is_err(),
        "a structurally invalid console request must never reach the device"
    );

    server.abort();
}

#[tokio::test]
async fn console_requires_control_of_the_device() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let (status, body) = console(&app, &device_id, "user-b", "props", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "lease_read_only");

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/console/logcat?user_id=user-a"),
            None,
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "missing_credentials");

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), socket.next())
            .await
            .is_err(),
        "a refused console request must never reach the device"
    );

    server.abort();
}

#[tokio::test]
async fn console_to_an_offline_device_is_device_offline_and_audited() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("user-a").await;

    let (status, body) = console(&app, &device_id, "user-a", "shell", json!({})).await;

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
