//! The app routes: they forward `apps.*` commands to the device with the same authorization
//! and audit as any other command, and refuse a request that is not a package name themselves.

mod common;

use axum::http::{Method, StatusCode};
use common::TestApp;
use common::control;
use futures_util::StreamExt;
use phoneconnect_server::store::DeviceStore;
use serde_json::{Value, json};

async fn apps(
    app: &TestApp,
    device_id: &str,
    user_id: &str,
    operation: &str,
    body: Value,
) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/devices/{device_id}/apps/{operation}?user_id={user_id}"),
        Some(common::ADMIN_TOKEN),
        Some(body),
    )
    .await
}

async fn dispatch(app: &TestApp, device_id: &str, operation: &str, body: Value) -> String {
    let (status, accepted) = apps(app, device_id, "user-a", operation, body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    accepted["command_id"]
        .as_str()
        .expect("command_id")
        .to_owned()
}

#[tokio::test]
async fn each_app_operation_is_forwarded_with_its_own_command_name() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let cases = [
        ("list", json!({}), "apps.list", json!({})),
        (
            "launch",
            json!({ "package": "com.example.zeta" }),
            "apps.launch",
            json!({ "package": "com.example.zeta" }),
        ),
        (
            "stop",
            json!({ "package": "com.example.zeta" }),
            "apps.stop",
            json!({ "package": "com.example.zeta" }),
        ),
        (
            "clear",
            json!({ "package": "com.example.zeta" }),
            "apps.clear",
            json!({ "package": "com.example.zeta" }),
        ),
        (
            "set_enabled",
            json!({ "package": "com.example.zeta", "enabled": false }),
            "apps.set_enabled",
            json!({ "package": "com.example.zeta", "enabled": false }),
        ),
    ];

    for (operation, body, name, expected_args) in cases {
        let command_id = dispatch(&app, &device_id, operation, body).await;
        let frame = control::next_json(&mut socket).await;
        assert_eq!(frame["type"], "command");
        assert_eq!(frame["name"], name);
        assert_eq!(frame["request_id"], command_id);
        assert_eq!(
            frame["args"], expected_args,
            "the device receives exactly what the caller asked for"
        );
    }

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn the_devices_listing_is_the_only_listing() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let command_id = dispatch(&app, &device_id, "list", json!({})).await;
    control::next_json(&mut socket).await;

    // Nothing is invented while the device has not answered.
    let (status, record) = app.command(&command_id, "user-a").await;
    assert_eq!(status, StatusCode::OK, "{record}");
    assert_eq!(record["status"], "pending");
    assert_eq!(record["output"], json!(null));

    control::send(
        &mut socket,
        control::result(
            &command_id,
            "ok",
            json!({ "apps": [{
                "package": "com.example.zeta",
                "label": "Zeta",
                "version_name": "1.0",
                "version_code": 1,
                "system": false,
                "enabled": true,
                "updated_ms": 1,
            }] }),
        ),
    )
    .await;

    let record = wait_for_completion(&app, &command_id).await;
    assert_eq!(record["status"], "ok");
    assert_eq!(record["output"]["apps"][0]["package"], "com.example.zeta");
    assert_eq!(record["output"]["apps"][0]["label"], "Zeta");
    assert_eq!(record["error"], json!(null));

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_device_refusal_keeps_the_devices_machine_code() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let refusals = [
        (
            "launch",
            "launch_blocked",
            "background_activity_start_restricted",
        ),
        (
            "clear",
            "not_permitted",
            "clearing app data needs a signature-level permission",
        ),
    ];

    for (operation, code, message) in refusals {
        let command_id = dispatch(
            &app,
            &device_id,
            operation,
            json!({ "package": "com.example.zeta" }),
        )
        .await;
        control::next_json(&mut socket).await;
        control::send(
            &mut socket,
            control::error_result(&command_id, code, message),
        )
        .await;

        let record = wait_for_completion(&app, &command_id).await;
        assert_eq!(record["status"], "error");
        assert_eq!(record["error"], code);
        assert_eq!(record["message"], message);
        assert_eq!(record["output"], json!(null));
    }

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn an_app_request_that_is_not_a_package_name_is_refused_before_dispatch() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let bodies = [
        json!({}),
        json!({ "package": 7 }),
        json!({ "package": "   " }),
        json!({ "package": "x".repeat(256) }),
        json!({ "package": "com.example.zeta", "enabled": "yes" }),
    ];

    for body in bodies {
        let operation = if body.get("enabled").is_some() {
            "set_enabled"
        } else {
            "launch"
        };
        let (status, response) = apps(&app, &device_id, "user-a", operation, body).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{response}");
        assert_eq!(response["error"], "invalid_request");
    }

    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), socket.next())
            .await
            .is_err(),
        "a refused request must never reach the device"
    );

    let rows = app
        .store
        .list_audit(Some(&device_id), 10)
        .await
        .expect("audit rows");
    assert_eq!(rows.len(), 5, "every server-side refusal is audited");
    assert!(rows.iter().all(|row| row.outcome == "refused"));
    assert!(
        rows.iter()
            .all(|row| row.error.as_deref() == Some("invalid_request"))
    );

    server.abort();
}

#[tokio::test]
async fn an_empty_list_body_is_accepted() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let (status, accepted) = apps(
        &app,
        &device_id,
        "user-a",
        "list",
        json!({ "ignored": true }),
    )
    .await;

    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    let frame = control::next_json(&mut socket).await;
    assert_eq!(frame["name"], "apps.list");
    assert_eq!(
        frame["args"],
        json!({}),
        "the device receives exactly the arguments apps.list takes"
    );

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn apps_require_control_of_the_device() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let (status, body) = apps(&app, &device_id, "user-b", "list", json!({})).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "lease_read_only");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), socket.next())
            .await
            .is_err(),
        "a refused request must never reach the device"
    );

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/apps/launch?user_id=user-a"),
            None,
            Some(json!({ "package": "com.example.zeta" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "missing_credentials");

    server.abort();
}

#[tokio::test]
async fn apps_to_an_offline_device_are_device_offline() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("user-a").await;

    let (status, body) = apps(
        &app,
        &device_id,
        "user-a",
        "launch",
        json!({ "package": "com.example.zeta" }),
    )
    .await;

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
