//! The file routes: they forward `files.*` commands to the device with the same authorization
//! and audit as any other command, and refuse an oversized write themselves.

mod common;

use axum::http::{Method, StatusCode};
use base64::Engine as _;
use base64::engine::general_purpose::STANDARD;
use common::TestApp;
use common::control;
use futures_util::StreamExt;
use phoneconnect_server::store::DeviceStore;
use serde_json::{Value, json};

const ONE_MEBIBYTE: usize = 1024 * 1024;

async fn files(
    app: &TestApp,
    device_id: &str,
    user_id: &str,
    operation: &str,
    body: Value,
) -> (StatusCode, Value) {
    app.request(
        Method::POST,
        &format!("/api/devices/{device_id}/files/{operation}?user_id={user_id}"),
        Some(common::ADMIN_TOKEN),
        Some(body),
    )
    .await
}

async fn dispatch(app: &TestApp, device_id: &str, operation: &str, body: Value) -> String {
    let (status, accepted) = files(app, device_id, "user-a", operation, body).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    accepted["command_id"]
        .as_str()
        .expect("command_id")
        .to_owned()
}

#[tokio::test]
async fn each_file_operation_is_forwarded_with_its_own_command_name() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let cases = [
        (
            "list",
            json!({ "path": "photos" }),
            "files.list",
            json!({ "path": "photos" }),
        ),
        (
            "read",
            json!({ "path": "photos/a.jpg", "offset": 10, "length": 20 }),
            "files.read",
            json!({ "path": "photos/a.jpg", "offset": 10, "length": 20 }),
        ),
        (
            "write",
            json!({ "path": "notes.txt", "data_base64": "aGVsbG8=", "append": true }),
            "files.write",
            json!({ "path": "notes.txt", "data_base64": "aGVsbG8=", "append": true }),
        ),
        (
            "mkdir",
            json!({ "path": "new" }),
            "files.mkdir",
            json!({ "path": "new" }),
        ),
        (
            "delete",
            json!({ "path": "gone.txt" }),
            "files.delete",
            json!({ "path": "gone.txt" }),
        ),
        (
            "rename",
            json!({ "from": "a.txt", "to": "b.txt" }),
            "files.rename",
            json!({ "from": "a.txt", "to": "b.txt" }),
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
async fn the_devices_answer_is_the_only_answer() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let command_id = dispatch(&app, &device_id, "list", json!({ "path": "" })).await;
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
            json!({ "entries": [{ "name": "a.txt", "path": "a.txt", "is_dir": false, "size_bytes": 5, "modified_ms": 1 }] }),
        ),
    )
    .await;

    let record = wait_for_completion(&app, &command_id).await;
    assert_eq!(record["status"], "ok");
    assert_eq!(record["output"]["entries"][0]["name"], "a.txt");
    assert_eq!(record["error"], json!(null));

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_device_refusal_keeps_the_devices_machine_code() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let command_id = dispatch(&app, &device_id, "delete", json!({ "path": "full" })).await;
    control::next_json(&mut socket).await;
    control::send(
        &mut socket,
        control::error_result(&command_id, "dir_not_empty", "\"full\" is not empty"),
    )
    .await;

    let record = wait_for_completion(&app, &command_id).await;
    assert_eq!(record["status"], "error");
    assert_eq!(record["error"], "dir_not_empty");
    assert_eq!(record["output"], json!(null));

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_write_over_one_mebibyte_is_refused_before_it_reaches_the_device() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let oversized = STANDARD.encode(vec![b'x'; ONE_MEBIBYTE + 1]);
    let (status, body) = files(
        &app,
        &device_id,
        "user-a",
        "write",
        json!({ "path": "huge.bin", "data_base64": oversized }),
    )
    .await;

    assert_eq!(status, StatusCode::PAYLOAD_TOO_LARGE, "{body}");
    assert_eq!(body["error"], "too_large");
    assert!(
        tokio::time::timeout(std::time::Duration::from_millis(150), socket.next())
            .await
            .is_err(),
        "a refused write must never reach the device"
    );

    let rows = app
        .store
        .list_audit(Some(&device_id), 10)
        .await
        .expect("audit rows");
    assert_eq!(rows[0].outcome, "refused");
    assert_eq!(rows[0].error.as_deref(), Some("too_large"));

    server.abort();
}

#[tokio::test]
async fn a_write_at_the_limit_is_forwarded_and_never_echoed_back() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let encoded = STANDARD.encode(vec![b'x'; ONE_MEBIBYTE]);
    let command_id = dispatch(
        &app,
        &device_id,
        "write",
        json!({ "path": "big.bin", "data_base64": encoded }),
    )
    .await;
    let frame = control::next_json(&mut socket).await;
    assert_eq!(frame["name"], "files.write");
    assert_eq!(frame["args"]["data_base64"], json!(encoded));

    control::send(
        &mut socket,
        control::result(&command_id, "ok", json!({ "bytes_written": ONE_MEBIBYTE })),
    )
    .await;

    // The record carries the device's count, never the content the caller sent.
    let record = wait_for_completion(&app, &command_id).await;
    assert_eq!(record["output"], json!({ "bytes_written": ONE_MEBIBYTE }));
    assert!(
        !record.to_string().contains("data_base64"),
        "the server must not store file content: {record}"
    );

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn invalid_base64_is_refused() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("user-a").await;

    let (status, body) = files(
        &app,
        &device_id,
        "user-a",
        "write",
        json!({ "path": "x.bin", "data_base64": "not base64!" }),
    )
    .await;

    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_base64");
}

#[tokio::test]
async fn a_file_request_without_a_path_or_with_an_absurd_one_is_refused() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("user-a").await;

    let (status, body) = files(&app, &device_id, "user-a", "list", json!({})).await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");

    let (status, body) = files(
        &app,
        &device_id,
        "user-a",
        "list",
        json!({ "path": "x".repeat(4_097) }),
    )
    .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn files_require_control_of_the_device() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let (status, body) = files(&app, &device_id, "user-b", "list", json!({ "path": "" })).await;
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
            &format!("/api/devices/{device_id}/files/list?user_id=user-a"),
            None,
            Some(json!({ "path": "" })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "missing_credentials");

    server.abort();
}

#[tokio::test]
async fn files_to_an_offline_device_are_device_offline() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("user-a").await;

    let (status, body) = files(
        &app,
        &device_id,
        "user-a",
        "read",
        json!({ "path": "a.txt" }),
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
