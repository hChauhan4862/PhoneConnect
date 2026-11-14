//! Command API contract: authorization, explicit outcome, deadlines, bounded results, and
//! the durable audit trace.

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::TestApp;
use common::control;
use futures_util::StreamExt;
use phoneconnect_server::management::{DEFAULT_COMMAND_TIMEOUT_MS, MAX_IN_FLIGHT_PER_DEVICE};
use phoneconnect_server::store::DeviceStore;
use serde_json::json;

fn info_command() -> serde_json::Value {
    json!({ "name": "device.info", "args": null, "timeout_ms": null })
}

#[tokio::test]
async fn a_command_with_no_lease_is_refused() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    // user-b is neither the owner nor the active lease holder.
    let (status, body) = app
        .dispatch_command(&device_id, "user-b", info_command())
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "lease_read_only");

    // Refused before it reached the device.
    assert!(
        tokio::time::timeout(Duration::from_millis(150), socket.next())
            .await
            .is_err(),
        "a refused command must never reach the device"
    );

    server.abort();
}

#[tokio::test]
async fn the_device_owner_may_command_without_a_lease() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let (status, body) = app
        .dispatch_command(&device_id, "user-a", info_command())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let request = control::next_json(&mut socket).await;
    assert_eq!(request["type"], "command");
    assert_eq!(request["name"], "device.info");

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_command_to_an_offline_device_is_device_offline() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("user-a").await;

    let (status, body) = app
        .dispatch_command(&device_id, "user-a", info_command())
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "device_offline");
}

#[tokio::test]
async fn a_command_to_a_revoked_device_is_device_revoked() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("user-a").await;
    let (status, body) = app
        .revoke("devices", &device_id, Some(common::ADMIN_TOKEN))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = app
        .dispatch_command(&device_id, "user-a", info_command())
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "device_revoked");
}

#[tokio::test]
async fn a_command_requires_the_admin_token() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("user-a").await;

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/commands?user_id=user-a"),
            None,
            Some(info_command()),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "missing_credentials");
}

#[tokio::test]
async fn a_command_without_an_actor_is_refused() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("user-a").await;

    let (status, body) = app
        .dispatch_command_at(
            &format!("/api/devices/{device_id}/commands"),
            info_command(),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn an_invalid_timeout_is_refused() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (_socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    for timeout_ms in [0_i64, 60_001] {
        let (status, body) = app
            .dispatch_command(
                &device_id,
                "user-a",
                json!({ "name": "device.ping", "args": null, "timeout_ms": timeout_ms }),
            )
            .await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_timeout");
    }

    server.abort();
}

#[tokio::test]
async fn a_valid_command_round_trips_device_info() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let (status, body) = app
        .dispatch_command(&device_id, "user-a", info_command())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let command_id = body["command_id"].as_str().expect("command_id").to_owned();
    assert!(command_id.starts_with("cmd_"), "{command_id}");

    let request = control::next_json(&mut socket).await;
    assert_eq!(request["type"], "command");
    assert_eq!(
        request["request_id"].as_str().expect("request_id"),
        command_id
    );
    assert_eq!(request["name"], "device.info");
    assert_eq!(request["args"], json!(null));
    assert_eq!(request["deadline_ms"], DEFAULT_COMMAND_TIMEOUT_MS);

    let (status, body) = app.command(&command_id, "user-a").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "pending");
    assert_eq!(body["completed_at_ms"], json!(null));

    control::send(
        &mut socket,
        control::result(&command_id, "ok", json!({ "model": "Pixel 8", "sdk": 35 })),
    )
    .await;

    let body = wait_for_completion(&app, &command_id, "user-a").await;
    assert_eq!(body["command_id"], command_id);
    assert_eq!(body["device_id"], device_id);
    assert_eq!(body["name"], "device.info");
    assert_eq!(body["status"], "ok");
    assert_eq!(body["output"], json!({ "model": "Pixel 8", "sdk": 35 }));
    assert_eq!(body["error"], json!(null));
    assert_eq!(body["created_at_ms"], app.now());
    assert!(body["completed_at_ms"].is_i64(), "{body}");

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_command_times_out_when_the_device_does_not_answer() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let (status, body) = app
        .dispatch_command(
            &device_id,
            "user-a",
            json!({ "name": "device.ping", "args": null, "timeout_ms": 500 }),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let command_id = body["command_id"].as_str().expect("command_id").to_owned();
    let request = control::next_json(&mut socket).await;
    assert_eq!(request["deadline_ms"], 500);

    app.clock.advance_ms(500);

    let (status, body) = app.command(&command_id, "user-a").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "timeout");
    assert_eq!(body["output"], json!(null));
    assert!(body["completed_at_ms"].is_i64(), "{body}");

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_device_error_result_is_reported_as_error() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let (status, body) = app
        .dispatch_command(&device_id, "user-a", info_command())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let command_id = body["command_id"].as_str().expect("command_id").to_owned();
    control::next_json(&mut socket).await;

    control::send(
        &mut socket,
        control::error_result(&command_id, "not_permitted", "the app cannot read this"),
    )
    .await;

    let body = wait_for_completion(&app, &command_id, "user-a").await;
    assert_eq!(body["status"], "error");
    assert_eq!(body["error"], "not_permitted");
    assert_eq!(body["message"], "the app cannot read this");
    assert_eq!(body["output"], json!(null));

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn an_oversized_result_is_refused_and_bounded() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let (status, body) = app
        .dispatch_command(&device_id, "user-a", info_command())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let command_id = body["command_id"].as_str().expect("command_id").to_owned();
    control::next_json(&mut socket).await;

    let oversized = "x".repeat(2 * 1024 * 1024);
    control::send(
        &mut socket,
        control::result(&command_id, "ok", json!({ "payload": oversized })),
    )
    .await;

    let body = wait_for_completion(&app, &command_id, "user-a").await;
    assert_eq!(body["status"], "error");
    assert_eq!(body["error"], "result_too_large");
    assert_eq!(body["output"], json!(null));

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn the_server_forwards_any_command_name_and_the_device_answers_unknown_command() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    // The command vocabulary belongs to the device: the server routes a name it does not
    // know, and the device's `unknown_command` is the answer the caller sees.
    let (status, body) = app
        .dispatch_command(
            &device_id,
            "user-a",
            json!({ "name": "files.list", "args": { "path": "/" }, "timeout_ms": null }),
        )
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let command_id = body["command_id"].as_str().expect("command_id").to_owned();
    let request = control::next_json(&mut socket).await;
    assert_eq!(request["name"], "files.list");
    assert_eq!(request["args"], json!({ "path": "/" }));

    control::send(
        &mut socket,
        control::error_result(
            &command_id,
            "unknown_command",
            "files.list is not supported",
        ),
    )
    .await;

    let body = wait_for_completion(&app, &command_id, "user-a").await;
    assert_eq!(body["status"], "error");
    assert_eq!(body["error"], "unknown_command");

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn in_flight_commands_per_device_are_capped() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (_socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    for index in 0..MAX_IN_FLIGHT_PER_DEVICE {
        let (status, body) = app
            .dispatch_command(
                &device_id,
                "user-a",
                json!({ "name": "device.ping", "args": { "index": index }, "timeout_ms": null }),
            )
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "command {index}: {body}");
    }
    let (status, body) = app
        .dispatch_command(&device_id, "user-a", info_command())
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], "command_capacity");

    server.abort();
}

#[tokio::test]
async fn an_unknown_command_id_is_not_found() {
    let app = TestApp::new();
    let (status, body) = app.command("cmd_missing", "user-a").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], "command_unknown");
}

#[tokio::test]
async fn reading_a_command_requires_control_of_its_device() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("user-a").await;
    let (status, body) = app
        .dispatch_command(&device_id, "user-a", info_command())
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    // A command id is not a capability: another user cannot read the record.
    let (status, body) = app
        .dispatch_command_at(
            &format!("/api/devices/{device_id}/commands?user_id=user-b"),
            info_command(),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "lease_read_only");

    let (status, body) = app.command("cmd_missing", "user-b").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
}

#[tokio::test]
async fn every_dispatch_attempt_writes_one_audit_row() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;

    // Refused: the device is offline, which is still a traceable attempt.
    let (status, body) = app
        .dispatch_command(&device_id, "user-a", info_command())
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;
    let (status, body) = app
        .dispatch_command(&device_id, "user-a", info_command())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");

    let rows = app
        .store
        .list_audit(Some(&device_id), 10)
        .await
        .expect("audit rows readable");
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].action, "command.dispatch");
    assert_eq!(rows[0].actor, "user-a");
    assert_eq!(rows[0].device_id, device_id);
    assert_eq!(rows[0].outcome, "accepted");
    assert_eq!(rows[0].error, None);
    assert_eq!(rows[1].outcome, "refused");
    assert_eq!(rows[1].error.as_deref(), Some("device_offline"));
    assert!(rows[0].at_ms >= rows[1].at_ms, "newest first");

    socket.close(None).await.expect("channel closed");
    server.abort();
}

async fn wait_for_completion(app: &TestApp, command_id: &str, user_id: &str) -> serde_json::Value {
    for _ in 0..200 {
        let (status, body) = app.command(command_id, user_id).await;
        assert_eq!(status, StatusCode::OK, "{body}");
        if body["status"] != "pending" {
            return body;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("command {command_id} never completed");
}
