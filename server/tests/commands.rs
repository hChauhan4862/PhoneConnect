//! Command API contract: authorization, explicit outcome, deadlines, bounded results, and
//! the durable audit trace.

mod common;

use std::time::Duration;

use axum::http::{Method, StatusCode};
use common::TestApp;
use common::control;
use futures_util::StreamExt;
use phoneconnect_server::management::{
    DEFAULT_COMMAND_TIMEOUT_MS, MAX_IN_FLIGHT_PER_DEVICE, MAX_RETAINED_ANSWER_BYTES,
};
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
    assert_eq!(
        request["expires_at_ms"],
        json!(app.now() + DEFAULT_COMMAND_TIMEOUT_MS),
        "the device needs the server's absolute deadline, not only a duration"
    );

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
async fn retained_results_are_bounded_by_bytes_as_well_as_count() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    // A `files.read` chunk is ~350 KiB of base64, so a count-only cap would let a few thousand
    // records retain gigabytes. Each answer here is a full mebibyte.
    let payload = "x".repeat(1024 * 1024);
    let turns = MAX_RETAINED_ANSWER_BYTES / payload.len() + 8;
    let mut ids = Vec::new();
    for _ in 0..turns {
        // Pace command creation: this test is about retained bytes, not the creation rate.
        app.clock.advance_ms(120);
        let (status, body) = app
            .dispatch_command(&device_id, "user-a", info_command())
            .await;
        assert_eq!(status, StatusCode::ACCEPTED, "{body}");
        let command_id = body["command_id"].as_str().expect("command_id").to_owned();
        let request = control::next_json(&mut socket).await;
        assert_eq!(request["request_id"], command_id);
        control::send(
            &mut socket,
            control::result(&command_id, "ok", json!({ "chunk": payload })),
        )
        .await;
        ids.push(command_id);
    }

    // The newest answer is intact: the budget trims the oldest, never the answer being read.
    // Frames are applied in order on one socket, so waiting for the last answer also means
    // every earlier one was applied (and the trimming has run).
    let newest = wait_for_completion(&app, ids.last().expect("commands"), "user-a").await;
    assert_eq!(newest["status"], "ok");
    assert_eq!(
        newest["output"]["chunk"].as_str().map(str::len),
        Some(payload.len())
    );

    // An old answer is gone exactly as if it were past the count cap: `command_unknown`.
    let (status, body) = app.command(&ids[0], "user-a").await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], "command_unknown");

    // And what is still resident fits the budget instead of growing with the count.
    let mut retained = 0usize;
    let mut live = 0usize;
    for command_id in &ids {
        let (status, record) = app.command(command_id, "user-a").await;
        if status == StatusCode::OK {
            live += 1;
            retained += serde_json::to_vec(&record["output"]).expect("json").len();
        }
    }
    assert!(live > 0, "the newest answers are retained");
    assert!(
        live < ids.len(),
        "old answers were trimmed: {live} of {}",
        ids.len()
    );
    assert!(
        retained <= MAX_RETAINED_ANSWER_BYTES,
        "{retained} bytes retained, budget {MAX_RETAINED_ANSWER_BYTES}"
    );

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_large_message_cannot_bypass_the_retained_budget() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    // A frame may carry up to MAX_RESULT_BYTES + 64 KiB, so `message` and `error` are as able
    // to grow the table as `output`. Both are stored bounded, and the retained answer as a
    // whole is charged.
    let prose = "m".repeat(2 * 1024 * 1024);
    // One frame may not exceed MAX_RESULT_BYTES + 64 KiB, so the error result splits its bulk
    // between the code and the message.
    let code = format!("{}tail", "e".repeat(1024 * 1024));
    let error_prose = "n".repeat(1024 * 1024);

    app.clock.advance_ms(120);
    let (status, accepted) = app
        .dispatch_command(&device_id, "user-a", info_command())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    let ok_id = accepted["command_id"]
        .as_str()
        .expect("command_id")
        .to_owned();
    control::next_json(&mut socket).await;
    control::send(
        &mut socket,
        json!({
            "type": "result", "request_id": ok_id, "status": "ok",
            "output": null, "error": null, "message": prose,
        }),
    )
    .await;

    app.clock.advance_ms(120);
    let (status, accepted) = app
        .dispatch_command(&device_id, "user-a", info_command())
        .await;
    assert_eq!(status, StatusCode::ACCEPTED, "{accepted}");
    let error_id = accepted["command_id"]
        .as_str()
        .expect("command_id")
        .to_owned();
    control::next_json(&mut socket).await;
    control::send(
        &mut socket,
        json!({
            "type": "result", "request_id": error_id, "status": "error",
            "output": null, "error": code, "message": error_prose,
        }),
    )
    .await;

    let ok = wait_for_completion(&app, &ok_id, "user-a").await;
    assert_eq!(ok["status"], "ok", "{ok}");
    let stored = ok["message"].as_str().expect("message");
    assert!(
        stored.len() <= 4_096,
        "a 2 MiB message must not be retained whole: {} bytes",
        stored.len()
    );
    assert!(
        stored.starts_with("mmm"),
        "the beginning of the device's text stays useful: {stored}"
    );

    let failure = wait_for_completion(&app, &error_id, "user-a").await;
    assert_eq!(failure["status"], "error", "{failure}");
    let stored_code = failure["error"].as_str().expect("error");
    assert!(stored_code.len() <= 4_096, "{} bytes", stored_code.len());
    assert!(
        stored_code.starts_with("eee"),
        "the code keeps its beginning: {stored_code}"
    );
    assert!(
        failure["message"].as_str().expect("message").len() <= 4_096,
        "the message is bounded too"
    );

    // What is resident is charged as a whole answer, so it cannot exceed the budget.
    let mut retained = 0usize;
    for command_id in [&ok_id, &error_id] {
        let (status, record) = app.command(command_id, "user-a").await;
        assert_eq!(status, StatusCode::OK, "{record}");
        retained += serde_json::to_vec(&record["output"]).expect("json").len();
        retained += record["message"].as_str().map(str::len).unwrap_or(0);
        retained += record["error"].as_str().map(str::len).unwrap_or(0);
    }
    assert!(
        retained <= MAX_RETAINED_ANSWER_BYTES,
        "{retained} bytes retained, budget {MAX_RETAINED_ANSWER_BYTES}"
    );

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn in_flight_commands_per_device_are_capped() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (_socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    for index in 0..MAX_IN_FLIGHT_PER_DEVICE {
        // Pace the dispatches: this test is about the in-flight cap, not the creation rate.
        app.clock.advance_ms(100);
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
async fn a_lease_holder_may_command_until_the_lease_is_revoked() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    // The owner hands control to user-b; user-b is now the actor who may command.
    let (status, handoff) = app.handoff_lease(&device_id, "user-a", "user-b", 600).await;
    assert_eq!(status, StatusCode::OK, "{handoff}");
    let lease_id = handoff["lease"]["lease_id"]
        .as_str()
        .expect("lease_id")
        .to_owned();

    let (status, body) = app.dispatch_command(&device_id, "user-b", info_command()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "{body}");
    let request = control::next_json(&mut socket).await;
    assert_eq!(request["name"], "device.info");

    // Revocation ends the holder's authorization immediately.
    let (status, body) = app.revoke_lease(&lease_id, "user-a").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = app.dispatch_command(&device_id, "user-b", info_command()).await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], "lease_read_only");

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn command_creation_is_throttled_per_device() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    // The bucket starts full and the server clock does not advance, so it must empty.
    let mut accepted = 0;
    loop {
        let (status, _body, _headers) = app
            .request_with_headers(
                Method::POST,
                &format!("/api/devices/{device_id}/commands?user_id=user-a"),
                Some(common::ADMIN_TOKEN),
                Some(info_command()),
            )
            .await;
        if status != StatusCode::ACCEPTED {
            break;
        }
        accepted += 1;
        assert!(accepted <= 128, "the throttle never fired");
    }
    assert!(
        (1..MAX_IN_FLIGHT_PER_DEVICE).contains(&accepted),
        "the throttle must fire before the in-flight cap, got {accepted}"
    );

    let (status, headers, body) = app
        .request_with_headers(
            Method::POST,
            &format!("/api/devices/{device_id}/commands?user_id=user-a"),
            Some(common::ADMIN_TOKEN),
            Some(info_command()),
        )
        .await;
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], "rate_limited");
    let retry_after = headers
        .get("retry-after")
        .expect("a throttled command says when to retry")
        .to_str()
        .expect("ascii")
        .parse::<u64>()
        .expect("seconds");
    assert!((1..=60).contains(&retry_after), "{retry_after}");

    // A throttled attempt is still a traceable attempt.
    let rows = app
        .store
        .list_audit(Some(&device_id), 10)
        .await
        .expect("audit rows readable");
    assert_eq!(rows[0].outcome, "refused");
    assert_eq!(rows[0].error.as_deref(), Some("rate_limited"));

    // The bucket refills with time, so the device is usable again.
    app.clock.advance_ms(1_000);
    let (status, body) = app.dispatch_command(&device_id, "user-a", info_command()).await;
    assert_eq!(status, StatusCode::ACCEPTED, "a refilled bucket accepts again: {body}");

    socket.close(None).await.expect("channel closed");
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
