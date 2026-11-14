//! Management channel contract: authenticated device only, one connection per device,
//! bounded telemetry, and explicit close reasons.

mod common;

use common::TestApp;
use common::control;
use phoneconnect_server::management;
use phoneconnect_server::store::DeviceStore;
use serde_json::json;

#[tokio::test]
async fn control_channel_rejects_a_bad_device_credential() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (base, server) = control::serve(&app).await;

    let (status, body) = control::reject(&base, &device_id, "pcdev_not_a_real_credential").await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "invalid_credential");

    // The route is upgrade-only; a valid credential on a plain GET is refused as a
    // transport request rather than being read as a bad credential.
    let (status, body) = control::plain_get(&app, &device_id, &credential).await;
    assert_eq!(status, axum::http::StatusCode::BAD_REQUEST, "{body}");
    assert!(body.contains("upgrade"), "{body}");

    server.abort();
}

#[tokio::test]
async fn control_channel_refuses_a_credential_for_another_device() {
    let app = TestApp::new();
    let (device_a, _credential_a) = app.enroll_new("user-a").await;
    let (_device_b, credential_b) = app.enroll_new("user-b").await;
    let (base, server) = control::serve(&app).await;

    let (status, body) = control::reject(&base, &device_a, &credential_b).await;
    assert_eq!(status, 403, "{body}");
    assert_eq!(body["error"], "device_scope_mismatch");

    server.abort();
}

#[tokio::test]
async fn a_revoked_device_cannot_open_a_control_channel() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (status, body) = app
        .revoke("devices", &device_id, Some(common::ADMIN_TOKEN))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");

    let (base, server) = control::serve(&app).await;
    let (status, body) = control::reject(&base, &device_id, &credential).await;
    assert_eq!(status, 401, "{body}");
    assert_eq!(body["error"], "device_revoked");

    server.abort();
}

#[tokio::test]
async fn hello_records_the_device_description() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    control::send(
        &mut socket,
        json!({
            "type": "hello",
            "model": "Pixel 8",
            "android_version": "15",
            "sdk": 35
        }),
    )
    .await;
    let hello = wait_for_hello(&app, &device_id).await;
    assert_eq!(hello.model, "Pixel 8");
    assert_eq!(hello.android_version, "15");
    assert_eq!(hello.sdk, 35);

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn telemetry_frames_are_aggregated_for_the_status_surface() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    control::send(
        &mut socket,
        json!({
            "type": "telemetry",
            "sample": {
                "sampled_at_ms": app.now(),
                "cpu_percent": 21.5,
                "memory_used_bytes": 2_097_152,
                "memory_total_bytes": 8_388_608,
                "battery_percent": 55,
                "battery_charging": true,
                "connectivity": "wifi"
            }
        }),
    )
    .await;

    let aggregate = wait_for_telemetry(&app, &device_id).await;
    assert_eq!(aggregate["latest"]["battery_percent"], 55);
    assert_eq!(aggregate["latest"]["connectivity"], "wifi");
    assert_eq!(aggregate["samples_received"], 1);

    let (status, body) = app.device_status(&device_id, "user-a").await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["telemetry"]["freshness"], "fresh");
    assert_eq!(body["telemetry"]["latest"]["battery_percent"], 55);

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_new_connection_replaces_the_old_one_and_fails_its_pending_command() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut first, base, server) = control::connect_ok(&app, &device_id, &credential).await;

    // A command accepted while the first connection is live is never answered.
    let (status, body) = app
        .dispatch_command(
            &device_id,
            "user-a",
            json!({ "name": "device.ping", "args": null, "timeout_ms": null }),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    let command_id = body["command_id"].as_str().expect("command_id").to_owned();
    let outbound = control::next_json(&mut first).await;
    assert_eq!(outbound["type"], "command");
    assert_eq!(
        outbound["expires_at_ms"],
        json!(app.now() + 10_000),
        "the frame carries the server's absolute deadline, not only a duration"
    );

    // One connection per device: the second attach closes the first explicitly.
    let mut second = control::connect(&base, &device_id, &credential)
        .await
        .expect("a replacement connection is accepted");
    let (code, reason) = control::next_close(&mut first).await;
    assert_eq!(code, 1008, "a policy close, not a generic drop");
    assert_eq!(reason, "replaced");

    // The replaced connection's in-flight command completes as offline, never stays pending.
    let (status, body) = app.command(&command_id, "user-a").await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "error");
    assert_eq!(body["error"], "device_offline");
    assert!(body["completed_at_ms"].is_i64(), "{body}");

    // The replacement is the connection that receives new commands.
    let (status, body) = app
        .dispatch_command(
            &device_id,
            "user-a",
            json!({ "name": "device.info", "args": null, "timeout_ms": null }),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    let request = control::next_json(&mut second).await;
    assert_eq!(request["type"], "command");
    assert_eq!(request["name"], "device.info");

    second.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_telemetry_flood_closes_the_channel_as_rate_limited() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    // The server clock does not advance, so nothing refills: the frame budget must run out.
    let mut sent = 0usize;
    while sent < 1_000 {
        let frame = json!({
            "type": "telemetry",
            "sample": { "sampled_at_ms": app.now(), "battery_percent": 50 }
        });
        if !control::try_send(&mut socket, frame).await {
            break;
        }
        sent += 1;
    }

    let (code, reason) = control::next_close(&mut socket).await;
    assert_eq!(code, 1008);
    assert_eq!(reason, "rate_limited");
    control::wait_offline(&app, &device_id).await;

    server.abort();
}

#[tokio::test]
async fn a_normal_telemetry_cadence_is_not_rate_limited() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    // The agent's cadence is one sample every 30 s; the limiter must not mistake it for a flood.
    for _ in 0..4 {
        app.clock.advance_ms(30_000);
        control::send(
            &mut socket,
            json!({
                "type": "telemetry",
                "sample": { "sampled_at_ms": app.now(), "battery_percent": 55 }
            }),
        )
        .await;
    }
    let mut received = 0;
    for _ in 0..200 {
        if let Some(aggregate) = app.state.telemetry.aggregate(&device_id) {
            received = aggregate.samples_received;
            if received == 4 {
                break;
            }
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(received, 4, "every sample in a normal cadence is ingested");
    assert!(
        app.state.management.is_online(&device_id),
        "a normal cadence must leave the channel open"
    );

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_failed_upgrade_does_not_displace_the_live_channel() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    // A second upgrade that fails after the handler answered must not evict the healthy
    // connection: the registration is only made once a socket actually exists.
    let status = control::failed_upgrade(&app, &device_id, &credential).await;
    assert_eq!(
        status,
        axum::http::StatusCode::SWITCHING_PROTOCOLS,
        "the handler answered the upgrade; only the upgrade itself failed"
    );
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;

    let (status, body) = app
        .dispatch_command(
            &device_id,
            "user-a",
            json!({ "name": "device.ping", "args": null, "timeout_ms": null }),
        )
        .await;
    assert_eq!(
        status,
        axum::http::StatusCode::ACCEPTED,
        "the device must still be online after a failed upgrade: {body}"
    );
    let request = control::next_json(&mut socket).await;
    assert_eq!(
        request["type"], "command",
        "the healthy channel still receives commands, got {request}"
    );

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_full_flush_of_results_keeps_the_channel_open() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    // The worst legitimate case: every in-flight command is answered in one burst. The frame
    // budget must be at least the in-flight cap, or the device is cut off mid-flush and the
    // commands it did execute are reported as offline.
    assert!(
        management::limits::BYTE_BURST
            >= (management::MAX_RESULT_BYTES * management::MAX_IN_FLIGHT_PER_DEVICE) as f64,
        "the byte burst must cover a full-size result for every in-flight command"
    );
    let mut command_ids = Vec::new();
    for index in 0..phoneconnect_server::management::MAX_IN_FLIGHT_PER_DEVICE {
        // Pace the dispatches past the creation throttle; the clock does not advance while
        // the device answers, so the result burst is exactly one burst.
        app.clock.advance_ms(100);
        let (status, body) = app
            .dispatch_command(
                &device_id,
                "user-a",
                json!({ "name": "device.ping", "args": { "index": index }, "timeout_ms": 60_000 }),
            )
            .await;
        assert_eq!(
            status,
            axum::http::StatusCode::ACCEPTED,
            "command {index}: {body}"
        );
        command_ids.push(body["command_id"].as_str().expect("command_id").to_owned());
    }
    for _ in 0..command_ids.len() {
        let frame = control::next_json(&mut socket).await;
        assert_eq!(frame["type"], "command");
    }

    for command_id in &command_ids {
        control::send(
            &mut socket,
            control::result(command_id, "ok", json!({ "pong": true })),
        )
        .await;
    }

    for command_id in &command_ids {
        let body = wait_for_completion(&app, command_id, "user-a").await;
        assert_eq!(
            body["status"], "ok",
            "every executed command keeps its result: {body}"
        );
    }
    assert!(
        app.state.management.is_online(&device_id),
        "a device that answers everything it owes must stay connected"
    );

    socket.close(None).await.expect("channel closed");
    server.abort();
}

#[tokio::test]
async fn a_closed_channel_fails_pending_commands_as_device_offline() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    let (status, body) = app
        .dispatch_command(
            &device_id,
            "user-a",
            json!({ "name": "device.info", "args": null, "timeout_ms": null }),
        )
        .await;
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    let command_id = body["command_id"].as_str().expect("command_id").to_owned();
    control::next_json(&mut socket).await;

    socket.close(None).await.expect("channel closed");
    control::wait_offline(&app, &device_id).await;

    let (status, body) = app.command(&command_id, "user-a").await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["status"], "error");
    assert_eq!(body["error"], "device_offline");

    // The channel ending is a terminal state without a device answer, so it appends the outcome
    // row the dispatch row needs to be readable as "accepted and never answered".
    let mut rows = Vec::new();
    for _ in 0..200 {
        rows = app
            .store
            .list_audit(Some(&device_id), 10)
            .await
            .expect("audit rows readable");
        if rows.len() >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(rows.len(), 2, "dispatch plus outcome: {rows:?}");
    let outcome = rows
        .iter()
        .find(|row| row.action == "command.outcome")
        .expect("a channel that ended mid-command records its outcome");
    assert_eq!(outcome.outcome, "device_offline");
    assert_eq!(outcome.actor, "user-a");
    assert_eq!(outcome.device_id, device_id);

    server.abort();
}

#[tokio::test]
async fn a_malformed_frame_closes_the_channel_with_a_reason() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    control::send_text(&mut socket, "this is not JSON").await;

    let (code, reason) = control::next_close(&mut socket).await;
    assert_eq!(code, 1008);
    assert_eq!(reason, "malformed_frame");
    control::wait_offline(&app, &device_id).await;

    server.abort();
}

#[tokio::test]
async fn revoking_a_device_closes_its_channel_and_stops_telemetry() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let (mut socket, _base, server) = control::connect_ok(&app, &device_id, &credential).await;

    control::send(
        &mut socket,
        json!({
            "type": "telemetry",
            "sample": { "sampled_at_ms": app.now(), "battery_percent": 55 }
        }),
    )
    .await;
    let aggregate = wait_for_telemetry(&app, &device_id).await;
    assert_eq!(aggregate["samples_received"], 1);

    let (status, body) = app
        .revoke("devices", &device_id, Some(common::ADMIN_TOKEN))
        .await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");

    // The credential is revoked, so its channel cannot stay open: the device is told why and
    // the registration is gone before the request returns.
    let (code, reason) = control::next_close(&mut socket).await;
    assert_eq!(code, 1008);
    assert_eq!(reason, "device_revoked");
    assert!(
        !app.state.management.is_online(&device_id),
        "a revoked device is not online"
    );

    // A frame the device sent before it read the close is dropped, not ingested.
    let _ = control::try_send(
        &mut socket,
        json!({
            "type": "telemetry",
            "sample": { "sampled_at_ms": app.now(), "battery_percent": 99 }
        }),
    )
    .await;
    tokio::time::sleep(std::time::Duration::from_millis(50)).await;
    assert_eq!(
        app.state
            .telemetry
            .aggregate(&device_id)
            .expect("the earlier sample is still shown")
            .samples_received,
        1,
        "no telemetry is ingested after revocation"
    );

    // Status stops claiming freshness once the last accepted sample ages out: nothing new
    // arrives to refresh it.
    app.clock
        .advance_ms(phoneconnect_server::telemetry::STALE_AFTER_MS + 1);
    let (status, body) = app.device_status(&device_id, "user-a").await;
    assert_eq!(status, axum::http::StatusCode::OK, "{body}");
    assert_eq!(body["device"]["state"], "revoked");
    assert_eq!(
        body["telemetry"]["freshness"], "stale",
        "a revoked device cannot keep its telemetry fresh: {body}"
    );

    server.abort();
}

#[tokio::test]
async fn a_deadline_that_passed_before_the_channel_closed_is_a_timeout() {
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
    assert_eq!(status, axum::http::StatusCode::ACCEPTED, "{body}");
    control::next_json(&mut socket).await;

    // Nothing reads the command table while the deadline passes, so the record is still
    // `pending` when the channel ends. The deadline happened first, and the trace must say so.
    app.clock.advance_ms(600);
    socket.close(None).await.expect("channel closed");
    control::wait_offline(&app, &device_id).await;

    let mut rows = Vec::new();
    for _ in 0..200 {
        rows = app
            .store
            .list_audit(Some(&device_id), 10)
            .await
            .expect("audit rows readable");
        if rows.len() >= 2 {
            break;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    assert_eq!(rows.len(), 2, "dispatch plus outcome: {rows:?}");
    let outcome = rows
        .iter()
        .find(|row| row.action == "command.outcome")
        .expect("the terminal state is traced");
    assert_eq!(
        outcome.outcome, "timeout",
        "a passed deadline is a timeout, not a channel ending: {rows:?}"
    );
    assert!(
        !rows.iter().any(|row| row.outcome == "device_offline"),
        "the channel ended after the deadline, so nothing is device_offline: {rows:?}"
    );

    server.abort();
}

#[tokio::test]
async fn a_channel_that_registers_after_revocation_is_closed_without_being_registered() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;

    // The upgrade's `require_device` passed before revocation committed; `connect` is the last
    // place that can refuse the registration. Calling the registry directly models exactly that
    // interleaving: the credential is still valid, the device is already revoked.
    assert!(
        !app.state.management.revoke(&device_id).await,
        "nothing was open yet"
    );

    let (base, server) = control::serve(&app).await;
    let mut socket = control::connect(&base, &device_id, &credential)
        .await
        .expect("the handshake still authenticates: revocation committed after it");

    let (code, reason) = control::next_close(&mut socket).await;
    assert_eq!(code, 1008);
    assert_eq!(
        reason, "device_revoked",
        "a refused registration tells the device why"
    );
    assert!(
        !app.state.management.is_online(&device_id),
        "a refused registration never becomes online"
    );

    server.abort();
}

async fn wait_for_completion(app: &TestApp, command_id: &str, user_id: &str) -> serde_json::Value {
    for _ in 0..200 {
        let (status, body) = app.command(command_id, user_id).await;
        assert_eq!(status, axum::http::StatusCode::OK, "{body}");
        if body["status"] != "pending" {
            return body;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("command {command_id} never completed");
}

async fn wait_for_hello(
    app: &TestApp,
    device_id: &str,
) -> phoneconnect_server::management::DeviceHello {
    for _ in 0..200 {
        if let Some(hello) = app.state.management.hello(device_id) {
            return hello;
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the hello frame was never recorded");
}

async fn wait_for_telemetry(app: &TestApp, device_id: &str) -> serde_json::Value {
    for _ in 0..200 {
        if let Some(aggregate) = app.state.telemetry.aggregate(device_id) {
            return serde_json::to_value(aggregate).expect("aggregate is JSON");
        }
        tokio::time::sleep(std::time::Duration::from_millis(10)).await;
    }
    panic!("the telemetry frame was never ingested");
}
