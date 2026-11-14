//! Management channel contract: authenticated device only, one connection per device,
//! bounded telemetry, and explicit close reasons.

mod common;

use common::TestApp;
use common::control;
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
