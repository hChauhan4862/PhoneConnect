//! Telemetry aggregation: one bounded window per device, explicit staleness, no raw
//! high-rate persistence, and 30-day retention deletion.

mod common;

use std::sync::Arc;

use axum::http::{Method, StatusCode};
use common::{ADMIN_TOKEN, NOW_MS, TestApp};
use phoneconnect_server::store::{Clock, ManualClock, SystemClock};
use phoneconnect_server::telemetry::{
    MAX_CONNECTIVITY_BYTES, MAX_RECENT_SAMPLES, MAX_TRACKED_DEVICES, RETENTION_MS, STALE_AFTER_MS,
    TelemetryAggregator, TelemetryError, TelemetryFreshness, TelemetrySample,
};
use serde_json::{Value, json};

fn sample(sampled_at_ms: i64, cpu_percent: f64, battery_percent: u8) -> TelemetrySample {
    TelemetrySample {
        sampled_at_ms,
        cpu_percent: Some(cpu_percent),
        memory_used_bytes: Some(1_048_576),
        memory_total_bytes: Some(8_388_608),
        battery_percent: Some(battery_percent),
        battery_charging: Some(true),
        connectivity: Some("wifi".to_owned()),
    }
}

fn aggregator_at(now_ms: i64) -> (TelemetryAggregator, Arc<ManualClock>) {
    let clock = Arc::new(ManualClock::new(now_ms));
    (TelemetryAggregator::new(clock.clone()), clock)
}

#[tokio::test]
async fn a_high_rate_device_keeps_a_bounded_window() {
    let (aggregator, clock) = aggregator_at(NOW_MS);

    for index in 0..1_000 {
        let cpu = index as f64;
        aggregator
            .ingest("dev_a", sample(clock.now_ms() + index, cpu, 50))
            .expect("sample accepted");
    }

    let aggregate = aggregator.aggregate("dev_a").expect("tracked");
    assert_eq!(
        aggregate.window_samples, MAX_RECENT_SAMPLES,
        "only a bounded recent window is retained"
    );
    assert_eq!(aggregate.samples_received, 1_000);
    assert_eq!(
        aggregate.window_cpu_percent.expect("cpu aggregate").latest,
        999.0,
        "the newest sample is the reported latest value"
    );
    assert_eq!(aggregate.latest.battery_percent, Some(50));

    // An invalid sample is refused rather than stored as a plausible reading.
    assert!(matches!(
        aggregator.ingest("dev_a", sample(clock.now_ms(), f64::NAN, 50)),
        Err(TelemetryError::InvalidSample { .. })
    ));
    assert!(matches!(
        aggregator.ingest("", sample(clock.now_ms(), 1.0, 50)),
        Err(TelemetryError::InvalidDevice)
    ));
}

#[tokio::test]
async fn two_hundred_devices_aggregate_independently_and_stay_bounded() {
    let (aggregator, clock) = aggregator_at(NOW_MS);

    for device in 0..MAX_TRACKED_DEVICES {
        for index in 0..50 {
            aggregator
                .ingest(
                    &format!("dev_{device}"),
                    sample(clock.now_ms() + index, device as f64, 80),
                )
                .expect("sample accepted");
        }
    }

    assert_eq!(aggregator.tracked_devices(), MAX_TRACKED_DEVICES);
    for device in [0usize, 99, MAX_TRACKED_DEVICES - 1] {
        let aggregate = aggregator
            .aggregate(&format!("dev_{device}"))
            .unwrap_or_else(|| panic!("device {device} is tracked"));
        assert_eq!(
            aggregate.window_cpu_percent.expect("cpu aggregate").latest,
            device as f64,
            "each device keeps its own aggregate"
        );
        assert_eq!(aggregate.window_samples, MAX_RECENT_SAMPLES);
        assert_eq!(aggregate.samples_received, 50);
    }

    // The 201st device is refused explicitly instead of evicting a tracked device.
    assert_eq!(
        aggregator.ingest("dev_overflow", sample(clock.now_ms(), 1.0, 50)),
        Err(TelemetryError::Capacity {
            limit: MAX_TRACKED_DEVICES
        })
    );
    assert_eq!(aggregator.tracked_devices(), MAX_TRACKED_DEVICES);
}

#[tokio::test]
async fn a_stale_device_is_reported_as_stale_not_fresh() {
    let (aggregator, clock) = aggregator_at(NOW_MS);
    aggregator
        .ingest("dev_a", sample(NOW_MS, 10.0, 50))
        .expect("sample accepted");

    assert_eq!(
        aggregator.freshness("dev_a", clock.now_ms()).state,
        TelemetryFreshness::Fresh
    );
    assert_eq!(
        aggregator.freshness("dev_a", NOW_MS + STALE_AFTER_MS).state,
        TelemetryFreshness::Fresh,
        "a sample exactly at the staleness bound is still fresh"
    );

    let stale = aggregator.freshness("dev_a", NOW_MS + STALE_AFTER_MS + 1);
    assert_eq!(stale.state, TelemetryFreshness::Stale);
    assert_eq!(stale.age_ms, Some(STALE_AFTER_MS + 1));

    let missing = aggregator.freshness("dev_unknown", NOW_MS);
    assert_eq!(missing.state, TelemetryFreshness::Missing);
    assert_eq!(missing.age_ms, None);
}

#[tokio::test]
async fn telemetry_aggregates_are_deleted_after_thirty_days() {
    let (aggregator, clock) = aggregator_at(NOW_MS);
    aggregator
        .ingest("dev_old", sample(NOW_MS, 10.0, 50))
        .expect("sample accepted");
    clock.advance_ms(29 * 24 * 60 * 60 * 1_000);
    aggregator
        .ingest("dev_new", sample(clock.now_ms(), 20.0, 60))
        .expect("sample accepted");

    assert_eq!(
        RETENTION_MS,
        30 * 24 * 60 * 60 * 1_000,
        "the default retention is 30 days"
    );
    let cutoff = clock.now_ms() - RETENTION_MS;
    assert!(
        aggregator.purge_older_than(cutoff).is_empty(),
        "nothing is older than the retention window yet"
    );
    assert_eq!(aggregator.tracked_devices(), 2);

    clock.advance_ms(2 * 24 * 60 * 60 * 1_000);
    let deleted = aggregator.purge_older_than(clock.now_ms() - RETENTION_MS);
    assert_eq!(deleted, vec!["dev_old".to_owned()]);
    assert_eq!(aggregator.tracked_devices(), 1);
    assert_eq!(
        aggregator.freshness("dev_old", clock.now_ms()).state,
        TelemetryFreshness::Missing
    );
    assert_eq!(
        aggregator.freshness("dev_new", clock.now_ms()).state,
        TelemetryFreshness::Stale,
        "the surviving device is still reported, as stale"
    );
}

#[tokio::test]
async fn a_device_reports_telemetry_only_for_itself() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("owner-1").await;
    let (other_device, _other_credential) = app.enroll_new("owner-2").await;

    let (status, body) = app.ingest_telemetry(&device_id, &credential, 64).await;
    assert_eq!(status, StatusCode::OK, "ingest failed: {body}");
    assert_eq!(body["device_id"], Value::from(device_id.clone()));
    assert_eq!(body["latest"]["battery_percent"], Value::from(64));

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{other_device}/telemetry"),
            Some(&credential),
            Some(json!({ "sampled_at_ms": app.now(), "battery_percent": 10 })),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(body["error"], Value::from("device_scope_mismatch"));

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/telemetry"),
            Some(ADMIN_TOKEN),
            Some(json!({ "battery_percent": 10 })),
        )
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], Value::from("invalid_credential"));

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/telemetry"),
            Some(&credential),
            Some(json!({ "sampled_at_ms": app.now(), "battery_percent": 101 })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], Value::from("invalid_sample"));

    assert_eq!(
        app.state
            .telemetry
            .freshness(&other_device, app.now())
            .state,
        TelemetryFreshness::Missing,
        "a refused report creates no aggregate"
    );
}

#[tokio::test]
async fn the_http_telemetry_route_shares_the_per_device_budget() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("owner-1").await;

    // The management channel's budget is the one that protects ingest; the HTTP route feeds
    // the same mutex, so it must be charged from the same budget.
    let mut accepted = 0;
    let (status, headers, body) = loop {
        let (status, headers, body) = app
            .request_with_headers(
                Method::POST,
                &format!("/api/devices/{device_id}/telemetry"),
                Some(&credential),
                Some(json!({ "sampled_at_ms": app.now(), "battery_percent": 50 })),
            )
            .await;
        if status != StatusCode::OK {
            break (status, headers, body);
        }
        accepted += 1;
        assert!(
            accepted < 500,
            "the HTTP telemetry route is never throttled"
        );
    };
    assert_eq!(status, StatusCode::TOO_MANY_REQUESTS, "{body}");
    assert_eq!(body["error"], "rate_limited");
    assert!(
        headers.get("retry-after").is_some(),
        "a throttled report says when to retry"
    );
    assert!(
        (40..500).contains(&accepted),
        "the burst covers a real burst, not an unlimited stream: {accepted}"
    );

    // The agent's normal cadence is one report every 30 s, which must always pass.
    app.clock.advance_ms(30_000);
    let (status, body) = app.ingest_telemetry(&device_id, &credential, 50).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "a normal cadence is accepted: {body}"
    );
}

#[tokio::test]
async fn the_status_surface_reports_telemetry_freshness() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("owner-1").await;

    let (status, body) = app.device_status(&device_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "status failed: {body}");
    assert_eq!(body["telemetry"]["freshness"], Value::from("missing"));
    assert_eq!(body["telemetry"]["latest"], Value::Null);

    app.ingest_telemetry(&device_id, &credential, 71).await;
    let (status, body) = app.device_status(&device_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["telemetry"]["freshness"], Value::from("fresh"));
    assert_eq!(body["telemetry"]["age_ms"], Value::from(0));
    assert_eq!(
        body["telemetry"]["latest"]["battery_percent"],
        Value::from(71)
    );

    app.clock.advance_ms(STALE_AFTER_MS + 1);
    let (status, body) = app.device_status(&device_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["telemetry"]["freshness"], Value::from("stale"));
    assert_eq!(
        body["telemetry"]["latest"]["battery_percent"],
        Value::from(71),
        "a stale reading is still shown, explicitly marked stale"
    );
}

#[tokio::test]
async fn connectivity_must_be_a_short_printed_label() {
    let (aggregator, clock) = aggregator_at(NOW_MS);

    // A real label is accepted and kept verbatim.
    let mut legitimate = sample(clock.now_ms(), 5.0, 50);
    legitimate.connectivity = Some("wifi".to_owned());
    aggregator
        .ingest("dev_a", legitimate)
        .expect("a short label is accepted");
    assert_eq!(
        aggregator
            .aggregate("dev_a")
            .expect("tracked")
            .latest
            .connectivity
            .as_deref(),
        Some("wifi")
    );

    // The cap itself is inclusive: a value at the documented length still fits.
    let mut at_cap = sample(clock.now_ms(), 5.0, 50);
    at_cap.connectivity = Some("c".repeat(MAX_CONNECTIVITY_BYTES));
    aggregator
        .ingest("dev_a", at_cap)
        .expect("a label at the cap is accepted");

    // One byte past it is refused, so 16 retained samples cannot pin an unbounded string.
    let mut too_long = sample(clock.now_ms(), 5.0, 50);
    too_long.connectivity = Some("c".repeat(MAX_CONNECTIVITY_BYTES + 1));
    assert!(matches!(
        aggregator.ingest("dev_a", too_long),
        Err(TelemetryError::InvalidSample { reason }) if reason.contains("connectivity")
    ));

    // Printable ASCII only: a captured value cannot smuggle control characters onward.
    let mut control_chars = sample(clock.now_ms(), 5.0, 50);
    control_chars.connectivity = Some("wifi\nDEBUG".to_owned());
    assert!(matches!(
        aggregator.ingest("dev_a", control_chars),
        Err(TelemetryError::InvalidSample { reason }) if reason.contains("printable")
    ));

    // The HTTP route applies the same bound.
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("owner-1").await;
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/telemetry"),
            Some(&credential),
            Some(json!({
                "sampled_at_ms": app.now(),
                "connectivity": "x".repeat(MAX_CONNECTIVITY_BYTES + 1)
            })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_sample");
}

#[tokio::test]
async fn no_raw_payload_or_file_is_retained() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("owner-1").await;

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/telemetry"),
            Some(&credential),
            Some(json!({
                "sampled_at_ms": app.now(),
                "battery_percent": 55,
                "cpu_percent": 5.0,
                "files": [{ "name": "secret.bin", "bytes": "UEFZTE9BRA" }],
                "payload": "PC-TELEMETRY-PAYLOAD-MUST-NOT-PERSIST"
            })),
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let aggregate = app
        .state
        .telemetry
        .aggregate(&device_id)
        .expect("aggregate tracked");
    let rendered = format!("{aggregate:?}");
    assert!(
        !rendered.contains("PC-TELEMETRY-PAYLOAD-MUST-NOT-PERSIST"),
        "raw payload bytes are never retained: {rendered}"
    );
    assert!(
        !rendered.contains("secret.bin"),
        "no file metadata is retained"
    );

    let tables = app.store.schema().expect("schema readable");
    assert!(
        !tables.iter().any(|table| table.contains("telemetry")),
        "telemetry aggregates live in bounded memory, not in a raw sample table: {tables:?}"
    );
}

#[tokio::test]
async fn the_aggregator_uses_the_injected_clock() {
    let clock = Arc::new(SystemClock);
    let aggregator = TelemetryAggregator::new(clock.clone());
    aggregator
        .ingest("dev_a", sample(clock.now_ms(), 1.0, 50))
        .expect("sample accepted");
    assert_eq!(
        aggregator.freshness("dev_a", clock.now_ms()).state,
        TelemetryFreshness::Fresh
    );
}
