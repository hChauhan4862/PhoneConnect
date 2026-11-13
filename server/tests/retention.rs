//! The 30-day retention job deletes session records, control leases, and telemetry
//! aggregates, and keeps everything inside the window.

mod common;

use axum::http::StatusCode;
use common::{NOW_MS, TestApp};
use phoneconnect_server::retention::RetentionJob;
use phoneconnect_server::store::{DeviceStore, StoreError, UnixMs};
use phoneconnect_server::telemetry::RETENTION_MS;

const DAY_MS: UnixMs = 24 * 60 * 60 * 1_000;

fn job(app: &TestApp) -> RetentionJob {
    RetentionJob::new(
        app.store.clone(),
        app.state.telemetry.clone(),
        app.clock.clone(),
    )
}

#[tokio::test]
async fn records_older_than_thirty_days_are_deleted() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("owner-1").await;

    let (status, granted) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CREATED, "{granted}");
    let lease_id = granted["lease_id"].as_str().expect("lease id").to_owned();
    let (status, body) = app
        .create_control_session(&device_id, "owner-1", &TestApp::identity_key())
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let session_id = body["session_id"].as_str().expect("session id").to_owned();
    app.ingest_telemetry(&device_id, &credential, 55).await;

    assert_eq!(RETENTION_MS, 30 * DAY_MS);

    // Inside the window nothing is deleted, even though the session and lease expired.
    app.clock.advance_ms(29 * DAY_MS);
    let report = job(&app).run(app.now()).await.expect("retention runs");
    assert_eq!(report.cutoff_ms, app.now() - RETENTION_MS);
    assert_eq!(report.records.total(), 0);
    assert!(report.telemetry_devices_deleted.is_empty());
    assert!(app.store.session(&session_id).await.is_ok());
    assert!(app.store.lease(&lease_id).await.is_ok());

    // Past the window, the ended session, its lease link, the lease, and the telemetry
    // aggregate are all deleted.
    app.clock.advance_ms(2 * DAY_MS);
    let report = job(&app).run_due().await.expect("retention runs");
    assert_eq!(report.records.sessions_deleted, 1);
    assert_eq!(report.records.lease_links_deleted, 1);
    assert_eq!(report.records.leases_deleted, 1);
    assert_eq!(report.telemetry_devices_deleted, vec![device_id.clone()]);

    assert!(matches!(
        app.store.session(&session_id).await,
        Err(StoreError::UnknownSession { .. })
    ));
    assert!(matches!(
        app.store.lease(&lease_id).await,
        Err(StoreError::UnknownLease { .. })
    ));
    assert!(
        app.state.telemetry.aggregate(&device_id).is_none(),
        "the telemetry aggregate is deleted too"
    );

    // Deleting is idempotent: a second run finds nothing left.
    let report = job(&app).run_due().await.expect("retention runs");
    assert_eq!(report.records.total(), 0);
    assert!(report.telemetry_devices_deleted.is_empty());
}

#[tokio::test]
async fn current_records_survive_while_older_ones_are_deleted() {
    let app = TestApp::new();
    let (old_device, old_credential) = app.enroll_new("owner-old").await;
    app.acquire_lease(&old_device, "owner-old", 600).await;
    let old_session = app.create_session(&old_device).await;
    app.ingest_telemetry(&old_device, &old_credential, 10).await;

    app.clock.advance_ms(29 * DAY_MS);
    let (new_device, new_credential) = app.enroll_new("owner-new").await;
    app.acquire_lease(&new_device, "owner-new", 600).await;
    let new_session = app.create_session(&new_device).await;
    app.ingest_telemetry(&new_device, &new_credential, 20).await;

    app.clock.advance_ms(2 * DAY_MS);
    let report = job(&app).run_due().await.expect("retention runs");

    assert_eq!(report.records.sessions_deleted, 1);
    assert_eq!(report.records.leases_deleted, 1);
    assert_eq!(report.telemetry_devices_deleted, vec![old_device.clone()]);
    assert!(
        app.store
            .session(old_session["session_id"].as_str().expect("session id"))
            .await
            .is_err(),
        "the old session is gone"
    );
    assert_eq!(
        app.store
            .session(new_session["session_id"].as_str().expect("session id"))
            .await
            .expect("the current session is retained")
            .device_id,
        new_device
    );
    assert!(
        app.state.telemetry.aggregate(&new_device).is_some(),
        "the current telemetry aggregate is retained"
    );
    assert_eq!(app.state.telemetry.now_ms(), NOW_MS + 31 * DAY_MS);
}
