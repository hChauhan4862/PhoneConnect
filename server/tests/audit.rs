//! The audit surface: the durable trace of every command attempt, newest first, filtered,
//! bounded, and read-only. Rows never carry a path, a file byte, an argument, or an image.
//!
//! The same retention job that ages out leases and sessions deletes audit rows older than
//! 30 days, deterministically.

mod common;

use std::path::PathBuf;
use std::sync::Arc;

use axum::http::{Method, StatusCode};
use common::{ADMIN_TOKEN, NOW_MS, TestApp};
use phoneconnect_server::retention::RetentionJob;
use phoneconnect_server::store::{
    AUDIT_PAGE_SQL, AuditEntry, DeviceStore, SqliteStore, StoreError, UnixMs,
};
use phoneconnect_server::telemetry::RETENTION_MS;
use serde_json::{Value, json};

const DAY_MS: UnixMs = 24 * 60 * 60 * 1_000;

async fn seed(
    app: &TestApp,
    device_id: &str,
    actor: &str,
    at_ms: UnixMs,
    outcome: &str,
    error: Option<&str>,
) {
    app.store
        .insert_audit(AuditEntry {
            at_ms,
            actor: actor.to_owned(),
            action: "command.dispatch".to_owned(),
            device_id: device_id.to_owned(),
            outcome: outcome.to_owned(),
            error: error.map(str::to_owned),
        })
        .await
        .expect("audit row");
}

async fn audit(app: &TestApp, query: &str) -> (StatusCode, Value) {
    app.request(
        Method::GET,
        &format!("/api/audit{query}"),
        Some(ADMIN_TOKEN),
        None,
    )
    .await
}

fn job(app: &TestApp) -> RetentionJob {
    RetentionJob::new(
        app.store.clone(),
        app.state.telemetry.clone(),
        app.clock.clone(),
    )
}

#[tokio::test]
async fn audit_returns_newest_first_rows_with_the_documented_fields_only() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    seed(&app, &device_id, "owner-1", NOW_MS, "accepted", None).await;
    seed(
        &app,
        &device_id,
        "user-b",
        NOW_MS + 1,
        "refused",
        Some("device_offline"),
    )
    .await;
    seed(&app, &device_id, "owner-1", NOW_MS + 2, "accepted", None).await;

    let (status, body) = audit(&app, &format!("?device_id={device_id}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body.as_array().expect("an audit entry list");
    assert_eq!(rows.len(), 3);
    assert_eq!(rows[0]["at_ms"], json!(NOW_MS + 2));
    assert_eq!(rows[1]["at_ms"], json!(NOW_MS + 1));
    assert_eq!(rows[2]["at_ms"], json!(NOW_MS));

    assert_eq!(
        rows[1],
        json!({
            "at_ms": NOW_MS + 1,
            "actor": "user-b",
            "action": "command.dispatch",
            "device_id": device_id,
            "outcome": "refused",
            "error": "device_offline",
        })
    );
    assert!(
        rows[0].get("error").is_some_and(Value::is_null),
        "an accepted attempt carries no error code"
    );
    let mut keys: Vec<&str> = rows[0]
        .as_object()
        .expect("one audit entry")
        .keys()
        .map(String::as_str)
        .collect();
    keys.sort_unstable();
    assert_eq!(
        keys,
        ["action", "actor", "at_ms", "device_id", "error", "outcome"],
        "the surface exposes the stored columns and nothing else"
    );
}

#[tokio::test]
async fn audit_requires_the_admin_token_and_serves_no_mutation() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("owner-1").await;
    seed(&app, &device_id, "owner-1", NOW_MS, "accepted", None).await;

    let (status, body) = app.request(Method::GET, "/api/audit", None, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "missing_credentials");

    let (status, body) = app
        .request(Method::GET, "/api/audit", Some(&credential), None)
        .await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "invalid_admin_token");

    // The surface is read-only: there is no endpoint that changes a row.
    let (status, _body) = app
        .request(
            Method::POST,
            "/api/audit",
            Some(ADMIN_TOKEN),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::METHOD_NOT_ALLOWED);
}

#[tokio::test]
async fn the_device_filter_never_returns_another_devices_rows() {
    let app = TestApp::new();
    let (first, _first_credential) = app.enroll_new("owner-1").await;
    let (second, _second_credential) = app.enroll_new("owner-2").await;
    seed(&app, &first, "owner-1", NOW_MS, "accepted", None).await;
    seed(
        &app,
        &second,
        "owner-2",
        NOW_MS + 1,
        "refused",
        Some("device_offline"),
    )
    .await;

    let (status, body) = audit(&app, &format!("?device_id={first}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body.as_array().expect("an audit entry list");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0]["device_id"], first, "only the requested device");

    // An unknown device is an empty list, never another device's history.
    let (status, body) = audit(&app, "?device_id=device-that-never-enrolled").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!([]));

    // Without a filter the admin sees both, newest first.
    let (status, body) = audit(&app, "").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body.as_array().expect("an audit entry list");
    assert_eq!(rows.len(), 2);
    assert_eq!(rows[0]["device_id"], second);
    assert_eq!(rows[1]["device_id"], first);
}

#[tokio::test]
async fn audit_is_bounded_at_two_hundred_rows_and_refuses_an_unusable_limit() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    for offset in 0..205 {
        seed(
            &app,
            &device_id,
            "owner-1",
            NOW_MS + offset,
            "accepted",
            None,
        )
        .await;
    }

    let (status, body) = audit(&app, &format!("?device_id={device_id}&limit=200")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body.as_array().expect("an audit entry list");
    assert_eq!(rows.len(), 200);
    assert_eq!(rows[0]["at_ms"], json!(NOW_MS + 204), "newest first");
    assert_eq!(rows[199]["at_ms"], json!(NOW_MS + 5));

    // A larger request cannot read more than the cap.
    let (status, body) = audit(&app, &format!("?device_id={device_id}&limit=5000")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body.as_array().expect("an audit entry list").len(), 200);

    // A caller that names no limit gets the documented default page.
    let (status, body) = audit(&app, &format!("?device_id={device_id}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body.as_array().expect("an audit entry list").len(), 50);

    for unusable in ["0", "-1", "many"] {
        let (status, body) = audit(&app, &format!("?limit={unusable}")).await;
        assert_eq!(status, StatusCode::BAD_REQUEST, "limit={unusable}: {body}");
        assert_eq!(body["error"], "invalid_request");
    }

    // An explicitly empty filter is a request error, not "everything".
    let (status, body) = audit(&app, "?device_id=%20").await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn a_file_attempt_stores_no_path_no_content_and_no_arguments() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;

    // The device is offline, so both attempts are refused and audited — and what was asked
    // for must not survive in the row.
    let path = "secrets/report.txt";
    let data = "c2VjcmV0IGJ5dGVz";
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/files/write?user_id=owner-1"),
            Some(ADMIN_TOKEN),
            Some(json!({ "path": path, "data_base64": data })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "device_offline");

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/files/read?user_id=owner-1"),
            Some(ADMIN_TOKEN),
            Some(json!({ "path": path })),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");

    let rows = app
        .store
        .list_audit(Some(&device_id), 10)
        .await
        .expect("audit rows");
    assert_eq!(rows.len(), 2, "one row per attempt");
    for row in &rows {
        assert_eq!(row.outcome, "refused");
        assert_eq!(row.error.as_deref(), Some("device_offline"));
        for field in [&row.actor, &row.action, &row.device_id, &row.outcome] {
            assert!(!field.contains("secrets"), "{row:?} carries a path");
            assert!(!field.contains("report"), "{row:?} carries a path");
            assert!(!field.contains(data), "{row:?} carries file content");
            assert!(
                !field.contains("secret bytes"),
                "{row:?} carries file content"
            );
        }
        assert!(
            row.error
                .as_deref()
                .is_some_and(|code| !code.contains("secrets")),
            "{row:?} carries a path in its error"
        );
    }

    // The whole serialized surface, not just the fields a test remembered to check.
    let (status, body) = audit(&app, &format!("?device_id={device_id}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rendered = body.to_string();
    for forbidden in ["secrets", "report.txt", "secret bytes", data] {
        assert!(
            !rendered.contains(forbidden),
            "the audit surface exposes {forbidden}: {rendered}"
        );
    }
}

#[tokio::test]
async fn revocations_are_audited_against_their_device() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    let (status, granted) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CREATED, "{granted}");
    let lease_id = granted["lease_id"].as_str().expect("lease id").to_owned();
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"]
        .as_str()
        .expect("session id")
        .to_owned();

    let (status, body) = app.revoke_lease(&lease_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = app.revoke("sessions", &session_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = app.revoke("devices", &device_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let (status, body) = audit(&app, &format!("?device_id={device_id}")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let rows = body.as_array().expect("an audit entry list");
    let actions: Vec<&str> = rows
        .iter()
        .map(|row| row["action"].as_str().expect("action"))
        .collect();
    assert_eq!(
        actions,
        ["device.revoke", "session.revoke", "lease.revoke"],
        "each revocation leaves one newest-first row"
    );
    assert_eq!(rows[0]["actor"], "admin");
    assert_eq!(rows[1]["actor"], "admin");
    assert_eq!(rows[2]["actor"], "owner-1", "the lease actor is recorded");
    for row in rows {
        assert_eq!(row["outcome"], "accepted");
        assert_eq!(row["device_id"], device_id);
        assert_ne!(row["action"], "command.dispatch");
    }
}

#[tokio::test]
async fn an_idempotent_revocation_retry_appends_no_second_row() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    let (status, granted) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CREATED, "{granted}");
    let lease_id = granted["lease_id"].as_str().expect("lease id").to_owned();
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"]
        .as_str()
        .expect("session id")
        .to_owned();

    let (status, body) = app.revoke_lease(&lease_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = app.revoke("sessions", &session_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = app.revoke("devices", &device_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let first_revocation_ms = app.now();

    // Every revocation endpoint is idempotent. A retry is not a second event: it must keep
    // the original timestamp and append nothing.
    app.clock.advance_ms(DAY_MS);
    let (status, body) = app.revoke_lease(&lease_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = app.revoke("sessions", &session_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let (status, body) = app.revoke("devices", &device_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let rows = app
        .store
        .list_audit(Some(&device_id), 10)
        .await
        .expect("audit rows");
    assert_eq!(
        rows.len(),
        3,
        "one row per revocation event, not per call: {rows:?}"
    );
    for row in &rows {
        assert_eq!(row.at_ms, first_revocation_ms, "the effective time is kept");
        assert_eq!(row.outcome, "accepted");
    }
}

#[tokio::test]
async fn a_repeat_revocation_by_another_allowed_actor_keeps_the_first_actor() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    let (status, granted) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CREATED, "{granted}");
    let (status, body) = app
        .handoff_lease(&device_id, "owner-1", "user-b", 600)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let lease_id = body["lease"]["lease_id"]
        .as_str()
        .expect("the handed-off lease")
        .to_owned();
    let handed_off_ms = app.now();

    app.clock.advance_ms(60_000);
    let (status, body) = app.revoke_lease(&lease_id, "user-b").await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let revoked_ms = app.now();

    // The owner is allowed to revoke too; the retry must not relabel the event.
    app.clock.advance_ms(60_000);
    let (status, body) = app.revoke_lease(&lease_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    let rows = app
        .store
        .list_audit(Some(&device_id), 10)
        .await
        .expect("audit rows");
    let revocations: Vec<_> = rows
        .iter()
        .filter(|row| row.action == "lease.revoke")
        .collect();
    assert_eq!(revocations.len(), 1, "{rows:?}");
    assert_eq!(revocations[0].actor, "user-b");
    assert_eq!(revocations[0].at_ms, revoked_ms);
    assert_ne!(handed_off_ms, revoked_ms);
}

#[tokio::test]
async fn a_handoff_records_the_replaced_lease_and_its_actor() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    let (status, granted) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CREATED, "{granted}");

    app.clock.advance_ms(1_000);
    let (status, body) = app
        .handoff_lease(&device_id, "owner-1", "user-b", 600)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(
        !body["replaced"].is_null(),
        "the previous lease is reported"
    );
    let handed_off_ms = app.now();

    let rows = app
        .store
        .list_audit(Some(&device_id), 10)
        .await
        .expect("audit rows");
    assert_eq!(rows.len(), 1, "one sharing event: {rows:?}");
    assert_eq!(rows[0].action, "lease.handoff");
    assert_eq!(rows[0].actor, "owner-1");
    assert_eq!(rows[0].at_ms, handed_off_ms);
    assert_eq!(rows[0].outcome, "accepted");
    assert!(rows[0].error.is_none());
}

#[tokio::test]
async fn a_handoff_that_replaces_nothing_is_not_an_event() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    let (status, granted) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CREATED, "{granted}");
    let lease_id = granted["lease_id"].as_str().expect("lease id").to_owned();
    let (status, body) = app.revoke_lease(&lease_id, "owner-1").await;
    assert_eq!(status, StatusCode::OK, "{body}");

    app.clock.advance_ms(1_000);
    let (status, body) = app
        .handoff_lease(&device_id, "owner-1", "user-b", 600)
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert!(body["replaced"].is_null());

    let rows = app
        .store
        .list_audit(Some(&device_id), 10)
        .await
        .expect("audit rows");
    assert_eq!(rows.len(), 1, "nothing was replaced: {rows:?}");
    assert_eq!(rows[0].action, "lease.revoke");
}

#[tokio::test]
async fn a_dispatch_audit_failure_is_counted_and_reported_by_health() {
    // Real SQLite: the audit table is gone, so the best-effort dispatch row cannot be
    // written. The refusal is still the response, the failure is visible in /health, and
    // nothing pretends the attempt was traced.
    let path = scratch_path("dispatch-audit-failure");
    let store = Arc::new(SqliteStore::open(&path).expect("file store"));
    let app = TestApp::with_store(store);
    let (device_id, _credential) = app.enroll_new("owner-1").await;

    let probe = rusqlite::Connection::open(&path).expect("probe connection");
    probe
        .execute_batch("DROP TABLE audit_log")
        .expect("the audit table is broken on purpose");

    let (status, body) = app
        .dispatch_command(
            &device_id,
            "owner-1",
            json!({ "name": "device.ping", "args": null, "timeout_ms": null }),
        )
        .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "device_offline", "the refusal is unchanged");

    let (status, body) = app.request(Method::GET, "/health", None, None).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "ok");
    assert_eq!(
        body["audit_write_failures"], 1,
        "the untraced attempt is visible: {body}"
    );
}

#[tokio::test]
async fn a_revocation_whose_audit_row_cannot_be_written_fails_closed() {
    // The row is part of the revocation transaction, so a store that cannot write it must not
    // let the revocation happen: the request is a store failure and the record stays active.
    let path = scratch_path("revocation-audit-failure");
    let store = Arc::new(SqliteStore::open(&path).expect("file store"));
    let app = TestApp::with_store(store);
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    let (status, granted) = app.acquire_lease(&device_id, "owner-1", 600).await;
    assert_eq!(status, StatusCode::CREATED, "{granted}");
    let lease_id = granted["lease_id"].as_str().expect("lease id").to_owned();
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"]
        .as_str()
        .expect("session id")
        .to_owned();

    let probe = rusqlite::Connection::open(&path).expect("probe connection");
    probe
        .execute_batch("DROP TABLE audit_log")
        .expect("the audit table is broken on purpose");

    let (status, body) = app.revoke("devices", &device_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["error"], "store_failure");
    assert!(
        !app.store
            .device(&device_id)
            .await
            .expect("device")
            .is_revoked(),
        "a failed audit write must not leave the device revoked"
    );

    let (status, body) = app.revoke_lease(&lease_id, "owner-1").await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["error"], "store_failure");
    assert!(
        !app.store
            .lease(&lease_id)
            .await
            .expect("lease")
            .is_revoked(),
        "a failed audit write must not leave the lease revoked"
    );

    let (status, body) = app.revoke("sessions", &session_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::INTERNAL_SERVER_ERROR, "{body}");
    assert_eq!(body["error"], "store_failure");
    assert!(
        !app.store
            .session(&session_id)
            .await
            .expect("session")
            .is_revoked(),
        "a failed audit write must not leave the session revoked"
    );
}

#[tokio::test]
async fn the_unfiltered_listing_is_served_by_an_index_not_a_table_scan() {
    let path = scratch_path("unfiltered-listing");
    let store = SqliteStore::open(&path).expect("file store");
    for offset in 0..10 {
        store
            .insert_audit(AuditEntry {
                at_ms: NOW_MS + offset,
                actor: "owner-1".to_owned(),
                action: "command.dispatch".to_owned(),
                device_id: "dev_1".to_owned(),
                outcome: "accepted".to_owned(),
                error: None,
            })
            .await
            .expect("audit row");
    }

    let probe = rusqlite::Connection::open(&path).expect("probe connection");
    let plan = {
        let mut statement = probe
            .prepare(&format!("EXPLAIN QUERY PLAN {AUDIT_PAGE_SQL}"))
            .expect("prepare");
        statement
            .query_map([50_i64], |row| row.get::<_, String>(3))
            .expect("plan")
            .collect::<Result<Vec<_>, _>>()
            .expect("plan rows")
            .join(" | ")
    };
    assert!(
        plan.contains("audit_log_by_time"),
        "the unfiltered listing needs its index: {plan}"
    );
    assert!(
        !plan
            .split(" | ")
            .any(|step| step.contains("SCAN audit_log") && !step.contains("USING INDEX")),
        "the unfiltered listing must not scan the table: {plan}"
    );
}

/// A fresh database path under Cargo's per-test scratch directory.
fn scratch_path(name: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("audit");
    std::fs::create_dir_all(&directory).expect("scratch directory");
    let path = directory.join(format!("{name}.db"));
    let _ = std::fs::remove_file(&path);
    path
}

#[tokio::test]
async fn audit_rows_older_than_thirty_days_are_deleted_by_the_retention_job() {
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    assert_eq!(RETENTION_MS, 30 * DAY_MS);

    seed(&app, &device_id, "owner-1", NOW_MS, "accepted", None).await;
    seed(
        &app,
        &device_id,
        "owner-1",
        NOW_MS + DAY_MS,
        "refused",
        Some("device_offline"),
    )
    .await;

    // Inside the window every row is kept.
    app.clock.advance_ms(29 * DAY_MS);
    let report = job(&app).run_due().await.expect("retention runs");
    assert_eq!(report.cutoff_ms, app.now() - RETENTION_MS);
    assert_eq!(report.records.audit_deleted, 0);
    assert_eq!(
        app.store
            .list_audit(Some(&device_id), 10)
            .await
            .expect("audit rows")
            .len(),
        2
    );

    // Past the window the older row is deleted and the one inside it survives.
    app.clock.advance_ms(2 * DAY_MS);
    let report = job(&app).run_due().await.expect("retention runs");
    assert_eq!(report.records.audit_deleted, 1);
    let rows = app
        .store
        .list_audit(Some(&device_id), 10)
        .await
        .expect("audit rows");
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].at_ms, NOW_MS + DAY_MS);

    // Retention is idempotent.
    let report = job(&app).run_due().await.expect("retention runs");
    assert_eq!(report.records.audit_deleted, 0);
}

#[tokio::test]
async fn a_retention_run_needs_no_device_to_delete_audit_rows() {
    // A revoked or ended device's history is retained by the same window; the job deletes
    // by time, not by whether the device is still listed.
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    seed(&app, &device_id, "owner-1", NOW_MS, "accepted", None).await;
    let (status, body) = app.revoke("devices", &device_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");

    app.clock.advance_ms(31 * DAY_MS);
    let report = job(&app).run_due().await.expect("retention runs");
    assert_eq!(
        report.records.audit_deleted, 2,
        "the row and the revocation"
    );
    assert!(
        app.store
            .list_audit(Some(&device_id), 10)
            .await
            .expect("audit rows")
            .is_empty()
    );
    assert!(
        app.store.device(&device_id).await.is_ok(),
        "a device record is not aged out with its audit rows"
    );
}

#[tokio::test]
async fn the_device_filter_is_an_exact_match_not_a_prefix() {
    // A prefix that a `LIKE` would have matched must not reach the seeded device's history.
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;
    seed(&app, &device_id, "owner-1", NOW_MS, "accepted", None).await;

    let (status, body) = audit(&app, &format!("?device_id={device_id}nope")).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body, json!([]), "a prefix is not the device");

    let (status, body) = app
        .request(
            Method::GET,
            &format!("/api/audit?device_id={device_id}"),
            Some(ADMIN_TOKEN),
            None,
        )
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body.as_array().expect("a list").len(), 1);
    assert!(matches!(
        app.store.device(&format!("{device_id}nope")).await,
        Err(StoreError::UnknownDevice { .. })
    ));
}

#[tokio::test]
async fn an_unauthorized_caller_cannot_shape_or_redirect_the_refusal_it_causes() {
    // The actor of a row is asserted by the admin-token holder: nothing verifies it until
    // accounts exist. What the server can decide is *whether* the caller may act on the device
    // it named, so a refusal row is only written after that decision. A stranger therefore
    // cannot make a request-shape check append `invalid_request` in someone else's name, and
    // the row always names the device the caller actually named.
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;

    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/files/list?user_id=user-b"),
            Some(ADMIN_TOKEN),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
    assert_eq!(
        body["error"], "lease_read_only",
        "the authorization failure classifies the attempt, not its body"
    );

    let rows = app
        .store
        .list_audit(Some(&device_id), 10)
        .await
        .expect("audit rows");
    assert_eq!(rows.len(), 1, "{rows:?}");
    assert_eq!(rows[0].outcome, "refused");
    assert_eq!(rows[0].error.as_deref(), Some("lease_read_only"));
    assert_eq!(rows[0].device_id, device_id);
    assert_eq!(
        rows[0].actor, "user-b",
        "the row carries the caller's own assertion, and nothing else"
    );

    // An authorized caller's malformed body is still traced under its own, more specific code.
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/files/list?user_id=owner-1"),
            Some(ADMIN_TOKEN),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");

    let rows = app
        .store
        .list_audit(Some(&device_id), 10)
        .await
        .expect("audit rows");
    assert_eq!(rows.len(), 2, "{rows:?}");
    assert_eq!(rows[0].outcome, "refused");
    assert_eq!(rows[0].error.as_deref(), Some("invalid_request"));
    assert_eq!(rows[0].actor, "owner-1");
}

#[tokio::test]
async fn refused_attempts_charge_the_creation_budget_so_the_log_is_bounded() {
    // A refusal is traced, so it takes the same per-device token a dispatch takes. Past the
    // burst nothing more is appended: rows per device are bounded by the documented throttle,
    // not by how fast a caller can send requests.
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;

    let mut refused = 0;
    loop {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/devices/{device_id}/files/list?user_id=owner-1"),
                Some(ADMIN_TOKEN),
                Some(json!({})),
            )
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(body["error"], "rate_limited");
            break;
        }
        assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
        assert_eq!(body["error"], "invalid_request");
        refused += 1;
        assert!(refused <= 128, "the throttle never fired");
    }
    assert!(
        refused >= 20,
        "at least the documented burst of refusals is traced: {refused}"
    );

    let rows = app
        .store
        .list_audit(Some(&device_id), 200)
        .await
        .expect("audit rows");
    assert_eq!(
        rows.len(),
        refused,
        "a throttled attempt appends nothing: {rows:?}"
    );
    assert!(rows.iter().all(|row| {
        row.outcome == "refused" && row.error.as_deref() == Some("invalid_request")
    }));

    // The bucket refills with time, so the refusal is traceable again.
    app.clock.advance_ms(1_000);
    let (status, body) = app
        .request(
            Method::POST,
            &format!("/api/devices/{device_id}/files/list?user_id=owner-1"),
            Some(ADMIN_TOKEN),
            Some(json!({})),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    let rows = app
        .store
        .list_audit(Some(&device_id), 200)
        .await
        .expect("audit rows");
    assert_eq!(rows.len(), refused + 1, "a refilled bucket traces again");
}

#[tokio::test]
async fn an_unauthorized_callers_refusals_are_throttled_too() {
    // The device-access decision is the first traceable step, so its refusals take the token as
    // well. A stranger cannot append `lease_read_only` rows at HTTP speed either.
    let app = TestApp::new();
    let (device_id, _credential) = app.enroll_new("owner-1").await;

    let mut refused = 0;
    loop {
        let (status, body) = app
            .request(
                Method::POST,
                &format!("/api/devices/{device_id}/files/list?user_id=user-b"),
                Some(ADMIN_TOKEN),
                Some(json!({})),
            )
            .await;
        if status == StatusCode::TOO_MANY_REQUESTS {
            assert_eq!(body["error"], "rate_limited");
            break;
        }
        assert_eq!(status, StatusCode::FORBIDDEN, "{body}");
        assert_eq!(body["error"], "lease_read_only");
        refused += 1;
        assert!(refused <= 128, "the throttle never fired");
    }
    assert!(refused >= 20, "the burst of traced refusals is {refused}");

    let rows = app
        .store
        .list_audit(Some(&device_id), 200)
        .await
        .expect("audit rows");
    assert_eq!(rows.len(), refused, "the throttled attempt appends nothing");
    assert!(rows.iter().all(|row| {
        row.outcome == "refused"
            && row.error.as_deref() == Some("lease_read_only")
            && row.actor == "user-b"
    }));
}
