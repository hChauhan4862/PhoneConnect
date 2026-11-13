//! Security contract for enrollment, device credentials, sessions, and rendezvous.
//!
//! Every test drives the public HTTP surface; the store is only touched to simulate an
//! operator revoking a credential, which is how revocation reaches the server.

mod common;

use axum::http::StatusCode;
use common::{ADMIN_TOKEN, TestApp};
use phoneconnect_server::auth::hash_secret;
use phoneconnect_server::store::DeviceStore;
use serde_json::Value;

#[tokio::test]
async fn enrollment_token_is_consumed_exactly_once() {
    let app = TestApp::new();
    let token = app.issue_token("user-a").await;

    let (first_status, first) = app.enroll_raw(&token).await;
    assert_eq!(first_status, StatusCode::CREATED, "{first}");
    assert!(
        first["device_id"]
            .as_str()
            .is_some_and(|id| id.starts_with("dev_"))
    );
    assert!(
        first["credential"]
            .as_str()
            .is_some_and(|c| c.starts_with("pcdev_"))
    );

    let (second_status, second) = app.enroll_raw(&token).await;
    assert_eq!(second_status, StatusCode::CONFLICT, "{second}");
    assert_eq!(second["error"], "enrollment_token_used");
}

#[tokio::test]
async fn concurrent_enrollment_with_one_token_succeeds_once() {
    let app = TestApp::new();
    let token = app.issue_token("user-a").await;

    let (first, second) = tokio::join!(app.enroll_raw(&token), app.enroll_raw(&token));
    let statuses = [first.0, second.0];
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::CREATED)
            .count(),
        1,
        "exactly one enrollment may win: {statuses:?}"
    );
    assert_eq!(
        statuses
            .iter()
            .filter(|s| **s == StatusCode::CONFLICT)
            .count(),
        1,
        "the loser must see a consumed token: {statuses:?}"
    );
}

#[tokio::test]
async fn expired_enrollment_token_is_rejected() {
    let app = TestApp::new();
    let token = app.issue_token_with_ttl("user-a", 60).await;

    app.clock.advance_ms(60_000);
    let (status, body) = app.enroll_raw(&token).await;
    assert_eq!(status, StatusCode::GONE, "{body}");
    assert_eq!(body["error"], "enrollment_token_expired");

    // Expiry must not consume the token into a usable state later.
    let (again, again_body) = app.enroll_raw(&token).await;
    assert_eq!(again, StatusCode::GONE, "{again_body}");
}

#[tokio::test]
async fn revoked_enrollment_token_is_rejected() {
    let app = TestApp::new();
    let token = app.issue_token("user-a").await;
    app.store
        .revoke_enrollment_token(&hash_secret(&token), app.now())
        .await
        .expect("token revocation persists");

    let (status, body) = app.enroll_raw(&token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "enrollment_token_revoked");
}

#[tokio::test]
async fn unknown_enrollment_token_is_rejected() {
    let app = TestApp::new();
    let (status, body) = app.enroll_raw("pcenr_not-a-real-token").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "enrollment_token_unknown");
}

#[tokio::test]
async fn credential_and_token_secrets_are_stored_as_hashes() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let capability = session["capability"].as_str().expect("capability");

    let device = app.store.device(&device_id).await.expect("device record");
    assert_ne!(
        device.credential_hash, credential,
        "raw credential must not persist"
    );
    assert_eq!(device.credential_hash, hash_secret(&credential));

    let session_id = session["session_id"].as_str().expect("session_id");
    let record = app.store.session(session_id).await.expect("session record");
    assert_ne!(
        record.capability_hash, capability,
        "raw capability must not persist"
    );
    assert_eq!(record.capability_hash, hash_secret(capability));
}

#[tokio::test]
async fn admin_endpoints_reject_missing_and_wrong_bearer_tokens() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;

    let (missing, missing_body) = app
        .request(
            axum::http::Method::POST,
            "/api/enrollment-tokens",
            None,
            Some(serde_json::json!({ "owner_id": "user-a" })),
        )
        .await;
    assert_eq!(missing, StatusCode::UNAUTHORIZED, "{missing_body}");
    assert_eq!(missing_body["error"], "missing_credentials");

    let (wrong, wrong_body) = app
        .request(
            axum::http::Method::POST,
            "/api/enrollment-tokens",
            Some("not-the-admin-token"),
            Some(serde_json::json!({ "owner_id": "user-a" })),
        )
        .await;
    assert_eq!(wrong, StatusCode::UNAUTHORIZED, "{wrong_body}");
    assert_eq!(wrong_body["error"], "invalid_admin_token");

    let (device_as_admin, device_body) =
        app.create_session_raw(&device_id, Some(&credential)).await;
    assert_eq!(device_as_admin, StatusCode::UNAUTHORIZED, "{device_body}");
    assert_eq!(device_body["error"], "invalid_admin_token");
}

#[tokio::test]
async fn session_requires_an_enrolled_device() {
    let app = TestApp::new();
    let (status, body) = app
        .create_session_raw("dev_unknown", Some(ADMIN_TOKEN))
        .await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], "device_unknown");
}

#[tokio::test]
async fn session_creation_refuses_a_revoked_device() {
    let app = TestApp::new();
    let (device_id, _) = app.enroll_new("user-a").await;
    app.store
        .revoke_device(&device_id, app.now())
        .await
        .expect("device revocation persists");

    let (status, body) = app.create_session_raw(&device_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "device_revoked");
}

#[tokio::test]
async fn session_issue_returns_a_short_lived_capability_and_ticket() {
    let app = TestApp::new();
    let (device_id, _) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;

    let session_id = session["session_id"].as_str().expect("session_id");
    let capability = session["capability"].as_str().expect("capability");
    assert!(session_id.starts_with("sess_"));
    assert!(capability.starts_with("pcsess_"));

    let expires_at = session["expires_at"].as_i64().expect("expires_at");
    assert_eq!(expires_at, app.now() + 300_000, "sessions are short-lived");
    assert!(
        expires_at < app.now() + 3_600_000,
        "session ttl must stay short"
    );

    let ticket = &session["ticket"];
    assert_eq!(ticket["session_id"], session_id);
    assert_eq!(ticket["device_id"], device_id);
    assert_eq!(ticket["expires_at"].as_i64(), Some(expires_at));
    assert!(
        ticket["nonce"]
            .as_str()
            .is_some_and(|nonce| nonce.len() >= 16),
        "ticket carries a rendezvous nonce: {ticket}"
    );
}

#[tokio::test]
async fn session_candidates_are_only_returned_to_the_session_peers() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"].as_str().expect("session_id");
    let capability = session["capability"].as_str().expect("capability");

    let (status, body) = app.candidates(session_id, Some(capability)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["session_id"], session_id);
    let candidates = body["candidates"].as_array().expect("candidates");
    assert_eq!(
        candidates.len(),
        1,
        "task 2 publishes only the relay candidate: {body}"
    );
    assert_eq!(candidates[0]["kind"], "relay");
    assert_eq!(candidates[0]["endpoint"], common::RELAY_ENDPOINT);

    // The owning device may fetch its own rendezvous data with its device credential.
    let (device_status, device_body) = app.candidates(session_id, Some(&credential)).await;
    assert_eq!(device_status, StatusCode::OK, "{device_body}");
    assert_eq!(device_body["session_id"], session_id);
}

#[tokio::test]
async fn session_capability_is_scoped_to_one_session() {
    let app = TestApp::new();
    let (device_a, _) = app.enroll_new("user-a").await;
    let (device_b, credential_b) = app.enroll_new("user-b").await;
    let session_a = app.create_session(&device_a).await;
    let session_b = app.create_session(&device_b).await;

    let capability_a = session_a["capability"].as_str().expect("capability");
    let session_b_id = session_b["session_id"].as_str().expect("session_id");

    let (status, body) = app.candidates(session_b_id, Some(capability_a)).await;
    assert_eq!(
        status,
        StatusCode::FORBIDDEN,
        "user-a must not read user-b rendezvous data: {body}"
    );
    assert_eq!(body["error"], "session_scope_mismatch");

    // Another device's credential is rejected for a session it does not own.
    let session_a_id = session_a["session_id"].as_str().expect("session_id");
    let (device_status, device_body) = app.candidates(session_a_id, Some(&credential_b)).await;
    assert_eq!(device_status, StatusCode::FORBIDDEN, "{device_body}");
    assert_eq!(device_body["error"], "session_scope_mismatch");

    // An admin token is not a peer credential.
    let (admin_status, admin_body) = app.candidates(session_a_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(admin_status, StatusCode::UNAUTHORIZED, "{admin_body}");
    assert_eq!(admin_body["error"], "invalid_credential");
}

#[tokio::test]
async fn candidates_require_credentials() {
    let app = TestApp::new();
    let (device_id, _) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"].as_str().expect("session_id");

    let (status, body) = app.candidates(session_id, None).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "missing_credentials");
}

#[tokio::test]
async fn unknown_session_is_rejected() {
    let app = TestApp::new();
    let (_, credential) = app.enroll_new("user-a").await;

    let (status, body) = app.candidates("sess_unknown", Some(&credential)).await;
    assert_eq!(status, StatusCode::NOT_FOUND, "{body}");
    assert_eq!(body["error"], "session_unknown");
}

#[tokio::test]
async fn expired_session_is_rejected_without_refresh() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"].as_str().expect("session_id");
    let capability = session["capability"].as_str().expect("capability");

    app.clock.advance_ms(300_000);
    let (status, body) = app.candidates(session_id, Some(capability)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "session_expired");

    let (device_status, device_body) = app.candidates(session_id, Some(&credential)).await;
    assert_eq!(device_status, StatusCode::UNAUTHORIZED, "{device_body}");
    assert_eq!(device_body["error"], "session_expired");
}

#[tokio::test]
async fn revoked_device_credential_fails_immediately() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"].as_str().expect("session_id");
    let capability = session["capability"].as_str().expect("capability");

    app.store
        .revoke_device(&device_id, app.now())
        .await
        .expect("device revocation persists");

    let (device_status, device_body) = app.candidates(session_id, Some(&credential)).await;
    assert_eq!(device_status, StatusCode::UNAUTHORIZED, "{device_body}");
    assert_eq!(device_body["error"], "device_revoked");

    // Revoking a device revokes its live sessions in the same transaction.
    let (session_status, session_body) = app.candidates(session_id, Some(capability)).await;
    assert_eq!(session_status, StatusCode::UNAUTHORIZED, "{session_body}");
    assert_eq!(session_body["error"], "session_revoked");
}

#[tokio::test]
async fn revoked_session_fails_immediately() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"].as_str().expect("session_id");
    let capability = session["capability"].as_str().expect("capability");

    app.store
        .revoke_session(session_id, app.now())
        .await
        .expect("session revocation persists");

    let (status, body) = app.candidates(session_id, Some(capability)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "session_revoked");

    let (device_status, device_body) = app.candidates(session_id, Some(&credential)).await;
    assert_eq!(device_status, StatusCode::UNAUTHORIZED, "{device_body}");
    assert_eq!(device_body["error"], "session_revoked");
}

#[tokio::test]
async fn health_endpoint_is_unauthenticated_and_explicit() {
    let app = TestApp::new();
    let (status, body) = app
        .request(axum::http::Method::GET, "/health", None, None)
        .await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body, serde_json::json!({ "status": "ok" }));
}

#[tokio::test]
async fn enrollment_requires_an_owner() {
    let app = TestApp::new();
    let (status, body) = app
        .request(
            axum::http::Method::POST,
            "/api/enrollment-tokens",
            Some(ADMIN_TOKEN),
            Some(serde_json::json!({ "owner_id": "  " })),
        )
        .await;
    assert_eq!(status, StatusCode::BAD_REQUEST, "{body}");
    assert_eq!(body["error"], "invalid_request");
}

#[tokio::test]
async fn malformed_json_body_is_rejected() {
    let app = TestApp::new();
    let response = app
        .request(
            axum::http::Method::POST,
            "/api/devices/enroll",
            None,
            Some(Value::String("not-an-object".into())),
        )
        .await;
    assert_eq!(
        response.0,
        StatusCode::UNPROCESSABLE_ENTITY,
        "{}",
        response.1
    );
}

#[tokio::test]
async fn admin_revocation_endpoints_require_the_admin_token() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"].as_str().expect("session_id");
    let token = app.issue_token("user-a").await;

    for (kind, id) in [
        ("devices", device_id.as_str()),
        ("sessions", session_id),
        ("enrollment-tokens", token.as_str()),
    ] {
        let (status, body) = app.revoke(kind, id, None).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{kind}: {body}");
        assert_eq!(body["error"], "missing_credentials");

        let (status, body) = app.revoke(kind, id, Some("pcdev_not-the-admin")).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{kind}: {body}");
        assert_eq!(body["error"], "invalid_admin_token");
    }

    // A refused request revokes nothing.
    let (status, body) = app.candidates(session_id, Some(&credential)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
}

#[tokio::test]
async fn admin_can_revoke_an_enrollment_token() {
    let app = TestApp::new();
    let token = app.issue_token("user-a").await;

    let (status, body) = app
        .revoke("enrollment-tokens", &token, Some(ADMIN_TOKEN))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked"], true);
    let revoked_at = body["revoked_at"].as_i64().expect("revoked_at");
    assert_eq!(revoked_at, app.now());

    let (status, body) = app.enroll_raw(&token).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "enrollment_token_revoked");

    // Revocation is idempotent so an operator can retry safely, and the reported time
    // stays the moment revocation took effect rather than the retry time.
    app.clock.advance_ms(1_000);
    let (status, body) = app
        .revoke("enrollment-tokens", &token, Some(ADMIN_TOKEN))
        .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked_at"].as_i64(), Some(revoked_at));
}

#[tokio::test]
async fn admin_can_revoke_a_session() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"].as_str().expect("session_id");
    let capability = session["capability"].as_str().expect("capability");

    let (status, body) = app.revoke("sessions", session_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked"], true);
    let revoked_at = body["revoked_at"].as_i64().expect("revoked_at");

    for bearer in [capability, credential.as_str()] {
        let (status, body) = app.candidates(session_id, Some(bearer)).await;
        assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
        assert_eq!(body["error"], "session_revoked");
    }

    app.clock.advance_ms(1_000);
    let (status, body) = app.revoke("sessions", session_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(
        status,
        StatusCode::OK,
        "revoking the same session twice stays safe: {body}"
    );
    assert_eq!(
        body["revoked_at"].as_i64(),
        Some(revoked_at),
        "a repeat revocation keeps the first revocation time"
    );
}

#[tokio::test]
async fn admin_can_revoke_a_device() {
    let app = TestApp::new();
    let (device_id, credential) = app.enroll_new("user-a").await;
    let session = app.create_session(&device_id).await;
    let session_id = session["session_id"].as_str().expect("session_id");
    let capability = session["capability"].as_str().expect("capability");

    let (status, body) = app.revoke("devices", &device_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["revoked"], true);

    let (status, body) = app.candidates(session_id, Some(&credential)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "device_revoked");

    // The device's live sessions are revoked with it.
    let (status, body) = app.candidates(session_id, Some(capability)).await;
    assert_eq!(status, StatusCode::UNAUTHORIZED, "{body}");
    assert_eq!(body["error"], "session_revoked");

    let (status, body) = app.create_session_raw(&device_id, Some(ADMIN_TOKEN)).await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert_eq!(body["error"], "device_revoked");
}

#[tokio::test]
async fn revoking_an_unknown_id_is_a_not_found() {
    let app = TestApp::new();

    for (kind, id, code) in [
        ("devices", "dev_unknown", "device_unknown"),
        ("sessions", "sess_unknown", "session_unknown"),
        (
            "enrollment-tokens",
            "pcenr_unknown",
            "enrollment_token_unknown",
        ),
    ] {
        let (status, body) = app.revoke(kind, id, Some(ADMIN_TOKEN)).await;
        assert_eq!(status, StatusCode::NOT_FOUND, "{kind}: {body}");
        assert_eq!(body["error"], code, "{kind}");
    }
}
