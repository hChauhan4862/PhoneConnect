//! Shared helpers for the PhoneConnect server integration tests.

#![allow(dead_code)]

use std::sync::Arc;

use axum::Router;
use axum::body::Body;
use axum::http::{Method, Request, StatusCode, header};
use http_body_util::BodyExt;
use phoneconnect_server::relay::RelayLimits;
use phoneconnect_server::store::{Clock, ManualClock, SqliteStore};
use phoneconnect_server::{AppState, build_router};
use serde_json::{Value, json};
use tower::ServiceExt;

pub const ADMIN_TOKEN: &str = "test-admin-token";
pub const RELAY_ENDPOINT: &str = "https://relay.test/api/relay";
pub const NOW_MS: i64 = 1_760_000_000_000;

pub struct TestApp {
    pub state: Arc<AppState>,
    pub store: Arc<SqliteStore>,
    pub clock: Arc<ManualClock>,
    router: Router,
}

impl TestApp {
    pub fn new() -> Self {
        Self::with_relay(RelayLimits::default())
    }

    pub fn with_relay(limits: RelayLimits) -> Self {
        let store = Arc::new(SqliteStore::in_memory().expect("in-memory sqlite store"));
        let clock = Arc::new(ManualClock::new(NOW_MS));
        let state = Arc::new(
            AppState::new(
                store.clone(),
                ADMIN_TOKEN,
                RELAY_ENDPOINT,
                limits,
                clock.clone(),
            )
            .expect("app state accepts a non-empty admin token"),
        );
        let router = build_router(state.clone());
        Self {
            state,
            store,
            clock,
            router,
        }
    }

    pub fn now(&self) -> i64 {
        self.clock.now_ms()
    }

    pub async fn request(
        &self,
        method: Method,
        uri: &str,
        bearer: Option<&str>,
        body: Option<Value>,
    ) -> (StatusCode, Value) {
        let mut builder = Request::builder().method(method).uri(uri);
        if let Some(token) = bearer {
            builder = builder.header(header::AUTHORIZATION, format!("Bearer {token}"));
        }
        let body = match body {
            Some(value) => {
                builder = builder.header(header::CONTENT_TYPE, "application/json");
                Body::from(serde_json::to_vec(&value).expect("json body"))
            }
            None => Body::empty(),
        };
        let response = self
            .router
            .clone()
            .oneshot(builder.body(body).expect("request"))
            .await
            .expect("router responds");
        let status = response.status();
        let bytes = response
            .into_body()
            .collect()
            .await
            .expect("body collected")
            .to_bytes();
        let value = if bytes.is_empty() {
            Value::Null
        } else {
            serde_json::from_slice(&bytes).expect("json response")
        };
        (status, value)
    }

    pub async fn issue_token(&self, owner_id: &str) -> String {
        self.issue_token_with_ttl(owner_id, 900).await
    }

    pub async fn issue_token_with_ttl(&self, owner_id: &str, ttl_seconds: i64) -> String {
        let (status, body) = self
            .request(
                Method::POST,
                "/api/enrollment-tokens",
                Some(ADMIN_TOKEN),
                Some(json!({ "owner_id": owner_id, "expires_in_seconds": ttl_seconds })),
            )
            .await;
        assert_eq!(status, StatusCode::CREATED, "issue token failed: {body}");
        body["token"].as_str().expect("token").to_owned()
    }

    pub async fn enroll_raw(&self, token: &str) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            "/api/devices/enroll",
            None,
            Some(json!({ "token": token })),
        )
        .await
    }

    pub async fn enroll_new(&self, owner_id: &str) -> (String, String) {
        let token = self.issue_token(owner_id).await;
        let (status, body) = self.enroll_raw(&token).await;
        assert_eq!(status, StatusCode::CREATED, "enroll failed: {body}");
        (
            body["device_id"].as_str().expect("device_id").to_owned(),
            body["credential"].as_str().expect("credential").to_owned(),
        )
    }

    pub async fn create_session_raw(
        &self,
        device_id: &str,
        bearer: Option<&str>,
    ) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            "/api/sessions",
            bearer,
            Some(json!({ "device_id": device_id })),
        )
        .await
    }

    pub async fn create_session(&self, device_id: &str) -> Value {
        let (status, body) = self.create_session_raw(device_id, Some(ADMIN_TOKEN)).await;
        assert_eq!(status, StatusCode::OK, "create session failed: {body}");
        body
    }

    pub async fn candidates(&self, session_id: &str, bearer: Option<&str>) -> (StatusCode, Value) {
        self.request(
            Method::GET,
            &format!("/api/sessions/{session_id}/candidates"),
            bearer,
            None,
        )
        .await
    }

    pub async fn relay_upgrade(
        &self,
        session_id: &str,
        bearer: Option<&str>,
    ) -> (StatusCode, Value) {
        self.request(
            Method::POST,
            &format!("/api/sessions/{session_id}/relay"),
            bearer,
            None,
        )
        .await
    }
}
