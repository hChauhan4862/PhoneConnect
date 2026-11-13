//! PhoneConnect server: authorization authority, rendezvous service, and encrypted relay.
//!
//! The server authorizes every session before it issues a short-lived capability. Device
//! and session secrets are never stored in the clear, and relay frames are forwarded as
//! opaque bytes inside bounded in-memory queues.

#![deny(unsafe_code)]

pub mod admin;
pub mod auth;
pub mod enrollment;
pub mod relay;
pub mod rendezvous;
pub mod store;

use std::sync::Arc;

use axum::Json;
use axum::Router;
use axum::extract::{FromRequest, Request, rejection::JsonRejection};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::de::DeserializeOwned;
use serde_json::json;

pub use relay::PeerRole;

use auth::{AuthError, Authenticator};
use relay::{Relay, RelayLimits};
use rendezvous::{Rendezvous, TicketAuthority, TicketError};
use store::{Clock, DeviceStore};

/// Server-wide dependencies shared by the HTTP handlers.
pub struct AppState {
    pub store: Arc<dyn DeviceStore>,
    pub auth: Arc<Authenticator>,
    pub rendezvous: Arc<Rendezvous>,
    pub relay: Arc<Relay>,
    pub clock: Arc<dyn Clock>,
}

/// Startup failures. Both a missing admin token and an unavailable signature key stop the
/// server: neither can be replaced with a weaker fallback.
#[derive(Debug, thiserror::Error)]
pub enum AppStateError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Ticket(#[from] TicketError),
}

impl AppState {
    /// Builds the state from a store, bootstrap admin token, relay base endpoint, relay
    /// limits, and clock. The relay endpoint is the URL peers reach the relay through; one
    /// session's transport appends `/{session_id}/relay`.
    pub fn new(
        store: Arc<dyn DeviceStore>,
        admin_token: impl Into<String>,
        relay_endpoint: impl Into<String>,
        relay_limits: RelayLimits,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, AppStateError> {
        let relay_endpoint = relay_endpoint.into();
        let auth = Arc::new(Authenticator::new(
            Arc::clone(&store),
            admin_token,
            Arc::clone(&clock),
        )?);
        let relay = Arc::new(Relay::new(
            relay_endpoint.clone(),
            relay_limits,
            Arc::clone(&store),
            Arc::clone(&clock),
        ));
        let tickets = Arc::new(TicketAuthority::new()?);
        Ok(Self {
            store,
            auth,
            rendezvous: Arc::new(Rendezvous::new(relay_endpoint, tickets)),
            relay,
            clock,
        })
    }

    pub fn now_ms(&self) -> i64 {
        self.clock.now_ms()
    }
}

/// Explicit HTTP error. Responses never look like a success: the body always carries a
/// stable machine-readable code.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApiError {
    status: StatusCode,
    code: &'static str,
}

impl ApiError {
    pub fn new(status: StatusCode, code: &'static str) -> Self {
        Self { status, code }
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        (self.status, Json(json!({ "error": self.code }))).into_response()
    }
}

/// JSON request body that fails with the same `{"error": ...}` envelope as every other
/// rejection, so a client never has to guess whether a body problem is its fault.
pub struct ApiJson<T>(pub T);

impl<S, T> FromRequest<S> for ApiJson<T>
where
    T: DeserializeOwned,
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request(request: Request, state: &S) -> Result<Self, Self::Rejection> {
        let Json(value) =
            Json::<T>::from_request(request, state)
                .await
                .map_err(|rejection: JsonRejection| {
                    let code = match rejection {
                        JsonRejection::JsonSyntaxError(_) => "malformed_json",
                        JsonRejection::JsonDataError(_) => "invalid_request_body",
                        JsonRejection::MissingJsonContentType(_) => "unsupported_content_type",
                        _ => "malformed_request_body",
                    };
                    ApiError::new(rejection.status(), code)
                })?;
        Ok(Self(value))
    }
}

pub fn build_router(state: Arc<AppState>) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/api/enrollment-tokens", post(enrollment::issue_token))
        .route(
            "/api/enrollment-tokens/{token}/revoke",
            post(admin::revoke_enrollment_token),
        )
        .route("/api/devices/enroll", post(enrollment::enroll_device))
        .route(
            "/api/devices/{device_id}/revoke",
            post(admin::revoke_device),
        )
        .route("/api/sessions", post(rendezvous::create_session))
        .route(
            "/api/sessions/{session_id}/revoke",
            post(admin::revoke_session),
        )
        .route(
            "/api/sessions/{session_id}/ticket",
            get(rendezvous::session_ticket),
        )
        .route(
            "/api/sessions/{session_id}/candidates",
            get(rendezvous::session_candidates).post(rendezvous::register_candidate),
        )
        .route(
            "/api/sessions/{session_id}/relay",
            post(relay::upgrade_to_relay).get(relay::relay_socket),
        )
        .with_state(state)
}

async fn health() -> impl IntoResponse {
    Json(json!({ "status": "ok" }))
}
