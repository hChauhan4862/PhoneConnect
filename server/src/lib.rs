//! PhoneConnect server: authorization authority, rendezvous service, and encrypted relay.
//!
//! The server authorizes every session before it issues a short-lived capability. Device
//! and session secrets are never stored in the clear, and relay frames are forwarded as
//! opaque bytes inside bounded in-memory queues.

#![deny(unsafe_code)]

pub mod admin;
pub mod apps;
pub mod audit;
pub mod auth;
pub mod commands;
pub mod config;
pub mod console;
pub mod controls;
pub mod enrollment;
pub mod files;
pub mod leases;
pub mod management;
pub mod relay;
pub mod rendezvous;
pub mod retention;
pub mod screen;
pub mod signing_key;
pub mod status;
pub mod store;
pub mod telemetry;
pub mod web;

use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};

use axum::Json;
use axum::Router;
use axum::extract::{FromRequest, Request, State, rejection::JsonRejection};
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::routing::{get, post};
use serde::de::DeserializeOwned;
use serde_json::json;

pub use relay::PeerRole;

use auth::{AuthError, Authenticator};
use leases::LeaseStore;
use management::DeviceRegistry;
use relay::{Relay, RelayLimits};
use rendezvous::{Rendezvous, TicketAuthority, TicketError};
use store::{Clock, DeviceStore};
use telemetry::TelemetryAggregator;

/// Server-wide dependencies shared by the HTTP handlers.
pub struct AppState {
    pub store: Arc<dyn DeviceStore>,
    pub auth: Arc<Authenticator>,
    pub rendezvous: Arc<Rendezvous>,
    pub relay: Arc<Relay>,
    pub leases: Arc<LeaseStore>,
    pub telemetry: Arc<TelemetryAggregator>,
    /// The management channel: one authenticated device connection per device and the
    /// bounded in-flight command table commands are dispatched through.
    pub management: Arc<DeviceRegistry>,
    pub clock: Arc<dyn Clock>,
    /// Audit rows are written after the action is resolved and are best-effort. This counts
    /// the writes that failed, so an untraced attempt — accepted, refused, or an outcome the
    /// device never answered — is visible in `/health` instead of only on stderr.
    audit_write_failures: Arc<AtomicU64>,
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
        Self::with_tickets(
            store,
            admin_token,
            relay_endpoint,
            relay_limits,
            clock,
            Arc::new(TicketAuthority::new()?),
        )
    }

    /// Builds the state with a caller-supplied ticket authority, so a deployment can persist
    /// its signing key instead of generating a new one on every start.
    pub fn with_tickets(
        store: Arc<dyn DeviceStore>,
        admin_token: impl Into<String>,
        relay_endpoint: impl Into<String>,
        relay_limits: RelayLimits,
        clock: Arc<dyn Clock>,
        tickets: Arc<TicketAuthority>,
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
        let leases = Arc::new(LeaseStore::new(
            Arc::clone(&store),
            Arc::clone(&relay),
            Arc::clone(&clock),
        ));
        let telemetry = Arc::new(TelemetryAggregator::new(Arc::clone(&clock)));
        let audit_write_failures = Arc::new(AtomicU64::new(0));
        // The registry writes `command.outcome` rows on the same store path and the same
        // failure counter, so a command that ends without a device answer is as traceable as
        // its dispatch.
        let management = Arc::new(DeviceRegistry::new(
            Arc::clone(&clock),
            Arc::clone(&store),
            Arc::clone(&audit_write_failures),
        ));
        Ok(Self {
            store,
            auth,
            rendezvous: Arc::new(Rendezvous::new(relay_endpoint, tickets)),
            relay,
            leases,
            telemetry,
            management,
            clock,
            audit_write_failures,
        })
    }

    pub fn now_ms(&self) -> i64 {
        self.clock.now_ms()
    }

    /// Records one failed best-effort audit write. The action it describes already happened,
    /// so this is an operational signal, never a change to the caller's outcome.
    pub fn note_audit_write_failure(&self) -> u64 {
        self.audit_write_failures.fetch_add(1, Ordering::Relaxed) + 1
    }

    /// How many best-effort audit writes have failed since this process started.
    pub fn audit_write_failures(&self) -> u64 {
        self.audit_write_failures.load(Ordering::Relaxed)
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
        .route("/api/devices", get(status::list_devices))
        .route(
            "/api/devices/{device_id}/status",
            get(status::device_status),
        )
        .route(
            "/api/devices/{device_id}/telemetry",
            post(telemetry::ingest_telemetry),
        )
        // The management channel: telemetry and commands over one authenticated device
        // WebSocket, and the HTTP surface the one web UI dispatches through.
        .route(
            "/api/devices/{device_id}/control",
            get(management::control_socket),
        )
        .route(
            "/api/devices/{device_id}/commands",
            post(commands::dispatch_command),
        )
        .route("/api/commands/{command_id}", get(commands::command_state))
        // The audit trace: every dispatch attempt and every revocation. Read-only; there is
        // no endpoint that changes or deletes a row (retention deletes by age).
        .route("/api/audit", get(audit::list_audit))
        // File operations are commands with a typed front door: the server authorizes,
        // bounds, and forwards, and the device's path guard is the safety authority.
        .route(
            "/api/devices/{device_id}/files/list",
            post(files::list_files),
        )
        .route(
            "/api/devices/{device_id}/files/read",
            post(files::read_file),
        )
        .route(
            "/api/devices/{device_id}/files/write",
            post(files::write_file),
        )
        .route(
            "/api/devices/{device_id}/files/mkdir",
            post(files::make_directory),
        )
        .route(
            "/api/devices/{device_id}/files/delete",
            post(files::delete_entry),
        )
        .route(
            "/api/devices/{device_id}/files/rename",
            post(files::rename_entry),
        )
        // App operations are commands with a typed front door too. The device decides what
        // its platform permits; the server forwards and never invents an app.
        .route("/api/devices/{device_id}/apps/list", post(apps::list_apps))
        .route(
            "/api/devices/{device_id}/apps/launch",
            post(apps::launch_app),
        )
        .route("/api/devices/{device_id}/apps/stop", post(apps::stop_app))
        .route("/api/devices/{device_id}/apps/clear", post(apps::clear_app))
        .route(
            "/api/devices/{device_id}/apps/set_enabled",
            post(apps::set_app_enabled),
        )
        // Screen capture and the console: one real capability and two documented refusals.
        // The device decides whether it holds a projection; the server forwards and bounds.
        .route(
            "/api/devices/{device_id}/screen/snapshot",
            post(screen::snapshot_screen),
        )
        .route(
            "/api/devices/{device_id}/console/props",
            post(console::read_properties),
        )
        .route(
            "/api/devices/{device_id}/console/shell",
            post(console::run_shell),
        )
        .route(
            "/api/devices/{device_id}/console/logcat",
            post(console::tail_logcat),
        )
        // Device control: the readings the device can produce, the three changes it can make,
        // and the constant refusals for everything Android removed or made signature-level.
        .route(
            "/api/devices/{device_id}/control/get",
            post(controls::read_controls),
        )
        .route(
            "/api/devices/{device_id}/control/set",
            post(controls::set_control),
        )
        .route(
            "/api/devices/{device_id}/control/reboot",
            post(controls::reboot_device),
        )
        .route(
            "/api/devices/{device_id}/lease",
            post(leases::acquire_lease).get(leases::lease_status),
        )
        .route(
            "/api/devices/{device_id}/lease/handoff",
            post(leases::handoff_lease),
        )
        .route("/api/leases/{lease_id}/revoke", post(leases::revoke_lease))
        .route(
            "/api/devices/{device_id}/revoke",
            post(admin::revoke_device),
        )
        // A device credential learns which session a client authorized for it, with a
        // device-role ticket. A device never sees another device's sessions.
        .route(
            "/api/devices/{device_id}/sessions/next",
            get(rendezvous::device_session),
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

/// Liveness plus the one operational counter this server keeps: best-effort audit writes that
/// failed. A non-zero count means an executed command may be untraced.
async fn health(State(state): State<Arc<AppState>>) -> impl IntoResponse {
    Json(json!({
        "status": "ok",
        "audit_write_failures": state.audit_write_failures(),
    }))
}
