//! The command HTTP surface: who may command a device, what happens when it cannot, and the
//! durable audit trace.
//!
//! A command is authorized by the admin bearer token (this milestone) *and* the actor's
//! access to the device: its owner, or the holder of the active control lease. Refusals fail
//! fast and explicitly — `409 device_revoked`, `409 device_offline`, `403 lease_read_only` —
//! so a caller never waits on a device that cannot answer.
//!
//! The command table itself is in memory and bounded (see [`crate::management`]); only the
//! audit row is durable. Every dispatch attempt writes one row, accepted or refused.
//!
//! The actor comes from the `user_id` query parameter, matching the status and lease routes:
//! the bootstrap admin token carries no user identity of its own.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::{Value, json};

use crate::auth::AuthError;
use crate::leases::LeaseError;
use crate::management::{CommandRecord, Dispatch, DispatchError};
use crate::store::{AuditEntry, StoreError};
use crate::{ApiJson, AppState};

/// The audit action one dispatch attempt records.
pub const AUDIT_ACTION_DISPATCH: &str = "command.dispatch";

/// `POST /api/devices/{id}/commands?user_id=...`
#[derive(Debug, Deserialize)]
pub struct DispatchCommandRequest {
    pub name: String,
    #[serde(default)]
    pub args: Option<Value>,
    #[serde(default)]
    pub timeout_ms: Option<i64>,
}

/// The actor every command call must name, because the admin token has no identity.
#[derive(Debug, Deserialize)]
pub struct CommandQuery {
    #[serde(default)]
    pub user_id: Option<String>,
}

/// One command's acceptance. The id is what the caller polls.
#[derive(Debug, serde::Serialize)]
pub struct CommandAccepted {
    pub command_id: String,
}

/// Explicit command failures. None of them is shaped like a success.
#[derive(Debug, thiserror::Error)]
pub enum CommandError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Lease(#[from] LeaseError),
    #[error("device {device_id} is unknown")]
    DeviceUnknown { device_id: String },
    #[error("device {device_id} is revoked")]
    DeviceRevoked { device_id: String },
    #[error("device {device_id} has no management channel")]
    DeviceOffline { device_id: String },
    #[error("device {device_id} already has {limit} commands in flight")]
    Capacity { device_id: String, limit: usize },
    #[error("timeout_ms is out of range")]
    InvalidTimeout,
    #[error("command name is invalid")]
    InvalidName,
    #[error("invalid command request: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("command {command_id} is unknown")]
    CommandUnknown { command_id: String },
    #[error("command creation is throttled; retry in {retry_after_ms}ms")]
    RateLimited { retry_after_ms: i64 },
    #[error("the audit trace is unavailable: {0}")]
    StoreFailure(String),
}

impl CommandError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Auth(error) => error.code(),
            Self::Lease(error) => error.code(),
            Self::DeviceUnknown { .. } => "device_unknown",
            Self::DeviceRevoked { .. } => "device_revoked",
            Self::DeviceOffline { .. } => "device_offline",
            Self::Capacity { .. } => "command_capacity",
            Self::InvalidTimeout => "invalid_timeout",
            Self::InvalidName => "invalid_command_name",
            Self::InvalidRequest { .. } => "invalid_request",
            Self::CommandUnknown { .. } => "command_unknown",
            Self::RateLimited { .. } => "rate_limited",
            Self::StoreFailure(_) => "store_failure",
        }
    }

    fn status(&self) -> StatusCode {
        match self {
            Self::Auth(error) => error.status(),
            Self::Lease(error) => error.status(),
            Self::DeviceUnknown { .. } | Self::CommandUnknown { .. } => StatusCode::NOT_FOUND,
            Self::DeviceRevoked { .. } | Self::DeviceOffline { .. } => StatusCode::CONFLICT,
            Self::Capacity { .. } | Self::RateLimited { .. } => StatusCode::TOO_MANY_REQUESTS,
            Self::InvalidTimeout | Self::InvalidName | Self::InvalidRequest { .. } => {
                StatusCode::BAD_REQUEST
            }
            Self::StoreFailure(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for CommandError {
    fn into_response(self) -> Response {
        let status = self.status();
        // A throttled caller is told when the budget refills; every other refusal is the
        // same `{"error": code}` envelope as the rest of the API.
        let retry_after_seconds = match &self {
            Self::RateLimited { retry_after_ms } => Some(((*retry_after_ms + 999) / 1_000).max(1)),
            _ => None,
        };
        let mut response = (status, Json(json!({ "error": self.code() }))).into_response();
        if let Some(seconds) = retry_after_seconds {
            if let Ok(value) = axum::http::HeaderValue::from_str(&seconds.to_string()) {
                response
                    .headers_mut()
                    .insert(axum::http::header::RETRY_AFTER, value);
            }
        }
        response
    }
}

impl From<StoreError> for CommandError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::UnknownDevice { device_id } => Self::DeviceUnknown { device_id },
            StoreError::DeviceRevoked { device_id } => Self::DeviceRevoked { device_id },
            other => Self::StoreFailure(other.to_string()),
        }
    }
}

impl From<DispatchError> for CommandError {
    fn from(error: DispatchError) -> Self {
        match error {
            DispatchError::Offline { device_id } => Self::DeviceOffline { device_id },
            DispatchError::Capacity { device_id, limit } => Self::Capacity { device_id, limit },
            DispatchError::InvalidTimeout => Self::InvalidTimeout,
            DispatchError::InvalidName => Self::InvalidName,
            DispatchError::RateLimited { retry_after_ms } => Self::RateLimited { retry_after_ms },
            DispatchError::Internal => {
                Self::StoreFailure("command id was not generated".to_owned())
            }
        }
    }
}

fn required_user(query: &CommandQuery) -> Result<String, CommandError> {
    query
        .user_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(CommandError::InvalidRequest {
            reason: "user_id query parameter is required",
        })
}

/// `POST /api/devices/{id}/commands?user_id=...`: dispatch one command to a connected device.
pub async fn dispatch_command(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<DispatchCommandRequest>,
) -> Result<(StatusCode, Json<CommandAccepted>), CommandError> {
    state.auth.require_admin(&headers)?;
    let actor = required_user(&query)?;

    let outcome = dispatch_for(&state, &device_id, &actor, &request).await;
    record_attempt(&state, &device_id, &actor, &outcome).await;
    let dispatch = outcome?;
    Ok((
        StatusCode::ACCEPTED,
        Json(CommandAccepted {
            command_id: dispatch.command_id,
        }),
    ))
}

async fn dispatch_for(
    state: &AppState,
    device_id: &str,
    actor: &str,
    request: &DispatchCommandRequest,
) -> Result<Dispatch, CommandError> {
    let device = state.store.device(device_id).await?;
    if device.is_revoked() {
        return Err(CommandError::DeviceRevoked {
            device_id: device.device_id,
        });
    }
    // Control is explicit: the owner, or the holder of the active lease. A viewer never
    // dispatches anything.
    let access = state.leases.access(&device.device_id, actor).await?;
    if !(access.is_owner || access.can_control) {
        return Err(CommandError::Lease(LeaseError::ReadOnly {
            device_id: device.device_id,
            user_id: actor.to_owned(),
        }));
    }
    Ok(state.management.dispatch(
        &device.device_id,
        &request.name,
        request.args.clone(),
        request.timeout_ms,
    )?)
}

/// Writes the durable trace for one attempt. A refused attempt is as traceable as an
/// accepted one; an audit failure is reported operationally, never as the command's outcome.
async fn record_attempt(
    state: &AppState,
    device_id: &str,
    actor: &str,
    outcome: &Result<Dispatch, CommandError>,
) {
    let (outcome_label, error) = match outcome {
        Ok(_) => ("accepted", None),
        Err(error) => ("refused", Some(error.code().to_owned())),
    };
    let entry = AuditEntry {
        at_ms: state.now_ms(),
        actor: actor.to_owned(),
        action: AUDIT_ACTION_DISPATCH.to_owned(),
        device_id: device_id.to_owned(),
        outcome: outcome_label.to_owned(),
        error,
    };
    if let Err(error) = state.store.insert_audit(entry).await {
        eprintln!("phoneconnect: command audit write failed: {error}");
    }
}

/// `GET /api/commands/{id}?user_id=...`: one command's state.
///
/// A command id is not a capability: reading a record requires the same control of the
/// device that dispatching it does.
pub async fn command_state(
    State(state): State<Arc<AppState>>,
    Path(command_id): Path<String>,
    Query(query): Query<CommandQuery>,
    headers: HeaderMap,
) -> Result<Json<CommandRecord>, CommandError> {
    state.auth.require_admin(&headers)?;
    let actor = required_user(&query)?;
    let record =
        state
            .management
            .command(&command_id)
            .ok_or_else(|| CommandError::CommandUnknown {
                command_id: command_id.clone(),
            })?;

    let device = state.store.device(&record.device_id).await?;
    if device.owner_id != actor {
        let access = state.leases.access(&device.device_id, &actor).await?;
        if !access.can_control {
            return Err(CommandError::Lease(LeaseError::ReadOnly {
                device_id: device.device_id,
                user_id: actor,
            }));
        }
    }
    Ok(Json(record))
}
