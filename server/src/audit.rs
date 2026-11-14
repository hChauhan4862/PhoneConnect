//! The audit surface: every command attempt and every revocation, newest first.
//!
//! The log is append-only. Writers record an event where it happens — a dispatch attempt in
//! [`crate::commands`], an administrative revocation in [`crate::admin`] or
//! [`crate::leases`] — and this module reads it back, filtered and bounded. A row carries
//! identity, the action, the outcome, and a machine error code only: never a command
//! argument, a file path, a file byte, or an image.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Deserialize;
use serde_json::json;

use crate::AppState;
use crate::auth::AuthError;
use crate::store::{AuditEntry, StoreError};

/// The most rows one request may return. The store itself allows a larger internal page;
/// the HTTP surface never hands a caller more than this.
pub const MAX_AUDIT_LIMIT: usize = 200;

/// The page a caller that names no `limit` receives.
pub const DEFAULT_AUDIT_LIMIT: usize = 50;

/// Revocations are administrative: the bootstrap token carries no user identity, so the
/// actor of a device or session revocation is the token class itself.
pub const ADMIN_ACTOR: &str = "admin";

pub const ACTION_DEVICE_REVOKE: &str = "device.revoke";
pub const ACTION_SESSION_REVOKE: &str = "session.revoke";
pub const ACTION_LEASE_REVOKE: &str = "lease.revoke";
pub const ACTION_LEASE_HANDOFF: &str = "lease.handoff";

/// `GET /api/audit?device_id=&limit=`: newest-first audit rows, for one device when a filter
/// is named. A device id that never enrolled is an empty list, never another device's rows.
pub async fn list_audit(
    State(state): State<Arc<AppState>>,
    Query(query): Query<AuditQuery>,
    headers: HeaderMap,
) -> Result<Json<Vec<AuditEntry>>, AuditError> {
    state.auth.require_admin(&headers)?;
    let device_id = requested_device(&query)?;
    let limit = requested_limit(&query)?;
    let entries = state
        .store
        .list_audit(device_id.as_deref(), limit)
        .await
        .map_err(AuditError::from)?;
    Ok(Json(entries))
}

/// Records one accepted revocation. The event already happened, so a failed audit write is
/// reported operationally and never turns the revocation into an error.
pub async fn record_revocation(state: &AppState, actor: &str, action: &str, device_id: &str) {
    let entry = AuditEntry {
        at_ms: state.now_ms(),
        actor: actor.to_owned(),
        action: action.to_owned(),
        device_id: device_id.to_owned(),
        outcome: "accepted".to_owned(),
        error: None,
    };
    if let Err(error) = state.store.insert_audit(entry).await {
        eprintln!("phoneconnect: revocation audit write failed: {error}");
    }
}

#[derive(Debug, Deserialize)]
pub struct AuditQuery {
    /// Omitted means every device. Present-but-blank is refused, not widened to "everything".
    #[serde(default)]
    pub device_id: Option<String>,
    /// A decimal page size. Above [`MAX_AUDIT_LIMIT`] it is capped; zero, negative, or
    /// non-numeric is refused rather than silently changed.
    #[serde(default)]
    pub limit: Option<String>,
}

fn requested_device(query: &AuditQuery) -> Result<Option<String>, AuditError> {
    match query.device_id.as_deref() {
        None => Ok(None),
        Some(value) => {
            let value = value.trim();
            if value.is_empty() {
                return Err(AuditError::InvalidRequest {
                    reason: "device_id must not be empty",
                });
            }
            Ok(Some(value.to_owned()))
        }
    }
}

fn requested_limit(query: &AuditQuery) -> Result<usize, AuditError> {
    let Some(value) = query.limit.as_deref() else {
        return Ok(DEFAULT_AUDIT_LIMIT);
    };
    let parsed = value
        .trim()
        .parse::<i64>()
        .map_err(|_| AuditError::InvalidRequest {
            reason: "limit must be a positive integer",
        })?;
    if parsed < 1 {
        return Err(AuditError::InvalidRequest {
            reason: "limit must be a positive integer",
        });
    }
    Ok(usize::try_from(parsed)
        .unwrap_or(MAX_AUDIT_LIMIT)
        .min(MAX_AUDIT_LIMIT))
}

#[derive(Debug, thiserror::Error)]
pub enum AuditError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("invalid audit query: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("the audit log is unavailable: {0}")]
    StoreFailure(String),
}

impl From<StoreError> for AuditError {
    fn from(error: StoreError) -> Self {
        Self::StoreFailure(error.to_string())
    }
}

impl IntoResponse for AuditError {
    fn into_response(self) -> Response {
        match self {
            Self::Auth(error) => error.into_response(),
            Self::InvalidRequest { .. } => (
                StatusCode::BAD_REQUEST,
                Json(json!({ "error": "invalid_request" })),
            )
                .into_response(),
            Self::StoreFailure(_) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({ "error": "store_failure" })),
            )
                .into_response(),
        }
    }
}
