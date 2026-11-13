//! Operational revocation.
//!
//! An admin can end an enrollment token, a device, or a session before it expires.
//! Revocation is idempotent, and revoking a session or device also closes that relay in
//! this process, so attached peers stop forwarding without waiting for the next frame.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::Serialize;
use serde_json::json;

use crate::AppState;
use crate::auth::{AuthError, hash_secret};
use crate::relay::RelayClose;
use crate::store::{StoreError, UnixMs};

/// Result of a revocation request. The revoked secret is never echoed back.
#[derive(Debug, Serialize)]
pub struct Revocation {
    pub revoked: bool,
    pub revoked_at: UnixMs,
}

#[derive(Debug, thiserror::Error)]
pub enum RevocationError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl IntoResponse for RevocationError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Auth(error) => return error.clone().into_response(),
            Self::Store(StoreError::UnknownDevice { .. }) => {
                (StatusCode::NOT_FOUND, "device_unknown")
            }
            Self::Store(StoreError::UnknownSession { .. }) => {
                (StatusCode::NOT_FOUND, "session_unknown")
            }
            Self::Store(StoreError::UnknownEnrollmentToken) => {
                (StatusCode::NOT_FOUND, "enrollment_token_unknown")
            }
            Self::Store(_) => (StatusCode::INTERNAL_SERVER_ERROR, "store_failure"),
        };
        (status, Json(json!({ "error": code }))).into_response()
    }
}

/// `POST /api/devices/{id}/revoke`: revokes the device, its live sessions, and its relays.
pub async fn revoke_device(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Revocation>, RevocationError> {
    state.auth.require_admin(&headers)?;
    let revoked_at = state
        .store
        .revoke_device(&device_id, state.now_ms())
        .await?;
    state.relay.close_device(
        &device_id,
        RelayClose::DeviceRevoked {
            device_id: device_id.clone(),
        },
    );
    Ok(Json(Revocation {
        revoked: true,
        revoked_at,
    }))
}

/// `POST /api/sessions/{id}/revoke`: revokes the session and closes its relay.
pub async fn revoke_session(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Revocation>, RevocationError> {
    state.auth.require_admin(&headers)?;
    let revoked_at = state
        .store
        .revoke_session(&session_id, state.now_ms())
        .await?;
    state
        .relay
        .close_session(&session_id, RelayClose::SessionRevoked);
    Ok(Json(Revocation {
        revoked: true,
        revoked_at,
    }))
}

/// `POST /api/enrollment-tokens/{token}/revoke`: revokes one unused enrollment token.
pub async fn revoke_enrollment_token(
    State(state): State<Arc<AppState>>,
    Path(token): Path<String>,
    headers: HeaderMap,
) -> Result<Json<Revocation>, RevocationError> {
    state.auth.require_admin(&headers)?;
    let revoked_at = state
        .store
        .revoke_enrollment_token(&hash_secret(token.trim()), state.now_ms())
        .await?;
    Ok(Json(Revocation {
        revoked: true,
        revoked_at,
    }))
}
