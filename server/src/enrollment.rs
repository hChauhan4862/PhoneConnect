//! One-time enrollment tokens and device enrollment.
//!
//! Only an admin can mint a token, and only the holder of a live token can enroll once.
//! The token is consumed and the device created in one store transaction, so a token can
//! never enroll two devices even under concurrent requests.

use std::sync::Arc;

use axum::Json;
use axum::extract::State;
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::{AuthError, DEVICE_CREDENTIAL_PREFIX, generate_secret, hash_secret};
use crate::store::{EnrollmentTokenRecord, NewDevice, StoreError, UnixMs};
use crate::{ApiJson, AppState};

/// Prefix of a server-issued enrollment token.
pub const ENROLLMENT_TOKEN_PREFIX: &str = "pcenr_";

/// Default lifetime of an enrollment token.
pub const ENROLLMENT_TOKEN_TTL_SECONDS: i64 = 900;

/// Longest enrollment token lifetime an operator may request.
pub const MAX_ENROLLMENT_TOKEN_TTL_SECONDS: i64 = 3_600;

#[derive(Debug, Deserialize)]
pub struct IssueEnrollmentTokenRequest {
    pub owner_id: String,
    #[serde(default)]
    pub expires_in_seconds: Option<i64>,
}

/// The only two fields a caller needs: the token and when it stops working.
#[derive(Debug, Serialize)]
pub struct IssuedEnrollmentToken {
    pub token: String,
    pub expires_at: UnixMs,
}

#[derive(Debug, Deserialize)]
pub struct EnrollDeviceRequest {
    pub token: String,
}

#[derive(Debug, Serialize)]
pub struct EnrolledDevice {
    pub device_id: String,
    pub credential: String,
}

#[derive(Debug, thiserror::Error)]
pub enum EnrollmentError {
    #[error("invalid request: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("enrollment token is unknown")]
    TokenUnknown,
    #[error("enrollment token expired at {expires_at_ms}")]
    TokenExpired { expires_at_ms: UnixMs },
    #[error("enrollment token was already used")]
    TokenUsed,
    #[error("enrollment token was revoked")]
    TokenRevoked,
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Store(#[from] StoreError),
}

impl IntoResponse for EnrollmentError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::InvalidRequest { .. } => (StatusCode::BAD_REQUEST, "invalid_request"),
            Self::TokenUnknown => (StatusCode::UNAUTHORIZED, "enrollment_token_unknown"),
            Self::TokenExpired { .. } => (StatusCode::GONE, "enrollment_token_expired"),
            Self::TokenUsed => (StatusCode::CONFLICT, "enrollment_token_used"),
            Self::TokenRevoked => (StatusCode::UNAUTHORIZED, "enrollment_token_revoked"),
            Self::Auth(error) => return error.clone().into_response(),
            Self::Store(_) => (StatusCode::INTERNAL_SERVER_ERROR, "store_failure"),
        };
        (status, Json(json!({ "error": code }))).into_response()
    }
}

fn enrollment_error(error: StoreError) -> EnrollmentError {
    match error {
        StoreError::UnknownEnrollmentToken => EnrollmentError::TokenUnknown,
        StoreError::EnrollmentTokenExpired { expires_at_ms } => {
            EnrollmentError::TokenExpired { expires_at_ms }
        }
        StoreError::EnrollmentTokenConsumed => EnrollmentError::TokenUsed,
        StoreError::EnrollmentTokenRevoked => EnrollmentError::TokenRevoked,
        other => EnrollmentError::Store(other),
    }
}

/// `POST /api/enrollment-tokens`: mints a single-use token for one owner.
pub async fn issue_token(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<IssueEnrollmentTokenRequest>,
) -> Result<(StatusCode, Json<IssuedEnrollmentToken>), EnrollmentError> {
    state.auth.require_admin(&headers)?;

    let owner_id = request.owner_id.trim();
    if owner_id.is_empty() {
        return Err(EnrollmentError::InvalidRequest {
            reason: "owner_id must not be empty",
        });
    }
    let ttl_seconds = request
        .expires_in_seconds
        .unwrap_or(ENROLLMENT_TOKEN_TTL_SECONDS);
    if !(1..=MAX_ENROLLMENT_TOKEN_TTL_SECONDS).contains(&ttl_seconds) {
        return Err(EnrollmentError::InvalidRequest {
            reason: "expires_in_seconds must be between 1 and 3600",
        });
    }

    let token = generate_secret(ENROLLMENT_TOKEN_PREFIX)?;
    let now = state.now_ms();
    let expires_at = now + ttl_seconds * 1_000;
    state
        .store
        .insert_enrollment_token(EnrollmentTokenRecord {
            token_hash: hash_secret(&token),
            owner_id: owner_id.to_owned(),
            created_at_ms: now,
            expires_at_ms: expires_at,
        })
        .await?;

    Ok((
        StatusCode::CREATED,
        Json(IssuedEnrollmentToken { token, expires_at }),
    ))
}

/// `POST /api/devices/enroll`: consumes a token once and returns a device credential.
pub async fn enroll_device(
    State(state): State<Arc<AppState>>,
    ApiJson(request): ApiJson<EnrollDeviceRequest>,
) -> Result<(StatusCode, Json<EnrolledDevice>), EnrollmentError> {
    let token = request.token.trim();
    if token.is_empty() {
        return Err(EnrollmentError::InvalidRequest {
            reason: "token must not be empty",
        });
    }
    if !token.starts_with(ENROLLMENT_TOKEN_PREFIX) {
        return Err(EnrollmentError::TokenUnknown);
    }

    let now = state.now_ms();
    let credential = generate_secret(DEVICE_CREDENTIAL_PREFIX)?;
    let device_id = format!("dev_{}", generate_secret("")?);
    let device = state
        .store
        .consume_enrollment_token(
            &hash_secret(token),
            now,
            NewDevice {
                device_id,
                credential_hash: hash_secret(&credential),
                enrolled_at_ms: now,
            },
        )
        .await
        .map_err(enrollment_error)?;

    Ok((
        StatusCode::CREATED,
        Json(EnrolledDevice {
            device_id: device.device_id,
            credential,
        }),
    ))
}
