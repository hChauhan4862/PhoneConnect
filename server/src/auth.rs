//! Credential handling and explicit authorization checks.
//!
//! Three credential classes exist and never substitute for each other:
//! - the bootstrap admin bearer token from `PHONECONNECT_ADMIN_TOKEN`,
//! - a device credential issued once at enrollment,
//! - a short-lived session capability minted per authorized session.
//!
//! Secrets are compared in constant time against stored SHA-256 hashes. A device
//! credential authenticates only its own device, and a session capability authorizes only
//! the session it was minted for.

use std::sync::Arc;

use axum::Json;
use axum::http::{HeaderMap, StatusCode, header};
use axum::response::{IntoResponse, Response};
use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use serde_json::json;
use sha2::{Digest, Sha256};
use subtle::ConstantTimeEq;

use crate::store::{Clock, DeviceRecord, DeviceStore, SessionRecord, UnixMs};

/// Environment variable holding the bootstrap admin bearer token.
pub const ADMIN_TOKEN_ENV: &str = "PHONECONNECT_ADMIN_TOKEN";

/// Prefix of a device credential issued by `POST /api/devices/enroll`.
pub const DEVICE_CREDENTIAL_PREFIX: &str = "pcdev_";

/// Prefix of a short-lived session capability issued by `POST /api/sessions`.
pub const SESSION_CAPABILITY_PREFIX: &str = "pcsess_";

const SECRET_BYTES: usize = 32;

/// Bytes in an X25519 identity public key.
pub const IDENTITY_KEY_BYTES: usize = 32;

/// Identity keys are pinned outside a session, so a malformed one is refused at the
/// surface that registers it rather than discovered when a path fails.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum IdentityKeyError {
    #[error("identity_key must be 32 bytes of unpadded base64url")]
    Malformed,
}

/// Validates and canonicalizes an identity public key. The server only ever sees public
/// halves; traffic keys are agreed between the peers.
pub fn normalize_identity_key(value: &str) -> Result<String, IdentityKeyError> {
    let bytes = URL_SAFE_NO_PAD
        .decode(value.trim().as_bytes())
        .map_err(|_| IdentityKeyError::Malformed)?;
    if bytes.len() != IDENTITY_KEY_BYTES {
        return Err(IdentityKeyError::Malformed);
    }
    Ok(URL_SAFE_NO_PAD.encode(bytes))
}

/// Reads the bootstrap admin token from the environment.
pub fn admin_token_from_env() -> Result<String, AuthError> {
    let token = std::env::var(ADMIN_TOKEN_ENV).map_err(|_| AuthError::MissingAdminToken)?;
    if token.trim().is_empty() {
        return Err(AuthError::MissingAdminToken);
    }
    Ok(token)
}

/// Lower-case SHA-256 of `secret`, the only form in which a secret is ever stored.
pub fn hash_secret(secret: &str) -> String {
    sha256(secret.as_bytes())
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect()
}

fn sha256(bytes: &[u8]) -> [u8; 32] {
    let digest = Sha256::digest(bytes);
    let mut output = [0u8; 32];
    output.copy_from_slice(&digest);
    output
}

/// Generates a prefixed, 256-bit random secret.
pub fn generate_secret(prefix: &str) -> Result<String, AuthError> {
    let mut bytes = [0u8; SECRET_BYTES];
    getrandom::fill(&mut bytes).map_err(|error| AuthError::Random(error.to_string()))?;
    Ok(format!("{prefix}{}", URL_SAFE_NO_PAD.encode(bytes)))
}

fn secrets_match(stored_hash: &str, presented: &str) -> bool {
    let presented_hash = hash_secret(presented);
    stored_hash
        .as_bytes()
        .ct_eq(presented_hash.as_bytes())
        .into()
}

/// Authorization failures. Every variant maps to one stable HTTP code.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AuthError {
    #[error("PHONECONNECT_ADMIN_TOKEN must be set to a non-empty secret")]
    MissingAdminToken,
    #[error("missing credentials")]
    MissingCredentials,
    #[error("malformed bearer credentials")]
    MalformedCredentials,
    #[error("invalid admin token")]
    InvalidAdminToken,
    #[error("invalid credential")]
    InvalidCredential,
    #[error("device {device_id} is revoked")]
    DeviceRevoked { device_id: String },
    #[error("session {session_id} is unknown")]
    UnknownSession { session_id: String },
    #[error("session {session_id} expired at {expires_at_ms}")]
    SessionExpired {
        session_id: String,
        expires_at_ms: UnixMs,
    },
    #[error("session {session_id} was revoked at {revoked_at_ms}")]
    SessionRevoked {
        session_id: String,
        revoked_at_ms: UnixMs,
    },
    #[error("credential does not authorize session {session_id}")]
    SessionScopeMismatch { session_id: String },
    #[error("random source failed: {0}")]
    Random(String),
    #[error("authorization state is unavailable: {0}")]
    StoreFailure(String),
}

impl AuthError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::MissingAdminToken => "admin_token_missing",
            Self::MissingCredentials => "missing_credentials",
            Self::MalformedCredentials => "malformed_credentials",
            Self::InvalidAdminToken => "invalid_admin_token",
            Self::InvalidCredential => "invalid_credential",
            Self::DeviceRevoked { .. } => "device_revoked",
            Self::UnknownSession { .. } => "session_unknown",
            Self::SessionExpired { .. } => "session_expired",
            Self::SessionRevoked { .. } => "session_revoked",
            Self::SessionScopeMismatch { .. } => "session_scope_mismatch",
            Self::Random(_) => "random_source_failed",
            Self::StoreFailure(_) => "store_failure",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::MissingAdminToken | Self::Random(_) | Self::StoreFailure(_) => {
                StatusCode::INTERNAL_SERVER_ERROR
            }
            Self::MissingCredentials
            | Self::MalformedCredentials
            | Self::InvalidAdminToken
            | Self::InvalidCredential
            | Self::DeviceRevoked { .. }
            | Self::SessionExpired { .. }
            | Self::SessionRevoked { .. } => StatusCode::UNAUTHORIZED,
            Self::SessionScopeMismatch { .. } => StatusCode::FORBIDDEN,
            Self::UnknownSession { .. } => StatusCode::NOT_FOUND,
        }
    }
}

impl IntoResponse for AuthError {
    fn into_response(self) -> Response {
        (self.status(), Json(json!({ "error": self.code() }))).into_response()
    }
}

/// Extracts the bearer token from an `Authorization` header.
pub fn bearer_token(headers: &HeaderMap) -> Result<&str, AuthError> {
    let value = headers
        .get(header::AUTHORIZATION)
        .ok_or(AuthError::MissingCredentials)?
        .to_str()
        .map_err(|_| AuthError::MalformedCredentials)?;
    let token = value
        .strip_prefix("Bearer ")
        .ok_or(AuthError::MalformedCredentials)?
        .trim();
    if token.is_empty() {
        return Err(AuthError::MalformedCredentials);
    }
    Ok(token)
}

/// Verifies credentials against persisted authorization state.
pub struct Authenticator {
    store: Arc<dyn DeviceStore>,
    admin_token_digest: [u8; 32],
    clock: Arc<dyn Clock>,
}

impl Authenticator {
    pub fn new(
        store: Arc<dyn DeviceStore>,
        admin_token: impl Into<String>,
        clock: Arc<dyn Clock>,
    ) -> Result<Self, AuthError> {
        let admin_token = admin_token.into();
        if admin_token.trim().is_empty() {
            return Err(AuthError::MissingAdminToken);
        }
        Ok(Self {
            store,
            admin_token_digest: sha256(admin_token.trim().as_bytes()),
            clock,
        })
    }

    pub fn now_ms(&self) -> UnixMs {
        self.clock.now_ms()
    }

    /// Accepts only the bootstrap admin token.
    pub fn require_admin(&self, headers: &HeaderMap) -> Result<(), AuthError> {
        let presented = bearer_token(headers)?;
        let digest = sha256(presented.as_bytes());
        if digest.ct_eq(&self.admin_token_digest).into() {
            Ok(())
        } else {
            Err(AuthError::InvalidAdminToken)
        }
    }

    /// Resolves a device credential, refusing revoked devices immediately.
    pub async fn require_device(&self, headers: &HeaderMap) -> Result<DeviceRecord, AuthError> {
        let presented = bearer_token(headers)?;
        if !presented.starts_with(DEVICE_CREDENTIAL_PREFIX) {
            return Err(AuthError::InvalidCredential);
        }
        let presented_hash = hash_secret(presented);
        let record = self
            .store
            .device_by_credential(&presented_hash)
            .await
            .map_err(store_failure)?
            .ok_or(AuthError::InvalidCredential)?;
        if !secrets_match(&record.credential_hash, presented) {
            return Err(AuthError::InvalidCredential);
        }
        if record.is_revoked() {
            return Err(AuthError::DeviceRevoked {
                device_id: record.device_id,
            });
        }
        Ok(record)
    }

    /// Resolves a session capability that must have been minted for `session_id`.
    pub async fn require_session(
        &self,
        headers: &HeaderMap,
        session_id: &str,
    ) -> Result<SessionRecord, AuthError> {
        let presented = bearer_token(headers)?;
        if !presented.starts_with(SESSION_CAPABILITY_PREFIX) {
            return Err(AuthError::InvalidCredential);
        }
        let presented_hash = hash_secret(presented);
        let session = self
            .store
            .session_by_capability(&presented_hash)
            .await
            .map_err(store_failure)?
            .ok_or(AuthError::InvalidCredential)?;
        if !secrets_match(&session.capability_hash, presented) {
            return Err(AuthError::InvalidCredential);
        }
        if session.session_id != session_id {
            return Err(AuthError::SessionScopeMismatch {
                session_id: session_id.to_owned(),
            });
        }
        self.check_session_active(&session)?;
        Ok(session)
    }

    /// Authorizes either peer of `session_id`: the session capability, or the credential
    /// of the device that owns the session.
    pub async fn authorize_session_access(
        &self,
        headers: &HeaderMap,
        session_id: &str,
    ) -> Result<SessionRecord, AuthError> {
        let presented = bearer_token(headers)?;
        if presented.starts_with(SESSION_CAPABILITY_PREFIX) {
            return self.require_session(headers, session_id).await;
        }
        if !presented.starts_with(DEVICE_CREDENTIAL_PREFIX) {
            return Err(AuthError::InvalidCredential);
        }

        let device = self.require_device(headers).await?;
        let session = self.session_record(session_id).await?;
        if session.device_id != device.device_id {
            return Err(AuthError::SessionScopeMismatch {
                session_id: session.session_id,
            });
        }
        self.check_session_active(&session)?;
        Ok(session)
    }

    async fn session_record(&self, session_id: &str) -> Result<SessionRecord, AuthError> {
        self.store
            .session(session_id)
            .await
            .map_err(|error| match error {
                crate::store::StoreError::UnknownSession { .. } => AuthError::UnknownSession {
                    session_id: session_id.to_owned(),
                },
                other => store_failure(other),
            })
    }

    fn check_session_active(&self, session: &SessionRecord) -> Result<(), AuthError> {
        if let Some(revoked_at_ms) = session.revoked_at_ms {
            return Err(AuthError::SessionRevoked {
                session_id: session.session_id.clone(),
                revoked_at_ms,
            });
        }
        if session.is_expired(self.now_ms()) {
            return Err(AuthError::SessionExpired {
                session_id: session.session_id.clone(),
                expires_at_ms: session.expires_at_ms,
            });
        }
        Ok(())
    }
}

fn store_failure(error: crate::store::StoreError) -> AuthError {
    // Persistence failures must never read as authorization successes.
    AuthError::StoreFailure(error.to_string())
}
