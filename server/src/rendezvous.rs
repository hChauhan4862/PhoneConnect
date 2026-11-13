//! Session authorization and rendezvous data.
//!
//! The server authorizes a user before minting a short-lived session capability, and it is
//! the only source of candidate endpoints. Task 3 extends [`Rendezvous::candidates`] with
//! direct-path discovery; the authorization, expiry, and revocation checks stay here.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::{AuthError, generate_secret, hash_secret};
use crate::store::{SessionRecord, StoreError, UnixMs};
use crate::{ApiJson, AppState};

/// Prefix of a server-issued session identifier.
pub const SESSION_ID_PREFIX: &str = "sess_";

/// Sessions are short-lived; they are rejected rather than refreshed after this window.
pub const SESSION_TTL_MS: UnixMs = 300_000;

/// What a candidate endpoint can be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    /// The server relay; always available, bounded, end-to-end encrypted.
    Relay,
    /// A locally discovered address for one peer.
    Local,
    /// An address the server observed for one peer.
    ServerObserved,
}

/// One endpoint a peer may attempt, highest `priority` first.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct EndpointCandidate {
    pub kind: CandidateKind,
    pub endpoint: String,
    pub priority: u8,
}

/// Rendezvous data both peers receive for the same session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionCandidates {
    pub session_id: String,
    pub expires_at: UnixMs,
    pub candidates: Vec<EndpointCandidate>,
}

/// Short-lived ticket binding a session to one rendezvous attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RendezvousTicket {
    pub session_id: String,
    pub device_id: String,
    pub nonce: String,
    pub expires_at: UnixMs,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RendezvousError {
    #[error("random source failed: {0}")]
    Random(String),
}

/// Issues rendezvous data. Stateless apart from the relay endpoint peers should reach.
pub struct Rendezvous {
    relay_endpoint: String,
}

impl Rendezvous {
    pub fn new(relay_endpoint: impl Into<String>) -> Self {
        Self {
            relay_endpoint: relay_endpoint.into(),
        }
    }

    pub fn ticket(&self, session: &SessionRecord) -> Result<RendezvousTicket, RendezvousError> {
        Ok(RendezvousTicket {
            session_id: session.session_id.clone(),
            device_id: session.device_id.clone(),
            nonce: generate_secret("")
                .map_err(|error| RendezvousError::Random(error.to_string()))?,
            expires_at: session.expires_at_ms,
        })
    }

    /// Candidate endpoints for an already-authorized session. Only the relay exists until
    /// direct-path discovery adds local and server-observed candidates.
    pub fn candidates(&self, session: &SessionRecord) -> SessionCandidates {
        SessionCandidates {
            session_id: session.session_id.clone(),
            expires_at: session.expires_at_ms,
            candidates: vec![EndpointCandidate {
                kind: CandidateKind::Relay,
                endpoint: self.relay_endpoint.clone(),
                priority: 100,
            }],
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub device_id: String,
}

/// Capability and rendezvous ticket handed to both peers of a session.
#[derive(Debug, Serialize)]
pub struct IssuedSession {
    pub session_id: String,
    pub capability: String,
    pub expires_at: UnixMs,
    pub ticket: RendezvousTicket,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("device {device_id} is unknown")]
    DeviceUnknown { device_id: String },
    #[error("device {device_id} is revoked")]
    DeviceRevoked { device_id: String },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Rendezvous(#[from] RendezvousError),
}

impl IntoResponse for SessionError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Auth(error) => return error.clone().into_response(),
            Self::DeviceUnknown { .. } => (StatusCode::NOT_FOUND, "device_unknown"),
            Self::DeviceRevoked { .. } => (StatusCode::CONFLICT, "device_revoked"),
            Self::Store(_) => (StatusCode::INTERNAL_SERVER_ERROR, "store_failure"),
            Self::Rendezvous(_) => (StatusCode::INTERNAL_SERVER_ERROR, "random_source_failed"),
        };
        (status, Json(json!({ "error": code }))).into_response()
    }
}

/// `POST /api/sessions`: authorizes a device session and returns a capability plus ticket.
pub async fn create_session(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<CreateSessionRequest>,
) -> Result<(StatusCode, Json<IssuedSession>), SessionError> {
    state.auth.require_admin(&headers)?;

    let device_id = request.device_id.trim();
    let device = match state.store.device(device_id).await {
        Ok(device) => device,
        Err(StoreError::UnknownDevice { device_id }) => {
            return Err(SessionError::DeviceUnknown { device_id });
        }
        Err(error) => return Err(SessionError::Store(error)),
    };
    if device.is_revoked() {
        return Err(SessionError::DeviceRevoked {
            device_id: device.device_id,
        });
    }

    let now = state.now_ms();
    let session_id = format!("{SESSION_ID_PREFIX}{}", random_component()?);
    // The capability is returned to the caller but only its hash is persisted.
    let capability = generate_secret(crate::auth::SESSION_CAPABILITY_PREFIX)?;
    let session = SessionRecord {
        session_id,
        device_id: device.device_id.clone(),
        owner_id: device.owner_id.clone(),
        capability_hash: hash_secret(&capability),
        created_at_ms: now,
        expires_at_ms: now + SESSION_TTL_MS,
        revoked_at_ms: None,
    };
    state.store.insert_session(session.clone()).await?;

    let ticket = state.rendezvous.ticket(&session)?;
    Ok((
        StatusCode::OK,
        Json(IssuedSession {
            session_id: session.session_id,
            capability,
            expires_at: session.expires_at_ms,
            ticket,
        }),
    ))
}

/// `GET /api/sessions/{id}/candidates`: authenticated endpoint candidates for one session.
pub async fn session_candidates(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<SessionCandidates>, SessionError> {
    let session = state
        .auth
        .authorize_session_access(&headers, &session_id)
        .await?;
    Ok(Json(state.rendezvous.candidates(&session)))
}

fn random_component() -> Result<String, RendezvousError> {
    generate_secret("").map_err(|error| RendezvousError::Random(error.to_string()))
}
