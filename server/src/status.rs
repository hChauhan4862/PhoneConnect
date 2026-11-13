//! The status surface: what the one web UI renders for a device.
//!
//! Every field is an observed fact. A session is reported as active, expired, or revoked;
//! a path is reported as relay-attached, direct-ready, unknown, or absent; telemetry is
//! fresh, stale, or missing. Nothing here turns an unknown into a success.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::AppState;
use crate::auth::AuthError;
use crate::leases::{LeaseAccess, LeaseError, LeaseRole, LeaseStatus};
use crate::store::{DeviceRecord, StoreError, UnixMs};
use crate::telemetry::{TelemetryAggregate, TelemetryFreshness, TelemetrySample};

/// Public device fields. A credential, hash, or identity key is never part of a status view.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceView {
    pub device_id: String,
    pub owner_id: String,
    pub enrolled_at_ms: UnixMs,
    pub revoked_at_ms: Option<UnixMs>,
    pub state: DeviceState,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DeviceState {
    Enrolled,
    Revoked,
}

impl DeviceView {
    pub fn from_record(record: &DeviceRecord) -> Self {
        Self {
            device_id: record.device_id.clone(),
            owner_id: record.owner_id.clone(),
            enrolled_at_ms: record.enrolled_at_ms,
            revoked_at_ms: record.revoked_at_ms,
            state: if record.is_revoked() {
                DeviceState::Revoked
            } else {
                DeviceState::Enrolled
            },
        }
    }
}

/// The newest session for a device, whatever state it is in.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct SessionView {
    pub session_id: Option<String>,
    pub created_at_ms: Option<UnixMs>,
    pub expires_at_ms: Option<UnixMs>,
    pub revoked_at_ms: Option<UnixMs>,
    pub state: SessionState,
    pub path: PathView,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum SessionState {
    Active,
    Expired,
    Revoked,
    None,
}

/// What the server observed about a session's path. The choice between a validated direct
/// path and the relay belongs to the peers; this is evidence, not a claim.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct PathView {
    pub state: PathState,
    pub relay_attached: bool,
    pub direct_candidates: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum PathState {
    /// No session exists.
    None,
    /// A session exists but neither a relay attachment nor both peer endpoints yet.
    Unknown,
    /// Both peers published probe endpoints; a direct path can be negotiated.
    DirectReady,
    /// At least one peer is attached to the relay for this session.
    Relay,
}

impl PathView {
    fn absent() -> Self {
        Self {
            state: PathState::None,
            relay_attached: false,
            direct_candidates: false,
        }
    }
}

impl SessionView {
    fn absent() -> Self {
        Self {
            session_id: None,
            created_at_ms: None,
            expires_at_ms: None,
            revoked_at_ms: None,
            state: SessionState::None,
            path: PathView::absent(),
        }
    }
}

/// Telemetry as the UI shows it: the newest reading, its aggregate, and how old it is.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct TelemetryView {
    /// Fresh, stale, or missing. Named for what it is, not for a transport field.
    pub freshness: TelemetryFreshness,
    pub age_ms: Option<UnixMs>,
    pub sampled_at_ms: Option<UnixMs>,
    pub latest: Option<TelemetrySample>,
    pub aggregate: Option<TelemetryAggregate>,
}

#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct DeviceStatus {
    pub device: DeviceView,
    pub session: SessionView,
    pub lease: LeaseStatus,
    pub telemetry: TelemetryView,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct DeviceList {
    pub devices: Vec<DeviceView>,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum StatusError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Lease(#[from] LeaseError),
    #[error("device {device_id} is unknown")]
    DeviceUnknown { device_id: String },
    #[error("status is unavailable: {0}")]
    StoreFailure(String),
}

impl IntoResponse for StatusError {
    fn into_response(self) -> Response {
        match self {
            Self::Auth(error) => error.into_response(),
            Self::Lease(error) => error.into_response(),
            Self::DeviceUnknown { .. } => (
                StatusCode::NOT_FOUND,
                Json(json!({ "error": "device_unknown" })),
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

impl From<StoreError> for StatusError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::UnknownDevice { device_id } => Self::DeviceUnknown { device_id },
            other => Self::StoreFailure(other.to_string()),
        }
    }
}

#[derive(Debug, Deserialize)]
pub struct StatusQuery {
    #[serde(default)]
    pub user_id: Option<String>,
}

fn requested_user(query: &StatusQuery) -> Result<String, StatusError> {
    query
        .user_id
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_owned)
        .ok_or(StatusError::Lease(LeaseError::InvalidRequest {
            reason: "user_id query parameter is required",
        }))
}

/// `GET /api/devices`: the device list the UI navigates from.
pub async fn list_devices(
    State(state): State<Arc<AppState>>,
    headers: HeaderMap,
) -> Result<Json<DeviceList>, StatusError> {
    state.auth.require_admin(&headers)?;
    let records = state.store.devices().await.map_err(StatusError::from)?;
    Ok(Json(DeviceList {
        devices: records.iter().map(DeviceView::from_record).collect(),
    }))
}

/// `GET /api/devices/{id}/status?user_id=...`: everything the status screen renders.
pub async fn device_status(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<StatusQuery>,
    headers: HeaderMap,
) -> Result<Json<DeviceStatus>, StatusError> {
    state.auth.require_admin(&headers)?;
    let user_id = requested_user(&query)?;
    let now = state.now_ms();

    let device = state.store.device(&device_id).await?;
    let session = session_view(&state, &device, now).await?;
    let lease = if device.is_revoked() {
        // A revoked device has no lease and no control affordance, but it is still shown.
        LeaseStatus {
            lease: None,
            access: LeaseAccess {
                user_id: user_id.clone(),
                is_owner: device.owner_id == user_id,
                role: LeaseRole::Viewer,
                can_control: false,
            },
        }
    } else {
        state.leases.status(&device.device_id, &user_id).await?
    };
    let freshness = state.telemetry.freshness(&device.device_id, now);
    let aggregate = state.telemetry.aggregate(&device.device_id);
    Ok(Json(DeviceStatus {
        device: DeviceView::from_record(&device),
        session,
        lease,
        telemetry: TelemetryView {
            freshness: freshness.state,
            age_ms: freshness.age_ms,
            sampled_at_ms: freshness.sampled_at_ms,
            latest: aggregate.as_ref().map(|aggregate| aggregate.latest.clone()),
            aggregate,
        },
    }))
}

async fn session_view(
    state: &AppState,
    device: &DeviceRecord,
    now: UnixMs,
) -> Result<SessionView, StatusError> {
    // Report the session a client would actually join. Only when none is live does the
    // newest ended session explain why there is nothing to join.
    let live = state
        .store
        .latest_session_for_device(&device.device_id, now)
        .await
        .map_err(StatusError::from)?;
    let record = match live {
        Some(record) => record,
        None => {
            let Some(ended) = state
                .store
                .newest_session_for_device(&device.device_id)
                .await
                .map_err(StatusError::from)?
            else {
                return Ok(SessionView::absent());
            };
            ended
        }
    };
    let session_state = if record.is_revoked() {
        SessionState::Revoked
    } else if record.is_expired(now) {
        SessionState::Expired
    } else {
        SessionState::Active
    };
    let path = if session_state == SessionState::Active {
        let relay_attached = state.relay.has_attached_session(&record.session_id);
        let evidence = state.rendezvous.path_evidence(&record.session_id, now);
        let direct_candidates = evidence.supports_direct();
        PathView {
            state: if relay_attached {
                PathState::Relay
            } else if direct_candidates {
                PathState::DirectReady
            } else {
                PathState::Unknown
            },
            relay_attached,
            direct_candidates,
        }
    } else {
        PathView::absent()
    };
    Ok(SessionView {
        session_id: Some(record.session_id),
        created_at_ms: Some(record.created_at_ms),
        expires_at_ms: Some(record.expires_at_ms),
        revoked_at_ms: record.revoked_at_ms,
        state: session_state,
        path,
    })
}
