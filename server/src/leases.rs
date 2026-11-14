//! Control leases: one holder per device, explicit grant and handoff, read-only secondary
//! access, expiry, and revocation.
//!
//! A lease is the only thing that authorizes control commands for a device. The device
//! owner grants it, may hand it to another user, and may revoke it immediately; a second
//! user who holds nothing reads telemetry and status but is refused control with
//! [`LeaseError::ReadOnly`]. A control session is linked to the lease that authorized it,
//! so revocation closes those sessions and the relay attached to them in the same request.

use std::sync::Arc;

use axum::Json;
use axum::extract::{Path, Query, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::audit;
use crate::auth::{AuthError, generate_secret};
use crate::relay::{Relay, RelayClose};
use crate::store::{
    Clock, DeviceRecord, DeviceStore, LeaseRevocationReason, RevocationAudit, StoreError, UnixMs,
};
use crate::{ApiJson, AppState};

pub use crate::store::ControlLease;

/// Prefix of a server-issued control lease identifier.
pub const LEASE_ID_PREFIX: &str = "lease_";

/// Lifetime of a lease when the caller does not ask for one.
pub const DEFAULT_LEASE_TTL_SECONDS: i64 = 600;

/// Longest lease an operator may request. Control is re-granted explicitly, never assumed.
pub const MAX_LEASE_TTL_SECONDS: i64 = 3_600;

/// Which side of a lease a user is on. There is no third state: a user either controls the
/// device or reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseRole {
    Controller,
    Viewer,
}

/// One user's access to one device, as the lease store sees it right now.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeaseAccess {
    pub user_id: String,
    /// Whether this user owns the device, independent of who holds the lease.
    pub is_owner: bool,
    pub role: LeaseRole,
    /// True only for the active lease holder. A viewer never sees a control enabled.
    pub can_control: bool,
}

/// The active lease and the requesting user's access, which is what the UI renders.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeaseStatus {
    pub lease: Option<ControlLease>,
    pub access: LeaseAccess,
}

/// What a revocation actually ended. A protocol event, not a status code: the affected
/// clients learn which stream capabilities stopped working.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RevocationEvent {
    pub lease_id: String,
    pub device_id: String,
    pub actor_id: String,
    pub revoked_at_ms: UnixMs,
    pub reason: LeaseRevocationReason,
    /// Session capabilities the lease authorized, all invalidated by this event.
    pub invalidated_sessions: Vec<String>,
}

/// Result of an explicit handoff: the new lease and the one it replaced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct LeaseHandoff {
    pub lease: ControlLease,
    pub replaced: Option<RevocationEvent>,
}

/// Lease failures. Each maps to one stable HTTP code; none of them is a shaped success.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum LeaseError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("invalid lease request: {reason}")]
    InvalidRequest { reason: &'static str },
    #[error("device {device_id} is unknown")]
    DeviceUnknown { device_id: String },
    #[error("device {device_id} is revoked")]
    DeviceRevoked { device_id: String },
    #[error("only the owner of device {device_id} can grant control")]
    OwnerRequired { device_id: String },
    #[error("user {user_id} may not grant or revoke control of device {device_id}")]
    ActorNotAllowed { device_id: String, user_id: String },
    #[error("device {device_id} is already controlled by {holder_id}")]
    LeaseHeld {
        device_id: String,
        holder_id: String,
    },
    #[error("device {device_id} has no active control lease")]
    LeaseRequired { device_id: String },
    #[error("the control lease for device {device_id} expired")]
    LeaseExpired { device_id: String },
    #[error("user {user_id} has read-only access to device {device_id}")]
    ReadOnly { device_id: String, user_id: String },
    #[error("control lease {lease_id} is unknown")]
    LeaseUnknown { lease_id: String },
    #[error("lease state is unavailable: {0}")]
    StoreFailure(String),
}

impl LeaseError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::Auth(error) => error.code(),
            Self::InvalidRequest { .. } => "invalid_request",
            Self::DeviceUnknown { .. } => "device_unknown",
            Self::DeviceRevoked { .. } => "device_revoked",
            Self::OwnerRequired { .. } => "owner_required",
            Self::ActorNotAllowed { .. } => "lease_actor_not_allowed",
            Self::LeaseHeld { .. } => "lease_held",
            Self::LeaseRequired { .. } => "lease_required",
            Self::LeaseExpired { .. } => "lease_expired",
            Self::ReadOnly { .. } => "lease_read_only",
            Self::LeaseUnknown { .. } => "lease_unknown",
            Self::StoreFailure(_) => "store_failure",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::Auth(error) => error.status(),
            Self::InvalidRequest { .. } => StatusCode::BAD_REQUEST,
            Self::DeviceUnknown { .. } | Self::LeaseUnknown { .. } => StatusCode::NOT_FOUND,
            Self::DeviceRevoked { .. } | Self::LeaseHeld { .. } => StatusCode::CONFLICT,
            Self::OwnerRequired { .. }
            | Self::ActorNotAllowed { .. }
            | Self::LeaseRequired { .. }
            | Self::LeaseExpired { .. }
            | Self::ReadOnly { .. } => StatusCode::FORBIDDEN,
            Self::StoreFailure(_) => StatusCode::INTERNAL_SERVER_ERROR,
        }
    }
}

impl IntoResponse for LeaseError {
    fn into_response(self) -> Response {
        match self {
            Self::Auth(error) => error.into_response(),
            other => (other.status(), Json(json!({ "error": other.code() }))).into_response(),
        }
    }
}

impl From<StoreError> for LeaseError {
    fn from(error: StoreError) -> Self {
        match error {
            StoreError::UnknownDevice { device_id } => Self::DeviceUnknown { device_id },
            StoreError::UnknownLease { lease_id } => Self::LeaseUnknown { lease_id },
            StoreError::LeaseHeld { device_id } => Self::LeaseHeld {
                device_id,
                holder_id: String::new(),
            },
            other => Self::StoreFailure(other.to_string()),
        }
    }
}

/// Lease policy over persisted state. Device checks, the one-active-lease rule, and handoff
/// are decided here; the store only enforces them transactionally.
pub struct LeaseStore {
    store: Arc<dyn DeviceStore>,
    relay: Arc<Relay>,
    clock: Arc<dyn Clock>,
}

impl LeaseStore {
    pub fn new(store: Arc<dyn DeviceStore>, relay: Arc<Relay>, clock: Arc<dyn Clock>) -> Self {
        Self {
            store,
            relay,
            clock,
        }
    }

    pub fn now_ms(&self) -> UnixMs {
        self.clock.now_ms()
    }

    async fn device(&self, device_id: &str) -> Result<DeviceRecord, LeaseError> {
        let device = self.store.device(device_id).await?;
        if device.is_revoked() {
            return Err(LeaseError::DeviceRevoked {
                device_id: device.device_id,
            });
        }
        Ok(device)
    }

    /// Grants control to the device owner when no lease is active. A held lease is never
    /// displaced: the holder is removed only by an explicit handoff or revocation.
    pub async fn acquire(
        &self,
        device_id: &str,
        user_id: &str,
        expires_at_ms: UnixMs,
    ) -> Result<ControlLease, LeaseError> {
        let device = self.device(device_id).await?;
        if user_id != device.owner_id {
            return Err(LeaseError::OwnerRequired {
                device_id: device.device_id,
            });
        }
        let now = self.now_ms();
        if expires_at_ms <= now {
            return Err(LeaseError::InvalidRequest {
                reason: "expires_in_seconds must not be in the past",
            });
        }
        if let Some(active) = self
            .store
            .active_lease(&device.device_id, now)
            .await
            .map_err(store_failure)?
        {
            return Err(LeaseError::LeaseHeld {
                device_id: device.device_id,
                holder_id: active.holder_id,
            });
        }

        let lease = ControlLease {
            lease_id: format!(
                "{LEASE_ID_PREFIX}{}",
                generate_secret("").map_err(LeaseError::Auth)?
            ),
            device_id: device.device_id,
            owner_id: device.owner_id,
            holder_id: user_id.to_owned(),
            granted_by: user_id.to_owned(),
            acquired_at_ms: now,
            expires_at_ms,
            revoked_at_ms: None,
            revoked_reason: None,
        };
        match self.store.insert_lease_if_free(lease.clone()).await {
            Ok(()) => Ok(lease),
            // Two grants raced: report who actually holds the device, never an empty one.
            Err(StoreError::LeaseHeld { device_id }) => {
                let holder_id = self
                    .store
                    .active_lease(&device_id, now)
                    .await
                    .map_err(store_failure)?
                    .map(|active| active.holder_id)
                    .unwrap_or_default();
                Err(LeaseError::LeaseHeld {
                    device_id,
                    holder_id,
                })
            }
            Err(error) => Err(LeaseError::from(error)),
        }
    }

    /// Transfers control from the current holder (or from a free device) to `to_user_id`.
    /// The actor must be the owner or the current holder, and the replaced lease's streams
    /// are closed in the same call.
    pub async fn handoff(
        &self,
        device_id: &str,
        actor_id: &str,
        to_user_id: &str,
        expires_at_ms: UnixMs,
    ) -> Result<LeaseHandoff, LeaseError> {
        let device = self.device(device_id).await?;
        let now = self.now_ms();
        if expires_at_ms <= now {
            return Err(LeaseError::InvalidRequest {
                reason: "expires_in_seconds must not be in the past",
            });
        }
        let active = self
            .store
            .active_lease(&device.device_id, now)
            .await
            .map_err(store_failure)?;
        let actor_allowed = actor_id == device.owner_id
            || active
                .as_ref()
                .is_some_and(|lease| lease.holder_id == actor_id);
        if !actor_allowed {
            return Err(LeaseError::ActorNotAllowed {
                device_id: device.device_id,
                user_id: actor_id.to_owned(),
            });
        }

        let lease = ControlLease {
            lease_id: format!(
                "{LEASE_ID_PREFIX}{}",
                generate_secret("").map_err(LeaseError::Auth)?
            ),
            device_id: device.device_id.clone(),
            owner_id: device.owner_id,
            holder_id: to_user_id.to_owned(),
            granted_by: actor_id.to_owned(),
            acquired_at_ms: now,
            expires_at_ms,
            revoked_at_ms: None,
            revoked_reason: None,
        };
        let previous = self
            .store
            .replace_lease(
                lease.clone(),
                now,
                LeaseRevocationReason::Handoff,
                RevocationAudit {
                    actor: actor_id,
                    action: audit::ACTION_LEASE_HANDOFF,
                },
            )
            .await?;

        let replaced = match previous {
            Some(previous) => Some(
                self.revocation_event(&previous, actor_id, now, LeaseRevocationReason::Handoff)
                    .await?,
            ),
            None => None,
        };
        Ok(LeaseHandoff { lease, replaced })
    }

    /// Revokes one lease and closes every stream capability it authorized. Idempotent: a
    /// repeated revocation reports the original time and invalidates nothing further.
    pub async fn revoke(
        &self,
        lease_id: &str,
        actor_id: &str,
    ) -> Result<RevocationEvent, LeaseError> {
        let lease = self.store.lease(lease_id).await.map_err(LeaseError::from)?;
        let device = self
            .store
            .device(&lease.device_id)
            .await
            .map_err(LeaseError::from)?;
        if actor_id != lease.owner_id && actor_id != lease.holder_id {
            return Err(LeaseError::ActorNotAllowed {
                device_id: device.device_id,
                user_id: actor_id.to_owned(),
            });
        }
        let now = self.now_ms();
        // A repeat revocation keeps the original time *and* the original reason: a lease
        // that already ended by handoff is not relabelled as an explicit revocation.
        let already_revoked = lease.is_revoked();
        let reason = lease
            .revoked_reason
            .unwrap_or(LeaseRevocationReason::Revoked);
        let revoked_at_ms = self
            .store
            .revoke_lease(
                lease_id,
                now,
                reason,
                RevocationAudit {
                    actor: actor_id,
                    action: audit::ACTION_LEASE_REVOKE,
                },
            )
            .await?;
        let mut event = self
            .revocation_event(&lease, actor_id, revoked_at_ms, reason)
            .await?;
        if already_revoked {
            event.invalidated_sessions.clear();
        }
        Ok(event)
    }

    /// Admission for control commands: the caller must hold the device's active lease.
    pub async fn authorize_control(
        &self,
        device_id: &str,
        user_id: &str,
    ) -> Result<ControlLease, LeaseError> {
        let device = self.device(device_id).await?;
        let now = self.now_ms();
        if let Some(active) = self
            .store
            .active_lease(&device.device_id, now)
            .await
            .map_err(store_failure)?
        {
            if active.holder_id == user_id {
                return Ok(active);
            }
            return Err(LeaseError::ReadOnly {
                device_id: device.device_id,
                user_id: user_id.to_owned(),
            });
        }
        match self
            .store
            .latest_lease(&device.device_id)
            .await
            .map_err(store_failure)?
        {
            Some(lease) if !lease.is_revoked() && lease.is_expired(now) => {
                Err(LeaseError::LeaseExpired {
                    device_id: device.device_id,
                })
            }
            _ => Err(LeaseError::LeaseRequired {
                device_id: device.device_id,
            }),
        }
    }

    /// What `user_id` may do with the device right now.
    pub async fn access(&self, device_id: &str, user_id: &str) -> Result<LeaseAccess, LeaseError> {
        let device = self.device(device_id).await?;
        let active = self
            .store
            .active_lease(&device.device_id, self.now_ms())
            .await
            .map_err(store_failure)?;
        let controls = active
            .as_ref()
            .is_some_and(|lease| lease.holder_id == user_id);
        Ok(LeaseAccess {
            user_id: user_id.to_owned(),
            is_owner: device.owner_id == user_id,
            role: if controls {
                LeaseRole::Controller
            } else {
                LeaseRole::Viewer
            },
            can_control: controls,
        })
    }

    /// The active lease and one user's access to it.
    pub async fn status(&self, device_id: &str, user_id: &str) -> Result<LeaseStatus, LeaseError> {
        let device = self.device(device_id).await?;
        let lease = self
            .store
            .active_lease(&device.device_id, self.now_ms())
            .await
            .map_err(store_failure)?;
        let access = self.access(device_id, user_id).await?;
        Ok(LeaseStatus { lease, access })
    }

    /// The active lease for a device, if there is one.
    pub async fn active_lease(
        &self,
        device_id: &str,
        now_ms: UnixMs,
    ) -> Result<Option<ControlLease>, LeaseError> {
        self.store
            .active_lease(device_id, now_ms)
            .await
            .map_err(store_failure)
    }

    async fn revocation_event(
        &self,
        lease: &ControlLease,
        actor_id: &str,
        revoked_at_ms: UnixMs,
        reason: LeaseRevocationReason,
    ) -> Result<RevocationEvent, LeaseError> {
        // The store revokes the capabilities; the relay closes the attached transports, so
        // a peer learns the lease ended without waiting for a liveness poll.
        let invalidated_sessions = self
            .store
            .revoke_sessions_for_lease(&lease.lease_id, revoked_at_ms)
            .await?;
        for session_id in &invalidated_sessions {
            self.relay.close_session(
                session_id,
                RelayClose::LeaseRevoked {
                    lease_id: lease.lease_id.clone(),
                },
            );
        }
        Ok(RevocationEvent {
            lease_id: lease.lease_id.clone(),
            device_id: lease.device_id.clone(),
            actor_id: actor_id.to_owned(),
            revoked_at_ms,
            reason,
            invalidated_sessions,
        })
    }
}

fn store_failure(error: StoreError) -> LeaseError {
    LeaseError::StoreFailure(error.to_string())
}

#[derive(Debug, Deserialize)]
pub struct AcquireLeaseRequest {
    pub actor_id: String,
    #[serde(default)]
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct HandoffLeaseRequest {
    pub actor_id: String,
    pub to_user_id: String,
    #[serde(default)]
    pub expires_in_seconds: Option<i64>,
}

#[derive(Debug, Deserialize)]
pub struct RevokeLeaseRequest {
    pub actor_id: String,
}

#[derive(Debug, Deserialize)]
pub struct LeaseQuery {
    #[serde(default)]
    pub user_id: Option<String>,
}

fn required_id(value: &str, field: &'static str) -> Result<String, LeaseError> {
    let trimmed = value.trim();
    if trimmed.is_empty() {
        return Err(LeaseError::InvalidRequest { reason: field });
    }
    Ok(trimmed.to_owned())
}

fn requested_expiry(
    state: &AppState,
    expires_in_seconds: Option<i64>,
) -> Result<UnixMs, LeaseError> {
    let seconds = expires_in_seconds.unwrap_or(DEFAULT_LEASE_TTL_SECONDS);
    if !(1..=MAX_LEASE_TTL_SECONDS).contains(&seconds) {
        return Err(LeaseError::InvalidRequest {
            reason: "expires_in_seconds must be between 1 and 3600",
        });
    }
    Ok(state.now_ms() + seconds * 1_000)
}

/// `POST /api/devices/{id}/lease`: the owner grants control when the device is free.
pub async fn acquire_lease(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<AcquireLeaseRequest>,
) -> Result<(StatusCode, Json<ControlLease>), LeaseError> {
    state.auth.require_admin(&headers)?;
    let actor_id = required_id(&request.actor_id, "actor_id must not be empty")?;
    let expires_at = requested_expiry(&state, request.expires_in_seconds)?;
    let lease = state
        .leases
        .acquire(&device_id, &actor_id, expires_at)
        .await?;
    Ok((StatusCode::CREATED, Json(lease)))
}

/// `POST /api/devices/{id}/lease/handoff`: explicit transfer of control.
pub async fn handoff_lease(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<HandoffLeaseRequest>,
) -> Result<Json<LeaseHandoff>, LeaseError> {
    state.auth.require_admin(&headers)?;
    let actor_id = required_id(&request.actor_id, "actor_id must not be empty")?;
    let to_user_id = required_id(&request.to_user_id, "to_user_id must not be empty")?;
    let expires_at = requested_expiry(&state, request.expires_in_seconds)?;
    let handoff = state
        .leases
        .handoff(&device_id, &actor_id, &to_user_id, expires_at)
        .await?;
    Ok(Json(handoff))
}

/// `POST /api/leases/{id}/revoke`: immediate revocation of one lease.
pub async fn revoke_lease(
    State(state): State<Arc<AppState>>,
    Path(lease_id): Path<String>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<RevokeLeaseRequest>,
) -> Result<Json<RevocationEvent>, LeaseError> {
    state.auth.require_admin(&headers)?;
    let actor_id = required_id(&request.actor_id, "actor_id must not be empty")?;
    let event = state.leases.revoke(&lease_id, &actor_id).await?;
    Ok(Json(event))
}

/// `GET /api/devices/{id}/lease?user_id=...`: the active lease and one user's access.
pub async fn lease_status(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    Query(query): Query<LeaseQuery>,
    headers: HeaderMap,
) -> Result<Json<LeaseStatus>, LeaseError> {
    state.auth.require_admin(&headers)?;
    let user_id = required_id(
        query.user_id.as_deref().unwrap_or_default(),
        "user_id query parameter is required",
    )?;
    Ok(Json(state.leases.status(&device_id, &user_id).await?))
}
