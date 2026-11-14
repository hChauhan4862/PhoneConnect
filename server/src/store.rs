//! Persistence contract for enrollment tokens, devices, and sessions.
//!
//! [`DeviceStore`] is the boundary: it speaks plain records and never exposes a database
//! handle, statement, or row type. [`SqliteStore`] implements it for tests and single-node
//! deployments; a PostgreSQL adapter can implement the same trait later.
//!
//! Only credential hashes, expiry, and revocation state are persisted. Stream payloads,
//! files, and media never reach the store.

use std::path::Path;
use std::sync::{Mutex, MutexGuard};
use std::time::{SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use rusqlite::{Connection, OptionalExtension, params};
use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Milliseconds since the Unix epoch.
pub type UnixMs = i64;

/// Source of the current time. Tests drive a [`ManualClock`]; deployments use [`SystemClock`].
pub trait Clock: Send + Sync {
    fn now_ms(&self) -> i64;
}

#[derive(Debug, Clone, Copy, Default)]
pub struct SystemClock;

impl Clock for SystemClock {
    fn now_ms(&self) -> i64 {
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|elapsed| elapsed.as_millis() as i64)
            .unwrap_or_default()
    }
}

/// Clock that only moves when a test asks it to.
#[derive(Debug, Default)]
pub struct ManualClock {
    now_ms: std::sync::atomic::AtomicI64,
}

impl ManualClock {
    pub fn new(now_ms: UnixMs) -> Self {
        Self {
            now_ms: std::sync::atomic::AtomicI64::new(now_ms),
        }
    }

    pub fn advance_ms(&self, delta_ms: i64) {
        self.now_ms
            .fetch_add(delta_ms, std::sync::atomic::Ordering::SeqCst);
    }
}

impl Clock for ManualClock {
    fn now_ms(&self) -> i64 {
        self.now_ms.load(std::sync::atomic::Ordering::SeqCst)
    }
}

/// A single-use enrollment token. The token itself is only ever held as a hash.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EnrollmentTokenRecord {
    pub token_hash: String,
    pub owner_id: String,
    pub created_at_ms: UnixMs,
    pub expires_at_ms: UnixMs,
}

/// An enrolled device. `credential_hash` is the SHA-256 of the device credential.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DeviceRecord {
    pub device_id: String,
    pub owner_id: String,
    pub credential_hash: String,
    /// Base64url X25519 identity public key registered at enrollment. Its private half
    /// never leaves the device.
    pub identity_public_key: String,
    pub enrolled_at_ms: UnixMs,
    pub revoked_at_ms: Option<UnixMs>,
}

impl DeviceRecord {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at_ms.is_some()
    }
}

/// Live authorization state for one relay session: the current session record and whether
/// its device is revoked. One lookup, so the relay can re-check every frame cheaply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RelayAuthorization {
    pub session: SessionRecord,
    pub device_revoked: bool,
}

/// A device waiting to be enrolled by a consumed token.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NewDevice {
    pub device_id: String,
    pub credential_hash: String,
    pub identity_public_key: String,
    pub enrolled_at_ms: UnixMs,
}

/// An authorized device session and the hash of its short-lived capability.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SessionRecord {
    pub session_id: String,
    pub device_id: String,
    pub owner_id: String,
    pub capability_hash: String,
    /// Base64url X25519 identity public key the client registered for this session. It is
    /// the login-equivalent pin in this milestone; its private half never leaves the client.
    pub client_identity_key: String,
    /// Base64url X25519 identity public key of the session's device, read from the device
    /// record so every authorization path sees the same pinned key.
    pub device_identity_key: String,
    pub created_at_ms: UnixMs,
    pub expires_at_ms: UnixMs,
    pub revoked_at_ms: Option<UnixMs>,
    /// Whether a control lease authorized this session. A read-only session may receive
    /// events but may not send control frames; the relay enforces this per frame.
    pub control: bool,
}

impl SessionRecord {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at_ms.is_some()
    }

    pub fn is_expired(&self, now_ms: UnixMs) -> bool {
        now_ms >= self.expires_at_ms
    }
}

/// Why a control lease stopped being active. Recorded so a revoked lease keeps the reason
/// the holder and every affected client see.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LeaseRevocationReason {
    /// The owner or holder revoked it explicitly.
    Revoked,
    /// The owner or holder handed control to another user.
    Handoff,
}

impl LeaseRevocationReason {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Revoked => "revoked",
            Self::Handoff => "handoff",
        }
    }

    fn parse(value: &str) -> Option<Self> {
        match value {
            "revoked" => Some(Self::Revoked),
            "handoff" => Some(Self::Handoff),
            _ => None,
        }
    }
}

/// One user's control of one device. A device has at most one active lease, and an active
/// lease is the only thing that authorizes control commands.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ControlLease {
    pub lease_id: String,
    pub device_id: String,
    /// The device owner, who is the authority that grants and revokes control.
    pub owner_id: String,
    /// The user who currently controls the device.
    pub holder_id: String,
    /// The owner or holder that made this grant.
    pub granted_by: String,
    pub acquired_at_ms: UnixMs,
    pub expires_at_ms: UnixMs,
    pub revoked_at_ms: Option<UnixMs>,
    pub revoked_reason: Option<LeaseRevocationReason>,
}

impl ControlLease {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at_ms.is_some()
    }

    pub fn is_expired(&self, now_ms: UnixMs) -> bool {
        now_ms >= self.expires_at_ms
    }

    pub fn is_active(&self, now_ms: UnixMs) -> bool {
        !self.is_revoked() && !self.is_expired(now_ms)
    }
}

/// One durable audit row. Command records live in memory by design; this is the trace that
/// survives a restart and is what the audit surface reads.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct AuditEntry {
    pub at_ms: UnixMs,
    pub actor: String,
    pub action: String,
    pub device_id: String,
    /// `accepted` or `refused`; the outcome of the attempt, never a shaped success.
    pub outcome: String,
    pub error: Option<String>,
}

/// Newest audit rows returned by one query. The HTTP surface applies its own page limit;
/// this is the hard bound that keeps a query from reading the whole log.
pub const MAX_AUDIT_PAGE: usize = 1_000;

impl AuditEntry {
    /// The columns as the store returns them.
    fn validate(&self) -> Result<(), StoreError> {
        if self.actor.trim().is_empty() || self.action.trim().is_empty() {
            return Err(StoreError::Backend(
                "an audit row needs an actor and an action".to_owned(),
            ));
        }
        Ok(())
    }
}

/// How many stale records one retention run deleted.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize)]
pub struct RetentionCounts {
    pub sessions_deleted: usize,
    pub leases_deleted: usize,
    pub lease_links_deleted: usize,
    pub audit_deleted: usize,
}

impl RetentionCounts {
    pub fn total(&self) -> usize {
        self.sessions_deleted + self.leases_deleted + self.lease_links_deleted + self.audit_deleted
    }
}

/// Explicit persistence failures. Uniqueness, expiry, and one-time use are store-level
/// decisions so callers cannot skip them.
#[derive(Debug, Error)]
pub enum StoreError {
    #[error("enrollment token is unknown")]
    UnknownEnrollmentToken,
    #[error("enrollment token expired at {expires_at_ms}")]
    EnrollmentTokenExpired { expires_at_ms: UnixMs },
    #[error("enrollment token was already consumed")]
    EnrollmentTokenConsumed,
    #[error("enrollment token was revoked")]
    EnrollmentTokenRevoked,
    #[error("device {device_id} is unknown")]
    UnknownDevice { device_id: String },
    #[error("device {device_id} is revoked")]
    DeviceRevoked { device_id: String },
    #[error("session {session_id} is unknown")]
    UnknownSession { session_id: String },
    #[error("control lease {lease_id} is unknown")]
    UnknownLease { lease_id: String },
    #[error("device {device_id} already has an active control lease")]
    LeaseHeld { device_id: String },
    #[error("storage backend failed: {0}")]
    Backend(String),
}

/// Durable authorization state for enrollment, devices, and sessions.
#[async_trait]
pub trait DeviceStore: Send + Sync {
    async fn insert_enrollment_token(&self, token: EnrollmentTokenRecord)
    -> Result<(), StoreError>;

    /// Consumes `token_hash` and creates `device` in one transaction. Exactly one caller
    /// can win a token, and a token that is expired, revoked, or used never enrolls.
    async fn consume_enrollment_token(
        &self,
        token_hash: &str,
        now_ms: UnixMs,
        device: NewDevice,
    ) -> Result<DeviceRecord, StoreError>;

    /// Revokes `token_hash` and returns the time revocation took effect. Idempotent:
    /// revoking twice succeeds and keeps the first revocation time.
    /// `UnknownEnrollmentToken` means no such token exists.
    async fn revoke_enrollment_token(
        &self,
        token_hash: &str,
        now_ms: UnixMs,
    ) -> Result<UnixMs, StoreError>;

    async fn device(&self, device_id: &str) -> Result<DeviceRecord, StoreError>;

    /// Looks a device up by credential hash. `Ok(None)` means no device holds that hash.
    async fn device_by_credential(
        &self,
        credential_hash: &str,
    ) -> Result<Option<DeviceRecord>, StoreError>;

    /// Revokes the device and every live session it owns in one transaction, returning
    /// the time device revocation took effect. Idempotent: revoking twice succeeds and
    /// keeps the first revocation time.
    async fn revoke_device(&self, device_id: &str, now_ms: UnixMs) -> Result<UnixMs, StoreError>;

    async fn insert_session(&self, session: SessionRecord) -> Result<(), StoreError>;

    /// Current authorization state for a relay session, read from the store rather than
    /// from any snapshot the caller holds. `UnknownSession` means the session no longer
    /// exists and must not be relayed.
    async fn relay_authorization(&self, session_id: &str)
    -> Result<RelayAuthorization, StoreError>;

    async fn session(&self, session_id: &str) -> Result<SessionRecord, StoreError>;

    /// Newest session for `device_id` that is neither revoked nor expired at `now_ms`.
    ///
    /// This is how an enrolled device learns which session a client authorized for it: the
    /// device credential authorizes only its own device, and a device never sees another
    /// device's sessions. `Ok(None)` means there is nothing to join yet.
    async fn latest_session_for_device(
        &self,
        device_id: &str,
        now_ms: UnixMs,
    ) -> Result<Option<SessionRecord>, StoreError>;

    /// Newest session for `device_id`, whatever its state. The status surface uses it to
    /// report an expired or revoked session explicitly instead of claiming there was none.
    async fn newest_session_for_device(
        &self,
        device_id: &str,
    ) -> Result<Option<SessionRecord>, StoreError>;

    /// Looks a session up by capability hash. `Ok(None)` means no session holds that hash.
    async fn session_by_capability(
        &self,
        capability_hash: &str,
    ) -> Result<Option<SessionRecord>, StoreError>;

    async fn revoke_session(&self, session_id: &str, now_ms: UnixMs) -> Result<UnixMs, StoreError>;

    /// Every enrolled device, oldest first. The status surface lists devices; it never
    /// exposes credentials.
    async fn devices(&self) -> Result<Vec<DeviceRecord>, StoreError>;

    /// Inserts `lease` only if its device has no active lease at `lease.acquired_at_ms`.
    /// The check and the insert are one transaction, so two concurrent grants cannot both
    /// win.
    async fn insert_lease_if_free(&self, lease: ControlLease) -> Result<(), StoreError>;

    async fn lease(&self, lease_id: &str) -> Result<ControlLease, StoreError>;

    /// The lease that is neither revoked nor expired at `now_ms`, if any.
    async fn active_lease(
        &self,
        device_id: &str,
        now_ms: UnixMs,
    ) -> Result<Option<ControlLease>, StoreError>;

    /// The newest lease for `device_id`, active or not. This is how an expired grant is
    /// told apart from one that never existed.
    async fn latest_lease(&self, device_id: &str) -> Result<Option<ControlLease>, StoreError>;

    /// Revokes one lease and returns when revocation took effect. Idempotent: revoking
    /// twice keeps the first time and the first reason.
    async fn revoke_lease(
        &self,
        lease_id: &str,
        now_ms: UnixMs,
        reason: LeaseRevocationReason,
    ) -> Result<UnixMs, StoreError>;

    /// Revokes the device's active lease, if any, and inserts `lease` in one transaction,
    /// returning the replaced lease. Handoff is atomic, so control is never unowned.
    async fn replace_lease(
        &self,
        lease: ControlLease,
        now_ms: UnixMs,
        reason: LeaseRevocationReason,
    ) -> Result<Option<ControlLease>, StoreError>;

    /// Associates a session with the lease that authorized it. A control session's
    /// capability is exactly this link, which is what revocation invalidates.
    async fn link_session_to_lease(
        &self,
        lease_id: &str,
        session_id: &str,
        now_ms: UnixMs,
    ) -> Result<(), StoreError>;

    /// The lease that authorized `session_id`, if it is a control session.
    async fn lease_for_session(&self, session_id: &str) -> Result<Option<String>, StoreError>;

    /// Revokes every live session linked to `lease_id` and returns their ids.
    async fn revoke_sessions_for_lease(
        &self,
        lease_id: &str,
        now_ms: UnixMs,
    ) -> Result<Vec<String>, StoreError>;

    /// Deletes session records, leases, and lease links that ended before `cutoff_ms`, and
    /// audit rows written before it. This is the retention primitive; it decides nothing
    /// about the retention window.
    async fn delete_records_older_than(
        &self,
        cutoff_ms: UnixMs,
    ) -> Result<RetentionCounts, StoreError>;

    /// Appends one audit row. The audit log is append-only: a row is never updated or
    /// deleted by the store, only by retention.
    async fn insert_audit(&self, entry: AuditEntry) -> Result<(), StoreError>;

    /// Newest-first audit rows, optionally for one device, at most [`MAX_AUDIT_PAGE`].
    async fn list_audit(
        &self,
        device_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEntry>, StoreError>;
}

const SCHEMA: &str = "
CREATE TABLE IF NOT EXISTS enrollment_tokens (
    token_hash TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    used_at_ms INTEGER,
    revoked_at_ms INTEGER
);
CREATE TABLE IF NOT EXISTS devices (
    device_id TEXT PRIMARY KEY,
    owner_id TEXT NOT NULL,
    credential_hash TEXT NOT NULL UNIQUE,
    identity_public_key TEXT NOT NULL DEFAULT '',
    enrolled_at_ms INTEGER NOT NULL,
    revoked_at_ms INTEGER
);
CREATE TABLE IF NOT EXISTS sessions (
    session_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    owner_id TEXT NOT NULL,
    capability_hash TEXT NOT NULL UNIQUE,
    client_identity_key TEXT NOT NULL DEFAULT '',
    created_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    revoked_at_ms INTEGER,
    control INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS control_leases (
    lease_id TEXT PRIMARY KEY,
    device_id TEXT NOT NULL REFERENCES devices(device_id),
    owner_id TEXT NOT NULL,
    holder_id TEXT NOT NULL,
    granted_by TEXT NOT NULL,
    acquired_at_ms INTEGER NOT NULL,
    expires_at_ms INTEGER NOT NULL,
    revoked_at_ms INTEGER,
    revoked_reason TEXT
);
CREATE INDEX IF NOT EXISTS control_leases_by_device
    ON control_leases(device_id, revoked_at_ms, expires_at_ms);
CREATE TABLE IF NOT EXISTS lease_sessions (
    lease_id TEXT NOT NULL REFERENCES control_leases(lease_id),
    session_id TEXT NOT NULL REFERENCES sessions(session_id),
    linked_at_ms INTEGER NOT NULL,
    PRIMARY KEY (lease_id, session_id)
);
CREATE TABLE IF NOT EXISTS audit_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    at_ms INTEGER NOT NULL,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    device_id TEXT NOT NULL,
    outcome TEXT NOT NULL,
    error TEXT
);
CREATE INDEX IF NOT EXISTS audit_log_by_device
    ON audit_log(device_id, at_ms DESC, id DESC);
";

/// SQLite-backed [`DeviceStore`] for tests and single-node deployments.
pub struct SqliteStore {
    connection: Mutex<Connection>,
}

impl SqliteStore {
    pub fn in_memory() -> Result<Self, StoreError> {
        Self::from_connection(Connection::open_in_memory().map_err(backend_error)?)
    }

    pub fn open(path: impl AsRef<Path>) -> Result<Self, StoreError> {
        Self::from_connection(Connection::open(path).map_err(backend_error)?)
    }

    fn from_connection(connection: Connection) -> Result<Self, StoreError> {
        connection
            .execute_batch("PRAGMA foreign_keys = ON;")
            .map_err(backend_error)?;
        connection.execute_batch(SCHEMA).map_err(backend_error)?;
        migrate(&connection)?;
        Ok(Self {
            connection: Mutex::new(connection),
        })
    }

    /// Table names in the store, used to prove that no payload or file store exists.
    pub fn schema(&self) -> Result<Vec<String>, StoreError> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(
                    "SELECT name FROM sqlite_master
                     WHERE type = 'table' AND name NOT LIKE 'sqlite_%' ORDER BY name",
                )
                .map_err(backend_error)?;
            let names = statement
                .query_map([], |row| row.get::<_, String>(0))
                .map_err(backend_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(backend_error)?;
            Ok(names)
        })
    }

    fn with_connection<T>(
        &self,
        operation: impl FnOnce(&mut Connection) -> Result<T, StoreError>,
    ) -> Result<T, StoreError> {
        let mut connection: MutexGuard<'_, Connection> = self
            .connection
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        operation(&mut connection)
    }
}

#[async_trait]
impl DeviceStore for SqliteStore {
    async fn insert_enrollment_token(
        &self,
        token: EnrollmentTokenRecord,
    ) -> Result<(), StoreError> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO enrollment_tokens
                     (token_hash, owner_id, created_at_ms, expires_at_ms) VALUES (?1, ?2, ?3, ?4)",
                    params![
                        token.token_hash,
                        token.owner_id,
                        token.created_at_ms,
                        token.expires_at_ms
                    ],
                )
                .map_err(backend_error)?;
            Ok(())
        })
    }

    async fn consume_enrollment_token(
        &self,
        token_hash: &str,
        now_ms: UnixMs,
        device: NewDevice,
    ) -> Result<DeviceRecord, StoreError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction().map_err(backend_error)?;
            let row = transaction
                .query_row(
                    "SELECT owner_id, expires_at_ms, used_at_ms, revoked_at_ms
                     FROM enrollment_tokens WHERE token_hash = ?1",
                    params![token_hash],
                    |row| {
                        Ok((
                            row.get::<_, String>(0)?,
                            row.get::<_, UnixMs>(1)?,
                            row.get::<_, Option<UnixMs>>(2)?,
                            row.get::<_, Option<UnixMs>>(3)?,
                        ))
                    },
                )
                .optional()
                .map_err(backend_error)?;

            let Some((owner_id, expires_at_ms, used_at_ms, revoked_at_ms)) = row else {
                return Err(StoreError::UnknownEnrollmentToken);
            };
            if revoked_at_ms.is_some() {
                return Err(StoreError::EnrollmentTokenRevoked);
            }
            if used_at_ms.is_some() {
                return Err(StoreError::EnrollmentTokenConsumed);
            }
            if now_ms >= expires_at_ms {
                return Err(StoreError::EnrollmentTokenExpired { expires_at_ms });
            }

            transaction
                .execute(
                    "UPDATE enrollment_tokens SET used_at_ms = ?1 WHERE token_hash = ?2",
                    params![now_ms, token_hash],
                )
                .map_err(backend_error)?;
            transaction
                .execute(
                    "INSERT INTO devices
                     (device_id, owner_id, credential_hash, identity_public_key, enrolled_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5)",
                    params![
                        device.device_id,
                        owner_id,
                        device.credential_hash,
                        device.identity_public_key,
                        device.enrolled_at_ms
                    ],
                )
                .map_err(backend_error)?;
            transaction.commit().map_err(backend_error)?;

            Ok(DeviceRecord {
                device_id: device.device_id,
                owner_id,
                credential_hash: device.credential_hash,
                identity_public_key: device.identity_public_key,
                enrolled_at_ms: device.enrolled_at_ms,
                revoked_at_ms: None,
            })
        })
    }

    async fn revoke_enrollment_token(
        &self,
        token_hash: &str,
        now_ms: UnixMs,
    ) -> Result<UnixMs, StoreError> {
        self.with_connection(|connection| {
            let revoked = connection
                .query_row(
                    "SELECT revoked_at_ms FROM enrollment_tokens WHERE token_hash = ?1",
                    params![token_hash],
                    |row| row.get::<_, Option<UnixMs>>(0),
                )
                .optional()
                .map_err(backend_error)?;
            let Some(revoked_at_ms) = revoked else {
                return Err(StoreError::UnknownEnrollmentToken);
            };
            if let Some(revoked_at_ms) = revoked_at_ms {
                return Ok(revoked_at_ms);
            }
            connection
                .execute(
                    "UPDATE enrollment_tokens SET revoked_at_ms = ?1 WHERE token_hash = ?2",
                    params![now_ms, token_hash],
                )
                .map_err(backend_error)?;
            Ok(now_ms)
        })
    }

    async fn device(&self, device_id: &str) -> Result<DeviceRecord, StoreError> {
        let found = self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT device_id, owner_id, credential_hash, identity_public_key,
                            enrolled_at_ms, revoked_at_ms
                     FROM devices WHERE device_id = ?1",
                    params![device_id],
                    device_from_row,
                )
                .optional()
                .map_err(backend_error)
        })?;
        found.ok_or_else(|| StoreError::UnknownDevice {
            device_id: device_id.to_owned(),
        })
    }

    async fn device_by_credential(
        &self,
        credential_hash: &str,
    ) -> Result<Option<DeviceRecord>, StoreError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT device_id, owner_id, credential_hash, identity_public_key,
                            enrolled_at_ms, revoked_at_ms
                     FROM devices WHERE credential_hash = ?1",
                    params![credential_hash],
                    device_from_row,
                )
                .optional()
                .map_err(backend_error)
        })
    }

    async fn revoke_device(&self, device_id: &str, now_ms: UnixMs) -> Result<UnixMs, StoreError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction().map_err(backend_error)?;
            let revoked = transaction
                .query_row(
                    "SELECT revoked_at_ms FROM devices WHERE device_id = ?1",
                    params![device_id],
                    |row| row.get::<_, Option<UnixMs>>(0),
                )
                .optional()
                .map_err(backend_error)?;
            let Some(revoked_at_ms) = revoked else {
                return Err(StoreError::UnknownDevice {
                    device_id: device_id.to_owned(),
                });
            };
            let effective_ms = revoked_at_ms.unwrap_or(now_ms);
            if revoked_at_ms.is_none() {
                transaction
                    .execute(
                        "UPDATE devices SET revoked_at_ms = ?1 WHERE device_id = ?2",
                        params![effective_ms, device_id],
                    )
                    .map_err(backend_error)?;
            }
            // Cascade even on a repeat revocation, so no live session outlives its device.
            transaction
                .execute(
                    "UPDATE sessions SET revoked_at_ms = ?1
                     WHERE device_id = ?2 AND revoked_at_ms IS NULL",
                    params![now_ms, device_id],
                )
                .map_err(backend_error)?;
            transaction.commit().map_err(backend_error)?;
            Ok(effective_ms)
        })
    }

    async fn insert_session(&self, session: SessionRecord) -> Result<(), StoreError> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO sessions
                     (session_id, device_id, owner_id, capability_hash, client_identity_key,
                      created_at_ms, expires_at_ms, control)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8)",
                    params![
                        session.session_id,
                        session.device_id,
                        session.owner_id,
                        session.capability_hash,
                        session.client_identity_key,
                        session.created_at_ms,
                        session.expires_at_ms,
                        session.control
                    ],
                )
                .map_err(backend_error)?;
            Ok(())
        })
    }

    async fn relay_authorization(
        &self,
        session_id: &str,
    ) -> Result<RelayAuthorization, StoreError> {
        let found = self.with_connection(|connection| {
            connection
                .query_row(
                    &format!("{SESSION_SELECT} WHERE s.session_id = ?1"),
                    params![session_id],
                    |row| {
                        Ok(RelayAuthorization {
                            session: session_from_row(row)?,
                            device_revoked: row.get::<_, Option<UnixMs>>(9)?.is_some(),
                        })
                    },
                )
                .optional()
                .map_err(backend_error)
        })?;
        found.ok_or_else(|| StoreError::UnknownSession {
            session_id: session_id.to_owned(),
        })
    }

    async fn session(&self, session_id: &str) -> Result<SessionRecord, StoreError> {
        let found = self.with_connection(|connection| {
            connection
                .query_row(
                    &format!("{SESSION_SELECT} WHERE s.session_id = ?1"),
                    params![session_id],
                    session_from_row,
                )
                .optional()
                .map_err(backend_error)
        })?;
        found.ok_or_else(|| StoreError::UnknownSession {
            session_id: session_id.to_owned(),
        })
    }

    async fn latest_session_for_device(
        &self,
        device_id: &str,
        now_ms: UnixMs,
    ) -> Result<Option<SessionRecord>, StoreError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    &format!(
                        "{SESSION_SELECT}
                         WHERE s.device_id = ?1 AND s.revoked_at_ms IS NULL AND s.expires_at_ms > ?2
                         ORDER BY s.created_at_ms DESC, s.session_id DESC
                         LIMIT 1"
                    ),
                    params![device_id, now_ms],
                    session_from_row,
                )
                .optional()
                .map_err(backend_error)
        })
    }

    async fn newest_session_for_device(
        &self,
        device_id: &str,
    ) -> Result<Option<SessionRecord>, StoreError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    &format!(
                        "{SESSION_SELECT} WHERE s.device_id = ?1
                         ORDER BY s.created_at_ms DESC, s.session_id DESC LIMIT 1"
                    ),
                    params![device_id],
                    session_from_row,
                )
                .optional()
                .map_err(backend_error)
        })
    }

    async fn session_by_capability(
        &self,
        capability_hash: &str,
    ) -> Result<Option<SessionRecord>, StoreError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    &format!("{SESSION_SELECT} WHERE s.capability_hash = ?1"),
                    params![capability_hash],
                    session_from_row,
                )
                .optional()
                .map_err(backend_error)
        })
    }

    async fn revoke_session(&self, session_id: &str, now_ms: UnixMs) -> Result<UnixMs, StoreError> {
        self.with_connection(|connection| {
            let revoked = connection
                .query_row(
                    "SELECT revoked_at_ms FROM sessions WHERE session_id = ?1",
                    params![session_id],
                    |row| row.get::<_, Option<UnixMs>>(0),
                )
                .optional()
                .map_err(backend_error)?;
            let Some(revoked_at_ms) = revoked else {
                return Err(StoreError::UnknownSession {
                    session_id: session_id.to_owned(),
                });
            };
            if let Some(revoked_at_ms) = revoked_at_ms {
                return Ok(revoked_at_ms);
            }
            connection
                .execute(
                    "UPDATE sessions SET revoked_at_ms = ?1 WHERE session_id = ?2",
                    params![now_ms, session_id],
                )
                .map_err(backend_error)?;
            Ok(now_ms)
        })
    }

    async fn devices(&self) -> Result<Vec<DeviceRecord>, StoreError> {
        self.with_connection(|connection| {
            let mut statement = connection
                .prepare(
                    "SELECT device_id, owner_id, credential_hash, identity_public_key,
                            enrolled_at_ms, revoked_at_ms
                     FROM devices ORDER BY enrolled_at_ms, device_id",
                )
                .map_err(backend_error)?;
            let devices = statement
                .query_map([], device_from_row)
                .map_err(backend_error)?
                .collect::<Result<Vec<_>, _>>()
                .map_err(backend_error)?;
            Ok(devices)
        })
    }

    async fn insert_lease_if_free(&self, lease: ControlLease) -> Result<(), StoreError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction().map_err(backend_error)?;
            let held = active_lease_row(&transaction, &lease.device_id, lease.acquired_at_ms)?;
            if held.is_some() {
                return Err(StoreError::LeaseHeld {
                    device_id: lease.device_id,
                });
            }
            insert_lease_row(&transaction, &lease)?;
            transaction.commit().map_err(backend_error)?;
            Ok(())
        })
    }

    async fn lease(&self, lease_id: &str) -> Result<ControlLease, StoreError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    &format!("{LEASE_SELECT} WHERE lease_id = ?1"),
                    params![lease_id],
                    lease_from_row,
                )
                .optional()
                .map_err(backend_error)?
                .ok_or_else(|| StoreError::UnknownLease {
                    lease_id: lease_id.to_owned(),
                })
        })
    }

    async fn active_lease(
        &self,
        device_id: &str,
        now_ms: UnixMs,
    ) -> Result<Option<ControlLease>, StoreError> {
        self.with_connection(|connection| active_lease_row(connection, device_id, now_ms))
    }

    async fn latest_lease(&self, device_id: &str) -> Result<Option<ControlLease>, StoreError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    &format!(
                        "{LEASE_SELECT} WHERE device_id = ?1
                         ORDER BY acquired_at_ms DESC, lease_id DESC LIMIT 1"
                    ),
                    params![device_id],
                    lease_from_row,
                )
                .optional()
                .map_err(backend_error)
        })
    }

    async fn revoke_lease(
        &self,
        lease_id: &str,
        now_ms: UnixMs,
        reason: LeaseRevocationReason,
    ) -> Result<UnixMs, StoreError> {
        self.with_connection(|connection| {
            let existing = connection
                .query_row(
                    "SELECT revoked_at_ms FROM control_leases WHERE lease_id = ?1",
                    params![lease_id],
                    |row| row.get::<_, Option<UnixMs>>(0),
                )
                .optional()
                .map_err(backend_error)?;
            let Some(revoked_at_ms) = existing else {
                return Err(StoreError::UnknownLease {
                    lease_id: lease_id.to_owned(),
                });
            };
            if let Some(revoked_at_ms) = revoked_at_ms {
                return Ok(revoked_at_ms);
            }
            connection
                .execute(
                    "UPDATE control_leases SET revoked_at_ms = ?1, revoked_reason = ?2
                     WHERE lease_id = ?3",
                    params![now_ms, reason.as_str(), lease_id],
                )
                .map_err(backend_error)?;
            Ok(now_ms)
        })
    }

    async fn replace_lease(
        &self,
        lease: ControlLease,
        now_ms: UnixMs,
        reason: LeaseRevocationReason,
    ) -> Result<Option<ControlLease>, StoreError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction().map_err(backend_error)?;
            let previous = active_lease_row(&transaction, &lease.device_id, now_ms)?;
            if let Some(previous) = previous.as_ref() {
                transaction
                    .execute(
                        "UPDATE control_leases SET revoked_at_ms = ?1, revoked_reason = ?2
                         WHERE lease_id = ?3",
                        params![now_ms, reason.as_str(), previous.lease_id],
                    )
                    .map_err(backend_error)?;
            }
            insert_lease_row(&transaction, &lease)?;
            transaction.commit().map_err(backend_error)?;
            Ok(previous)
        })
    }

    async fn link_session_to_lease(
        &self,
        lease_id: &str,
        session_id: &str,
        now_ms: UnixMs,
    ) -> Result<(), StoreError> {
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT OR REPLACE INTO lease_sessions (lease_id, session_id, linked_at_ms)
                     VALUES (?1, ?2, ?3)",
                    params![lease_id, session_id, now_ms],
                )
                .map_err(backend_error)?;
            Ok(())
        })
    }

    async fn lease_for_session(&self, session_id: &str) -> Result<Option<String>, StoreError> {
        self.with_connection(|connection| {
            connection
                .query_row(
                    "SELECT lease_id FROM lease_sessions WHERE session_id = ?1",
                    params![session_id],
                    |row| row.get::<_, String>(0),
                )
                .optional()
                .map_err(backend_error)
        })
    }

    async fn revoke_sessions_for_lease(
        &self,
        lease_id: &str,
        now_ms: UnixMs,
    ) -> Result<Vec<String>, StoreError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction().map_err(backend_error)?;
            let session_ids = {
                let mut statement = transaction
                    .prepare(
                        "SELECT s.session_id FROM sessions s
                         JOIN lease_sessions l ON l.session_id = s.session_id
                         WHERE l.lease_id = ?1 AND s.revoked_at_ms IS NULL",
                    )
                    .map_err(backend_error)?;
                statement
                    .query_map(params![lease_id], |row| row.get::<_, String>(0))
                    .map_err(backend_error)?
                    .collect::<Result<Vec<_>, _>>()
                    .map_err(backend_error)?
            };
            for session_id in &session_ids {
                transaction
                    .execute(
                        "UPDATE sessions SET revoked_at_ms = ?1 WHERE session_id = ?2",
                        params![now_ms, session_id],
                    )
                    .map_err(backend_error)?;
            }
            transaction.commit().map_err(backend_error)?;
            Ok(session_ids)
        })
    }

    async fn delete_records_older_than(
        &self,
        cutoff_ms: UnixMs,
    ) -> Result<RetentionCounts, StoreError> {
        self.with_connection(|connection| {
            let transaction = connection.transaction().map_err(backend_error)?;
            let lease_links_deleted = transaction
                .execute(
                    "DELETE FROM lease_sessions
                     WHERE session_id IN (SELECT session_id FROM sessions WHERE expires_at_ms < ?1)
                        OR lease_id IN (SELECT lease_id FROM control_leases WHERE expires_at_ms < ?1)",
                    params![cutoff_ms],
                )
                .map_err(backend_error)?;
            let sessions_deleted = transaction
                .execute(
                    "DELETE FROM sessions WHERE expires_at_ms < ?1",
                    params![cutoff_ms],
                )
                .map_err(backend_error)?;
            let leases_deleted = transaction
                .execute(
                    "DELETE FROM control_leases WHERE expires_at_ms < ?1",
                    params![cutoff_ms],
                )
                .map_err(backend_error)?;
            let audit_deleted = transaction
                .execute(
                    "DELETE FROM audit_log WHERE at_ms < ?1",
                    params![cutoff_ms],
                )
                .map_err(backend_error)?;
            transaction.commit().map_err(backend_error)?;
            Ok(RetentionCounts {
                sessions_deleted,
                leases_deleted,
                lease_links_deleted,
                audit_deleted,
            })
        })
    }

    async fn insert_audit(&self, entry: AuditEntry) -> Result<(), StoreError> {
        entry.validate()?;
        self.with_connection(|connection| {
            connection
                .execute(
                    "INSERT INTO audit_log (at_ms, actor, action, device_id, outcome, error)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6)",
                    params![
                        entry.at_ms,
                        entry.actor,
                        entry.action,
                        entry.device_id,
                        entry.outcome,
                        entry.error,
                    ],
                )
                .map_err(backend_error)?;
            Ok(())
        })
    }

    async fn list_audit(
        &self,
        device_id: Option<&str>,
        limit: usize,
    ) -> Result<Vec<AuditEntry>, StoreError> {
        let limit = limit.clamp(1, MAX_AUDIT_PAGE) as i64;
        self.with_connection(|connection| {
            let rows = match device_id {
                Some(device_id) => {
                    let mut statement = connection
                        .prepare(
                            "SELECT at_ms, actor, action, device_id, outcome, error
                             FROM audit_log WHERE device_id = ?1
                             ORDER BY at_ms DESC, id DESC LIMIT ?2",
                        )
                        .map_err(backend_error)?;
                    statement
                        .query_map(params![device_id, limit], audit_from_row)
                        .map_err(backend_error)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(backend_error)?
                }
                None => {
                    let mut statement = connection
                        .prepare(
                            "SELECT at_ms, actor, action, device_id, outcome, error
                             FROM audit_log ORDER BY at_ms DESC, id DESC LIMIT ?1",
                        )
                        .map_err(backend_error)?;
                    statement
                        .query_map(params![limit], audit_from_row)
                        .map_err(backend_error)?
                        .collect::<Result<Vec<_>, _>>()
                        .map_err(backend_error)?
                }
            };
            Ok(rows)
        })
    }
}

fn audit_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<AuditEntry> {
    Ok(AuditEntry {
        at_ms: row.get(0)?,
        actor: row.get(1)?,
        action: row.get(2)?,
        device_id: row.get(3)?,
        outcome: row.get(4)?,
        error: row.get(5)?,
    })
}

const LEASE_SELECT: &str = "SELECT lease_id, device_id, owner_id, holder_id, granted_by,
                                   acquired_at_ms, expires_at_ms, revoked_at_ms, revoked_reason
                            FROM control_leases";

fn lease_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<ControlLease> {
    let reason: Option<String> = row.get(8)?;
    Ok(ControlLease {
        lease_id: row.get(0)?,
        device_id: row.get(1)?,
        owner_id: row.get(2)?,
        holder_id: row.get(3)?,
        granted_by: row.get(4)?,
        acquired_at_ms: row.get(5)?,
        expires_at_ms: row.get(6)?,
        revoked_at_ms: row.get(7)?,
        revoked_reason: reason.as_deref().and_then(LeaseRevocationReason::parse),
    })
}

fn active_lease_row(
    connection: &Connection,
    device_id: &str,
    now_ms: UnixMs,
) -> Result<Option<ControlLease>, StoreError> {
    connection
        .query_row(
            &format!(
                "{LEASE_SELECT} WHERE device_id = ?1 AND revoked_at_ms IS NULL
                 AND expires_at_ms > ?2
                 ORDER BY acquired_at_ms DESC, lease_id DESC LIMIT 1"
            ),
            params![device_id, now_ms],
            lease_from_row,
        )
        .optional()
        .map_err(backend_error)
}

fn insert_lease_row(connection: &Connection, lease: &ControlLease) -> Result<(), StoreError> {
    connection
        .execute(
            "INSERT INTO control_leases
             (lease_id, device_id, owner_id, holder_id, granted_by, acquired_at_ms,
              expires_at_ms, revoked_at_ms, revoked_reason)
             VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9)",
            params![
                lease.lease_id,
                lease.device_id,
                lease.owner_id,
                lease.holder_id,
                lease.granted_by,
                lease.acquired_at_ms,
                lease.expires_at_ms,
                lease.revoked_at_ms,
                lease.revoked_reason.map(LeaseRevocationReason::as_str),
            ],
        )
        .map_err(backend_error)?;
    Ok(())
}

fn device_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<DeviceRecord> {
    Ok(DeviceRecord {
        device_id: row.get(0)?,
        owner_id: row.get(1)?,
        credential_hash: row.get(2)?,
        identity_public_key: row.get(3)?,
        enrolled_at_ms: row.get(4)?,
        revoked_at_ms: row.get(5)?,
    })
}

const SESSION_SELECT: &str = "SELECT s.session_id, s.device_id, s.owner_id, s.capability_hash,
                                     s.client_identity_key, s.created_at_ms, s.expires_at_ms,
                                     s.revoked_at_ms, d.identity_public_key, d.revoked_at_ms,
                                     s.control
                              FROM sessions s JOIN devices d ON d.device_id = s.device_id";

fn session_from_row(row: &rusqlite::Row<'_>) -> rusqlite::Result<SessionRecord> {
    Ok(SessionRecord {
        session_id: row.get(0)?,
        device_id: row.get(1)?,
        owner_id: row.get(2)?,
        capability_hash: row.get(3)?,
        client_identity_key: row.get(4)?,
        created_at_ms: row.get(5)?,
        expires_at_ms: row.get(6)?,
        revoked_at_ms: row.get(7)?,
        device_identity_key: row.get(8)?,
        control: row.get(10)?,
    })
}

/// Adds columns introduced after the first schema to an existing database. A database
/// created by this build already has them; the check makes an upgrade safe rather than
/// failing with "no such column".
fn migrate(connection: &Connection) -> Result<(), StoreError> {
    ensure_column(
        connection,
        "devices",
        "identity_public_key",
        "ALTER TABLE devices ADD COLUMN identity_public_key TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        connection,
        "sessions",
        "client_identity_key",
        "ALTER TABLE sessions ADD COLUMN client_identity_key TEXT NOT NULL DEFAULT ''",
    )?;
    ensure_column(
        connection,
        "sessions",
        "control",
        "ALTER TABLE sessions ADD COLUMN control INTEGER NOT NULL DEFAULT 0",
    )?;
    Ok(())
}

fn ensure_column(
    connection: &Connection,
    table: &str,
    column: &str,
    statement: &str,
) -> Result<(), StoreError> {
    let existing = {
        let mut probe = connection
            .prepare(&format!("PRAGMA table_info({table})"))
            .map_err(backend_error)?;
        probe
            .query_map([], |row| row.get::<_, String>(1))
            .map_err(backend_error)?
            .collect::<Result<Vec<_>, _>>()
            .map_err(backend_error)?
    };
    if existing.iter().any(|name| name == column) {
        return Ok(());
    }
    connection.execute_batch(statement).map_err(backend_error)?;
    Ok(())
}

fn backend_error(error: rusqlite::Error) -> StoreError {
    StoreError::Backend(error.to_string())
}
