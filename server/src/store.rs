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
}

impl SessionRecord {
    pub fn is_revoked(&self) -> bool {
        self.revoked_at_ms.is_some()
    }

    pub fn is_expired(&self, now_ms: UnixMs) -> bool {
        now_ms >= self.expires_at_ms
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

    /// Looks a session up by capability hash. `Ok(None)` means no session holds that hash.
    async fn session_by_capability(
        &self,
        capability_hash: &str,
    ) -> Result<Option<SessionRecord>, StoreError>;

    async fn revoke_session(&self, session_id: &str, now_ms: UnixMs) -> Result<UnixMs, StoreError>;
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
    revoked_at_ms INTEGER
);
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
                      created_at_ms, expires_at_ms)
                     VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                    params![
                        session.session_id,
                        session.device_id,
                        session.owner_id,
                        session.capability_hash,
                        session.client_identity_key,
                        session.created_at_ms,
                        session.expires_at_ms
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
                                     s.revoked_at_ms, d.identity_public_key, d.revoked_at_ms
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
