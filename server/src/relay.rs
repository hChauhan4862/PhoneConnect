//! Bounded, end-to-end encrypted relay.
//!
//! The relay forwards opaque PhoneConnect frames between the two peers of an authorized
//! session. It never decodes a payload for its own purposes, never stores a frame, and
//! never queues more than [`RelayLimits`] allows. Every rejection is an explicit
//! [`RelayClose`] so peers can tell backpressure from authorization failure.
//!
//! [`authorize_relay`] holds the expiry and revocation rules for opening a session,
//! `RelaySession::check_live` applies the same rules to an attached session by re-reading
//! the clock and store, and [`Relay::attach`] is the only way to obtain a peer handle, so
//! later direct-path work can reuse them without weakening either.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use phoneconnect::v1::{
    Envelope, FrameLimits, STREAM_FRAME_LIMIT, StreamKind, decode_frame, encode_frame,
};
use serde::Serialize;
use serde_json::json;
use tokio::sync::Notify;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::AppState;
use crate::auth::AuthError;
use crate::store::{Clock, DeviceStore, SessionRecord, StoreError, UnixMs};

/// Frames a relay direction may hold before it reports backpressure.
pub const RELAY_MAX_QUEUED_FRAMES: usize = 32;

/// Bytes a relay direction may hold before it reports backpressure.
pub const RELAY_MAX_QUEUED_BYTES: usize = 16 * 1024 * 1024;

/// Bytes a single relay session may forward before it is closed.
pub const RELAY_MAX_SESSION_BYTES: u64 = 256 * 1024 * 1024;

/// How long a peer may wait for the next frame before the session is closed.
pub const RELAY_IDLE_TIMEOUT_MS: u64 = 30_000;

/// How often a peer blocked on receive re-reads the clock and store, so expiry and
/// out-of-band revocation end an attached session without waiting for the next frame.
pub const RELAY_LIVENESS_POLL_MS: u64 = 250;

/// Per-session relay bounds. Nothing is unbounded: queue depth, queue bytes, total bytes,
/// frame size, and idle time all have a ceiling.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
pub struct RelayLimits {
    pub max_frame_bytes: usize,
    pub max_queued_frames: usize,
    pub max_queued_bytes: usize,
    pub max_session_bytes: u64,
    pub idle_timeout_ms: u64,
}

impl Default for RelayLimits {
    fn default() -> Self {
        Self {
            max_frame_bytes: STREAM_FRAME_LIMIT as usize,
            max_queued_frames: RELAY_MAX_QUEUED_FRAMES,
            max_queued_bytes: RELAY_MAX_QUEUED_BYTES,
            max_session_bytes: RELAY_MAX_SESSION_BYTES,
            idle_timeout_ms: RELAY_IDLE_TIMEOUT_MS,
        }
    }
}

impl RelayLimits {
    fn frame_limits(&self) -> FrameLimits {
        let cap = u32::try_from(self.max_frame_bytes).unwrap_or(STREAM_FRAME_LIMIT);
        let mut limits = FrameLimits::default();
        for kind in [StreamKind::File, StreamKind::Media, StreamKind::Proxy] {
            if let Ok(updated) = limits.with_stream_limit(kind, cap) {
                limits = updated;
            }
        }
        if cap < STREAM_FRAME_LIMIT {
            if let Ok(updated) = limits.with_stream_limit(StreamKind::Control, cap) {
                limits = updated;
            }
        }
        limits
    }

    fn idle_timeout(&self) -> Duration {
        Duration::from_millis(self.idle_timeout_ms)
    }
}

/// Why a relay stream or session ended. Each reason is explicit; there is no silent close.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayClose {
    #[error("session is not authorized for relay")]
    UnknownSession,
    #[error("session expired")]
    SessionExpired,
    #[error("session was revoked")]
    SessionRevoked,
    #[error("the device that owns the session was revoked: {device_id}")]
    DeviceRevoked { device_id: String },
    #[error("peer closed its sending direction")]
    PeerClosed,
    #[error("malformed frame: {reason}")]
    MalformedFrame { reason: String },
    #[error("frame carries {extra} bytes beyond the {declared}-byte envelope")]
    TrailingBytes { declared: usize, extra: usize },
    #[error("oversized frame: {length} bytes exceeds the {limit}-byte limit")]
    OversizedFrame { length: usize, limit: usize },
    #[error("relay queue is full; the peer must drain before sending more")]
    Backpressure,
    #[error("session byte budget exhausted")]
    ByteBudgetExhausted,
    #[error("session was idle for longer than the permitted timeout")]
    IdleTimeout,
    #[error("relay session was closed by the server")]
    SessionClosed,
    #[error("authorization state is unavailable: {reason}")]
    StoreUnavailable { reason: String },
}

/// Which end of the session a handle represents.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PeerRole {
    Device,
    Client,
}

/// Relay lease handed to a peer after `POST /api/sessions/{id}/relay`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelayLease {
    pub session_id: String,
    /// Transport contract, not a live route: this is the address peers are expected to
    /// reach the relay through once the transport task binds it. Task 2 serves no route
    /// at this value, so a lease is a statement of where relay traffic will go, and
    /// nothing in this build may be probed there.
    pub endpoint: String,
    pub expires_at: UnixMs,
    pub limits: RelayLimits,
}

/// Authorizes a session for relay traffic at open time. Expiry and revocation are checked
/// here so every entry point shares one rule set; an attached session is re-checked
/// against the clock and store by the relay itself.
pub fn authorize_relay(session: &SessionRecord, now_ms: UnixMs) -> Result<(), RelayClose> {
    if session.is_revoked() {
        return Err(RelayClose::SessionRevoked);
    }
    if session.is_expired(now_ms) {
        return Err(RelayClose::SessionExpired);
    }
    Ok(())
}

/// The relay's sessions, keyed by session id.
pub struct Relay {
    endpoint: String,
    limits: RelayLimits,
    store: Arc<dyn DeviceStore>,
    clock: Arc<dyn Clock>,
    sessions: Mutex<HashMap<String, Arc<RelaySession>>>,
}

impl Relay {
    pub fn new(
        endpoint: impl Into<String>,
        limits: RelayLimits,
        store: Arc<dyn DeviceStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        Self {
            endpoint: endpoint.into(),
            limits,
            store,
            clock,
            sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Authorizes `session` and registers it for relay traffic. Expired, revoked, and
    /// closed sessions are dropped here, so the session table stays bounded by live
    /// sessions.
    pub fn open(&self, session: &SessionRecord, now_ms: UnixMs) -> Result<RelayLease, RelayClose> {
        authorize_relay(session, now_ms)?;
        let mut sessions = self.sessions();
        sessions.retain(|_, relay| !relay.is_stale(now_ms));
        match sessions.get(&session.session_id) {
            Some(existing) => existing.refresh_expiry(session.expires_at_ms),
            None => {
                sessions.insert(
                    session.session_id.clone(),
                    Arc::new(RelaySession::new(
                        session,
                        self.limits,
                        Arc::clone(&self.store),
                        Arc::clone(&self.clock),
                    )),
                );
            }
        }
        Ok(RelayLease {
            session_id: session.session_id.clone(),
            endpoint: self.endpoint.clone(),
            expires_at: session.expires_at_ms,
            limits: self.limits,
        })
    }

    /// Attaches one peer to an authorized session, re-reading the live record from the
    /// store so a session revoked or expired after `open` never yields a handle.
    pub async fn attach(&self, session_id: &str, role: PeerRole) -> Result<RelayPeer, RelayClose> {
        let session = {
            let sessions = self.sessions();
            Arc::clone(sessions.get(session_id).ok_or(RelayClose::UnknownSession)?)
        };
        session.check_live().await?;
        Ok(RelayPeer { session, role })
    }

    /// Closes a session and wakes every blocked peer with `reason`.
    pub fn close_session(&self, session_id: &str, reason: RelayClose) {
        let session = {
            let sessions = self.sessions();
            sessions.get(session_id).map(Arc::clone)
        };
        if let Some(session) = session {
            session.close(reason);
        }
    }

    /// Closes every relay session owned by `device_id`, so revoking a device ends its
    /// open relays without waiting for the next frame or a liveness poll.
    pub fn close_device(&self, device_id: &str, reason: RelayClose) {
        let affected: Vec<Arc<RelaySession>> = self
            .sessions()
            .values()
            .filter(|session| session.device_id == device_id)
            .map(Arc::clone)
            .collect();
        for session in affected {
            session.close(reason.clone());
        }
    }

    fn sessions(&self) -> MutexGuard<'_, HashMap<String, Arc<RelaySession>>> {
        self.sessions
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// One peer's handle to a session. Frames are opaque; the handle never inspects payloads.
pub struct RelayPeer {
    session: Arc<RelaySession>,
    role: PeerRole,
}

impl std::fmt::Debug for RelayPeer {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RelayPeer")
            .field("session_id", &self.session.session_id)
            .field("role", &self.role)
            .finish()
    }
}

impl RelayPeer {
    /// Validates and enqueues an envelope for the other peer.
    pub async fn send_frame(&self, envelope: &Envelope) -> Result<(), RelayClose> {
        self.session.check_live().await?;
        let frame = encode_frame(envelope, &self.session.frame_limits)
            .map_err(RelayClose::from_protocol)?;
        self.enqueue(frame)
    }

    /// Validates and enqueues an already framed envelope. The frame is forwarded byte for
    /// byte after validation, so the relay never rewrites or interprets a payload. The
    /// buffer must be exactly one frame: trailing bytes are refused rather than forwarded
    /// past the declared length.
    pub async fn send_bytes(&self, frame: &[u8]) -> Result<(), RelayClose> {
        self.session.check_live().await?;
        let decoded =
            decode_frame(frame, &self.session.frame_limits).map_err(RelayClose::from_protocol)?;
        if frame.len() != decoded.consumed {
            return Err(RelayClose::TrailingBytes {
                declared: decoded.consumed,
                extra: frame.len() - decoded.consumed,
            });
        }
        self.enqueue(frame.to_vec())
    }

    fn enqueue(&self, frame: Vec<u8>) -> Result<(), RelayClose> {
        let length = frame.len();
        self.session.reserve_bytes(length)?;
        let queued = self.outbound().push(frame);
        if queued.is_err() {
            self.session.release_bytes(length);
        }
        queued
    }

    /// Waits for the next frame from the other peer within the idle timeout. While it
    /// waits, the session's expiry and revocation state are re-read on a bounded interval,
    /// so an attached relay stops forwarding when its authorization ends.
    pub async fn recv_bytes(&self) -> Result<Vec<u8>, RelayClose> {
        let deadline = Instant::now() + self.session.limits.idle_timeout();
        let mut closed = self.session.closed.subscribe();
        loop {
            let readable = self.inbound().readable.notified();
            tokio::pin!(readable);

            self.session.check_live().await?;
            if let Some(frame) = self.inbound().try_pop() {
                return Ok(frame);
            }
            if self.inbound().is_sender_closed() {
                return Err(RelayClose::PeerClosed);
            }

            tokio::select! {
                _ = &mut readable => {}
                changed = closed.changed() => {
                    if changed.is_err() {
                        return Err(RelayClose::SessionClosed);
                    }
                }
                _ = tokio::time::sleep(Duration::from_millis(RELAY_LIVENESS_POLL_MS)) => {}
                _ = tokio::time::sleep_until(deadline) => return Err(RelayClose::IdleTimeout),
            }
        }
    }

    /// Convenience wrapper that decodes the forwarded frame for the receiving peer.
    pub async fn recv_frame(&self) -> Result<Envelope, RelayClose> {
        let frame = self.recv_bytes().await?;
        let decoded =
            decode_frame(&frame, &self.session.frame_limits).map_err(RelayClose::from_protocol)?;
        Ok(decoded.envelope)
    }

    /// Half-closes the sending direction. The opposite direction keeps working.
    pub fn close_send(&self) -> Result<(), RelayClose> {
        self.session.check_open()?;
        self.outbound().close_sender();
        Ok(())
    }

    fn outbound(&self) -> &Arc<Direction> {
        match self.role {
            PeerRole::Device => &self.session.to_client,
            PeerRole::Client => &self.session.to_device,
        }
    }

    fn inbound(&self) -> &Arc<Direction> {
        match self.role {
            PeerRole::Device => &self.session.to_device,
            PeerRole::Client => &self.session.to_client,
        }
    }
}

impl RelayClose {
    fn from_protocol(error: phoneconnect::v1::ProtocolError) -> Self {
        match error {
            phoneconnect::v1::ProtocolError::FrameTooLarge { length, limit, .. } => {
                Self::OversizedFrame { length, limit }
            }
            other => Self::MalformedFrame {
                reason: other.to_string(),
            },
        }
    }
}

struct RelaySession {
    session_id: String,
    device_id: String,
    expires_at_ms: AtomicI64,
    limits: RelayLimits,
    frame_limits: FrameLimits,
    store: Arc<dyn DeviceStore>,
    clock: Arc<dyn Clock>,
    to_device: Arc<Direction>,
    to_client: Arc<Direction>,
    used_bytes: AtomicU64,
    closed: watch::Sender<Option<RelayClose>>,
}

impl RelaySession {
    fn new(
        record: &SessionRecord,
        limits: RelayLimits,
        store: Arc<dyn DeviceStore>,
        clock: Arc<dyn Clock>,
    ) -> Self {
        let (closed, _) = watch::channel(None);
        Self {
            session_id: record.session_id.clone(),
            device_id: record.device_id.clone(),
            expires_at_ms: AtomicI64::new(record.expires_at_ms),
            limits,
            frame_limits: limits.frame_limits(),
            store,
            clock,
            to_device: Arc::new(Direction::new(limits)),
            to_client: Arc::new(Direction::new(limits)),
            used_bytes: AtomicU64::new(0),
            closed,
        }
    }

    fn refresh_expiry(&self, expires_at_ms: UnixMs) {
        self.expires_at_ms.store(expires_at_ms, Ordering::SeqCst);
    }

    /// True once the session must not accept new relay work. Only the snapshot is
    /// consulted here so pruning stays cheap; [`Self::check_live`] is authoritative.
    fn is_stale(&self, now_ms: UnixMs) -> bool {
        self.is_closed() || now_ms >= self.expires_at_ms.load(Ordering::SeqCst)
    }

    fn is_closed(&self) -> bool {
        self.closed.borrow().is_some()
    }

    fn check_open(&self) -> Result<(), RelayClose> {
        match self.closed.borrow().clone() {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }

    /// Re-reads the clock and the store. An attached session stops forwarding as soon as
    /// its expiry passes or its session, or owning device, is revoked. Any refusal closes
    /// the session so every attached peer learns why.
    async fn check_live(&self) -> Result<(), RelayClose> {
        self.check_open()?;
        let now = self.clock.now_ms();
        if now >= self.expires_at_ms.load(Ordering::SeqCst) {
            return Err(self.fail(RelayClose::SessionExpired));
        }
        let live = match self.store.relay_authorization(&self.session_id).await {
            Ok(live) => live,
            Err(StoreError::UnknownSession { .. }) => {
                return Err(self.fail(RelayClose::UnknownSession));
            }
            Err(error) => {
                return Err(self.fail(RelayClose::StoreUnavailable {
                    reason: error.to_string(),
                }));
            }
        };
        self.refresh_expiry(live.session.expires_at_ms);
        if live.device_revoked {
            return Err(self.fail(RelayClose::DeviceRevoked {
                device_id: live.session.device_id,
            }));
        }
        if live.session.is_revoked() {
            return Err(self.fail(RelayClose::SessionRevoked));
        }
        if live.session.is_expired(now) {
            return Err(self.fail(RelayClose::SessionExpired));
        }
        Ok(())
    }

    fn fail(&self, reason: RelayClose) -> RelayClose {
        self.close(reason.clone());
        reason
    }

    fn close(&self, reason: RelayClose) {
        // `send_if_modified` records the first reason even when no peer is subscribed yet
        // (`send` would silently drop it) and never overwrites it afterwards.
        self.closed.send_if_modified(|current| match current {
            Some(_) => false,
            None => {
                *current = Some(reason.clone());
                true
            }
        });
    }

    fn reserve_bytes(&self, length: usize) -> Result<(), RelayClose> {
        let length = length as u64;
        let mut current = self.used_bytes.load(Ordering::SeqCst);
        loop {
            if current.saturating_add(length) > self.limits.max_session_bytes {
                return Err(RelayClose::ByteBudgetExhausted);
            }
            match self.used_bytes.compare_exchange(
                current,
                current + length,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(()),
                Err(actual) => current = actual,
            }
        }
    }

    fn release_bytes(&self, length: usize) {
        self.used_bytes.fetch_sub(length as u64, Ordering::SeqCst);
    }
}

/// One direction of a session: a bounded queue plus a close signal for the receiving side.
struct Direction {
    limits: RelayLimits,
    state: Mutex<DirectionState>,
    readable: Notify,
}

struct DirectionState {
    frames: VecDeque<Vec<u8>>,
    queued_bytes: usize,
    sender_closed: bool,
}

impl Direction {
    fn new(limits: RelayLimits) -> Self {
        Self {
            limits,
            state: Mutex::new(DirectionState {
                frames: VecDeque::new(),
                queued_bytes: 0,
                sender_closed: false,
            }),
            readable: Notify::new(),
        }
    }

    fn push(&self, frame: Vec<u8>) -> Result<(), RelayClose> {
        let mut state = self.state();
        if state.sender_closed {
            return Err(RelayClose::PeerClosed);
        }
        if state.frames.len() >= self.limits.max_queued_frames
            || state.queued_bytes.saturating_add(frame.len()) > self.limits.max_queued_bytes
        {
            return Err(RelayClose::Backpressure);
        }
        state.queued_bytes += frame.len();
        state.frames.push_back(frame);
        drop(state);
        self.readable.notify_one();
        Ok(())
    }

    fn try_pop(&self) -> Option<Vec<u8>> {
        let mut state = self.state();
        let frame = state.frames.pop_front()?;
        state.queued_bytes = state.queued_bytes.saturating_sub(frame.len());
        Some(frame)
    }

    fn is_sender_closed(&self) -> bool {
        self.state().sender_closed
    }

    fn close_sender(&self) {
        self.state().sender_closed = true;
        self.readable.notify_one();
    }

    fn state(&self) -> MutexGuard<'_, DirectionState> {
        self.state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

#[derive(Debug, thiserror::Error)]
pub enum RelayUpgradeError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error("relay refused the session: {0}")]
    Refused(RelayClose),
}

impl IntoResponse for RelayUpgradeError {
    fn into_response(self) -> Response {
        match self {
            Self::Auth(error) => error.into_response(),
            Self::Refused(reason) => {
                let (status, code) = match reason {
                    RelayClose::UnknownSession => (StatusCode::NOT_FOUND, "session_unknown"),
                    RelayClose::SessionExpired => (StatusCode::UNAUTHORIZED, "session_expired"),
                    RelayClose::SessionRevoked => (StatusCode::UNAUTHORIZED, "session_revoked"),
                    _ => (StatusCode::CONFLICT, "relay_unavailable"),
                };
                (status, Json(json!({ "error": code }))).into_response()
            }
        }
    }
}

/// `POST /api/sessions/{id}/relay`: upgrades an authorized session to a bounded relay.
/// Both peers share one lease; each proves authorization with the credential it holds.
pub async fn upgrade_to_relay(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Result<(StatusCode, Json<RelayLease>), RelayUpgradeError> {
    let session = state
        .auth
        .authorize_session_access(&headers, &session_id)
        .await?;
    let lease = state
        .relay
        .open(&session, state.now_ms())
        .map_err(RelayUpgradeError::Refused)?;
    Ok((StatusCode::OK, Json(lease)))
}
