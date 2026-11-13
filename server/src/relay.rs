//! Bounded relay for end-to-end encrypted traffic.
//!
//! The relay forwards opaque PhoneConnect frames between the two peers of an authorized
//! session. The peers seal every frame with a key they agreed from their pinned identity
//! keys (`crates/transport`), so what the relay carries is a routing envelope whose payload
//! is ciphertext: this process holds only the public identity halves and cannot derive a
//! traffic key or read a request id, sequence number, deadline, or payload. It never queues
//! more than [`RelayLimits`] allows, and every rejection is an explicit [`RelayClose`] so
//! peers can tell backpressure from authorization failure.
//!
//! [`authorize_relay`] holds the expiry and revocation rules for opening a session,
//! `RelaySession::check_live` applies the same rules to an attached session by re-reading
//! the clock and store, and [`Relay::attach`] is the only way to obtain a peer handle, so
//! later direct-path work can reuse them without weakening either.

use std::collections::{HashMap, VecDeque};
use std::sync::atomic::{AtomicI64, AtomicU64, AtomicUsize, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::Duration;

use axum::Json;
use axum::extract::ws::{CloseFrame, Message, WebSocket, WebSocketUpgrade};
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use futures_util::{SinkExt, StreamExt};
use phoneconnect::v1::{
    Envelope, FrameLimits, STREAM_FRAME_LIMIT, StreamKind, decode_frame, encode_frame,
};
use serde::{Deserialize, Serialize};
use serde_json::json;
use tokio::sync::Notify;
use tokio::sync::watch;
use tokio::time::Instant;

use crate::AppState;
use crate::auth::{AuthError, SESSION_CAPABILITY_PREFIX, bearer_token};
use crate::store::{Clock, DeviceStore, RelayAuthorization, SessionRecord, StoreError, UnixMs};

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

/// How long a relay session may reuse its last authorization read. The data path runs per
/// frame, and a SQLite read per frame would serialize every attached peer on one mutex, so
/// a frame inside this window uses the cached decision. An out-of-band revocation therefore
/// takes effect within this bound (plus one [`RELAY_LIVENESS_POLL_MS`] for a blocked peer);
/// revocation that goes through this process's admin surface closes the relay immediately
/// because the close state is checked before the cache.
pub const RELAY_AUTHORIZATION_CACHE_MS: u64 = 200;

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
    #[error("the control lease that authorized the session was revoked: {lease_id}")]
    LeaseRevoked { lease_id: String },
    #[error("session {session_id} is read-only and may not send control frames")]
    ControlNotAuthorized { session_id: String },
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

/// Which end of the session a handle represents. Serialized as `device` or `client` so a
/// rendezvous ticket and the transport agree on the wire.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PeerRole {
    Device,
    Client,
}

impl PeerRole {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Device => "device",
            Self::Client => "client",
        }
    }

    pub fn opposite(self) -> Self {
        match self {
            Self::Device => Self::Client,
            Self::Client => Self::Device,
        }
    }
}

/// Relay lease handed to a peer after `POST /api/sessions/{id}/relay`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct RelayLease {
    pub session_id: String,
    /// The live route for this session's framed relay transport: an HTTP(S) URL upgraded
    /// to a WebSocket where each binary message is one PhoneConnect frame. It is served by
    /// [`relay_socket`], so a peer that follows the lease really can relay frames.
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

    /// Authorizes `session` and registers it for relay traffic. Expired sessions are
    /// dropped here, so the session table stays bounded by live sessions. A closed
    /// session is **not** dropped and never revived: its close reason and the bytes it
    /// already forwarded live as long as the session does.
    pub fn open(&self, session: &SessionRecord, now_ms: UnixMs) -> Result<RelayLease, RelayClose> {
        authorize_relay(session, now_ms)?;
        let mut sessions = self.sessions();
        sessions.retain(|_, relay| !relay.is_stale(now_ms));
        match sessions.get(&session.session_id) {
            Some(existing) => {
                // A new lease is not a new allowance: a closed relay stays closed, so
                // neither the per-session byte budget nor a close reason can be reset by
                // asking for another lease.
                existing.check_open()?;
                existing.refresh_expiry(session.expires_at_ms);
            }
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
            endpoint: self.endpoint_for(&session.session_id),
            expires_at: session.expires_at_ms,
            limits: self.limits,
        })
    }

    /// The advertised relay base. One session's transport route appends
    /// `/{session_id}/relay`.
    pub fn endpoint(&self) -> &str {
        &self.endpoint
    }

    /// The live relay route for `session_id`.
    pub fn endpoint_for(&self, session_id: &str) -> String {
        format!("{}/{session_id}/relay", self.endpoint.trim_end_matches('/'))
    }

    /// Attaches one peer to an authorized session, re-reading the live record from the
    /// store so a session revoked or expired after `open` never yields a handle.
    pub async fn attach(&self, session_id: &str, role: PeerRole) -> Result<RelayPeer, RelayClose> {
        let session = {
            let sessions = self.sessions();
            Arc::clone(sessions.get(session_id).ok_or(RelayClose::UnknownSession)?)
        };
        session.check_live().await?;
        session.attach_peer();
        Ok(RelayPeer { session, role })
    }

    /// Closes a session and wakes every blocked peer with `reason`. A close is final for
    /// the session's lifetime: a later [`Relay::open`] for the same session id returns the
    /// recorded reason instead of a new lease, and the entry is dropped only when the
    /// session expires.
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

    /// How many control frames a read-only session's client tried to send. The refusal is
    /// per frame, so this counter is how an operator sees that a viewer attempted control.
    pub fn control_refusals(&self, session_id: &str) -> u64 {
        self.sessions()
            .get(session_id)
            .map(|session| session.control_refusals.load(Ordering::SeqCst))
            .unwrap_or(0)
    }

    /// Whether any peer has attached to `session_id`, i.e. the session is carrying (or
    /// waiting to carry) relay traffic rather than only direct-path candidates.
    pub fn has_attached_session(&self, session_id: &str) -> bool {
        self.sessions()
            .get(session_id)
            .is_some_and(|session| session.has_peers())
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

impl Drop for RelayPeer {
    fn drop(&mut self) {
        self.session.detach_peer();
    }
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
        self.refuse_control_if_read_only(envelope)?;
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
        self.refuse_control_if_read_only(&decoded.envelope)?;
        self.enqueue(frame.to_vec())
    }

    /// A read-only session's client peer may not send control frames. The refusal is one
    /// frame, not the stream: a viewer that keeps receiving telemetry stays connected.
    fn refuse_control_if_read_only(&self, envelope: &Envelope) -> Result<(), RelayClose> {
        if self.role == PeerRole::Client
            && !self.session.allows_control()
            && envelope.stream_kind == i32::from(StreamKind::Control)
        {
            self.session.control_refusals.fetch_add(1, Ordering::SeqCst);
            return Err(RelayClose::ControlNotAuthorized {
                session_id: self.session.session_id.clone(),
            });
        }
        Ok(())
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
    /// Whether a control lease authorized this session. A read-only session may relay
    /// events but never a control frame; the check is per frame and does not end the stream.
    control: bool,
    /// Control frames this session's client tried to send while read-only.
    control_refusals: AtomicU64,
    expires_at_ms: AtomicI64,
    limits: RelayLimits,
    frame_limits: FrameLimits,
    store: Arc<dyn DeviceStore>,
    clock: Arc<dyn Clock>,
    to_device: Arc<Direction>,
    to_client: Arc<Direction>,
    used_bytes: AtomicU64,
    attached_peers: AtomicUsize,
    closed: watch::Sender<Option<RelayClose>>,
    authorization: Mutex<Option<CachedAuthorization>>,
}

/// The last store read for this session, with when it happened.
struct CachedAuthorization {
    read_at: std::time::Instant,
    authorization: RelayAuthorization,
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
            control: record.control,
            control_refusals: AtomicU64::new(0),
            expires_at_ms: AtomicI64::new(record.expires_at_ms),
            limits,
            frame_limits: limits.frame_limits(),
            store,
            clock,
            to_device: Arc::new(Direction::new(limits)),
            to_client: Arc::new(Direction::new(limits)),
            used_bytes: AtomicU64::new(0),
            attached_peers: AtomicUsize::new(0),
            closed,
            authorization: Mutex::new(None),
        }
    }

    fn allows_control(&self) -> bool {
        self.control
    }

    fn attach_peer(&self) {
        self.attached_peers.fetch_add(1, Ordering::SeqCst);
    }

    fn detach_peer(&self) {
        self.attached_peers.fetch_sub(1, Ordering::SeqCst);
    }

    fn has_peers(&self) -> bool {
        self.attached_peers.load(Ordering::SeqCst) > 0
    }

    fn refresh_expiry(&self, expires_at_ms: UnixMs) {
        self.expires_at_ms.store(expires_at_ms, Ordering::SeqCst);
    }

    /// True once the entry may be dropped. Only expiry qualifies: a closed session keeps
    /// its close reason and its spent byte budget until the session itself expires.
    fn is_stale(&self, now_ms: UnixMs) -> bool {
        now_ms >= self.expires_at_ms.load(Ordering::SeqCst)
    }

    fn check_open(&self) -> Result<(), RelayClose> {
        match self.closed.borrow().clone() {
            Some(reason) => Err(reason),
            None => Ok(()),
        }
    }

    /// Re-reads the clock and, at most once per [`RELAY_AUTHORIZATION_CACHE_MS`], the
    /// store. An attached session stops forwarding as soon as its expiry passes or its
    /// session, or owning device, is revoked. Any refusal closes the session so every
    /// attached peer learns why.
    async fn check_live(&self) -> Result<(), RelayClose> {
        self.check_open()?;
        let now = self.clock.now_ms();
        if now >= self.expires_at_ms.load(Ordering::SeqCst) {
            return Err(self.fail(RelayClose::SessionExpired));
        }
        let live = match self.cached_authorization() {
            Some(live) => live,
            None => {
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
                *self.authorization() = Some(CachedAuthorization {
                    read_at: std::time::Instant::now(),
                    authorization: live.clone(),
                });
                live
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

    fn cached_authorization(&self) -> Option<RelayAuthorization> {
        self.authorization()
            .as_ref()
            .filter(|cached| {
                cached.read_at.elapsed() < Duration::from_millis(RELAY_AUTHORIZATION_CACHE_MS)
            })
            .map(|cached| cached.authorization.clone())
    }

    fn authorization(&self) -> MutexGuard<'_, Option<CachedAuthorization>> {
        self.authorization
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn fail(&self, reason: RelayClose) -> RelayClose {
        self.close(reason.clone());
        reason
    }

    fn close(&self, reason: RelayClose) {
        // A close is authoritative from this moment; no cached read may outlive it.
        *self.authorization() = None;
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
                // Spending the budget ends the relay: the reason is sticky, so a later
                // lease request can never reset the allowance.
                return Err(self.fail(RelayClose::ByteBudgetExhausted));
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
                    RelayClose::LeaseRevoked { .. } => (StatusCode::UNAUTHORIZED, "lease_revoked"),
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

/// The role a bearer credential proves for a relay transport: a session capability is the
/// client end, a device credential is the device end.
fn peer_role(headers: &HeaderMap) -> Result<PeerRole, AuthError> {
    let token = bearer_token(headers)?;
    if token.starts_with(SESSION_CAPABILITY_PREFIX) {
        Ok(PeerRole::Client)
    } else {
        Ok(PeerRole::Device)
    }
}

/// Stable machine-readable close reason for a relay transport. The close frame carries it
/// so a peer learns *why* the stream ended: revocation is detected from this close, not
/// from the status the lease reported when it was issued.
fn close_code(reason: &RelayClose) -> &'static str {
    match reason {
        RelayClose::UnknownSession => "session_unknown",
        RelayClose::SessionExpired => "session_expired",
        RelayClose::SessionRevoked => "session_revoked",
        RelayClose::DeviceRevoked { .. } => "device_revoked",
        RelayClose::LeaseRevoked { .. } => "lease_revoked",
        RelayClose::ControlNotAuthorized { .. } => "control_not_authorized",
        RelayClose::PeerClosed => "peer_closed",
        RelayClose::MalformedFrame { .. } => "malformed_frame",
        RelayClose::TrailingBytes { .. } => "trailing_bytes",
        RelayClose::OversizedFrame { .. } => "oversized_frame",
        RelayClose::Backpressure => "backpressure",
        RelayClose::ByteBudgetExhausted => "byte_budget_exhausted",
        RelayClose::IdleTimeout => "idle_timeout",
        RelayClose::SessionClosed => "session_closed",
        RelayClose::StoreUnavailable { .. } => "store_unavailable",
    }
}

fn close_frame(reason: &RelayClose) -> CloseFrame {
    CloseFrame {
        code: 1008,
        reason: close_code(reason).into(),
    }
}

/// `GET /api/sessions/{id}/relay`: the framed relay transport for one session.
///
/// This is the route the relay lease advertises. Authorization happens before the HTTP
/// upgrade, so an unauthorized peer never reaches the WebSocket. Each binary message is
/// exactly one PhoneConnect frame; the relay forwards validated bytes without inspecting
/// a payload. A relay failure ends the transport with a close frame that names the reason,
/// so an attached peer sees `device_revoked` (or another explicit code) immediately.
pub async fn relay_socket(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    upgrade: WebSocketUpgrade,
) -> Result<Response, RelayUpgradeError> {
    let session = state
        .auth
        .authorize_session_access(&headers, &session_id)
        .await?;
    let role = peer_role(&headers)?;
    let lease = state
        .relay
        .open(&session, state.now_ms())
        .map_err(RelayUpgradeError::Refused)?;
    let peer = state
        .relay
        .attach(&session_id, role)
        .await
        .map_err(RelayUpgradeError::Refused)?;
    Ok(upgrade
        .max_message_size(lease.limits.max_frame_bytes)
        .max_frame_size(lease.limits.max_frame_bytes)
        .on_upgrade(move |socket| relay_connection(socket, peer))
        .into_response())
}

async fn relay_connection(socket: WebSocket, peer: RelayPeer) {
    let (mut sink, mut stream) = socket.split();
    loop {
        tokio::select! {
            outbound = peer.recv_bytes() => match outbound {
                Ok(frame) => {
                    if sink.send(Message::Binary(frame.into())).await.is_err() {
                        let _ = peer.close_send();
                        break;
                    }
                }
                Err(reason) => {
                    let _ = sink.send(Message::Close(Some(close_frame(&reason)))).await;
                    break;
                }
            },
            inbound = stream.next() => match inbound {
                Some(Ok(Message::Binary(bytes))) => {
                    match peer.send_bytes(&bytes).await {
                        Ok(()) => {}
                        // A read-only control frame is refused, not fatal: the frame is
                        // dropped and the viewer keeps receiving. The peer cannot be told
                        // per frame because the transport has no per-frame error, so the
                        // refusal is counted and surfaced in the status surface instead.
                        Err(RelayClose::ControlNotAuthorized { .. }) => {}
                        Err(reason) => {
                            let _ = sink.send(Message::Close(Some(close_frame(&reason)))).await;
                            break;
                        }
                    }
                }
                Some(Ok(Message::Ping(payload))) => {
                    if sink.send(Message::Pong(payload)).await.is_err() {
                        break;
                    }
                }
                Some(Ok(Message::Close(_))) | None => {
                    let _ = peer.close_send();
                    break;
                }
                Some(Ok(Message::Text(_))) => {
                    let _ = sink
                        .send(Message::Close(Some(close_frame(&RelayClose::MalformedFrame {
                            reason: "text messages are not PhoneConnect frames".to_owned(),
                        }))))
                        .await;
                    break;
                }
                Some(Ok(Message::Pong(_))) => {}
                Some(Err(_)) => {
                    let _ = peer.close_send();
                    break;
                }
            }
        }
    }
}
