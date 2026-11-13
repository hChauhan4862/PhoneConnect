//! Candidate probing, path selection, and migration.
//!
//! [`PathController::connect`] verifies the rendezvous ticket, tries every direct
//! candidate with bounded authenticated probes, and compares the validated direct
//! round-trip against the relay. The winner becomes the [`ConnectedPath`], which keeps
//! carrying the same session and request ids either way. When the relay wins first,
//! [`ConnectedPath::try_upgrade`] repeats negotiation and moves the same path to a direct
//! channel, leaving the relay attached as the fallback. A migration never closes the
//! relay session: a close is final for the session's lifetime.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use phoneconnect::v1::{
    Envelope, FrameLimits, ProtocolError, SessionId, decode_frame, encode_frame,
};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::candidates::{CandidateError, CandidateSet};
use crate::hole_punch::{
    HolePunchError, HolePunchOutcome, HolePuncher, MAX_DIRECT_FRAME_BYTES, ProbeConfig,
    ProbeCredentials, TicketRole,
};

/// Label of the canonical ticket signature payload. Changing it invalidates old tickets.
const TICKET_LABEL: &[u8] = b"phoneconnect-rendezvous-ticket-v1\n";

/// Server-issued, short-lived rendezvous ticket.
///
/// The signature covers the session, device, role, nonce, probe key, and expiry, so no
/// field can be changed without failing verification. Both peers present the same nonce;
/// it is what binds the direct-path key material to one rendezvous attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    pub session_id: String,
    pub device_id: String,
    pub role: TicketRole,
    pub nonce: String,
    pub probe_key: String,
    pub expires_at: i64,
    pub signature: String,
}

/// Ticket verification failures. Nothing degrades into "assume trusted".
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TicketError {
    #[error("ticket verification key {key} is not a 32-byte Ed25519 public key")]
    InvalidVerificationKey { key: String },
    #[error("ticket signature does not verify")]
    InvalidSignature,
    #[error("ticket probe key is not a 32-byte key")]
    InvalidProbeKey,
    #[error("ticket expired at {expires_at}")]
    Expired { expires_at: i64 },
    #[error("ticket is for session {found}, not {expected}")]
    SessionMismatch { found: String, expected: String },
    #[error("session id {session_id} is invalid: {reason}")]
    InvalidSession { session_id: String, reason: String },
}

impl Ticket {
    /// Canonical bytes the server signs. Both sides must agree byte for byte.
    fn signing_payload(
        session_id: &str,
        device_id: &str,
        role: TicketRole,
        nonce: &str,
        probe_key: &str,
        expires_at: i64,
    ) -> Vec<u8> {
        let role = match role {
            TicketRole::Client => "client",
            TicketRole::Device => "device",
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(TICKET_LABEL);
        for field in [
            session_id,
            device_id,
            role,
            nonce,
            probe_key,
            &expires_at.to_string(),
        ] {
            payload.extend_from_slice(field.as_bytes());
            payload.push(b'\n');
        }
        payload
    }

    /// Verifies the server signature and expiry, then returns the direct-path key
    /// material. A ticket the caller has no key for, a tampered ticket, and an expired
    /// ticket are all refused before a candidate is probed.
    pub fn verify(
        &self,
        verification_key: &str,
        now_ms: i64,
    ) -> Result<ProbeCredentials, TicketError> {
        let key_bytes = decode_hex::<32>(verification_key).ok_or_else(|| {
            TicketError::InvalidVerificationKey {
                key: verification_key.to_owned(),
            }
        })?;
        let verifying_key = VerifyingKey::from_bytes(&key_bytes).map_err(|_| {
            TicketError::InvalidVerificationKey {
                key: verification_key.to_owned(),
            }
        })?;
        let signature_bytes =
            decode_hex::<64>(&self.signature).ok_or(TicketError::InvalidSignature)?;
        let signature = Signature::from_bytes(&signature_bytes);

        let payload = Self::signing_payload(
            &self.session_id,
            &self.device_id,
            self.role,
            &self.nonce,
            &self.probe_key,
            self.expires_at,
        );
        verifying_key
            .verify_strict(&payload, &signature)
            .map_err(|_| TicketError::InvalidSignature)?;

        if now_ms >= self.expires_at {
            return Err(TicketError::Expired {
                expires_at: self.expires_at,
            });
        }

        SessionId::new(self.session_id.clone()).map_err(|error| TicketError::InvalidSession {
            session_id: self.session_id.clone(),
            reason: error.to_string(),
        })?;
        let probe_key = URL_SAFE_NO_PAD
            .decode(self.probe_key.as_bytes())
            .map_err(|_| TicketError::InvalidProbeKey)?;
        if probe_key.len() != 32 || self.nonce.is_empty() {
            return Err(TicketError::InvalidProbeKey);
        }

        ProbeCredentials::new(
            self.session_id.clone(),
            self.role,
            self.nonce.clone(),
            probe_key,
            self.expires_at,
        )
        .map_err(|_| TicketError::InvalidProbeKey)
    }

    /// Refuses a ticket issued for another session before its key material is used.
    pub fn require_session(&self, session_id: &str) -> Result<(), TicketError> {
        if self.session_id == session_id {
            Ok(())
        } else {
            Err(TicketError::SessionMismatch {
                found: self.session_id.clone(),
                expected: session_id.to_owned(),
            })
        }
    }
}

fn decode_hex<const N: usize>(value: &str) -> Option<[u8; N]> {
    if value.len() != N * 2 {
        return None;
    }
    let mut bytes = [0u8; N];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(bytes)
}

/// Which transport currently carries the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PathKind {
    /// A validated direct UDP path.
    Direct,
    /// The server's bounded relay.
    Relay,
}

impl fmt::Display for PathKind {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Direct => formatter.write_str("direct"),
            Self::Relay => formatter.write_str("relay"),
        }
    }
}

/// Explicit relay failures.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RelayError {
    /// The server answered `409 relay_unavailable` (or a close reason that ends the
    /// session). Terminal for this session id: create a new session, never retry.
    #[error("relay is unavailable for this session; create a new session before retrying")]
    Unavailable,
    /// The relay handshake was refused with an HTTP status that is not session-terminal.
    #[error("relay handshake was refused with HTTP {status}")]
    Refused { status: u16 },
    #[error("relay closed the transport: {reason}")]
    Closed { reason: String },
    #[error("relay reported backpressure; the peer must drain before sending more")]
    Backpressure,
    #[error("relay transport rejected the frame: {reason}")]
    Malformed { reason: String },
}

impl RelayError {
    /// True when retrying on the same session id can never succeed.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::Unavailable)
    }
}

/// The relay seam. A native client supplies [`crate::WebSocketRelay`]; the Android
/// adapter supplies its platform transport; tests supply an in-process relay.
#[async_trait::async_trait]
pub trait RelayChannel: Send + Sync {
    async fn send_frame(&self, frame: &[u8]) -> Result<(), RelayError>;
    async fn recv_frame(&self) -> Result<Vec<u8>, RelayError>;
    async fn close(&self) -> Result<(), RelayError>;

    /// Measured or configured relay round-trip time, when the transport knows one. It is
    /// only used to choose between a validated direct path and the relay.
    fn latency(&self) -> Option<Duration> {
        None
    }
}

/// Bounds applied to one path.
#[derive(Debug, Clone)]
pub struct PathConfig {
    /// Bounded direct negotiation.
    pub probe: ProbeConfig,
    /// Frame profile. Control paths must use [`FrameLimits::control_only`].
    pub frame_limits: FrameLimits,
    /// Largest frame the direct datagram path accepts.
    pub direct_frame_limit: usize,
    /// How long a receive waits before reporting a deadline.
    pub recv_timeout: Duration,
    /// Relay round-trip estimate used when the relay transport reports none.
    pub relay_latency_estimate: Duration,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            probe: ProbeConfig::default(),
            frame_limits: FrameLimits::control_only(),
            direct_frame_limit: MAX_DIRECT_FRAME_BYTES,
            recv_timeout: Duration::from_secs(5),
            relay_latency_estimate: Duration::from_millis(50),
        }
    }
}

/// Everything a path needs besides the ticket and candidates.
pub struct PathSetup {
    socket: Arc<UdpSocket>,
    relay: Option<Arc<dyn RelayChannel>>,
    config: PathConfig,
    now_ms: i64,
}

impl fmt::Debug for PathSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PathSetup")
            .field("relay", &self.relay.is_some())
            .field("config", &self.config)
            .field("now_ms", &self.now_ms)
            .finish_non_exhaustive()
    }
}

impl PathSetup {
    pub fn new(socket: Arc<UdpSocket>) -> Self {
        Self {
            socket,
            relay: None,
            config: PathConfig::default(),
            now_ms: unix_ms(),
        }
    }

    /// Attaches an already-authorized relay. The relay is the fallback and the migration
    /// target's safety net; it is never closed by a path change.
    pub fn with_relay(mut self, relay: Arc<dyn RelayChannel>) -> Self {
        self.relay = Some(relay);
        self
    }

    pub fn with_config(mut self, config: PathConfig) -> Self {
        self.config = config;
        self
    }

    /// Sets the clock the caller verified its ticket against. Tests pin it; a deployment
    /// passes the current Unix time.
    pub fn at(mut self, now_ms: i64) -> Self {
        self.now_ms = now_ms;
        self
    }
}

/// Explicit path failures. `ProtocolError` carries decoding detail that is neither
/// cloneable nor comparable, so path errors are matched by variant instead of compared.
#[derive(Debug, thiserror::Error)]
pub enum PathError {
    #[error(transparent)]
    Ticket(#[from] TicketError),
    #[error(transparent)]
    Candidate(#[from] CandidateError),
    #[error("no direct candidate and no relay are available for this session")]
    NoPath,
    #[error(transparent)]
    HolePunch(#[from] HolePunchError),
    /// Terminal for this session id: create a new session instead of retrying.
    #[error("relay is unavailable for this session; create a new session before retrying")]
    RelayUnavailable,
    #[error(transparent)]
    Relay(RelayError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("direct frame of {length} bytes exceeds the {limit}-byte datagram limit")]
    DirectFrameTooLarge { length: usize, limit: usize },
    #[error("path is shut down")]
    Shutdown,
}

impl From<RelayError> for PathError {
    fn from(error: RelayError) -> Self {
        match error {
            RelayError::Unavailable => Self::RelayUnavailable,
            other => Self::Relay(other),
        }
    }
}

impl PathError {
    /// True when retrying on the same session id can never succeed.
    pub fn is_terminal(&self) -> bool {
        matches!(
            self,
            Self::RelayUnavailable | Self::Ticket(TicketError::Expired { .. })
        )
    }
}

struct DirectPath {
    puncher: Arc<HolePuncher>,
    peer: SocketAddr,
    rtt: Duration,
}

const DIRECT: u8 = 0;
const RELAY: u8 = 1;

fn path_kind_byte(kind: PathKind) -> u8 {
    match kind {
        PathKind::Direct => DIRECT,
        PathKind::Relay => RELAY,
    }
}

struct PathState {
    direct: Option<DirectPath>,
    relay: Option<Arc<dyn RelayChannel>>,
    closed: bool,
}

/// Connected path over the lower-latency validated transport.
pub struct ConnectedPath {
    session_id: String,
    ticket: Ticket,
    candidates: CandidateSet,
    config: PathConfig,
    now_ms: i64,
    socket: Option<Arc<UdpSocket>>,
    kind: AtomicU8,
    state: RwLock<PathState>,
}

impl fmt::Debug for ConnectedPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectedPath")
            .field("session_id", &self.session_id)
            .field("path_kind", &self.path_kind())
            .field("config", &self.config)
            .finish_non_exhaustive()
    }
}

impl ConnectedPath {
    /// A path that only ever uses the relay. Used when a deployment disables UDP, and by
    /// callers that already hold an authorized relay channel.
    pub fn relay_only(relay: Arc<dyn RelayChannel>, config: PathConfig) -> Self {
        Self {
            session_id: String::new(),
            ticket: Ticket {
                session_id: String::new(),
                device_id: String::new(),
                role: TicketRole::Client,
                nonce: String::new(),
                probe_key: String::new(),
                expires_at: i64::MAX,
                signature: String::new(),
            },
            candidates: CandidateSet::empty(),
            config,
            now_ms: 0,
            socket: None,
            kind: AtomicU8::new(RELAY),
            state: RwLock::new(PathState {
                direct: None,
                relay: Some(relay),
                closed: false,
            }),
        }
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn path_kind(&self) -> PathKind {
        match self.kind.load(Ordering::SeqCst) {
            DIRECT => PathKind::Direct,
            _ => PathKind::Relay,
        }
    }

    /// Round trip measured while validating the direct path. Reported so a caller can
    /// surface path selection and latency, and `None` until a direct path validated.
    pub fn direct_rtt(&self) -> Option<Duration> {
        self.state
            .try_read()
            .ok()
            .and_then(|state| state.direct.as_ref().map(|direct| direct.rtt))
    }

    /// Encodes and sends one frame over the current path.
    pub async fn send_frame(&self, envelope: &Envelope) -> Result<(), PathError> {
        let frame = encode_frame(envelope, &self.config.frame_limits)?;
        let (kind, direct, relay) = {
            let state = self.state.read().await;
            if state.closed {
                return Err(PathError::Shutdown);
            }
            (
                self.path_kind(),
                state
                    .direct
                    .as_ref()
                    .map(|direct| (Arc::clone(&direct.puncher), direct.peer)),
                state.relay.clone(),
            )
        };
        match kind {
            PathKind::Direct => {
                let (puncher, peer) = direct.ok_or(PathError::Shutdown)?;
                if frame.len() > self.config.direct_frame_limit {
                    return Err(PathError::DirectFrameTooLarge {
                        length: frame.len(),
                        limit: self.config.direct_frame_limit,
                    });
                }
                puncher.send_frame(peer, &frame).await?;
                Ok(())
            }
            PathKind::Relay => {
                let relay = relay.ok_or(PathError::NoPath)?;
                relay.send_frame(&frame).await?;
                Ok(())
            }
        }
    }

    /// Receives one frame from the current path, bounded by `recv_timeout`.
    pub async fn recv_frame(&self) -> Result<Envelope, PathError> {
        let (kind, direct, relay) = {
            let state = self.state.read().await;
            if state.closed {
                return Err(PathError::Shutdown);
            }
            (
                self.path_kind(),
                state
                    .direct
                    .as_ref()
                    .map(|direct| (Arc::clone(&direct.puncher), direct.peer)),
                state.relay.clone(),
            )
        };
        let frame = match kind {
            PathKind::Direct => {
                let (puncher, peer) = direct.ok_or(PathError::Shutdown)?;
                puncher.recv_frame(peer, self.config.recv_timeout).await?
            }
            PathKind::Relay => {
                let relay = relay.ok_or(PathError::NoPath)?;
                relay.recv_frame().await?
            }
        };
        let decoded = decode_frame(&frame, &self.config.frame_limits)?;
        Ok(decoded.envelope)
    }

    /// Repeats direct negotiation with the ticket and clock this path was created from,
    /// and moves to the direct channel when it validates and is not slower than the relay.
    ///
    /// The relay session is left open: migration must be reversible and fallback must not
    /// need a new session. The transport deliberately has no clock of its own, so a caller
    /// that has been connected for a while passes a fresh ticket and the current time to
    /// [`Self::upgrade_with`] rather than trusting the snapshot held here.
    pub async fn try_upgrade(&self) -> Result<PathKind, PathError> {
        self.upgrade_with(&self.ticket, self.now_ms).await
    }

    /// Repeats direct negotiation with `ticket`. Request ids, sequence numbers, and the
    /// relay lease are untouched: the same session continues on a better path.
    pub async fn upgrade_with(&self, ticket: &Ticket, now_ms: i64) -> Result<PathKind, PathError> {
        let socket = self.socket.clone().ok_or(PathError::NoPath)?;
        ticket.require_session(&self.session_id)?;
        let credentials = ticket.verify(self.candidates.verification_key(), now_ms)?;
        if self.candidates.is_expired(now_ms) {
            return Err(CandidateError::Expired {
                expires_at: self.candidates.expires_at(),
            }
            .into());
        }
        let puncher = Arc::new(HolePuncher::new(Arc::clone(&socket), credentials));
        let direct = match puncher
            .punch(&self.candidates.direct(), self.config.probe)
            .await
        {
            Ok(outcome) => Some((puncher, outcome)),
            Err(HolePunchError::Timeout { .. }) | Err(HolePunchError::ReceiveTimeout) => None,
            Err(error) => return Err(error.into()),
        };

        let mut state = self.state.write().await;
        if state.closed {
            return Err(PathError::Shutdown);
        }
        let relay_latency = state.relay.as_ref().map(|relay| {
            relay
                .latency()
                .unwrap_or(self.config.relay_latency_estimate)
        });
        let direct_latency = direct.as_ref().map(|(_, outcome)| outcome.rtt);
        let selection =
            PathController::select(direct_latency, relay_latency).ok_or(PathError::NoPath)?;
        if selection == PathKind::Direct {
            if let Some((puncher, HolePunchOutcome { peer, rtt })) = direct {
                state.direct = Some(DirectPath { puncher, peer, rtt });
            }
        }
        self.kind.store(path_kind_byte(selection), Ordering::SeqCst);
        Ok(selection)
    }

    /// Moves back to the relay without closing the direct channel's state. Used when a
    /// direct path degrades or the network changes.
    pub async fn fallback_to_relay(&self) -> Result<PathKind, PathError> {
        let state = self.state.read().await;
        if state.closed {
            return Err(PathError::Shutdown);
        }
        if state.relay.is_none() {
            return Err(PathError::NoPath);
        }
        self.kind.store(RELAY, Ordering::SeqCst);
        Ok(PathKind::Relay)
    }

    /// Ends the path. The relay is closed here because the caller is done with the
    /// session; path migration never calls this.
    pub async fn shutdown(&self) -> Result<(), PathError> {
        let relay = {
            let mut state = self.state.write().await;
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            state.direct = None;
            state.relay.clone()
        };
        if let Some(relay) = relay {
            relay.close().await?;
        }
        Ok(())
    }
}

/// Entry point for establishing a path.
pub struct PathController;

impl PathController {
    /// Verifies the ticket, races bounded direct negotiation against the already
    /// authorized relay, and returns the lower-latency validated path.
    pub async fn connect(
        ticket: Ticket,
        candidates: CandidateSet,
        setup: PathSetup,
    ) -> Result<ConnectedPath, PathError> {
        ticket.require_session(candidates.session_id())?;
        let credentials = ticket.verify(candidates.verification_key(), setup.now_ms)?;
        if candidates.is_expired(setup.now_ms) {
            return Err(CandidateError::Expired {
                expires_at: candidates.expires_at(),
            }
            .into());
        }

        let PathSetup {
            socket,
            relay,
            config,
            now_ms,
        } = setup;
        let direct_addresses = candidates.direct();
        let puncher = Arc::new(HolePuncher::new(Arc::clone(&socket), credentials));
        let direct = match puncher.punch(&direct_addresses, config.probe).await {
            Ok(outcome) => Some((puncher, outcome)),
            Err(HolePunchError::Timeout { .. }) | Err(HolePunchError::ReceiveTimeout) => None,
            Err(error) => return Err(error.into()),
        };

        let relay_latency = relay
            .as_ref()
            .map(|relay| relay.latency().unwrap_or(config.relay_latency_estimate));
        let direct_latency = direct.as_ref().map(|(_, outcome)| outcome.rtt);
        let kind = match PathController::select(direct_latency, relay_latency) {
            Some(kind) => kind,
            None if direct_addresses.is_empty() => return Err(PathError::NoPath),
            None => {
                return Err(HolePunchError::Timeout {
                    attempts: config.probe.max_attempts,
                }
                .into());
            }
        };

        let direct_path = match (kind, direct) {
            (PathKind::Direct, Some((puncher, HolePunchOutcome { peer, rtt }))) => {
                Some(DirectPath { puncher, peer, rtt })
            }
            _ => None,
        };

        Ok(ConnectedPath {
            session_id: candidates.session_id().to_owned(),
            ticket,
            candidates,
            config,
            now_ms,
            socket: Some(socket),
            kind: AtomicU8::new(path_kind_byte(kind)),
            state: RwLock::new(PathState {
                direct: direct_path,
                relay,
                closed: false,
            }),
        })
    }

    /// Selects the lower of two validated round trips. A tie goes to the direct path, and
    /// `None` means no path validated. Parameters are (direct, relay).
    pub fn select(direct: Option<Duration>, relay: Option<Duration>) -> Option<PathKind> {
        match (direct, relay) {
            (Some(direct), Some(relay)) => {
                if direct <= relay {
                    Some(PathKind::Direct)
                } else {
                    Some(PathKind::Relay)
                }
            }
            (Some(_), None) => Some(PathKind::Direct),
            (None, Some(_)) => Some(PathKind::Relay),
            (None, None) => None,
        }
    }
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}
