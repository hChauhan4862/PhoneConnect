//! Candidate probing, path selection, migration, and per-frame encryption.
//!
//! [`PathController::connect`] verifies the signed rendezvous ticket, agrees a traffic key
//! from the two pinned identity keys, probes direct candidates with bounded authenticated
//! datagrams, and commits to a path only after the peer confirms it. The winner becomes the
//! [`ConnectedPath`], which seals every frame with the session cipher before either the
//! direct path or the relay sees it and keeps the same session and request ids either way.
//!
//! When the relay wins first, [`ConnectedPath::upgrade_with`] repeats negotiation with the
//! caller's fresh ticket and moves the same path to a direct channel, leaving the relay
//! attached as the fallback. A migration never closes the relay session: a close is final
//! for the session's lifetime, and fallback must not need a new session.
//!
//! A direct path pins the peer's address for this milestone. `send_to` succeeding is not
//! delivery: a peer that moved behind a new NAT mapping is only detected by the absence of
//! its frames, so callers must treat the direct path as best-effort until the reconnect
//! work renegotiates it.

use std::fmt;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicU8, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use ed25519_dalek::{Signature, VerifyingKey};
use phoneconnect::v1::{
    DeviceId, Envelope, FrameLimits, ProtocolError, RequestId, SessionId, decode_frame,
    encode_frame,
};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::RwLock;

use crate::aead::{AeadError, Epoch, IdentityKey, IdentityPublicKey, SealedHeader, SessionCipher};
use crate::candidates::{CandidateError, CandidateSet};
use crate::hole_punch::{
    DirectSocket, HolePunchError, HolePunchOutcome, MAX_DIRECT_FRAME_BYTES, ProbeConfig,
    ProbeCredentials, SwitchConfig, TicketRole,
};

/// Label of the canonical ticket signature payload. Changing it invalidates old tickets.
const TICKET_LABEL: &[u8] = b"phoneconnect-rendezvous-ticket-v1\n";

/// Server-issued, short-lived rendezvous ticket.
///
/// The signature covers the session, device, role, nonce, probe key, both pinned identity
/// keys, and the expiry, so no field can be changed without failing verification. Both
/// peers present the same nonce; it is what binds the direct-path key material to one
/// rendezvous attempt. Frame encryption keys are agreed between the identity keys and are
/// never derived from anything the server mints.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Ticket {
    pub session_id: String,
    pub device_id: String,
    pub role: TicketRole,
    pub nonce: String,
    /// Server-issued key that authenticates hole-punch datagrams only.
    pub probe_key: String,
    /// This peer's X25519 identity public key, as pinned outside the session.
    pub own_identity_key: String,
    /// The opposite peer's X25519 identity public key.
    pub peer_identity_key: String,
    pub expires_at: i64,
    pub signature: String,
}

/// Everything a verified ticket grants: probe credentials for the direct path and the
/// pinned peer identity that frame encryption is agreed with.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTicket {
    pub credentials: ProbeCredentials,
    pub own_identity_key: IdentityPublicKey,
    pub peer_identity_key: IdentityPublicKey,
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
    #[error("ticket identity key is invalid: {reason}")]
    InvalidIdentityKey { reason: String },
    #[error("ticket is for identity {found}, not the local identity {expected}")]
    IdentityMismatch { found: String, expected: String },
    #[error("ticket expired at {expires_at}")]
    Expired { expires_at: i64 },
    #[error("ticket is for session {found}, not {expected}")]
    SessionMismatch { found: String, expected: String },
    #[error("ticket names peer identity {found}, not the expected pinned identity {expected}")]
    PeerIdentityMismatch { found: String, expected: String },
    #[error("ticket {nonce} was already used by this process; fetch a fresh ticket per connect")]
    AlreadyUsed { nonce: String },
    #[error("session id {session_id} is invalid: {reason}")]
    InvalidSession { session_id: String, reason: String },
}

impl Ticket {
    /// Canonical bytes the server signs. Both sides must agree byte for byte.
    fn signing_payload(&self) -> Vec<u8> {
        let role = match self.role {
            TicketRole::Client => "client",
            TicketRole::Device => "device",
        };
        let mut payload = Vec::new();
        payload.extend_from_slice(TICKET_LABEL);
        for field in [
            self.session_id.as_str(),
            self.device_id.as_str(),
            role,
            self.nonce.as_str(),
            self.probe_key.as_str(),
            self.own_identity_key.as_str(),
            self.peer_identity_key.as_str(),
            &self.expires_at.to_string(),
        ] {
            payload.extend_from_slice(field.as_bytes());
            payload.push(b'\n');
        }
        payload
    }

    /// Verifies the server signature and expiry, then returns the direct-path credentials
    /// and the pinned peer identity. A ticket the caller has no key for, a tampered
    /// ticket, and an expired ticket are all refused before a candidate is probed.
    pub fn verify(
        &self,
        verification_key: &str,
        now_ms: i64,
    ) -> Result<VerifiedTicket, TicketError> {
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

        let payload = self.signing_payload();
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
        let own_identity_key =
            IdentityPublicKey::parse(&self.own_identity_key).map_err(|error| {
                TicketError::InvalidIdentityKey {
                    reason: error.to_string(),
                }
            })?;
        let peer_identity_key =
            IdentityPublicKey::parse(&self.peer_identity_key).map_err(|error| {
                TicketError::InvalidIdentityKey {
                    reason: error.to_string(),
                }
            })?;

        let credentials = ProbeCredentials::new(
            self.session_id.clone(),
            self.role,
            probe_key,
            self.expires_at,
        )
        .map_err(|_| TicketError::InvalidProbeKey)?;

        Ok(VerifiedTicket {
            credentials,
            own_identity_key,
            peer_identity_key,
        })
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

    /// Measured relay round-trip time. `None` means no measurement exists yet; selection
    /// then uses [`PathConfig::relay_latency_estimate`] as an upper bound.
    fn latency(&self) -> Option<Duration> {
        None
    }
}

/// Bounds applied to one path.
#[derive(Debug, Clone)]
pub struct PathConfig {
    /// Bounded direct negotiation.
    pub probe: ProbeConfig,
    /// Bounded switch confirmation.
    pub switch: SwitchConfig,
    /// A committed direct path with no authenticated datagram from the peer for this long is
    /// demoted to the relay, so a path that stops delivering can never black-hole frames.
    pub direct_health_timeout: Duration,
    /// How often an idle direct path sends a probe the peer acknowledges. This is what keeps
    /// an idle-but-working path healthy instead of demoting it for silence.
    pub keepalive_interval: Duration,
    /// Frame profile. Control paths must use [`FrameLimits::control_only`].
    pub frame_limits: FrameLimits,
    /// Largest sealed frame the direct datagram path accepts.
    pub direct_frame_limit: usize,
    /// How long a receive waits before reporting a deadline.
    pub recv_timeout: Duration,
    /// Relay round trip used only when the relay transport has no measurement.
    pub relay_latency_estimate: Duration,
}

impl Default for PathConfig {
    fn default() -> Self {
        Self {
            probe: ProbeConfig::default(),
            switch: SwitchConfig::default(),
            direct_health_timeout: Duration::from_secs(2),
            keepalive_interval: Duration::from_millis(500),
            frame_limits: FrameLimits::control_only(),
            direct_frame_limit: MAX_DIRECT_FRAME_BYTES,
            recv_timeout: Duration::from_secs(5),
            relay_latency_estimate: Duration::from_millis(50),
        }
    }
}

impl PathConfig {
    /// Refuses a configuration that cannot carry frames. A zero or oversized direct limit
    /// would fail on the first frame instead of at configuration time.
    pub fn validate(&self) -> Result<(), PathError> {
        if self.direct_frame_limit == 0 || self.direct_frame_limit > MAX_DIRECT_FRAME_BYTES {
            return Err(PathError::InvalidConfig {
                reason: format!(
                    "direct_frame_limit must be between 1 and {MAX_DIRECT_FRAME_BYTES}, got {}",
                    self.direct_frame_limit
                ),
            });
        }
        if self.probe.max_attempts == 0 {
            return Err(PathError::InvalidConfig {
                reason: "probe.max_attempts must be at least 1".to_owned(),
            });
        }
        if self.switch.retries == 0 || self.switch.timeout.is_zero() {
            return Err(PathError::InvalidConfig {
                reason: "switch retries and timeout must be non-zero".to_owned(),
            });
        }
        if self.recv_timeout.is_zero() || self.direct_health_timeout.is_zero() {
            return Err(PathError::InvalidConfig {
                reason: "recv_timeout and direct_health_timeout must be non-zero".to_owned(),
            });
        }
        if self.keepalive_interval.is_zero()
            || self.keepalive_interval >= self.direct_health_timeout
        {
            return Err(PathError::InvalidConfig {
                reason:
                    "keepalive_interval must be non-zero and shorter than direct_health_timeout"
                        .to_owned(),
            });
        }
        Ok(())
    }
}

/// Everything a relay-only path needs. It still seals frames, so it requires an identity, a
/// peer identity, and a connection epoch.
pub struct RelayOnlyPath<'a> {
    pub relay: Arc<dyn RelayChannel>,
    pub identity: &'a IdentityKey,
    pub peer_identity: IdentityPublicKey,
    pub session_id: &'a str,
    pub device_id: &'a str,
    pub role: TicketRole,
    pub epoch: &'a Epoch,
    pub config: PathConfig,
}

/// Everything a path needs besides the ticket and candidates.
pub struct PathSetup {
    socket: Arc<UdpSocket>,
    identity: IdentityKey,
    expected_peer_identity: Option<IdentityPublicKey>,
    relay: Option<Arc<dyn RelayChannel>>,
    config: PathConfig,
    now_ms: i64,
}

impl fmt::Debug for PathSetup {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PathSetup")
            .field("relay", &self.relay.is_some())
            .field("pinned_peer", &self.expected_peer_identity.is_some())
            .field("identity", &self.identity)
            .field("config", &self.config)
            .field("now_ms", &self.now_ms)
            .finish_non_exhaustive()
    }
}

impl PathSetup {
    /// `identity` is the peer's own X25519 identity key. It never leaves the peer.
    pub fn new(socket: Arc<UdpSocket>, identity: IdentityKey) -> Self {
        Self {
            socket,
            identity,
            expected_peer_identity: None,
            relay: None,
            config: PathConfig::default(),
            now_ms: unix_ms(),
        }
    }

    /// Pins the peer identity the caller expects, out of band.
    ///
    /// Peer identity otherwise arrives through the server-signed ticket (trust on first use
    /// via rendezvous). A caller that learned the peer's identity another way — a previous
    /// session, an operator-provided value — pins it here, and `connect` fails closed if the
    /// ticket names a different one.
    pub fn with_expected_peer_identity(mut self, peer: IdentityPublicKey) -> Self {
        self.expected_peer_identity = Some(peer);
        self
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
    #[error(transparent)]
    Aead(#[from] AeadError),
    #[error("no direct candidate and no relay are available for this session")]
    NoPath,
    #[error(transparent)]
    HolePunch(HolePunchError),
    /// Terminal for this session id: create a new session instead of retrying.
    #[error("relay is unavailable for this session; create a new session before retrying")]
    RelayUnavailable,
    #[error(transparent)]
    Relay(RelayError),
    #[error(transparent)]
    Protocol(#[from] ProtocolError),
    #[error("invalid path configuration: {reason}")]
    InvalidConfig { reason: String },
    /// The connection epoch is not available yet: the opposite peer has not registered its
    /// ticket nonce. Register with rendezvous and retry; this is never terminal.
    #[error("connection epoch is unavailable; register candidates and retry")]
    EpochUnavailable,
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

impl From<HolePunchError> for PathError {
    fn from(error: HolePunchError) -> Self {
        match error {
            HolePunchError::FrameTooLarge { length, limit } => {
                Self::DirectFrameTooLarge { length, limit }
            }
            other => Self::HolePunch(other),
        }
    }
}

impl PathError {
    /// True when retrying on the same session id can never succeed.
    ///
    /// An expired ticket is deliberately **not** terminal: tickets are renewable, and a
    /// caller that held a healthy session for longer than the ticket window refreshes it and
    /// calls `upgrade_with` again instead of tearing the session down.
    pub fn is_terminal(&self) -> bool {
        matches!(self, Self::RelayUnavailable)
    }
}

struct DirectState {
    socket: Arc<DirectSocket>,
    peer: SocketAddr,
    rtt: Duration,
}

struct PathState {
    /// The probe and data socket. Kept across a demotion so the path can be re-promoted and
    /// so a caller's next upgrade can succeed.
    direct: Option<DirectState>,
    relay: Option<Arc<dyn RelayChannel>>,
    closed: bool,
}

const DIRECT: u8 = 0;
const RELAY: u8 = 1;
/// Both paths are live: frames go out on both and are read from either. This is the state a
/// freshly confirmed direct path starts in, and it exists so that neither side can commit
/// alone: a frame sent while the peer is still on the relay still arrives, because the peer
/// drains both.
const PENDING: u8 = 2;

/// Tickets this process has already opened a path with, per session and role.
///
/// The real safety property is "one fresh ticket per connect": the server mints a fresh
/// single-use nonce per ticket, and the connection epoch is built from it. Reusing a ticket
/// would reuse the epoch, so it is refused here with an explicit error instead of failing
/// later as a key-reuse rejection.
type UsedTicket = (String, u8, String);

/// How long a used ticket is remembered. A session lives for five minutes, so an older
/// ticket can never be presented again.
const USED_TICKET_TTL: Duration = Duration::from_secs(600);

/// Largest number of used tickets remembered; the oldest are pruned first.
const MAX_USED_TICKETS: usize = 8192;

fn used_tickets()
-> &'static std::sync::Mutex<std::collections::HashMap<UsedTicket, std::time::Instant>> {
    static USED: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<UsedTicket, std::time::Instant>>,
    > = std::sync::OnceLock::new();
    USED.get_or_init(|| std::sync::Mutex::new(std::collections::HashMap::new()))
}

fn claim_ticket(session_id: &str, role: TicketRole, nonce: &str) -> Result<(), TicketError> {
    let role_byte = match role {
        TicketRole::Client => 1u8,
        TicketRole::Device => 2u8,
    };
    let mut used = used_tickets()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = std::time::Instant::now();
    used.retain(|_, seen| now.duration_since(*seen) < USED_TICKET_TTL);
    if used.len() >= MAX_USED_TICKETS {
        if let Some(oldest) = used
            .iter()
            .min_by_key(|(_, seen)| **seen)
            .map(|(key, _)| key.clone())
        {
            used.remove(&oldest);
        }
    }
    if used
        .insert((session_id.to_owned(), role_byte, nonce.to_owned()), now)
        .is_some()
    {
        return Err(TicketError::AlreadyUsed {
            nonce: nonce.to_owned(),
        });
    }
    Ok(())
}

fn direct_snapshot(state: &PathState) -> Option<(Arc<DirectSocket>, SocketAddr)> {
    state
        .direct
        .as_ref()
        .map(|direct| (Arc::clone(&direct.socket), direct.peer))
}

fn path_kind_byte(kind: PathKind) -> u8 {
    match kind {
        PathKind::Direct => DIRECT,
        PathKind::Relay => RELAY,
    }
}

/// Connected path over the lower-latency validated transport.
pub struct ConnectedPath {
    session_id: String,
    device_id: String,
    ticket: Ticket,
    cipher: SessionCipher,
    config: PathConfig,
    socket: Option<Arc<UdpSocket>>,
    /// The probe socket for the current ticket round. It outlives a relay selection so the
    /// peer can still be answered while it negotiates, and so a later upgrade reuses the
    /// same replay window and sequence space.
    probe_socket: std::sync::Mutex<Option<Arc<DirectSocket>>>,
    kind: AtomicU8,
    state: RwLock<PathState>,
}

impl fmt::Debug for ConnectedPath {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ConnectedPath")
            .field("session_id", &self.session_id)
            .field("path_kind", &self.path_kind())
            .field("key_id", &self.cipher.key_id())
            .finish_non_exhaustive()
    }
}

impl ConnectedPath {
    /// A path that only ever uses the relay. Used when a deployment disables UDP, and by
    /// callers that already hold an authorized relay channel. Frames still have to be
    /// sealed, so an identity and peer key are required.
    pub fn relay_only(setup: RelayOnlyPath<'_>) -> Result<Self, PathError> {
        let RelayOnlyPath {
            relay,
            identity,
            peer_identity,
            session_id,
            device_id,
            role,
            epoch,
            config,
        } = setup;
        config.validate()?;
        let cipher = SessionCipher::new(identity, peer_identity, session_id, role, epoch)?;
        Ok(Self {
            session_id: session_id.to_owned(),
            device_id: device_id.to_owned(),
            ticket: Ticket {
                session_id: session_id.to_owned(),
                device_id: device_id.to_owned(),
                role,
                nonce: String::new(),
                probe_key: String::new(),
                own_identity_key: identity.public_key().to_string(),
                peer_identity_key: peer_identity.to_string(),
                expires_at: i64::MAX,
                signature: String::new(),
            },
            cipher,
            config,
            socket: None,
            probe_socket: std::sync::Mutex::new(None),
            kind: AtomicU8::new(RELAY),
            state: RwLock::new(PathState {
                direct: None,
                relay: Some(relay),
                closed: false,
            }),
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn path_kind(&self) -> PathKind {
        match self.kind.load(Ordering::SeqCst) {
            // A transition path sends and reads both, so the session is already using the
            // direct path; the relay is only its safety net.
            DIRECT | PENDING => PathKind::Direct,
            _ => PathKind::Relay,
        }
    }

    /// Key id of the session's traffic keys. Reported so a caller can tell two identity
    /// pairs apart without ever seeing key material.
    pub fn key_id(&self) -> String {
        self.cipher.key_id()
    }

    /// The rendezvous round the direct probe socket currently uses, once one exists.
    pub async fn probe_round_id(&self) -> Option<String> {
        self.probe_socket().map(|socket| socket.round_id())
    }

    /// Round trip measured while validating the direct path. `None` until a direct path
    /// validated.
    pub fn direct_rtt(&self) -> Option<Duration> {
        self.state
            .try_read()
            .ok()
            .and_then(|state| state.direct.as_ref().map(|direct| direct.rtt))
    }

    /// Seals one frame and sends it over the current path.
    ///
    /// Neither the relay nor a direct-path observer receives the envelope: the relay gets a
    /// routing envelope whose payload is the ciphertext, and the direct path gets the sealed
    /// record inside its authenticated datagram.
    pub async fn send_frame(&self, envelope: &Envelope) -> Result<(), PathError> {
        validate_envelope_identity(envelope, &self.session_id, &self.device_id)?;
        let sealed = self.cipher.seal(envelope)?;
        let (state, direct, relay) = {
            let state = self.state.read().await;
            if state.closed {
                return Err(PathError::Shutdown);
            }
            (
                self.state_byte(),
                direct_snapshot(&state),
                state.relay.clone(),
            )
        };

        match state {
            DIRECT => {
                let (socket, peer) = direct.ok_or(PathError::Shutdown)?;
                if !socket.is_alive(self.config.direct_health_timeout) && relay.is_some() {
                    // The peer stopped answering, so hand the frame to the relay. The socket
                    // stays usable: its keepalive keeps probing, and the next inbound frame
                    // re-promotes it.
                    self.kind.store(RELAY, Ordering::SeqCst);
                    return self.send_via_relay(relay, &sealed).await;
                }
                self.check_direct_size(&sealed)?;
                socket.send_frame(peer, &sealed).await?;
                Ok(())
            }
            PENDING => {
                if !direct
                    .as_ref()
                    .map(|(socket, _)| socket.is_alive(self.config.direct_health_timeout))
                    .unwrap_or(false)
                    && relay.is_some()
                {
                    self.kind.store(RELAY, Ordering::SeqCst);
                    return self.send_via_relay(relay, &sealed).await;
                }
                // Both copies go out while the peer may still be reading the relay; its
                // replay window drops the duplicate. Success on either path is delivery.
                let direct_sent = match &direct {
                    Some((socket, peer)) if sealed.len() <= self.config.direct_frame_limit => {
                        socket.send_frame(*peer, &sealed).await.is_ok()
                    }
                    _ => false,
                };
                let relay_result = match relay {
                    Some(relay) => self.send_via_relay(Some(relay), &sealed).await,
                    None => Err(PathError::NoPath),
                };
                if direct_sent || relay_result.is_ok() {
                    Ok(())
                } else {
                    relay_result
                }
            }
            _ => match relay {
                Some(relay) => self.send_via_relay(Some(relay), &sealed).await,
                // A path built without a relay is direct or it is nothing: silence never
                // turns a usable direct socket into `NoPath`.
                None => match direct {
                    Some((socket, peer)) => {
                        self.check_direct_size(&sealed)?;
                        socket.send_frame(peer, &sealed).await?;
                        Ok(())
                    }
                    None => Err(PathError::NoPath),
                },
            },
        }
    }

    /// Receives one frame from the current path and opens it, bounded by `recv_timeout`.
    ///
    /// A duplicate that arrives on the other path during a transition, or twice from the
    /// network, is skipped rather than surfaced: the AEAD replay window already rejected it,
    /// and it is not an application error.
    pub async fn recv_frame(&self) -> Result<Envelope, PathError> {
        let deadline = std::time::Instant::now() + self.config.recv_timeout;
        loop {
            let sealed = self.next_sealed(deadline).await?;
            match self.cipher.open(&sealed) {
                Ok(envelope) => return Ok(envelope),
                Err(AeadError::Replayed { .. }) => continue,
                Err(error) => return Err(error.into()),
            }
        }
    }

    async fn next_sealed(&self, deadline: std::time::Instant) -> Result<Vec<u8>, PathError> {
        let (state, direct, relay) = {
            let state = self.state.read().await;
            if state.closed {
                return Err(PathError::Shutdown);
            }
            let mut current = self.state_byte();
            // A transition path lives as long as the peer answers keepalives. Only a dead
            // socket demotes it; an idle session must not lose its direct path.
            if current == PENDING {
                let dead = direct_snapshot(&state)
                    .map(|(socket, _)| !socket.is_alive(self.config.direct_health_timeout))
                    .unwrap_or(true);
                if dead && state.relay.is_some() {
                    self.kind.store(RELAY, Ordering::SeqCst);
                    current = RELAY;
                }
            }
            (current, direct_snapshot(&state), state.relay.clone())
        };
        let remaining = || deadline.saturating_duration_since(std::time::Instant::now());

        match state {
            DIRECT => {
                let (socket, _) = direct.ok_or(PathError::Shutdown)?;
                // With a relay to fall back to, never wait longer than the health bound: a
                // dead path must hand over promptly instead of blocking the caller.
                let wait = if relay.is_some() {
                    remaining().min(self.config.direct_health_timeout)
                } else {
                    remaining()
                };
                match socket.recv_frame(wait).await {
                    Ok(frame) => Ok(frame),
                    Err(HolePunchError::ReceiveTimeout) if relay.is_some() => {
                        self.kind.store(RELAY, Ordering::SeqCst);
                        self.recv_relay(relay).await
                    }
                    Err(error) => Err(error.into()),
                }
            }
            PENDING => {
                // The direct path is preferred and the relay is the safety net: wait for a
                // direct frame first, and fall back to the relay copy only if none arrives
                // within the health bound. A direct frame is the proof that commits the path.
                let (socket, _) = direct.ok_or(PathError::Shutdown)?;
                let wait = if relay.is_some() {
                    remaining().min(self.config.direct_health_timeout)
                } else {
                    remaining()
                };
                match socket.recv_frame(wait).await {
                    Ok(frame) => {
                        self.kind.store(DIRECT, Ordering::SeqCst);
                        Ok(frame)
                    }
                    Err(HolePunchError::ReceiveTimeout) => self.recv_relay(relay).await,
                    Err(error) => Err(error.into()),
                }
            }
            _ => {
                // A frame already queued on the direct socket means the peer is using direct
                // again; re-promote instead of leaving a working path idle.
                if let Some((socket, _)) = &direct {
                    if let Some(frame) = socket.try_recv_frame() {
                        self.kind.store(DIRECT, Ordering::SeqCst);
                        return Ok(frame);
                    }
                }
                match relay {
                    Some(relay) => self.recv_relay(Some(relay)).await,
                    None => match direct {
                        Some((socket, _)) => Ok(socket.recv_frame(remaining()).await?),
                        None => Err(PathError::NoPath),
                    },
                }
            }
        }
    }

    async fn recv_relay(&self, relay: Option<Arc<dyn RelayChannel>>) -> Result<Vec<u8>, PathError> {
        let relay = relay.ok_or(PathError::NoPath)?;
        let frame = relay.recv_frame().await?;
        let outer = decode_frame(&frame, &self.config.frame_limits)?;
        if outer.consumed != frame.len() {
            return Err(PathError::Relay(RelayError::Malformed {
                reason: "relay frame carried trailing bytes".to_owned(),
            }));
        }
        Ok(outer.envelope.payload)
    }

    async fn send_via_relay(
        &self,
        relay: Option<Arc<dyn RelayChannel>>,
        sealed: &[u8],
    ) -> Result<(), PathError> {
        let relay = relay.ok_or(PathError::NoPath)?;
        let frame = self.relay_envelope(sealed)?;
        relay.send_frame(&frame).await.map_err(PathError::from)
    }

    fn check_direct_size(&self, sealed: &[u8]) -> Result<(), PathError> {
        if sealed.len() > self.config.direct_frame_limit {
            return Err(PathError::DirectFrameTooLarge {
                length: sealed.len(),
                limit: self.config.direct_frame_limit,
            });
        }
        Ok(())
    }

    fn state_byte(&self) -> u8 {
        self.kind.load(Ordering::SeqCst)
    }

    /// Repeats direct negotiation with the caller's fresh ticket and moves to the direct
    /// channel when it validates, the peer confirms, and it is not slower than the relay.
    ///
    /// Request ids, sequence numbers, and the relay lease are untouched. The relay is left
    /// open: migration must be reversible and fallback must not need a new session. An
    /// expired ticket is reported as a ticket error and is explicitly not terminal.
    pub async fn upgrade_with(
        &self,
        ticket: &Ticket,
        candidates: &CandidateSet,
        now_ms: i64,
    ) -> Result<PathKind, PathError> {
        let udp = self.socket.clone().ok_or(PathError::NoPath)?;
        ticket.require_session(&self.session_id)?;
        let verified = ticket.verify(candidates.verification_key(), now_ms)?;
        if verified.own_identity_key != self.own_identity_key() {
            return Err(TicketError::IdentityMismatch {
                found: verified.own_identity_key.to_string(),
                expected: self.own_identity_key().to_string(),
            }
            .into());
        }
        if candidates.is_expired(now_ms) {
            return Err(CandidateError::Expired {
                expires_at: candidates.expires_at(),
            }
            .into());
        }

        let existing = self.probe_socket();
        let negotiated = negotiate_direct(
            udp,
            existing,
            verified.credentials,
            &candidates.direct(),
            self.config.probe,
            self.config.switch,
            self.config.keepalive_interval,
        )
        .await?;
        if let Some((socket, _)) = &negotiated {
            let previous = self.replace_probe_socket(Arc::clone(socket));
            if let Some(previous) = previous {
                if !Arc::ptr_eq(&previous, socket) {
                    previous.close();
                }
            }
        }
        let direct =
            negotiated.and_then(|(socket, outcome)| outcome.map(|outcome| (socket, outcome)));

        let mut state = self.state.write().await;
        if state.closed {
            return Err(PathError::Shutdown);
        }
        let relay_latency = self.relay_latency(&state);
        let direct_latency = direct.as_ref().map(|(_, outcome)| outcome.rtt);
        let selection =
            PathController::select(direct_latency, relay_latency).ok_or(PathError::NoPath)?;
        if selection == PathKind::Direct {
            if let Some((socket, HolePunchOutcome { peer, rtt })) = direct {
                state.direct = Some(DirectState { socket, peer, rtt });
                self.kind.store(PENDING, Ordering::SeqCst);
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
        let (relay, direct) = {
            let mut state = self.state.write().await;
            if state.closed {
                return Ok(());
            }
            state.closed = true;
            (state.relay.clone(), state.direct.take())
        };
        if let Some(direct) = direct {
            direct.socket.close();
        }
        if let Some(probe) = self.take_probe_socket() {
            probe.close();
        }
        if let Some(relay) = relay {
            relay.close().await?;
        }
        Ok(())
    }

    fn probe_socket(&self) -> Option<Arc<DirectSocket>> {
        self.probe_socket
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    fn replace_probe_socket(&self, socket: Arc<DirectSocket>) -> Option<Arc<DirectSocket>> {
        self.probe_socket
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .replace(socket)
    }

    fn take_probe_socket(&self) -> Option<Arc<DirectSocket>> {
        self.probe_socket
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
    }

    fn relay_latency(&self, state: &PathState) -> Option<Duration> {
        state.relay.as_ref().map(|relay| {
            relay
                .latency()
                .unwrap_or(self.config.relay_latency_estimate)
        })
    }

    fn relay_envelope(&self, sealed: &[u8]) -> Result<Vec<u8>, PathError> {
        let stream_kind =
            SealedHeader::stream_kind(sealed).ok_or(PathError::Aead(AeadError::Malformed {
                reason: "sealed frame has no stream kind".to_owned(),
            }))?;
        let device = DeviceId::new(self.device_id.clone())?;
        let session = SessionId::new(self.session_id.clone())?;
        let request = RequestId::new("relay").expect("a fixed request id is valid");
        let mut outer = Envelope::new(stream_kind, &device, &session, &request);
        outer.request_id = String::new();
        outer.payload = sealed.to_vec();
        Ok(encode_frame(&outer, &self.config.frame_limits)?)
    }

    fn own_identity_key(&self) -> IdentityPublicKey {
        IdentityPublicKey::parse(&self.ticket.own_identity_key).expect(
            "the ticket was verified before this path existed, and identity keys are immutable",
        )
    }
}

impl Drop for ConnectedPath {
    fn drop(&mut self) {
        // `shutdown` is the contract; this also stops a reader that was never explicitly
        // shut down, so abandoning a path does not leak a socket task.
        if let Ok(mut socket) = self.probe_socket.lock() {
            if let Some(socket) = socket.take() {
                socket.close();
            }
        }
    }
}

/// Hole punching plus the two-sided switch handshake.
///
/// The returned socket is validated and the peer has confirmed it too; a `None` means the
/// peer never confirmed, so neither side commits and the caller keeps using the relay.
async fn negotiate_direct(
    udp: Arc<UdpSocket>,
    existing: Option<Arc<DirectSocket>>,
    credentials: ProbeCredentials,
    candidates: &[SocketAddr],
    probe: ProbeConfig,
    switch: SwitchConfig,
    keepalive_interval: Duration,
) -> Result<Option<(Arc<DirectSocket>, Option<HolePunchOutcome>)>, PathError> {
    if candidates.is_empty() {
        return Ok(None);
    }
    // One reader per path: a new rendezvous round re-keys the existing socket instead of
    // starting a second task on the same file descriptor.
    let socket = match existing {
        Some(existing) => {
            if existing.round_id() != credentials.round_id() {
                existing.rekey(credentials);
            }
            existing
        }
        None => Arc::new(DirectSocket::open(udp, credentials, keepalive_interval).await?),
    };
    let outcome = match socket.punch(candidates, probe).await {
        Ok(outcome) => outcome,
        Err(HolePunchError::Timeout { .. }) | Err(HolePunchError::ReceiveTimeout) => {
            // Keep the socket: the opposite peer may still reach this side, and the
            // responder must outlive this attempt so a later upgrade can be confirmed.
            return Ok(Some((socket, None)));
        }
        Err(error) => return Err(error.into()),
    };
    let mut events = socket.subscribe();
    match socket.negotiate_switch(outcome.peer, switch).await {
        Ok(()) => {
            // Both switches completed; each side now says it is reading the direct path and
            // waits for the peer to say the same. Confirmations are retransmitted and
            // acknowledged, so a single lost datagram costs a retry instead of committing
            // one peer alone.
            if socket
                .confirm_both_ways(&mut events, outcome.peer, switch)
                .await
            {
                Ok(Some((socket, Some(outcome))))
            } else {
                Ok(Some((socket, None)))
            }
        }
        Err(HolePunchError::SwitchUnconfirmed) => Ok(Some((socket, None))),
        Err(error) => Err(error.into()),
    }
}

/// Entry point for establishing a path.
pub struct PathController;

impl PathController {
    /// Verifies the ticket, agrees the session keys, races bounded direct negotiation
    /// against the already authorized relay, and returns the lower-latency validated path.
    pub async fn connect(
        ticket: Ticket,
        candidates: CandidateSet,
        setup: PathSetup,
    ) -> Result<ConnectedPath, PathError> {
        setup.config.validate()?;
        ticket.require_session(candidates.session_id())?;
        let verified = ticket.verify(candidates.verification_key(), setup.now_ms)?;
        let local_identity = setup.identity.public_key();
        if verified.own_identity_key != local_identity {
            return Err(TicketError::IdentityMismatch {
                found: verified.own_identity_key.to_string(),
                expected: local_identity.to_string(),
            }
            .into());
        }
        if candidates.is_expired(setup.now_ms) {
            return Err(CandidateError::Expired {
                expires_at: candidates.expires_at(),
            }
            .into());
        }
        // Everything that can refuse the caller is checked before any state is claimed, so a
        // corrected retry with the same ticket still works.
        if let Some(expected) = setup.expected_peer_identity {
            if expected != verified.peer_identity_key {
                return Err(TicketError::PeerIdentityMismatch {
                    found: verified.peer_identity_key.to_string(),
                    expected: expected.to_string(),
                }
                .into());
            }
        }
        let peer_nonce = candidates.peer_nonce().ok_or(PathError::EpochUnavailable)?;
        claim_ticket(candidates.session_id(), ticket.role, &ticket.nonce)?;

        // The epoch is the two peers' single-use ticket nonces. Without the peer's nonce a
        // second connection on the same session would derive the same keys and the same
        // nonces, so this refuses to build a path until rendezvous has exchanged them.
        let epoch = Epoch::split(&ticket.nonce, peer_nonce, ticket.role)?;
        let cipher = SessionCipher::new(
            &setup.identity,
            verified.peer_identity_key,
            candidates.session_id(),
            ticket.role,
            &epoch,
        )?;

        let PathSetup {
            socket,
            relay,
            config,
            ..
        } = setup;

        let path = ConnectedPath {
            session_id: candidates.session_id().to_owned(),
            device_id: ticket.device_id.clone(),
            ticket: ticket.clone(),
            cipher,
            config: config.clone(),
            socket: Some(Arc::clone(&socket)),
            probe_socket: std::sync::Mutex::new(None),
            kind: AtomicU8::new(RELAY),
            state: RwLock::new(PathState {
                direct: None,
                relay: relay.clone(),
                closed: false,
            }),
        };

        let negotiated = negotiate_direct(
            Arc::clone(&socket),
            None,
            verified.credentials,
            &candidates.direct(),
            config.probe,
            config.switch,
            config.keepalive_interval,
        )
        .await?;
        if let Some((probe_socket, _)) = &negotiated {
            path.replace_probe_socket(Arc::clone(probe_socket));
        }
        let direct =
            negotiated.and_then(|(socket, outcome)| outcome.map(|outcome| (socket, outcome)));

        let relay_latency = path.relay_latency(&*path.state.read().await);
        let direct_latency = direct.as_ref().map(|(_, outcome)| outcome.rtt);
        let kind = match PathController::select(direct_latency, relay_latency) {
            Some(kind) => kind,
            None if candidates.direct().is_empty() => return Err(PathError::NoPath),
            None => {
                return Err(HolePunchError::Timeout {
                    attempts: config.probe.max_attempts,
                }
                .into());
            }
        };

        if kind == PathKind::Direct {
            if let Some((direct_socket, HolePunchOutcome { peer, rtt })) = direct {
                let mut state = path.state.write().await;
                state.direct = Some(DirectState {
                    socket: direct_socket,
                    peer,
                    rtt,
                });
                path.kind.store(PENDING, Ordering::SeqCst);
            }
        }

        Ok(path)
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

fn validate_envelope_identity(
    envelope: &Envelope,
    session_id: &str,
    device_id: &str,
) -> Result<(), PathError> {
    if envelope.session_id != session_id {
        return Err(PathError::Aead(AeadError::InvalidEnvelope {
            reason: format!(
                "envelope is for session {}, not {session_id}",
                envelope.session_id
            ),
        }));
    }
    if envelope.device_id != device_id {
        return Err(PathError::Aead(AeadError::InvalidEnvelope {
            reason: format!(
                "envelope is for device {}, not {device_id}",
                envelope.device_id
            ),
        }));
    }
    Ok(())
}

/// Entry point for establishing a path.
fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}
