//! Session authorization, rendezvous data, and direct-path tickets.
//!
//! The server authorizes a user before minting a short-lived session capability, and it is
//! the only source of candidate endpoints. Direct-path negotiation needs three things the
//! relay alone cannot provide:
//!
//! - a **signed ticket** per peer, bound to the session, device, role, nonce, probe key,
//!   and a short expiry, so neither peer can mint or mutate rendezvous key material;
//! - a **nonce replay guard**: a ticket nonce is redeemed once, by one peer role, before
//!   any path is established;
//! - **candidate exchange**: each peer reports the endpoint the server observed for it,
//!   and receives the endpoint observed for the opposite peer.
//!
//! Authorization, expiry, and revocation rules stay in [`crate::auth`]; nothing here
//! weakens them.

use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard};

use axum::Json;
use axum::extract::{Path, State};
use axum::http::{HeaderMap, StatusCode};
use axum::response::{IntoResponse, Response};
use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::json;

use crate::auth::{
    AuthError, IdentityKeyError, SESSION_CAPABILITY_PREFIX, bearer_token, generate_secret,
    hash_secret, normalize_identity_key,
};
use crate::relay::PeerRole;
use crate::store::{SessionRecord, StoreError, UnixMs};
use crate::{ApiJson, AppState};

/// Prefix of a server-issued session identifier.
pub const SESSION_ID_PREFIX: &str = "sess_";

/// Sessions are short-lived; they are rejected rather than refreshed after this window.
pub const SESSION_TTL_MS: UnixMs = 300_000;

/// Rendezvous tickets live only long enough to exchange candidates and punch. A path that
/// is not validated in this window must ask rendezvous for a new ticket.
pub const TICKET_TTL_MS: UnixMs = 30_000;

/// Domain separator of the ticket signature. It matches the transport crate's copy; a
/// change invalidates every outstanding ticket.
pub const TICKET_SIGNING_LABEL: &str = "phoneconnect-rendezvous-ticket-v1";

/// Largest number of redeemed nonces remembered for replay rejection.
pub const MAX_REMEMBERED_NONCES: usize = 4096;

/// What a candidate endpoint can be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    /// A locally discovered address for one peer.
    Local,
    /// An address the server observed for one peer.
    ServerObserved,
    /// The server relay; always available and bounded. Frames are sealed by the peers, so
    /// the relay carries ciphertext it cannot read.
    Relay,
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
    /// Hex-encoded Ed25519 key that verifies this session's tickets.
    pub verification_key: String,
    /// Redemption nonce of the opposite peer's ticket, once that peer has registered. The two
    /// nonces are the per-connection epoch the peers mix into their traffic-key derivation,
    /// so a reconnecting peer that re-registers with fresh tickets never reuses a key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peer_nonce: Option<String>,
    pub candidates: Vec<EndpointCandidate>,
}

/// Short-lived, server-signed ticket binding a session and one peer role to one
/// rendezvous attempt.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousTicket {
    pub session_id: String,
    pub device_id: String,
    pub role: PeerRole,
    pub nonce: String,
    /// Base64url-encoded 256-bit key used to authenticate direct-path probes. Both peers
    /// receive the same key inside their signed tickets. It authenticates hole-punch
    /// datagrams only and never keys frame encryption.
    pub probe_key: String,
    /// The receiving peer's own X25519 identity public key, pinned at enrollment or when
    /// the session was authorized. The private half is never here.
    pub own_identity_key: String,
    /// The opposite peer's X25519 identity public key. Frames are sealed for this key; the
    /// server holds only the public half and cannot derive the traffic keys.
    pub peer_identity_key: String,
    pub expires_at: UnixMs,
    /// Hex-encoded Ed25519 signature over the authority's canonical signing payload.
    pub signature: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum TicketError {
    #[error("ticket signature does not verify")]
    InvalidSignature,
    #[error("ticket expired at {expires_at}")]
    Expired { expires_at: UnixMs },
    #[error("ticket is for session {found}, not {expected}")]
    SessionMismatch { found: String, expected: String },
    #[error("ticket is bound to role {bound:?}, not {requested:?}")]
    RoleMismatch {
        bound: PeerRole,
        requested: PeerRole,
    },
    #[error("ticket nonce was already redeemed; a replayed ticket never starts a path")]
    Replayed,
    #[error("ticket nonce {nonce} is not bound to a valid observed endpoint")]
    InvalidNonce { nonce: String },
    #[error("random source failed: {0}")]
    Random(String),
    #[error("session has no pinned identity keys; re-enroll the device and re-authorize")]
    IdentityUnavailable,
}

impl TicketError {
    pub fn code(&self) -> &'static str {
        match self {
            Self::InvalidSignature => "ticket_invalid",
            Self::Expired { .. } => "ticket_expired",
            Self::SessionMismatch { .. }
            | Self::RoleMismatch { .. }
            | Self::InvalidNonce { .. } => "ticket_scope_mismatch",
            Self::Replayed => "ticket_replayed",
            Self::IdentityUnavailable => "ticket_identity_missing",
            Self::Random(_) => "random_source_failed",
        }
    }

    pub fn status(&self) -> StatusCode {
        match self {
            Self::Replayed => StatusCode::CONFLICT,
            Self::Random(_) | Self::IdentityUnavailable => StatusCode::INTERNAL_SERVER_ERROR,
            _ => StatusCode::UNAUTHORIZED,
        }
    }
}

impl IntoResponse for TicketError {
    fn into_response(self) -> Response {
        (self.status(), Json(json!({ "error": self.code() }))).into_response()
    }
}

/// A ticket whose signature, expiry, session, and role all checked out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedTicket {
    pub session_id: String,
    pub device_id: String,
    pub role: PeerRole,
    pub nonce: String,
    pub probe_key: String,
    pub own_identity_key: String,
    pub peer_identity_key: String,
    pub expires_at: UnixMs,
}

/// Issues and verifies rendezvous tickets with one in-process Ed25519 key.
///
/// The key is generated at startup, so a restart invalidates outstanding tickets; they
/// live for [`TICKET_TTL_MS`] and a peer re-requests one from rendezvous after a restart.
/// Only the public half leaves this type, through
/// [`SessionCandidates::verification_key`].
pub struct TicketAuthority {
    signing_key: SigningKey,
    verifying_key: VerifyingKey,
    verification_key: String,
    rounds: Mutex<HashMap<String, RoundKey>>,
    redeemed: Mutex<RedeemedNonces>,
}

/// The probe key both peers of one rendezvous round receive. It is signed into each ticket,
/// so neither peer can choose it. The redemption nonce is minted per ticket instead: a peer
/// that re-requests a ticket inside the window needs a nonce it has not redeemed, while both
/// peers must still probe with the same key.
struct RoundKey {
    probe_key: String,
    expires_at: UnixMs,
}

#[derive(Default)]
struct RedeemedNonces {
    /// nonce -> expiry. Bounded by [`MAX_REMEMBERED_NONCES`]; expired entries are pruned.
    /// Every ticket gets its own nonce, so a replay is exactly a nonce seen before.
    entries: HashMap<String, UnixMs>,
}

impl std::fmt::Debug for TicketAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TicketAuthority")
            .field("verification_key", &self.verification_key)
            .finish_non_exhaustive()
    }
}

impl TicketAuthority {
    /// Builds an authority with a fresh key.
    pub fn new() -> Result<Self, TicketError> {
        let mut secret = [0u8; 32];
        getrandom::fill(&mut secret).map_err(|error| TicketError::Random(error.to_string()))?;
        Ok(Self::from_signing_key(SigningKey::from_bytes(&secret)))
    }

    pub fn from_signing_key(signing_key: SigningKey) -> Self {
        let verifying_key = signing_key.verifying_key();
        Self {
            verification_key: hex(&verifying_key.to_bytes()),
            signing_key,
            verifying_key,
            rounds: Mutex::new(HashMap::new()),
            redeemed: Mutex::new(RedeemedNonces::default()),
        }
    }

    /// Hex-encoded Ed25519 public key peers use to verify tickets.
    pub fn verification_key(&self) -> &str {
        &self.verification_key
    }

    /// Canonical bytes this authority signs. The transport crate reconstructs the same
    /// layout, so any change here needs a matching change there.
    fn signing_payload(ticket: &RendezvousTicket) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(TICKET_SIGNING_LABEL.as_bytes());
        payload.push(b'\n');
        for field in [
            ticket.session_id.as_str(),
            ticket.device_id.as_str(),
            ticket.role.as_str(),
            ticket.nonce.as_str(),
            ticket.probe_key.as_str(),
            ticket.own_identity_key.as_str(),
            ticket.peer_identity_key.as_str(),
            &ticket.expires_at.to_string(),
        ] {
            payload.extend_from_slice(field.as_bytes());
            payload.push(b'\n');
        }
        payload
    }

    /// Signs a ticket for one peer role. The expiry never outlives the session.
    ///
    /// Both roles of one rendezvous round share the probe key: that shared value is what
    /// authenticates direct-path probes. Each ticket carries its own single-use nonce, so a
    /// peer that re-requests a ticket inside the window can always redeem the new one while
    /// still probing with the round key. [`Self::start_round`] begins a new round after a
    /// network change.
    pub fn issue(
        &self,
        session: &SessionRecord,
        role: PeerRole,
        now_ms: UnixMs,
    ) -> Result<RendezvousTicket, TicketError> {
        let expires_at = session.expires_at_ms.min(now_ms + TICKET_TTL_MS);
        let (own_identity_key, peer_identity_key) = identity_keys(session, role)?;
        let nonce = generate_secret("").map_err(|error| TicketError::Random(error.to_string()))?;
        let probe_key = self.round(&session.session_id, expires_at, now_ms)?;
        let mut ticket = RendezvousTicket {
            session_id: session.session_id.clone(),
            device_id: session.device_id.clone(),
            role,
            nonce,
            probe_key,
            own_identity_key,
            peer_identity_key,
            expires_at,
            signature: String::new(),
        };
        let signature = self.signing_key.sign(&Self::signing_payload(&ticket));
        ticket.signature = hex(&signature.to_bytes());
        Ok(ticket)
    }

    /// Starts a new rendezvous round for `session_id`, so a peer that repeats candidate
    /// discovery after a network change receives fresh key material instead of reusing a
    /// redeemed nonce.
    pub fn start_round(&self, session_id: &str) -> Result<(), TicketError> {
        self.rounds().remove(session_id);
        Ok(())
    }

    /// The probe key for the session's current round, minting one when the round is new or
    /// expired. Stable across ticket re-requests, so both peers always probe with the same
    /// key; [`Self::start_round`] rotates it explicitly.
    fn round(
        &self,
        session_id: &str,
        ticket_expires_at: UnixMs,
        now_ms: UnixMs,
    ) -> Result<String, TicketError> {
        let mut rounds = self.rounds();
        rounds.retain(|_, round| round.expires_at > now_ms);
        if let Some(round) = rounds.get(session_id) {
            if round.expires_at >= now_ms {
                return Ok(round.probe_key.clone());
            }
        }
        let probe_key =
            generate_secret("").map_err(|error| TicketError::Random(error.to_string()))?;
        rounds.insert(
            session_id.to_owned(),
            RoundKey {
                probe_key: probe_key.clone(),
                expires_at: ticket_expires_at,
            },
        );
        Ok(probe_key)
    }

    /// Verifies signature, expiry, session, and role. Replay is not considered here;
    /// [`Self::redeem`] adds the single-use rule.
    pub fn verify(
        &self,
        ticket: &RendezvousTicket,
        session_id: &str,
        role: PeerRole,
        now_ms: UnixMs,
    ) -> Result<VerifiedTicket, TicketError> {
        if ticket.session_id != session_id {
            return Err(TicketError::SessionMismatch {
                found: ticket.session_id.clone(),
                expected: session_id.to_owned(),
            });
        }
        if ticket.role != role {
            return Err(TicketError::RoleMismatch {
                bound: ticket.role,
                requested: role,
            });
        }
        let signature = decode_hex_64(&ticket.signature).ok_or(TicketError::InvalidSignature)?;
        let payload = Self::signing_payload(ticket);
        self.verifying_key
            .verify_strict(&payload, &Signature::from_bytes(&signature))
            .map_err(|_| TicketError::InvalidSignature)?;
        if now_ms >= ticket.expires_at {
            return Err(TicketError::Expired {
                expires_at: ticket.expires_at,
            });
        }
        if ticket.nonce.is_empty()
            || ticket.probe_key.is_empty()
            || ticket.own_identity_key.is_empty()
            || ticket.peer_identity_key.is_empty()
        {
            return Err(TicketError::InvalidSignature);
        }
        Ok(VerifiedTicket {
            session_id: ticket.session_id.clone(),
            device_id: ticket.device_id.clone(),
            role: ticket.role,
            nonce: ticket.nonce.clone(),
            probe_key: ticket.probe_key.clone(),
            own_identity_key: ticket.own_identity_key.clone(),
            peer_identity_key: ticket.peer_identity_key.clone(),
            expires_at: ticket.expires_at,
        })
    }

    /// Verifies a ticket and consumes its nonce. A nonce is redeemed at most once, so a
    /// replayed ticket is refused before any candidate is exchanged or path validated.
    pub fn redeem(
        &self,
        ticket: &RendezvousTicket,
        session_id: &str,
        role: PeerRole,
        now_ms: UnixMs,
    ) -> Result<VerifiedTicket, TicketError> {
        let verified = self.verify(ticket, session_id, role, now_ms)?;
        let mut redeemed = self.redeemed();
        redeemed.prune(now_ms);
        if redeemed.entries.contains_key(&verified.nonce) {
            return Err(TicketError::Replayed);
        }
        redeemed
            .entries
            .insert(verified.nonce.clone(), verified.expires_at);
        if redeemed.entries.len() > MAX_REMEMBERED_NONCES {
            redeemed.evict_earliest();
        }
        Ok(verified)
    }

    fn rounds(&self) -> MutexGuard<'_, HashMap<String, RoundKey>> {
        self.rounds
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn redeemed(&self) -> MutexGuard<'_, RedeemedNonces> {
        self.redeemed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl RedeemedNonces {
    fn prune(&mut self, now_ms: UnixMs) {
        self.entries.retain(|_, expires_at| *expires_at > now_ms);
    }

    fn evict_earliest(&mut self) {
        if let Some(earliest) = self
            .entries
            .iter()
            .min_by_key(|(_, expires_at)| **expires_at)
            .map(|(nonce, _)| nonce.clone())
        {
            self.entries.remove(&earliest);
        }
    }
}

/// What the server remembers about one peer's rendezvous registration.
///
/// The nonce and the endpoint are deliberately separate: a peer that only needs to publish
/// its half of the connection epoch registers a nonce with no endpoint, and then no
/// `server_observed` candidate is advertised to the opposite peer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ObservedEndpoint {
    /// The endpoint the peer reported, if it reported one. `None` means "nonce only".
    pub endpoint: Option<String>,
    pub observed_at_ms: UnixMs,
    /// The redemption nonce of the ticket that registered this peer.
    pub nonce: String,
}

#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RendezvousError {
    #[error("random source failed: {0}")]
    Random(String),
    #[error(transparent)]
    Ticket(#[from] TicketError),
}

/// Issues rendezvous data and remembers the endpoints peers report for one session.
pub struct Rendezvous {
    relay_endpoint: String,
    tickets: Arc<TicketAuthority>,
    observed: Mutex<HashMap<(String, PeerRole), ObservedEndpoint>>,
}

impl Rendezvous {
    pub fn new(relay_endpoint: impl Into<String>, tickets: Arc<TicketAuthority>) -> Self {
        Self {
            relay_endpoint: relay_endpoint.into(),
            tickets,
            observed: Mutex::new(HashMap::new()),
        }
    }

    pub fn tickets(&self) -> &Arc<TicketAuthority> {
        &self.tickets
    }

    /// The route that carries one session's relay transport.
    pub fn relay_endpoint(&self, session_id: &str) -> String {
        format!(
            "{}/{session_id}/relay",
            self.relay_endpoint.trim_end_matches('/')
        )
    }

    pub fn ticket(
        &self,
        session: &SessionRecord,
        role: PeerRole,
        now_ms: UnixMs,
    ) -> Result<RendezvousTicket, RendezvousError> {
        Ok(self.tickets.issue(session, role, now_ms)?)
    }

    /// Candidate endpoints for one peer of an authorized session: the relay plus the
    /// endpoint the server observed for the opposite peer, if that peer reported one.
    pub fn candidates(
        &self,
        session: &SessionRecord,
        role: PeerRole,
        now_ms: UnixMs,
    ) -> SessionCandidates {
        let mut candidates = Vec::new();
        let peer = self.observed_endpoint(&session.session_id, role.opposite(), now_ms);
        // Only a peer that published an endpoint becomes a probe target. A nonce-only
        // registration still supplies the epoch, which is all a relay-only session needs.
        if let Some(endpoint) = peer.as_ref().and_then(|observed| observed.endpoint.clone()) {
            candidates.push(EndpointCandidate {
                kind: CandidateKind::ServerObserved,
                endpoint,
                priority: 150,
            });
        }
        candidates.push(EndpointCandidate {
            kind: CandidateKind::Relay,
            endpoint: self.relay_endpoint(&session.session_id),
            priority: 100,
        });
        SessionCandidates {
            session_id: session.session_id.clone(),
            expires_at: session.expires_at_ms,
            verification_key: self.tickets.verification_key().to_owned(),
            peer_nonce: peer.map(|observed| observed.nonce),
            candidates,
        }
    }

    /// Records `role`'s redemption nonce, and its endpoint when it has one, then returns
    /// that peer's view.
    ///
    /// The ticket must redeem successfully first, so an unauthenticated, expired, revoked, or
    /// replayed registration never publishes a nonce another peer would derive keys from. An
    /// absent endpoint is valid: it publishes the nonce for the epoch without advertising a
    /// probe target that does not exist.
    pub fn observe(
        &self,
        session: &SessionRecord,
        role: PeerRole,
        ticket: &RendezvousTicket,
        endpoint: Option<&str>,
        now_ms: UnixMs,
    ) -> Result<SessionCandidates, TicketError> {
        let verified = self
            .tickets
            .redeem(ticket, &session.session_id, role, now_ms)?;
        let normalized = match endpoint.map(str::trim).filter(|value| !value.is_empty()) {
            None => None,
            Some(endpoint) => Some(normalize_endpoint(endpoint).ok_or_else(|| {
                TicketError::InvalidNonce {
                    nonce: ticket.nonce.clone(),
                }
            })?),
        };
        {
            let mut entries = self.observed();
            entries.retain(|(session_id, _), value| {
                session_id != &session.session_id || value.observed_at_ms + SESSION_TTL_MS > now_ms
            });
            entries.insert(
                (session.session_id.clone(), role),
                ObservedEndpoint {
                    endpoint: normalized,
                    observed_at_ms: now_ms,
                    nonce: verified.nonce.clone(),
                },
            );
        }
        Ok(self.candidates(session, role, now_ms))
    }

    fn observed_endpoint(
        &self,
        session_id: &str,
        role: PeerRole,
        now_ms: UnixMs,
    ) -> Option<ObservedEndpoint> {
        let mut entries = self.observed();
        entries.retain(|(_, _), value| value.observed_at_ms + SESSION_TTL_MS > now_ms);
        entries.get(&(session_id.to_owned(), role)).cloned()
    }

    fn observed(&self) -> MutexGuard<'_, HashMap<(String, PeerRole), ObservedEndpoint>> {
        self.observed
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

fn normalize_endpoint(endpoint: &str) -> Option<String> {
    endpoint
        .parse::<SocketAddr>()
        .ok()
        .map(|address| address.to_string())
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex_64(value: &str) -> Option<[u8; 64]> {
    if value.len() != 128 {
        return None;
    }
    let mut bytes = [0u8; 64];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(bytes)
}

#[derive(Debug, Deserialize)]
pub struct CreateSessionRequest {
    pub device_id: String,
    /// X25519 identity public key of the client. There is no local password login yet, so
    /// session authorization is the client's registration point; it is the login-equivalent
    /// pin for this milestone. The private half never leaves the client.
    #[serde(default)]
    pub client_identity_key: String,
}

/// Capability and rendezvous ticket handed to the peer that created the session.
#[derive(Debug, Serialize)]
pub struct IssuedSession {
    pub session_id: String,
    pub capability: String,
    pub expires_at: UnixMs,
    pub ticket: RendezvousTicket,
    pub verification_key: String,
}

/// Body of `POST /api/sessions/{id}/candidates`.
///
/// `endpoint` is optional: a peer with no direct path publishes its redemption nonce only, so
/// the opposite peer still learns its half of the epoch but is never told to probe an address
/// that cannot answer.
#[derive(Debug, Deserialize)]
pub struct ObserveRequest {
    pub ticket: RendezvousTicket,
    #[serde(default)]
    pub endpoint: Option<String>,
}

/// One peer's ticket, for the device that did not create the session.
#[derive(Debug, Serialize)]
pub struct IssuedTicket {
    pub ticket: RendezvousTicket,
    pub verification_key: String,
}

/// The session a device should join, as `GET /api/devices/{id}/sessions/next` returns it.
///
/// The device credential proves which device is asking; the ticket is minted for the device
/// role, so the peer identity and epoch nonces the device needs come from the server, and
/// the device never has to know a client identifier or hold client privileges.
#[derive(Debug, Serialize)]
pub struct DeviceSession {
    pub session_id: String,
    pub expires_at: UnixMs,
    pub ticket: RendezvousTicket,
    pub verification_key: String,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionError {
    #[error(transparent)]
    Auth(#[from] AuthError),
    #[error(transparent)]
    Ticket(#[from] TicketError),
    #[error("device {device_id} is unknown")]
    DeviceUnknown { device_id: String },
    #[error("device {device_id} is revoked")]
    DeviceRevoked { device_id: String },
    #[error("{endpoint} is not a socket address")]
    InvalidEndpoint { endpoint: String },
    #[error("client_identity_key is missing")]
    IdentityKeyMissing,
    #[error("client_identity_key is invalid")]
    IdentityKeyInvalid,
    #[error("device {device_id} has no identity key; it must be re-enrolled")]
    DeviceIdentityMissing { device_id: String },
    #[error("credential is not for device {device_id}")]
    DeviceScopeMismatch { device_id: String },
    #[error(transparent)]
    Store(#[from] StoreError),
    #[error(transparent)]
    Rendezvous(#[from] RendezvousError),
}

impl IntoResponse for SessionError {
    fn into_response(self) -> Response {
        let (status, code) = match &self {
            Self::Auth(error) => return error.clone().into_response(),
            Self::Ticket(error) => return error.clone().into_response(),
            Self::DeviceUnknown { .. } => (StatusCode::NOT_FOUND, "device_unknown"),
            Self::DeviceRevoked { .. } => (StatusCode::CONFLICT, "device_revoked"),
            Self::InvalidEndpoint { .. } => (StatusCode::BAD_REQUEST, "invalid_endpoint"),
            Self::IdentityKeyMissing => (StatusCode::BAD_REQUEST, "identity_key_required"),
            Self::IdentityKeyInvalid => (StatusCode::BAD_REQUEST, "invalid_identity_key"),
            Self::DeviceIdentityMissing { .. } => (StatusCode::CONFLICT, "device_identity_missing"),
            Self::DeviceScopeMismatch { .. } => (StatusCode::FORBIDDEN, "device_scope_mismatch"),
            Self::Store(_) => (StatusCode::INTERNAL_SERVER_ERROR, "store_failure"),
            Self::Rendezvous(_) => (StatusCode::INTERNAL_SERVER_ERROR, "random_source_failed"),
        };
        (status, Json(json!({ "error": code }))).into_response()
    }
}

/// `POST /api/sessions`: authorizes a device session and returns a capability plus the
/// client-side ticket.
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
    if device.identity_public_key.is_empty() {
        return Err(SessionError::DeviceIdentityMissing {
            device_id: device.device_id,
        });
    }
    if request.client_identity_key.trim().is_empty() {
        return Err(SessionError::IdentityKeyMissing);
    }
    let client_identity_key = normalize_identity_key(&request.client_identity_key).map_err(
        |error: IdentityKeyError| {
            let _ = error;
            SessionError::IdentityKeyInvalid
        },
    )?;

    let now = state.now_ms();
    let session_id = format!("{SESSION_ID_PREFIX}{}", random_component()?);
    // The capability is returned to the caller but only its hash is persisted.
    let capability = generate_secret(SESSION_CAPABILITY_PREFIX)?;
    let session = SessionRecord {
        session_id,
        device_id: device.device_id.clone(),
        owner_id: device.owner_id.clone(),
        capability_hash: hash_secret(&capability),
        client_identity_key,
        device_identity_key: device.identity_public_key.clone(),
        created_at_ms: now,
        expires_at_ms: now + SESSION_TTL_MS,
        revoked_at_ms: None,
    };
    state.store.insert_session(session.clone()).await?;

    let ticket = state.rendezvous.ticket(&session, PeerRole::Client, now)?;
    Ok((
        StatusCode::OK,
        Json(IssuedSession {
            session_id: session.session_id,
            capability,
            expires_at: session.expires_at_ms,
            ticket,
            verification_key: state.rendezvous.tickets().verification_key().to_owned(),
        }),
    ))
}

/// `GET /api/sessions/{id}/ticket`: a fresh short-lived ticket for the calling peer.
///
/// The session capability receives the client ticket; the owning device credential
/// receives the device ticket. Each call mints a new nonce, so a peer that lost its ticket
/// re-requests one instead of reusing a redeemed nonce.
pub async fn session_ticket(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<IssuedTicket>, SessionError> {
    let (session, role) = authorize_peer(&state, &headers, &session_id).await?;
    let ticket = state.rendezvous.ticket(&session, role, state.now_ms())?;
    Ok(Json(IssuedTicket {
        ticket,
        verification_key: state.rendezvous.tickets().verification_key().to_owned(),
    }))
}

/// `GET /api/devices/{id}/sessions/next`: the newest session a client authorized for this
/// device, with a device-role ticket, or `204` when there is nothing to join.
///
/// Sessions are authorized by a user or client, never by the device itself; this route is
/// how the enrolled device learns that one exists without holding any credential beyond its
/// own. A device can only ever see its own sessions.
pub async fn device_session(
    State(state): State<Arc<AppState>>,
    Path(device_id): Path<String>,
    headers: HeaderMap,
) -> Result<Response, SessionError> {
    let device = state.auth.require_device(&headers).await?;
    if device.device_id != device_id {
        return Err(SessionError::DeviceScopeMismatch { device_id });
    }
    let now = state.now_ms();
    let Some(session) = state
        .store
        .latest_session_for_device(&device.device_id, now)
        .await?
    else {
        return Ok(StatusCode::NO_CONTENT.into_response());
    };
    let ticket = state
        .rendezvous
        .ticket(&session, PeerRole::Device, now)?;
    Ok(Json(DeviceSession {
        session_id: session.session_id,
        expires_at: session.expires_at_ms,
        ticket,
        verification_key: state.rendezvous.tickets().verification_key().to_owned(),
    })
    .into_response())
}

/// `GET /api/sessions/{id}/candidates`: authenticated endpoint candidates for one session.
pub async fn session_candidates(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
) -> Result<Json<SessionCandidates>, SessionError> {
    let (session, role) = authorize_peer(&state, &headers, &session_id).await?;
    Ok(Json(state.rendezvous.candidates(
        &session,
        role,
        state.now_ms(),
    )))
}

/// `POST /api/sessions/{id}/candidates`: redeem a ticket and publish this peer's redemption
/// nonce, with an endpoint when it has one, returning the candidates for the opposite peer.
///
/// The ticket is single-use here, never on the read-only `GET`, so a poll never burns it.
pub async fn register_candidate(
    State(state): State<Arc<AppState>>,
    Path(session_id): Path<String>,
    headers: HeaderMap,
    ApiJson(request): ApiJson<ObserveRequest>,
) -> Result<Json<SessionCandidates>, SessionError> {
    let (session, role) = authorize_peer(&state, &headers, &session_id).await?;
    let endpoint = request
        .endpoint
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty());
    if let Some(endpoint) = endpoint {
        if endpoint.parse::<SocketAddr>().is_err() {
            return Err(SessionError::InvalidEndpoint {
                endpoint: endpoint.to_owned(),
            });
        }
    }
    let candidates =
        state
            .rendezvous
            .observe(&session, role, &request.ticket, endpoint, state.now_ms())?;
    Ok(Json(candidates))
}

/// Authorizes either peer of `session_id` and returns the role its credential proves.
async fn authorize_peer(
    state: &Arc<AppState>,
    headers: &HeaderMap,
    session_id: &str,
) -> Result<(SessionRecord, PeerRole), SessionError> {
    let session = state
        .auth
        .authorize_session_access(headers, session_id)
        .await?;
    let token = bearer_token(headers)?;
    let role = if token.starts_with(SESSION_CAPABILITY_PREFIX) {
        PeerRole::Client
    } else {
        PeerRole::Device
    };
    Ok((session, role))
}

/// The two identity public keys a ticket binds, in `(own, peer)` order for `role`.
fn identity_keys(session: &SessionRecord, role: PeerRole) -> Result<(String, String), TicketError> {
    if session.client_identity_key.is_empty() || session.device_identity_key.is_empty() {
        return Err(TicketError::IdentityUnavailable);
    }
    Ok(match role {
        PeerRole::Client => (
            session.client_identity_key.clone(),
            session.device_identity_key.clone(),
        ),
        PeerRole::Device => (
            session.device_identity_key.clone(),
            session.client_identity_key.clone(),
        ),
    })
}

fn random_component() -> Result<String, RendezvousError> {
    generate_secret("").map_err(|error| RendezvousError::Random(error.to_string()))
}
