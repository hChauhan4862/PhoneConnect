//! Candidate discovery.
//!
//! The server is the only source of candidates it can observe: it returns the relay and
//! the endpoint the opposite peer reported. A peer adds the endpoints it discovered for
//! that same peer locally. [`CandidateSet::discover`] merges both views into one ordered,
//! de-duplicated set and validates every direct endpoint before anything is probed.

use std::net::SocketAddr;

use serde::{Deserialize, Serialize};

use phoneconnect::v1::SessionId;

/// Priority of a locally discovered candidate. Higher is attempted first.
pub const LOCAL_PRIORITY: u8 = 200;
/// Priority of a candidate the server observed for the peer.
pub const SERVER_OBSERVED_PRIORITY: u8 = 150;
/// Priority of the relay candidate. Direct candidates outrank it, but the wire priority
/// the server sends is preserved so a deployment can prefer the relay.
pub const RELAY_PRIORITY: u8 = 100;

/// What a candidate endpoint can be used for.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CandidateKind {
    /// A locally discovered address for the opposite peer.
    Local,
    /// An address the server observed for the opposite peer.
    ServerObserved,
    /// The server relay, always available and bounded.
    Relay,
}

impl CandidateKind {
    pub fn is_direct(self) -> bool {
        matches!(self, Self::Local | Self::ServerObserved)
    }
}

/// One candidate exactly as the rendezvous service serializes it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WireCandidate {
    pub kind: CandidateKind,
    pub endpoint: String,
    pub priority: u8,
}

/// Rendezvous data a peer receives for one session.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RendezvousCandidates {
    pub session_id: String,
    pub expires_at: i64,
    /// Hex-encoded Ed25519 key that verifies the server's rendezvous tickets.
    #[serde(default)]
    pub verification_key: String,
    pub candidates: Vec<WireCandidate>,
}

/// One candidate a peer may attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct EndpointCandidate {
    pub kind: CandidateKind,
    /// The endpoint as advertised; a URL for the relay, an address for a direct path.
    pub endpoint: String,
    /// Parsed direct address. Always `None` for the relay candidate.
    pub address: Option<SocketAddr>,
    pub priority: u8,
}

/// Explicit candidate failures. Discovery never silently drops data it cannot use.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum CandidateError {
    #[error("rendezvous session id {session_id} is invalid: {reason}")]
    InvalidSession { session_id: String, reason: String },
    #[error("{kind:?} candidate endpoint {endpoint} is not a socket address")]
    InvalidEndpoint {
        kind: CandidateKind,
        endpoint: String,
    },
    #[error("relay candidate endpoint {endpoint} is not an http(s) or ws(s) URL")]
    InvalidRelayEndpoint { endpoint: String },
    #[error("rendezvous data expired at {expires_at}")]
    Expired { expires_at: i64 },
}

/// Ordered, validated candidates for one session.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CandidateSet {
    session_id: String,
    expires_at: i64,
    verification_key: String,
    candidates: Vec<EndpointCandidate>,
}

impl CandidateSet {
    /// An empty set. Used by a relay-only path, which has no direct candidates.
    pub(crate) fn empty() -> Self {
        Self {
            session_id: String::new(),
            expires_at: i64::MAX,
            verification_key: String::new(),
            candidates: Vec::new(),
        }
    }

    /// Merges the server's view with endpoints discovered locally for the same peer.
    ///
    /// Direct candidates are ordered by priority (local first, then server-observed) and
    /// de-duplicated by address; the relay appears once. Expiry is reported by
    /// [`Self::is_expired`] because discovery has no clock: the caller decides when its
    /// rendezvous data stopped being valid.
    pub fn discover(
        rendezvous: RendezvousCandidates,
        local: Vec<SocketAddr>,
    ) -> Result<Self, CandidateError> {
        SessionId::new(rendezvous.session_id.clone()).map_err(|error| {
            CandidateError::InvalidSession {
                session_id: rendezvous.session_id.clone(),
                reason: error.to_string(),
            }
        })?;

        let mut candidates: Vec<EndpointCandidate> = Vec::new();
        for address in local {
            push_direct(
                &mut candidates,
                CandidateKind::Local,
                address,
                LOCAL_PRIORITY,
            );
        }

        let mut relay: Option<String> = None;
        for wire in rendezvous.candidates {
            match wire.kind {
                CandidateKind::Relay => {
                    let endpoint = wire.endpoint.trim().to_owned();
                    if !is_relay_url(&endpoint) {
                        return Err(CandidateError::InvalidRelayEndpoint { endpoint });
                    }
                    if relay.is_none() {
                        relay = Some(endpoint.clone());
                        candidates.push(EndpointCandidate {
                            kind: CandidateKind::Relay,
                            endpoint,
                            address: None,
                            priority: wire.priority,
                        });
                    }
                }
                CandidateKind::Local | CandidateKind::ServerObserved => {
                    let address = wire.endpoint.parse::<SocketAddr>().map_err(|_| {
                        CandidateError::InvalidEndpoint {
                            kind: wire.kind,
                            endpoint: wire.endpoint.clone(),
                        }
                    })?;
                    let priority = match wire.kind {
                        CandidateKind::Local => wire.priority.max(LOCAL_PRIORITY),
                        _ => wire.priority.max(SERVER_OBSERVED_PRIORITY),
                    };
                    push_direct(&mut candidates, wire.kind, address, priority);
                }
            }
        }

        // Highest priority first; on a tie, direct candidates outrank the relay.
        candidates.sort_by(|left, right| {
            right
                .priority
                .cmp(&left.priority)
                .then_with(|| right.kind.is_direct().cmp(&left.kind.is_direct()))
        });

        Ok(Self {
            session_id: rendezvous.session_id,
            expires_at: rendezvous.expires_at,
            verification_key: rendezvous.verification_key,
            candidates,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    /// Hex-encoded Ed25519 key that verifies this session's tickets.
    pub fn verification_key(&self) -> &str {
        &self.verification_key
    }

    pub fn candidates(&self) -> &[EndpointCandidate] {
        &self.candidates
    }

    /// Direct candidates in attempt order.
    pub fn direct(&self) -> Vec<SocketAddr> {
        self.candidates
            .iter()
            .filter_map(|candidate| match candidate.kind {
                CandidateKind::Local | CandidateKind::ServerObserved => candidate.address,
                CandidateKind::Relay => None,
            })
            .collect()
    }

    /// The relay endpoint, when the server issued one.
    pub fn relay(&self) -> Option<String> {
        self.candidates
            .iter()
            .find(|candidate| candidate.kind == CandidateKind::Relay)
            .map(|candidate| candidate.endpoint.clone())
    }

    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at
    }
}

fn push_direct(
    candidates: &mut Vec<EndpointCandidate>,
    kind: CandidateKind,
    address: SocketAddr,
    priority: u8,
) {
    if candidates
        .iter()
        .any(|candidate| candidate.address == Some(address))
    {
        return;
    }
    candidates.push(EndpointCandidate {
        kind,
        endpoint: address.to_string(),
        address: Some(address),
        priority,
    });
}

fn is_relay_url(endpoint: &str) -> bool {
    ["http://", "https://", "ws://", "wss://"]
        .iter()
        .any(|scheme| endpoint.starts_with(scheme))
}
