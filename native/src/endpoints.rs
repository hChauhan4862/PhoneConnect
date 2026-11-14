//! Endpoint lifecycle: establish or reuse a session, open a loopback port, serve it.
//!
//! This is the body of the shell's `open_endpoint`, `close_endpoint`, and `local_endpoints`
//! commands. It is plain Rust with no webview so the whole command path is testable, and it
//! is the only place that ties a [`SessionClient`] to a [`ProxyAllocator`].
//!
//! A session is established from data the page already has: the shell's own identity public
//! key is pinned by `POST /api/sessions`, and the page passes the issued ticket, the
//! candidates view, and the session capability back here. No credential is embedded in the
//! page: the ticket is single-use and short-lived, and the identity private half never leaves
//! the shell.

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use phoneconnect::v1::{DeviceId, STREAM_FRAME_LIMIT};
use phoneconnect_transport::{
    CandidateError, CandidateKind, CandidateSet, IdentityKey, PathSetup, RelayError,
    RendezvousCandidates, Ticket, WebSocketRelay, relay_url,
};
use serde::{Deserialize, Serialize};
use tokio::net::UdpSocket;
use tokio::sync::Mutex;
use url::Url;

use crate::proxy::{LocalEndpoint, ProxyAllocator, ProxyCapability, ProxyError, ProxyLimits};
use crate::session_client::{SessionClient, SessionClientError, SessionPath};
use crate::trust::{TicketTrust, TrustError};

/// Longest lifetime the shell grants one endpoint. A capability is short-lived; an endpoint
/// that outlives it would keep a local port pointing at a dead stream.
pub const MAX_ENDPOINT_TTL_SECONDS: u64 = 3_600;

/// What the shell accepts from the page.
///
/// The page cannot choose the transport's trust anchors: the relay must be on the configured
/// server's origin, page-supplied direct candidates are refused (relay-only for this
/// milestone), and, once the shell pins a ticket verification key, the page-supplied key must
/// match it. Without these, a page at the trusted origin could make the shell dial arbitrary
/// hosts and hole-punch arbitrary UDP endpoints.
#[derive(Debug, Clone)]
pub struct EndpointPolicy {
    /// The origin the webview loaded. Everything the page asks the shell to dial must be on it.
    pub server_url: Url,
    /// Ed25519 key tickets must verify against, once the shell obtains it out of band.
    pub verification_key: Option<String>,
}

impl EndpointPolicy {
    pub fn new(server_url: Url) -> Self {
        Self {
            server_url,
            verification_key: None,
        }
    }

    pub fn with_verification_key(&self, verification_key: impl Into<String>) -> Self {
        Self {
            server_url: self.server_url.clone(),
            verification_key: Some(verification_key.into()),
        }
    }

    /// Checks the parts of a candidates view the shell controls: the relay must be on the
    /// configured origin, and a pinned key must match. Direct candidates are not checked here
    /// because they are filtered out before discovery — the shell never dials one.
    pub fn validate_candidates(&self, candidates: &CandidateSet) -> Result<(), EndpointError> {
        let relay = candidates.relay().ok_or(EndpointError::NoRelay)?;
        let parsed = Url::parse(&relay).map_err(|_| EndpointError::RelayOriginOutsideServer {
            endpoint: relay.clone(),
            server: self.server_url.as_str().to_owned(),
        })?;
        if parsed.origin() != self.server_url.origin() {
            return Err(EndpointError::RelayOriginOutsideServer {
                endpoint: relay,
                server: self.server_url.as_str().to_owned(),
            });
        }
        if let Some(pinned) = &self.verification_key
            && candidates.verification_key() != pinned
        {
            return Err(EndpointError::VerificationKeyMismatch {
                expected: pinned.clone(),
                found: candidates.verification_key().to_owned(),
            });
        }
        Ok(())
    }
}

/// Keeps only the relay candidate.
///
/// Direct candidates are dropped before discovery, never dialed: this milestone routes every
/// endpoint over the relay, and a page-influenced address must not make the shell send UDP
/// probes. The server's relay is always present, so a peer that advertises an endpoint still
/// opens.
fn relay_only(candidates: &RendezvousCandidates) -> RendezvousCandidates {
    RendezvousCandidates {
        session_id: candidates.session_id.clone(),
        expires_at: candidates.expires_at,
        verification_key: candidates.verification_key.clone(),
        peer_nonce: candidates.peer_nonce.clone(),
        candidates: candidates
            .candidates
            .iter()
            .filter(|candidate| candidate.kind == CandidateKind::Relay)
            .cloned()
            .collect(),
    }
}

/// What the page (or a test) asks the shell to open.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct OpenEndpointRequest {
    pub device_id: String,
    /// Name of the mapped stream, for example `adb`.
    pub stream: String,
    /// How long the endpoint may stay open, bounded by [`MAX_ENDPOINT_TTL_SECONDS`] and by
    /// the ticket's own expiry.
    pub ttl_seconds: u64,
    pub session: SessionAccess,
}

/// How the shell obtains the transport for a device.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "camelCase")]
pub enum SessionAccess {
    /// A session the page created on the server with the shell's identity key.
    Rendezvous {
        /// The session capability the server issued; also the relay bearer.
        capability: String,
        /// This peer's rendezvous ticket.
        ticket: Box<Ticket>,
        /// This peer's candidates view (`GET /api/sessions/{id}/candidates`).
        candidates: Box<RendezvousCandidates>,
    },
    /// A session a caller already negotiated and adopted. Not exposed to the page; it is the
    /// seam for embedding and for tests.
    Established { session_id: String },
}

/// One endpoint the manager is serving.
#[derive(Debug)]
struct ServingEndpoint {
    endpoint: LocalEndpoint,
    task: tokio::task::JoinHandle<()>,
}

/// Owns the session(s) and endpoints the shell exposes.
#[derive(Debug)]
pub struct EndpointManager {
    identity: IdentityKey,
    limits: ProxyLimits,
    policy: EndpointPolicy,
    trust: Option<Arc<TicketTrust>>,
    allocator: Arc<ProxyAllocator>,
    sessions: Mutex<HashMap<String, Arc<SessionPath>>>,
    serving: Mutex<HashMap<String, ServingEndpoint>>,
}

#[derive(Debug, thiserror::Error)]
pub enum EndpointError {
    #[error("device id {device_id:?} is not a valid identifier: {reason}")]
    InvalidDevice { device_id: String, reason: String },
    #[error("the endpoint lifetime must be between 1 and {MAX_ENDPOINT_TTL_SECONDS} seconds")]
    InvalidLifetime,
    #[error("the session for device {device_id} has expired")]
    SessionExpired { device_id: String },
    #[error("the session {session_id} is closed; create a new session")]
    SessionClosed { session_id: String },
    #[error("no adopted session for device {device_id}")]
    SessionNotFound { device_id: String },
    #[error("the adopted session is {found}, not the requested {expected}")]
    SessionMismatch { expected: String, found: String },
    #[error("the request is for device {requested} but the ticket is for {ticket}")]
    DeviceMismatch { requested: String, ticket: String },
    #[error("the rendezvous view carries no relay and no direct path was probed")]
    NoRelay,
    #[error("relay {endpoint} is not on the configured server origin {server}")]
    RelayOriginOutsideServer { endpoint: String, server: String },
    #[error("the shell has no source for the pinned ticket verification key")]
    TrustUnavailable,
    #[error("ticket verification key {found} is not the pinned {expected}")]
    VerificationKeyMismatch { expected: String, found: String },
    #[error("the ticket's session has no peer nonce yet; register candidates and retry")]
    PeerNonceMissing,
    #[error(transparent)]
    Candidate(#[from] CandidateError),
    #[error(transparent)]
    Relay(#[from] RelayError),
    #[error(transparent)]
    Session(#[from] SessionClientError),
    #[error(transparent)]
    Proxy(#[from] ProxyError),
    #[error(transparent)]
    Trust(#[from] TrustError),
    #[error("{operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: std::io::Error,
    },
}

impl EndpointManager {
    pub fn new(
        identity: IdentityKey,
        limits: ProxyLimits,
        policy: EndpointPolicy,
        trust: Option<Arc<TicketTrust>>,
    ) -> Self {
        Self {
            identity,
            limits,
            policy,
            trust,
            allocator: Arc::new(ProxyAllocator::new()),
            sessions: Mutex::new(HashMap::new()),
            serving: Mutex::new(HashMap::new()),
        }
    }

    /// The public half of the identity the page must pin when it creates a session.
    pub fn identity_public_key(&self) -> String {
        self.identity.public_key().to_string()
    }

    /// Registers an already-negotiated session so `open` does not negotiate its own.
    pub async fn adopt(&self, device_id: &str, session: SessionPath) -> Result<(), EndpointError> {
        let device = self.device_id(device_id)?;
        if session.device_id().as_str() != device.as_str() {
            return Err(EndpointError::SessionMismatch {
                expected: device.as_str().to_owned(),
                found: session.device_id().as_str().to_owned(),
            });
        }
        self.sessions
            .lock()
            .await
            .insert(device.as_str().to_owned(), Arc::new(session));
        Ok(())
    }

    /// Opens (or reuses) a loopback endpoint and starts serving it.
    ///
    /// The returned URL is what the page shows. The serving task accepts one connection at a
    /// time and keeps accepting until the endpoint is closed, its capability expires, or the
    /// session path fails.
    pub async fn open(&self, request: OpenEndpointRequest) -> Result<LocalEndpoint, EndpointError> {
        let device = self.device_id(&request.device_id)?;
        if request.ttl_seconds == 0 || request.ttl_seconds > MAX_ENDPOINT_TTL_SECONDS {
            return Err(EndpointError::InvalidLifetime);
        }
        if let SessionAccess::Rendezvous { ticket, .. } = &request.session
            && ticket.device_id != request.device_id
        {
            return Err(EndpointError::DeviceMismatch {
                requested: request.device_id.clone(),
                ticket: ticket.device_id.clone(),
            });
        }
        let key = endpoint_key(device.as_str(), &request.stream);
        if let Some(existing) = self.live_serving(&key).await {
            return Ok(existing);
        }

        let session = self.session_for(&request).await?;
        let now = Instant::now();
        let mut expires_at = now + Duration::from_secs(request.ttl_seconds);
        if let SessionAccess::Rendezvous { ticket, .. } = &request.session {
            expires_at = expires_at.min(instant_at_ms(ticket.expires_at, now));
        }
        if expires_at <= now {
            return Err(EndpointError::SessionExpired {
                device_id: device.as_str().to_owned(),
            });
        }
        let capability = ProxyCapability::new(request.stream.clone(), expires_at)?;
        let endpoint = match self.allocator.bind(device.as_str(), capability).await {
            Ok(endpoint) => endpoint,
            // A concurrent open won the race; hand back the same endpoint.
            Err(ProxyError::AlreadyBound { .. }) => {
                if let Some(existing) = self.live_serving(&key).await {
                    return Ok(existing);
                }
                return Err(ProxyError::AlreadyBound {
                    device_id: device.as_str().to_owned(),
                    stream: request.stream,
                }
                .into());
            }
            Err(error) => return Err(error.into()),
        };

        let allocator = Arc::clone(&self.allocator);
        let session = Arc::clone(&session);
        let limits = self.limits.clone();
        let served = endpoint.clone();
        let task = tokio::spawn(async move {
            serve_endpoint(allocator, session, served, limits).await;
        });
        self.serving.lock().await.insert(
            key,
            ServingEndpoint {
                endpoint: endpoint.clone(),
                task,
            },
        );
        Ok(endpoint)
    }

    /// Stops one endpoint. `false` means it was not open (already closed or expired).
    pub async fn close(&self, device_id: &str, stream: &str) -> bool {
        let key = endpoint_key(device_id, stream);
        let mut serving = self.serving.lock().await;
        serving.retain(|_, entry| !entry.task.is_finished());
        let stopped = serving.remove(&key).map(|entry| {
            entry.task.abort();
            entry.task
        });
        let removed = self.allocator.close(device_id, stream).await;
        if let Some(task) = stopped {
            // Waiting for the task drops the listener, so a refused connection is immediate.
            let _ = task.await;
            return true;
        }
        removed
    }

    /// The endpoints a page may use right now, with expired and finished ones removed.
    pub async fn endpoints(&self) -> Vec<LocalEndpoint> {
        let live = self.allocator.endpoints().await;
        let mut serving = self.serving.lock().await;
        serving.retain(|_, entry| {
            !entry.task.is_finished() && live.iter().any(|endpoint| endpoint == &entry.endpoint)
        });
        live
    }

    /// Stops every endpoint and session; used when the shell exits.
    pub async fn close_all(&self) {
        let mut serving = self.serving.lock().await;
        for (_, entry) in serving.drain() {
            entry.task.abort();
            let _ = entry.task.await;
            self.allocator
                .close(&entry.endpoint.device_id, &entry.endpoint.stream)
                .await;
        }
        let sessions: Vec<Arc<SessionPath>> =
            self.sessions.lock().await.drain().map(|(_, s)| s).collect();
        for session in sessions {
            // Stop the relay keepalive and let the hub reader exit.
            let _ = session.shutdown().await;
        }
    }

    async fn live_serving(&self, key: &str) -> Option<LocalEndpoint> {
        let mut serving = self.serving.lock().await;
        serving.retain(|_, entry| !entry.task.is_finished());
        serving.get(key).map(|entry| entry.endpoint.clone())
    }

    async fn session_for(
        &self,
        request: &OpenEndpointRequest,
    ) -> Result<Arc<SessionPath>, EndpointError> {
        match &request.session {
            SessionAccess::Established { session_id } => {
                let sessions = self.sessions.lock().await;
                let session = sessions.get(&request.device_id).ok_or_else(|| {
                    EndpointError::SessionNotFound {
                        device_id: request.device_id.clone(),
                    }
                })?;
                if session.session_id() != session_id {
                    return Err(EndpointError::SessionMismatch {
                        expected: session_id.clone(),
                        found: session.session_id().to_owned(),
                    });
                }
                if !session.is_usable().await {
                    return Err(EndpointError::SessionClosed {
                        session_id: session_id.clone(),
                    });
                }
                Ok(Arc::clone(session))
            }
            SessionAccess::Rendezvous {
                capability,
                ticket,
                candidates,
            } => {
                {
                    let sessions = self.sessions.lock().await;
                    if let Some(session) = sessions.get(&request.device_id) {
                        if session.session_id() == ticket.session_id && session.is_usable().await {
                            return Ok(Arc::clone(session));
                        }
                    }
                }
                let session = self.establish(capability, ticket, candidates).await?;
                let session = Arc::new(session);
                self.sessions
                    .lock()
                    .await
                    .insert(request.device_id.clone(), Arc::clone(&session));
                Ok(session)
            }
        }
    }

    async fn establish(
        &self,
        capability: &str,
        ticket: &Ticket,
        view: &RendezvousCandidates,
    ) -> Result<SessionPath, EndpointError> {
        if view.peer_nonce.is_none() {
            return Err(EndpointError::PeerNonceMissing);
        }
        // The trust anchor comes from the configured origin, never from the page.
        let trust = self.trust.as_ref().ok_or(EndpointError::TrustUnavailable)?;
        let pinned = trust
            .verify_supplied(&view.verification_key, &ticket.session_id, capability)
            .await?;
        let candidates = CandidateSet::discover(relay_only(view), Vec::new())?;
        self.policy
            .with_verification_key(pinned)
            .validate_candidates(&candidates)?;
        let relay_base = candidates.relay().ok_or(EndpointError::NoRelay)?;
        let url = relay_url(&relay_base, &ticket.session_id);
        let relay = WebSocketRelay::connect(&url, capability, STREAM_FRAME_LIMIT as usize).await?;
        let socket = UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|source| EndpointError::Io {
                operation: "bind the direct-path socket",
                source,
            })?;
        let setup = PathSetup::new(Arc::new(socket), self.identity.clone())
            .with_relay(relay)
            .at(unix_ms());
        Ok(SessionClient::new()
            .connect(ticket.clone(), candidates, setup)
            .await?)
    }

    fn device_id(&self, device_id: &str) -> Result<DeviceId, EndpointError> {
        DeviceId::new(device_id).map_err(|error| EndpointError::InvalidDevice {
            device_id: device_id.to_owned(),
            reason: error.to_string(),
        })
    }
}

/// Serves one endpoint until it is closed or expires. One local connection at a time; a
/// failed pump leaves the port open for the next connection unless the endpoint itself is
/// gone or its session path has failed.
async fn serve_endpoint(
    allocator: Arc<ProxyAllocator>,
    session: Arc<SessionPath>,
    endpoint: LocalEndpoint,
    limits: ProxyLimits,
) {
    loop {
        let proxy = match session
            .proxy_session(&endpoint.stream, limits.clone())
            .await
        {
            Ok(proxy) => proxy,
            // A previous connection is still releasing its route.
            Err(ProxyError::StreamInUse { .. }) => {
                tokio::time::sleep(Duration::from_millis(20)).await;
                continue;
            }
            Err(_) => break,
        };
        let outcome = tokio::select! {
            result = allocator.serve(&endpoint, proxy) => Some(result),
            // The path failed while this endpoint waited for a connection. Stop instead of
            // handing the next client a tunnel that can never carry a byte.
            _ = session.wait_closed() => None,
        };
        match outcome {
            None => break,
            Some(Ok(_)) => {}
            Some(Err(
                ProxyError::UnknownEndpoint { .. }
                | ProxyError::CapabilityExpired { .. }
                | ProxyError::StreamMismatch { .. },
            )) => break,
            // The endpoint is still live: a transport fault ended one connection, not the
            // port. The next local connection gets a fresh stream.
            Some(Err(_)) => {}
        }
    }
    allocator.close(&endpoint.device_id, &endpoint.stream).await;
}

fn endpoint_key(device_id: &str, stream: &str) -> String {
    format!("{device_id}/{stream}")
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}

fn instant_at_ms(deadline_ms: i64, now: Instant) -> Instant {
    let remaining = deadline_ms.saturating_sub(unix_ms()).max(0) as u64;
    now + Duration::from_millis(remaining)
}

#[cfg(test)]
mod tests {
    use super::*;
    use phoneconnect_transport::CandidateKind;
    use phoneconnect_transport::candidates::WireCandidate;

    fn policy(server: &str, pin: Option<&str>) -> EndpointPolicy {
        let policy = EndpointPolicy::new(Url::parse(server).expect("server URL"));
        match pin {
            Some(pin) => policy.with_verification_key(pin),
            None => policy,
        }
    }

    fn view(relay: &str, key: &str, direct: Option<&str>) -> RendezvousCandidates {
        let mut candidates = vec![WireCandidate {
            kind: CandidateKind::Relay,
            endpoint: relay.to_owned(),
            priority: 100,
        }];
        if let Some(endpoint) = direct {
            candidates.push(WireCandidate {
                kind: CandidateKind::ServerObserved,
                endpoint: endpoint.to_owned(),
                priority: 150,
            });
        }
        RendezvousCandidates {
            session_id: "sess_policy".to_owned(),
            expires_at: i64::MAX,
            verification_key: key.to_owned(),
            peer_nonce: Some("peer-nonce".to_owned()),
            candidates,
        }
    }

    fn candidates(relay: &str, key: &str, direct: Option<&str>) -> CandidateSet {
        CandidateSet::discover(view(relay, key, direct), Vec::new()).expect("candidate set")
    }

    #[test]
    fn the_default_server_and_client_configurations_agree() {
        // The relay below is what the server derives from its default public origin.
        let relay = format!("{}/api/sessions", phoneconnect::DEFAULT_SERVER_ORIGIN);
        assert_eq!(
            crate::web_shell::DEFAULT_SERVER_URL,
            phoneconnect::DEFAULT_SERVER_ORIGIN
        );
        policy(phoneconnect::DEFAULT_SERVER_ORIGIN, None)
            .validate_candidates(&candidates(&relay, "key", None))
            .expect("the default client origin accepts the default relay");
    }

    #[test]
    fn a_relay_on_the_configured_origin_is_accepted() {
        policy("http://127.0.0.1:8080", None)
            .validate_candidates(&candidates(
                "http://127.0.0.1:8080/api/sessions",
                "key",
                None,
            ))
            .expect("the configured origin is allowed");
    }

    #[test]
    fn a_relay_on_another_origin_is_refused() {
        let error = policy("https://phoneconnect.example", None)
            .validate_candidates(&candidates(
                "https://evil.example/api/sessions",
                "key",
                None,
            ))
            .expect_err("another origin is not dialed");
        assert!(
            matches!(error, EndpointError::RelayOriginOutsideServer { .. }),
            "{error:?}"
        );
    }

    #[test]
    fn a_server_observed_candidate_is_filtered_and_the_relay_is_used() {
        let view = view(
            "http://127.0.0.1:8080/api/sessions",
            "key",
            Some("203.0.113.9:9"),
        );
        let filtered = relay_only(&view);
        assert!(
            filtered
                .candidates
                .iter()
                .all(|candidate| candidate.kind == CandidateKind::Relay),
            "a direct candidate never reaches the transport"
        );
        let set = CandidateSet::discover(filtered, Vec::new()).expect("candidate set");
        assert!(set.direct().is_empty(), "no address is ever probed");
        assert_eq!(
            set.relay().as_deref(),
            Some("http://127.0.0.1:8080/api/sessions")
        );
        policy("http://127.0.0.1:8080", None)
            .validate_candidates(&set)
            .expect("the relay is still accepted");
        assert_eq!(
            phoneconnect_transport::PathController::select(None, Some(Duration::from_millis(5))),
            Some(phoneconnect_transport::PathKind::Relay),
            "with no direct candidate the relay is the selected path"
        );
    }

    #[test]
    fn a_pinned_verification_key_cannot_be_replaced_by_the_page() {
        let error = policy("http://127.0.0.1:8080", Some("the-pinned-key"))
            .validate_candidates(&candidates(
                "http://127.0.0.1:8080/api/sessions",
                "page-chosen-key",
                None,
            ))
            .expect_err("the page cannot choose the trust anchor");
        assert!(
            matches!(error, EndpointError::VerificationKeyMismatch { .. }),
            "{error:?}"
        );

        policy("http://127.0.0.1:8080", Some("the-pinned-key"))
            .validate_candidates(&candidates(
                "http://127.0.0.1:8080/api/sessions",
                "the-pinned-key",
                None,
            ))
            .expect("the pinned key is accepted");
    }
}
