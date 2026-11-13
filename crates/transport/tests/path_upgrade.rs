//! Direct-path transport contract.
//!
//! Every test drives real loopback UDP sockets and the server's bounded relay, so a path is
//! only reported as validated when an authenticated peer actually answered, the peer
//! confirmed the switch, and a sealed frame actually crossed it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use phoneconnect::v1::{
    DeviceId, Envelope, FrameLimits, RequestId, SessionId, StreamKind, decode_frame, encode_frame,
};
use phoneconnect_server::PeerRole;
use phoneconnect_server::relay::{Relay, RelayClose, RelayLimits, RelayPeer};
use phoneconnect_server::rendezvous::TicketAuthority;
use phoneconnect_server::store::{
    DeviceStore, EnrollmentTokenRecord, ManualClock, NewDevice, SessionRecord, SqliteStore,
};
use phoneconnect_transport::{
    CandidateKind, CandidateSet, ConnectedPath, Epoch, HolePunchError, IdentityKey,
    IdentityPublicKey, PathConfig, PathController, PathError, PathKind, PathSetup,
    ProbeAuthenticator, ProbeConfig, ProbeCredentials, ProbePacket, RelayChannel, RelayError,
    RelayOnlyPath, RendezvousCandidates, SessionCipher, SwitchConfig, Ticket, TicketError,
    TicketRole,
};
use serde_json::json;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const NOW_MS: i64 = 1_760_000_000_000;
const DEVICE_ID: &str = "dev_transport";
const RELAY_ENDPOINT: &str = "http://relay.test/api/sessions";
const SESSION: &str = "sess_direct";

// --------------------------------------------------------------------------------------
// Server-side rendezvous and relay fixtures. The transport crate deliberately has no
// server dependency, so the tests supply the server side the way the real server does:
// signed tickets from `TicketAuthority` and bounded relay handles from `Relay`.
// --------------------------------------------------------------------------------------

struct Harness {
    relay: Arc<Relay>,
    authority: Arc<TicketAuthority>,
    record: SessionRecord,
    client_identity: IdentityKey,
    device_identity: IdentityKey,
}

impl Harness {
    async fn new(session_id: &str) -> Self {
        let store = Arc::new(SqliteStore::in_memory().expect("in-memory store"));
        let clock = Arc::new(ManualClock::new(NOW_MS));
        let client_identity = IdentityKey::generate().expect("client identity");
        let device_identity = IdentityKey::generate().expect("device identity");
        let record = SessionRecord {
            session_id: session_id.to_owned(),
            device_id: DEVICE_ID.to_owned(),
            owner_id: "user-a".to_owned(),
            capability_hash: "capability-hash".to_owned(),
            client_identity_key: client_identity.public_key().as_str(),
            device_identity_key: device_identity.public_key().as_str(),
            created_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + 300_000,
            revoked_at_ms: None,
        };
        store
            .insert_enrollment_token(EnrollmentTokenRecord {
                token_hash: "transport-enrollment".to_owned(),
                owner_id: "user-a".to_owned(),
                created_at_ms: NOW_MS,
                expires_at_ms: NOW_MS + 900_000,
            })
            .await
            .expect("enrollment token persists");
        store
            .consume_enrollment_token(
                "transport-enrollment",
                NOW_MS,
                NewDevice {
                    device_id: DEVICE_ID.to_owned(),
                    credential_hash: "transport-credential".to_owned(),
                    identity_public_key: device_identity.public_key().as_str(),
                    enrolled_at_ms: NOW_MS,
                },
            )
            .await
            .expect("device persists");
        store
            .insert_session(record.clone())
            .await
            .expect("session persists");
        Self {
            relay: Arc::new(Relay::new(
                RELAY_ENDPOINT,
                RelayLimits::default(),
                store,
                clock,
            )),
            authority: Arc::new(TicketAuthority::new().expect("ticket authority")),
            record,
            client_identity,
            device_identity,
        }
    }

    fn verification_key(&self) -> String {
        self.authority.verification_key().to_owned()
    }

    fn identity(&self, role: PeerRole) -> IdentityKey {
        match role {
            PeerRole::Client => self.client_identity.clone(),
            PeerRole::Device => self.device_identity.clone(),
        }
    }

    fn peer_identity(&self, role: PeerRole) -> IdentityPublicKey {
        match role {
            PeerRole::Client => self.device_identity.public_key(),
            PeerRole::Device => self.client_identity.public_key(),
        }
    }

    /// Issues a ticket the way `POST /api/sessions` and the device ticket route do, then
    /// round-trips it through JSON so the transport type must stay wire-compatible.
    fn ticket_at(&self, role: PeerRole, now_ms: i64) -> Ticket {
        let issued = self
            .authority
            .issue(&self.record, role, now_ms)
            .expect("ticket issued");
        serde_json::from_value(serde_json::to_value(issued).expect("ticket json"))
            .expect("transport accepts the server ticket shape")
    }

    fn ticket(&self, role: PeerRole) -> Ticket {
        self.ticket_at(role, NOW_MS)
    }

    /// One ticket per role, whose nonces form the connection epoch each peer receives as its
    /// `peer_nonce`.
    fn peer_tickets(&self) -> (Ticket, Ticket) {
        (self.ticket(PeerRole::Client), self.ticket(PeerRole::Device))
    }

    fn credentials(&self, role: PeerRole) -> ProbeCredentials {
        self.ticket(role)
            .verify(&self.verification_key(), NOW_MS)
            .expect("ticket verifies")
            .credentials
    }

    async fn relay_peer(&self, role: PeerRole) -> RelayPeer {
        self.relay
            .open(&self.record, NOW_MS)
            .expect("relay authorizes the session");
        self.relay
            .attach(&self.record.session_id, role)
            .await
            .expect("peer attaches")
    }

    async fn relay_channel(
        &self,
        role: PeerRole,
        latency: Option<Duration>,
    ) -> (Arc<dyn RelayChannel>, Arc<RelayProbe>) {
        let peer = self.relay_peer(role).await;
        let probe = Arc::new(RelayProbe::default());
        let channel = Arc::new(StubRelay {
            peer,
            latency,
            probe: Arc::clone(&probe),
        });
        (channel, probe)
    }
}

/// Observations a test makes about the relay path.
#[derive(Debug, Default)]
struct RelayProbe {
    sends: AtomicUsize,
    closed: AtomicBool,
    last_frame: std::sync::Mutex<Option<Vec<u8>>>,
}

impl RelayProbe {
    fn sends(&self) -> usize {
        self.sends.load(Ordering::SeqCst)
    }

    fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
    }

    fn last_frame(&self) -> Option<Vec<u8>> {
        self.last_frame
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }
}

struct StubRelay {
    peer: RelayPeer,
    latency: Option<Duration>,
    probe: Arc<RelayProbe>,
}

#[async_trait]
impl RelayChannel for StubRelay {
    async fn send_frame(&self, frame: &[u8]) -> Result<(), RelayError> {
        self.probe.sends.fetch_add(1, Ordering::SeqCst);
        *self
            .probe
            .last_frame
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = Some(frame.to_vec());
        self.peer.send_bytes(frame).await.map_err(relay_error)
    }

    async fn recv_frame(&self) -> Result<Vec<u8>, RelayError> {
        self.peer.recv_bytes().await.map_err(relay_error)
    }

    async fn close(&self) -> Result<(), RelayError> {
        self.probe.closed.store(true, Ordering::SeqCst);
        Ok(())
    }

    fn latency(&self) -> Option<Duration> {
        self.latency
    }
}

fn relay_error(reason: RelayClose) -> RelayError {
    match reason {
        RelayClose::UnknownSession
        | RelayClose::SessionExpired
        | RelayClose::SessionRevoked
        | RelayClose::DeviceRevoked { .. } => RelayError::Unavailable,
        RelayClose::Backpressure => RelayError::Backpressure,
        RelayClose::SessionClosed => RelayError::Closed {
            reason: "session closed".to_owned(),
        },
        other => RelayError::Malformed {
            reason: other.to_string(),
        },
    }
}

// --------------------------------------------------------------------------------------
// Candidate and ticket fixtures.
// --------------------------------------------------------------------------------------

fn rendezvous(
    session_id: &str,
    verification_key: &str,
    peer: SocketAddr,
    relay: &str,
    peer_nonce: &str,
) -> RendezvousCandidates {
    serde_json::from_value(json!({
        "session_id": session_id,
        "expires_at": NOW_MS + 300_000,
        "verification_key": verification_key,
        "peer_nonce": peer_nonce,
        "candidates": [
            { "kind": "server_observed", "endpoint": peer.to_string(), "priority": 150 },
            { "kind": "relay", "endpoint": relay, "priority": 100 }
        ]
    }))
    .expect("server candidate shape")
}

fn rendezvous_only(
    session_id: &str,
    verification_key: &str,
    relay: &str,
    peer_nonce: &str,
) -> RendezvousCandidates {
    serde_json::from_value(json!({
        "session_id": session_id,
        "expires_at": NOW_MS + 300_000,
        "verification_key": verification_key,
        "peer_nonce": peer_nonce,
        "candidates": [{ "kind": "relay", "endpoint": relay, "priority": 100 }]
    }))
    .expect("server candidate shape")
}

/// The epoch both peers of one connection derive: each side's single-use ticket nonce,
/// ordered by role.
fn epoch_of(client_nonce: &str, device_nonce: &str) -> Epoch {
    Epoch::new(client_nonce, device_nonce).expect("epoch")
}

/// A fresh epoch for a path that is not backed by tickets, as a caller would build from a
/// rendezvous round it just read.
fn unique_epoch() -> Epoch {
    epoch_of(
        &IdentityKey::generate().expect("nonce").to_secret_string(),
        &IdentityKey::generate().expect("nonce").to_secret_string(),
    )
}

fn fast_probes() -> ProbeConfig {
    ProbeConfig {
        attempt_timeout: Duration::from_millis(40),
        max_attempts: 3,
    }
}

fn fast_switch() -> SwitchConfig {
    SwitchConfig {
        retries: 4,
        timeout: Duration::from_millis(100),
        confirmation_timeout: Duration::from_millis(600),
    }
}

fn config(probe: ProbeConfig) -> PathConfig {
    PathConfig {
        probe,
        switch: fast_switch(),
        ..PathConfig::default()
    }
}

fn envelope(request: &str, payload: &[u8]) -> Envelope {
    let device = DeviceId::new(DEVICE_ID).expect("device id");
    let session = SessionId::new(SESSION).expect("session id");
    let request = RequestId::new(request).expect("request id");
    let mut envelope = Envelope::new(StreamKind::Control, &device, &session, &request);
    envelope.payload = payload.to_vec();
    envelope
}

async fn socket() -> Arc<UdpSocket> {
    Arc::new(UdpSocket::bind("127.0.0.1:0").await.expect("udp socket"))
}

async fn recv(path: &ConnectedPath) -> Envelope {
    timeout(Duration::from_secs(3), path.recv_frame())
        .await
        .expect("frame arrives within the test deadline")
        .expect("frame decodes")
}

fn client_setup(socket: Arc<UdpSocket>, harness: &Harness) -> PathSetup {
    PathSetup::new(socket, harness.identity(PeerRole::Client))
}

fn device_setup(socket: Arc<UdpSocket>, harness: &Harness) -> PathSetup {
    PathSetup::new(socket, harness.identity(PeerRole::Device))
}

// --------------------------------------------------------------------------------------
// Candidate discovery.
// --------------------------------------------------------------------------------------

#[test]
fn discovery_covers_local_server_observed_and_relay_candidates() {
    let local_one: SocketAddr = "10.0.0.7:51000".parse().expect("addr");
    let local_two: SocketAddr = "192.168.1.20:51000".parse().expect("addr");
    let observed: SocketAddr = "203.0.113.9:62000".parse().expect("addr");

    let set = CandidateSet::discover(
        rendezvous(SESSION, "key", observed, RELAY_ENDPOINT, "peer-nonce"),
        vec![local_one, local_two],
    )
    .expect("candidates discovered");

    assert_eq!(set.session_id(), SESSION);
    assert_eq!(set.expires_at(), NOW_MS + 300_000);
    assert_eq!(set.verification_key(), "key");

    let kinds: Vec<CandidateKind> = set.candidates().iter().map(|item| item.kind).collect();
    assert!(kinds.contains(&CandidateKind::Local), "{kinds:?}");
    assert!(kinds.contains(&CandidateKind::ServerObserved), "{kinds:?}");
    assert!(kinds.contains(&CandidateKind::Relay), "{kinds:?}");

    assert_eq!(
        set.direct(),
        vec![local_one, local_two, observed],
        "local candidates outrank the server-observed endpoint"
    );
    assert_eq!(set.relay(), Some(RELAY_ENDPOINT.to_owned()));
    assert!(
        set.candidates()
            .windows(2)
            .all(|pair| pair[0].priority >= pair[1].priority)
    );
}

#[test]
fn discovery_refuses_an_expired_or_malformed_rendezvous_view() {
    let expired: RendezvousCandidates = serde_json::from_value(json!({
        "session_id": SESSION,
        "expires_at": NOW_MS - 1,
        "verification_key": "key",
        "peer_nonce": "peer-nonce",
        "candidates": [{ "kind": "relay", "endpoint": RELAY_ENDPOINT, "priority": 100 }]
    }))
    .expect("shape");
    let set = CandidateSet::discover(expired, vec![]).expect("shape accepted at discovery");
    assert!(
        set.is_expired(NOW_MS),
        "the caller must reject expired rendezvous data"
    );

    let malformed: RendezvousCandidates = serde_json::from_value(json!({
        "session_id": SESSION,
        "expires_at": NOW_MS + 1000,
        "verification_key": "key",
        "peer_nonce": "peer-nonce",
        "candidates": [{ "kind": "server_observed", "endpoint": "not-an-address", "priority": 150 }]
    }))
    .expect("shape");
    assert!(CandidateSet::discover(malformed, vec![]).is_err());
}

// --------------------------------------------------------------------------------------
// Ticket authentication and nonce binding.
// --------------------------------------------------------------------------------------

#[test]
fn ticket_signature_binds_session_role_identity_and_nonce() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let harness = runtime.block_on(Harness::new(SESSION));
    let key = harness.verification_key();
    let ticket = harness.ticket(PeerRole::Client);

    let verified = ticket
        .verify(&key, NOW_MS)
        .expect("server-signed ticket verifies");
    assert_eq!(verified.credentials.session_id(), SESSION);
    assert_eq!(
        verified.own_identity_key,
        harness.client_identity.public_key(),
        "the ticket binds the receiving peer's pinned identity key"
    );
    assert_eq!(
        verified.peer_identity_key,
        harness.device_identity.public_key(),
        "the ticket binds the opposite peer's identity key"
    );

    let mut swapped_identity = ticket.clone();
    swapped_identity.own_identity_key = harness.device_identity.public_key().as_str();
    assert_eq!(
        swapped_identity.verify(&key, NOW_MS),
        Err(TicketError::InvalidSignature)
    );

    let mut expired = ticket.clone();
    expired.expires_at = NOW_MS - 1;
    // Expiry is inside the signature, so tampering with it is a signature failure.
    assert_eq!(
        expired.verify(&key, NOW_MS),
        Err(TicketError::InvalidSignature)
    );

    let stale = harness.ticket(PeerRole::Client);
    assert_eq!(
        stale.verify(&key, NOW_MS + 300_001),
        Err(TicketError::Expired {
            expires_at: NOW_MS + 30_000
        })
    );
    assert!(
        !PathError::from(TicketError::Expired {
            expires_at: NOW_MS + 30_000
        })
        .is_terminal(),
        "an expired ticket is renewable and must never be terminal"
    );

    let other_authority = TicketAuthority::new().expect("ticket authority");
    assert_eq!(
        ticket.verify(other_authority.verification_key(), NOW_MS),
        Err(TicketError::InvalidSignature)
    );
    assert!(matches!(
        ticket.verify("not-a-key", NOW_MS),
        Err(TicketError::InvalidVerificationKey { .. })
    ));
}

#[tokio::test]
async fn a_ticket_for_another_identity_is_refused_at_connect() {
    let harness = Harness::new(SESSION).await;
    let key = harness.verification_key();
    let candidates = CandidateSet::discover(
        rendezvous_only(SESSION, &key, RELAY_ENDPOINT, "peer-nonce"),
        vec![],
    )
    .expect("candidates");
    let (relay, _probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(5)))
        .await;

    let error = PathController::connect(
        harness.ticket(PeerRole::Client),
        candidates,
        PathSetup::new(
            socket().await,
            IdentityKey::generate().expect("other identity"),
        )
        .with_relay(relay)
        .at(NOW_MS),
    )
    .await
    .expect_err("a ticket bound to another identity is useless");

    assert!(
        matches!(
            error,
            PathError::Ticket(TicketError::IdentityMismatch { .. })
        ),
        "{error}"
    );
}

#[test]
fn replayed_probes_are_rejected_before_a_path_is_established() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let harness = runtime.block_on(Harness::new(SESSION));
    let key = harness.verification_key();

    let client = harness.ticket(PeerRole::Client);
    let device = harness.ticket(PeerRole::Device);
    assert_eq!(
        client.probe_key, device.probe_key,
        "both peers probe with the same rendezvous round key"
    );
    assert_ne!(
        client.nonce, device.nonce,
        "each ticket has its own single-use redemption nonce"
    );

    let device_credentials = device
        .verify(&key, NOW_MS)
        .expect("device ticket")
        .credentials;
    let client_credentials = client
        .verify(&key, NOW_MS)
        .expect("client ticket")
        .credentials;

    let probe = ProbePacket::probe(7);
    let datagram = probe.encode(&device_credentials);
    let authenticator = ProbeAuthenticator::new(&client_credentials);

    assert!(matches!(
        authenticator.accept(&datagram),
        Ok(ProbePacket::Probe { seq: 7 })
    ));
    assert_eq!(
        authenticator.accept(&datagram),
        Err(HolePunchError::Replayed),
        "a byte-identical probe replay never validates a second path"
    );

    let newer = ProbePacket::probe(8);
    assert!(
        authenticator
            .accept(&newer.encode(&device_credentials))
            .is_ok()
    );
    assert_eq!(
        authenticator.accept(&datagram),
        Err(HolePunchError::Replayed)
    );

    let other_session = runtime.block_on(Harness::new("sess_other"));
    let other = other_session
        .ticket(PeerRole::Device)
        .verify(&other_session.verification_key(), NOW_MS)
        .expect("other ticket")
        .credentials;
    let foreign = ProbePacket::probe(9);
    assert_eq!(
        authenticator.accept(&foreign.encode(&other)),
        Err(HolePunchError::Unauthenticated)
    );
}

// --------------------------------------------------------------------------------------
// Direct path, relay fallback, and migration.
// --------------------------------------------------------------------------------------

#[tokio::test]
async fn direct_path_is_selected_when_both_peers_answer_authenticated_probes() {
    let harness = Harness::new(SESSION).await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    let device_socket = socket().await;
    let client_addr = client_socket.local_addr().expect("client addr");
    let device_addr = device_socket.local_addr().expect("device addr");

    let (client_ticket, device_ticket) = harness.peer_tickets();
    let client_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            device_addr,
            RELAY_ENDPOINT,
            &device_ticket.nonce,
        ),
        vec![client_addr],
    )
    .expect("client candidates");
    let device_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            client_addr,
            RELAY_ENDPOINT,
            &client_ticket.nonce,
        ),
        vec![device_addr],
    )
    .expect("device candidates");

    let (client_relay, client_probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(120)))
        .await;
    let (device_relay, _device_probe) = harness
        .relay_channel(PeerRole::Device, Some(Duration::from_millis(120)))
        .await;

    let (client_path, device_path) = tokio::join!(
        PathController::connect(
            client_ticket,
            client_candidates,
            client_setup(client_socket, &harness)
                .with_relay(client_relay)
                .with_config(config(fast_probes()))
                .at(NOW_MS)
        ),
        PathController::connect(
            device_ticket,
            device_candidates,
            device_setup(device_socket, &harness)
                .with_relay(device_relay)
                .with_config(config(fast_probes()))
                .at(NOW_MS)
        ),
    );
    let client_path = client_path.expect("client connects");
    let device_path = device_path.expect("device connects");

    assert_eq!(
        client_path.path_kind(),
        PathKind::Direct,
        "a validated direct path beats a 120 ms relay"
    );
    assert_eq!(device_path.path_kind(), PathKind::Direct);
    assert!(
        client_path.direct_rtt().is_some(),
        "the selected direct path reports the round trip it measured"
    );
    assert_eq!(
        client_path.key_id(),
        device_path.key_id(),
        "both peers agreed on the same traffic keys"
    );

    let frame = envelope("req-direct-1", b"direct payload");
    client_path.send_frame(&frame).await.expect("direct send");
    assert_eq!(recv(&device_path).await, frame);

    let reply = envelope("req-direct-2", b"direct reply");
    device_path.send_frame(&reply).await.expect("direct reply");
    assert_eq!(recv(&client_path).await, reply);

    assert_eq!(
        client_probe.sends(),
        0,
        "the relay carried nothing once the direct path validated"
    );
    client_path.shutdown().await.expect("shutdown");
    device_path.shutdown().await.expect("shutdown");
}

#[tokio::test]
async fn relay_path_is_used_transparently_when_direct_negotiation_fails() {
    let harness = Harness::new(SESSION).await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    // The device holds a UDP socket but never answers, which is what a restrictive
    // firewall or symmetric NAT looks like to the probing peer.
    let silent_device = UdpSocket::bind("127.0.0.1:0").await.expect("device socket");
    let device_addr = silent_device.local_addr().expect("device addr");
    let client_addr = client_socket.local_addr().expect("client addr");

    let (client_ticket, device_ticket) = harness.peer_tickets();
    let client_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            device_addr,
            RELAY_ENDPOINT,
            &device_ticket.nonce,
        ),
        vec![client_addr],
    )
    .expect("client candidates");
    let device_candidates = CandidateSet::discover(
        rendezvous_only(SESSION, &key, RELAY_ENDPOINT, &client_ticket.nonce),
        vec![],
    )
    .expect("device candidates");

    let (client_relay, client_probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(10)))
        .await;
    let (device_relay, _device_probe) = harness
        .relay_channel(PeerRole::Device, Some(Duration::from_millis(10)))
        .await;

    let client_path = PathController::connect(
        client_ticket,
        client_candidates,
        client_setup(client_socket, &harness)
            .with_relay(client_relay)
            .with_config(config(ProbeConfig {
                attempt_timeout: Duration::from_millis(20),
                max_attempts: 2,
            }))
            .at(NOW_MS),
    )
    .await
    .expect("relay fallback");
    let device_path = PathController::connect(
        device_ticket,
        device_candidates,
        device_setup(socket().await, &harness)
            .with_relay(device_relay)
            .with_config(config(fast_probes()))
            .at(NOW_MS),
    )
    .await
    .expect("relay path");

    assert_eq!(client_path.path_kind(), PathKind::Relay);
    assert_eq!(device_path.path_kind(), PathKind::Relay);
    assert_eq!(client_probe.sends(), 0, "no frame is relayed until sent");

    let frame = envelope("req-relay-1", b"relayed payload");
    client_path.send_frame(&frame).await.expect("relay send");

    // The relay only ever received ciphertext: a routing envelope whose payload cannot be
    // read, so the payload marker never appears on the wire.
    let forwarded = client_probe.last_frame().expect("the relay got a frame");
    let outer = decode_frame(&forwarded, &FrameLimits::control_only())
        .expect("the routing envelope is well formed")
        .envelope;
    assert!(
        !outer
            .payload
            .windows(b"relayed payload".len())
            .any(|window| window == b"relayed payload"),
        "the relay must only see ciphertext"
    );
    assert!(
        !forwarded
            .windows(b"req-relay-1".len())
            .any(|window| window == b"req-relay-1"),
        "the request id is inside the ciphertext"
    );

    assert_eq!(
        recv(&device_path).await,
        frame,
        "the relay path carries the same envelope the direct path would"
    );
    assert!(!client_probe.closed(), "a fallback path stays open");
}

#[tokio::test]
async fn direct_negotiation_fails_explicitly_without_a_relay() {
    let harness = Harness::new(SESSION).await;
    let key = harness.verification_key();
    let client_socket = socket().await;

    // No peer-reported endpoint and no local discovery: there is nothing direct to try.
    let candidates = CandidateSet::discover(
        rendezvous_only(SESSION, &key, RELAY_ENDPOINT, "peer-nonce"),
        vec![],
    )
    .expect("candidates");

    let started = Instant::now();
    let error = PathController::connect(
        harness.ticket(PeerRole::Client),
        candidates,
        client_setup(client_socket, &harness)
            .with_config(PathConfig {
                probe: ProbeConfig {
                    attempt_timeout: Duration::from_millis(20),
                    max_attempts: 2,
                },
                switch: fast_switch(),
                ..PathConfig::default()
            })
            .at(NOW_MS),
    )
    .await
    .expect_err("there is no path to report");

    assert!(matches!(error, PathError::NoPath), "{error}");
    assert!(
        started.elapsed() < Duration::from_millis(500),
        "bounded probes fail fast instead of hanging"
    );
}

#[tokio::test]
async fn probe_timeouts_are_bounded_and_reported() {
    let harness = Harness::new(SESSION).await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    let silent = UdpSocket::bind("127.0.0.1:0").await.expect("device socket");

    let ticket = harness.ticket(PeerRole::Client);
    let candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            silent.local_addr().expect("device addr"),
            RELAY_ENDPOINT,
            "peer-nonce",
        ),
        vec![],
    )
    .expect("candidates");

    let probes = ProbeConfig {
        attempt_timeout: Duration::from_millis(25),
        max_attempts: 2,
    };
    let started = Instant::now();
    let error = PathController::connect(
        ticket,
        candidates,
        client_setup(client_socket, &harness)
            .with_config(config(probes))
            .at(NOW_MS),
    )
    .await
    .expect_err("silence is a failure, not a path");
    let elapsed = started.elapsed();

    assert!(
        matches!(
            error,
            PathError::HolePunch(HolePunchError::Timeout { attempts: 2 })
        ),
        "{error}"
    );
    assert!(
        elapsed < Duration::from_millis(300),
        "two 25 ms attempts cannot take {elapsed:?}"
    );
}

#[tokio::test]
async fn a_relay_session_migrates_to_a_direct_path_and_keeps_relay_fallback() {
    let harness = Harness::new(SESSION).await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    let device_socket = socket().await;
    let client_addr = client_socket.local_addr().expect("client addr");
    let device_addr = device_socket.local_addr().expect("device addr");

    // Phase one: each peer only knows the relay, so both start there deterministically.
    let (client_ticket, device_ticket) = harness.peer_tickets();
    let client_relay_only = CandidateSet::discover(
        rendezvous_only(SESSION, &key, RELAY_ENDPOINT, &device_ticket.nonce),
        vec![],
    )
    .expect("candidates");
    let device_relay_only = CandidateSet::discover(
        rendezvous_only(SESSION, &key, RELAY_ENDPOINT, &client_ticket.nonce),
        vec![],
    )
    .expect("candidates");
    let (client_relay, client_probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(10)))
        .await;
    let (device_relay, device_probe) = harness
        .relay_channel(PeerRole::Device, Some(Duration::from_millis(10)))
        .await;

    let client_path = PathController::connect(
        client_ticket,
        client_relay_only,
        client_setup(Arc::clone(&client_socket), &harness)
            .with_relay(client_relay)
            .with_config(config(fast_probes()))
            .at(NOW_MS),
    )
    .await
    .expect("relay path");
    let device_path = PathController::connect(
        device_ticket,
        device_relay_only,
        device_setup(Arc::clone(&device_socket), &harness)
            .with_relay(device_relay)
            .with_config(config(fast_probes()))
            .at(NOW_MS),
    )
    .await
    .expect("relay path");
    assert_eq!(client_path.path_kind(), PathKind::Relay);
    assert_eq!(device_path.path_kind(), PathKind::Relay);

    let first = envelope("req-migrate-1", b"over relay");
    client_path.send_frame(&first).await.expect("relay send");
    assert_eq!(recv(&device_path).await, first);

    // Phase two: candidate discovery finds the direct addresses and both peers repeat
    // negotiation with the same session and ticket round — no new session, no new key.
    let (client_upgrade_ticket, device_upgrade_ticket) = harness.peer_tickets();
    let client_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            device_addr,
            RELAY_ENDPOINT,
            &device_upgrade_ticket.nonce,
        ),
        vec![client_addr],
    )
    .expect("client candidates");
    let device_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            client_addr,
            RELAY_ENDPOINT,
            &client_upgrade_ticket.nonce,
        ),
        vec![device_addr],
    )
    .expect("device candidates");
    let (client_upgrade, device_upgrade) = tokio::join!(
        client_path.upgrade_with(&client_upgrade_ticket, &client_candidates, NOW_MS),
        device_path.upgrade_with(&device_upgrade_ticket, &device_candidates, NOW_MS),
    );
    assert_eq!(client_upgrade.expect("client upgrades"), PathKind::Direct);
    assert_eq!(device_upgrade.expect("device upgrades"), PathKind::Direct);
    assert_eq!(client_path.path_kind(), PathKind::Direct);

    let second = envelope("req-migrate-2", b"over direct");
    client_path.send_frame(&second).await.expect("direct send");
    assert_eq!(recv(&device_path).await, second);

    // The relay was never closed by the migration: it is still the fallback.
    assert!(!client_probe.closed(), "migration must not close the relay");
    assert!(!device_probe.closed());
    assert_eq!(
        harness
            .relay
            .attach(&harness.record.session_id, PeerRole::Device)
            .await
            .err(),
        None,
        "the relay session stays attachable after the upgrade"
    );

    assert_eq!(
        client_path.fallback_to_relay().await.expect("fallback"),
        PathKind::Relay
    );
    assert_eq!(
        device_path.fallback_to_relay().await.expect("fallback"),
        PathKind::Relay
    );
    let third = envelope("req-migrate-3", b"back on relay");
    client_path.send_frame(&third).await.expect("relay send");
    assert_eq!(recv(&device_path).await, third);
}

// --------------------------------------------------------------------------------------
// Upgrade safety: replay across upgrades, frames in flight, one-sided switching.
// --------------------------------------------------------------------------------------

/// A minimal peer that speaks the direct-path protocol without the path state machine, so a
/// test can capture and replay exact datagrams.
struct SpyPeer {
    socket: UdpSocket,
    credentials: ProbeCredentials,
    cipher: SessionCipher,
    seq: u32,
    peer: Option<SocketAddr>,
}

impl SpyPeer {
    async fn new(harness: &Harness, role: TicketRole, epoch: &Epoch) -> Self {
        let server_role = match role {
            TicketRole::Client => PeerRole::Client,
            TicketRole::Device => PeerRole::Device,
        };
        let identity = harness.identity(server_role);
        let credentials = harness.credentials(server_role);
        let cipher = SessionCipher::new(
            &identity,
            harness.peer_identity(server_role),
            SESSION,
            role,
            epoch,
        )
        .expect("spy cipher");
        Self {
            socket: UdpSocket::bind("127.0.0.1:0").await.expect("spy socket"),
            credentials,
            cipher,
            seq: 0,
            peer: None,
        }
    }

    fn address(&self) -> SocketAddr {
        self.socket.local_addr().expect("spy addr")
    }

    fn next_seq(&mut self) -> u32 {
        let seq = self.seq;
        self.seq += 1;
        seq
    }

    /// Answers probes and switch requests like a validated peer would, until `deadline`.
    async fn serve(&mut self, until: Instant) {
        let mut buffer = vec![0u8; 65_535];
        while Instant::now() < until {
            let remaining = until - Instant::now();
            let Ok(Ok((length, from))) =
                tokio::time::timeout(remaining, self.socket.recv_from(&mut buffer)).await
            else {
                return;
            };
            match ProbePacket::decode(&buffer[..length], &self.credentials) {
                Ok(ProbePacket::Probe { seq }) => {
                    self.peer = Some(from);
                    let ack = ProbePacket::ack(self.next_seq(), seq).encode(&self.credentials);
                    let _ = self.socket.send_to(&ack, from).await;
                }
                Ok(ProbePacket::Switch { seq }) => {
                    let ack =
                        ProbePacket::switch_ack(self.next_seq(), seq).encode(&self.credentials);
                    let _ = self.socket.send_to(&ack, from).await;
                    // A validated peer confirms that it reads the path, which is what lets
                    // the other side commit.
                    self.peer = Some(from);
                    let confirm = ProbePacket::confirm(self.next_seq()).encode(&self.credentials);
                    let _ = self.socket.send_to(&confirm, from).await;
                }
                _ => {}
            }
        }
    }

    /// Seals one envelope and sends the exact datagram it produces.
    async fn send_sealed(&mut self, envelope: &Envelope) -> Vec<u8> {
        let peer = self.peer.expect("the spy knows the peer");
        let sealed = self.cipher.seal(envelope).expect("spy seals");
        let datagram = ProbePacket::frame(self.next_seq(), sealed)
            .expect("sealed frame fits a datagram")
            .encode(&self.credentials);
        self.socket
            .send_to(&datagram, peer)
            .await
            .expect("spy sends");
        datagram
    }
}

#[tokio::test]
async fn a_captured_frame_cannot_be_replayed_after_an_upgrade() {
    let harness = Harness::new(SESSION).await;
    let key = harness.verification_key();
    let device_socket = socket().await;
    let device_addr = device_socket.local_addr().expect("device addr");
    let device_ticket = harness.ticket(PeerRole::Device);
    // The spy stands in for the client, and its ticket nonce is the one the device learned
    // from rendezvous, so both derive the same connection epoch.
    let spy_nonce = "spy-client-nonce";
    let epoch = epoch_of(spy_nonce, &device_ticket.nonce);
    let mut spy = SpyPeer::new(&harness, TicketRole::Client, &epoch).await;
    let spy_addr = spy.address();

    let candidates = CandidateSet::discover(
        rendezvous(SESSION, &key, spy_addr, RELAY_ENDPOINT, spy_nonce),
        vec![device_addr],
    )
    .expect("candidates");
    let (relay, _probe) = harness
        .relay_channel(PeerRole::Device, Some(Duration::from_millis(20)))
        .await;

    let serve = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_millis(1_500);
        spy.serve(deadline).await;
        spy
    });
    let device_path = PathController::connect(
        device_ticket,
        candidates.clone(),
        device_setup(device_socket, &harness)
            .with_relay(relay)
            .with_config(config(fast_probes()))
            .at(NOW_MS),
    )
    .await
    .expect("device connects");
    assert_eq!(device_path.path_kind(), PathKind::Direct);

    let mut spy = serve.await.expect("spy task");
    let captured = spy.send_sealed(&envelope("req-replay-1", b"first")).await;
    assert_eq!(recv(&device_path).await, envelope("req-replay-1", b"first"));

    // Upgrade in place with the same ticket round: the replay window and sequence space
    // must survive, or the captured frame below would be accepted again.
    let serve = tokio::spawn(async move {
        let deadline = Instant::now() + Duration::from_millis(1_200);
        spy.serve(deadline).await;
        spy
    });
    let upgrade_ticket = harness.ticket(PeerRole::Device);
    assert_eq!(
        device_path
            .upgrade_with(&upgrade_ticket, &candidates, NOW_MS)
            .await
            .expect("upgrade keeps the direct path"),
        PathKind::Direct
    );
    let mut spy = serve.await.expect("spy task");

    // Replay the captured datagram byte for byte: it must never surface as a frame.
    let peer = spy.peer.expect("peer known");
    spy.socket
        .send_to(&captured, peer)
        .await
        .expect("replay sent");
    let replay = timeout(Duration::from_millis(250), device_path.recv_frame()).await;
    assert!(
        replay.is_err(),
        "a replayed pre-upgrade frame must not be delivered: {replay:?}"
    );

    // A fresh frame in the same direction still arrives, so only the replay was dropped.
    let fresh = spy.send_sealed(&envelope("req-replay-2", b"second")).await;
    assert_eq!(
        recv(&device_path).await,
        envelope("req-replay-2", b"second")
    );
    assert_ne!(captured, fresh);
}

#[tokio::test]
async fn frames_crossing_a_concurrent_upgrade_are_not_lost() {
    let harness = Harness::new(SESSION).await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    let device_socket = socket().await;
    let client_addr = client_socket.local_addr().expect("client addr");
    let device_addr = device_socket.local_addr().expect("device addr");

    let (client_ticket, device_ticket) = harness.peer_tickets();
    let client_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            device_addr,
            RELAY_ENDPOINT,
            &device_ticket.nonce,
        ),
        vec![client_addr],
    )
    .expect("client candidates");
    let device_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            client_addr,
            RELAY_ENDPOINT,
            &client_ticket.nonce,
        ),
        vec![device_addr],
    )
    .expect("device candidates");

    let (client_relay, _probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(60)))
        .await;
    let (device_relay, _probe) = harness
        .relay_channel(PeerRole::Device, Some(Duration::from_millis(60)))
        .await;
    let (client_path, device_path) = tokio::join!(
        PathController::connect(
            client_ticket,
            client_candidates.clone(),
            client_setup(client_socket, &harness)
                .with_relay(client_relay)
                .with_config(config(fast_probes()))
                .at(NOW_MS)
        ),
        PathController::connect(
            device_ticket,
            device_candidates.clone(),
            device_setup(device_socket, &harness)
                .with_relay(device_relay)
                .with_config(config(fast_probes()))
                .at(NOW_MS)
        ),
    );
    let client_path = Arc::new(client_path.expect("client connects"));
    let device_path = Arc::new(device_path.expect("device connects"));
    assert_eq!(client_path.path_kind(), PathKind::Direct);

    // One task keeps sending while both peers upgrade; another drains the receiver. A
    // second reader on the socket would steal probes or drop frames here.
    let sender = tokio::spawn({
        let client_path = Arc::clone(&client_path);
        async move {
            let mut sent = Vec::new();
            for index in 0..8 {
                let frame = envelope(&format!("req-flight-{index}"), b"in-flight");
                client_path
                    .send_frame(&frame)
                    .await
                    .expect("send during upgrade");
                sent.push(frame);
                tokio::time::sleep(Duration::from_millis(12)).await;
            }
            sent
        }
    });
    let receiver = tokio::spawn({
        let device_path = Arc::clone(&device_path);
        async move {
            let mut received = Vec::new();
            for _ in 0..8 {
                received.push(recv(&device_path).await);
            }
            received
        }
    });
    let client_ticket = harness.ticket(PeerRole::Client);
    let device_ticket = harness.ticket(PeerRole::Device);
    let upgrades = async {
        let (client, device) = tokio::join!(
            client_path.upgrade_with(&client_ticket, &client_candidates, NOW_MS),
            device_path.upgrade_with(&device_ticket, &device_candidates, NOW_MS),
        );
        (
            client.expect("client upgrades"),
            device.expect("device upgrades"),
        )
    };

    let (sent, received, upgraded) = tokio::join!(sender, receiver, upgrades);
    let sent = sent.expect("sender");
    let received = received.expect("receiver");
    assert_eq!(upgraded, (PathKind::Direct, PathKind::Direct));
    assert_eq!(
        received, sent,
        "every frame that crossed the upgrade arrived exactly once and in order"
    );
}

#[tokio::test]
async fn a_one_sided_punch_stays_on_the_relay() {
    let harness = Harness::new(SESSION).await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    let device_socket = socket().await;
    let client_addr = client_socket.local_addr().expect("client addr");
    let device_addr = device_socket.local_addr().expect("device addr");
    let dead: SocketAddr = "127.0.0.1:9".parse().expect("dead addr");

    // The device can reach the client, but the client's only candidate is dead, so only
    // the device validates the path. The client must not confirm the switch.
    let (client_ticket, device_ticket) = harness.peer_tickets();
    let client_candidates = CandidateSet::discover(
        rendezvous(SESSION, &key, dead, RELAY_ENDPOINT, &device_ticket.nonce),
        vec![dead],
    )
    .expect("client candidates");
    let device_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            client_addr,
            RELAY_ENDPOINT,
            &client_ticket.nonce,
        ),
        vec![device_addr],
    )
    .expect("device candidates");

    let (client_relay, _client_probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(10)))
        .await;
    let (device_relay, _device_probe) = harness
        .relay_channel(PeerRole::Device, Some(Duration::from_millis(10)))
        .await;

    let (client_path, device_path) = tokio::join!(
        PathController::connect(
            client_ticket,
            client_candidates,
            client_setup(client_socket, &harness)
                .with_relay(client_relay)
                .with_config(config(ProbeConfig {
                    attempt_timeout: Duration::from_millis(20),
                    max_attempts: 2,
                }))
                .at(NOW_MS)
        ),
        PathController::connect(
            device_ticket,
            device_candidates,
            device_setup(device_socket, &harness)
                .with_relay(device_relay)
                .with_config(config(ProbeConfig {
                    attempt_timeout: Duration::from_millis(20),
                    max_attempts: 2,
                }))
                .at(NOW_MS)
        ),
    );
    let client_path = client_path.expect("client connects");
    let device_path = device_path.expect("device connects");

    assert_eq!(
        device_path.path_kind(),
        PathKind::Relay,
        "a validated one-sided punch must not commit without the peer's confirmation"
    );
    assert_eq!(client_path.path_kind(), PathKind::Relay);

    // No frame is black-holed: the session still delivers over the relay.
    let frame = envelope("req-one-sided", b"still delivered");
    client_path.send_frame(&frame).await.expect("relay send");
    assert_eq!(recv(&device_path).await, frame);
}

// --------------------------------------------------------------------------------------
// Selection rule, relay terminality, and frame bounds.
// --------------------------------------------------------------------------------------

#[test]
fn selection_prefers_the_lowest_latency_validated_path() {
    let direct = Duration::from_millis(3);
    let relay = Duration::from_millis(40);
    assert_eq!(
        PathController::select(Some(direct), Some(relay)),
        Some(PathKind::Direct)
    );
    assert_eq!(
        PathController::select(Some(relay), Some(direct)),
        Some(PathKind::Relay),
        "a relay that measures faster wins"
    );
    assert_eq!(
        PathController::select(Some(direct), None),
        Some(PathKind::Direct)
    );
    assert_eq!(
        PathController::select(None, Some(relay)),
        Some(PathKind::Relay)
    );
    assert_eq!(PathController::select(None, None), None);
}

#[tokio::test]
async fn relay_unavailable_is_terminal_and_never_retried() {
    let harness = Harness::new(SESSION).await;
    let relay = Arc::new(UnavailableRelay::default());
    let identity = harness.identity(PeerRole::Client);
    let epoch = unique_epoch();
    let path = ConnectedPath::relay_only(RelayOnlyPath {
        relay: relay.clone(),
        identity: &identity,
        peer_identity: harness.device_identity.public_key(),
        session_id: SESSION,
        device_id: DEVICE_ID,
        role: TicketRole::Client,
        epoch: &epoch,
        config: PathConfig::default(),
    })
    .expect("relay path");

    let error = path
        .send_frame(&envelope("req-terminal", b"payload"))
        .await
        .expect_err("terminal relay failure surfaces");
    assert!(matches!(error, PathError::RelayUnavailable), "{error}");
    assert!(error.is_terminal());
    assert_eq!(relay.attempts(), 1, "the frame was never retried");
}

#[derive(Default)]
struct UnavailableRelay {
    attempts: AtomicUsize,
}

impl UnavailableRelay {
    fn attempts(&self) -> usize {
        self.attempts.load(Ordering::SeqCst)
    }
}

#[async_trait]
impl RelayChannel for UnavailableRelay {
    async fn send_frame(&self, _frame: &[u8]) -> Result<(), RelayError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        Err(RelayError::Unavailable)
    }

    async fn recv_frame(&self) -> Result<Vec<u8>, RelayError> {
        Err(RelayError::Unavailable)
    }

    async fn close(&self) -> Result<(), RelayError> {
        Ok(())
    }
}

#[tokio::test]
async fn control_paths_are_bounded_by_the_control_only_frame_profile() {
    let harness = Harness::new(SESSION).await;

    assert_eq!(
        PathConfig::default().frame_limits.max_limit(),
        FrameLimits::control_only().max_limit()
    );

    let (relay, _probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(5)))
        .await;
    let identity = harness.identity(PeerRole::Client);
    let epoch = unique_epoch();
    let path = ConnectedPath::relay_only(RelayOnlyPath {
        relay,
        identity: &identity,
        peer_identity: harness.device_identity.public_key(),
        session_id: SESSION,
        device_id: DEVICE_ID,
        role: TicketRole::Client,
        epoch: &epoch,
        config: PathConfig::default(),
    })
    .expect("relay path");

    let mut too_large = envelope("req-oversized", &[]);
    too_large.payload = vec![0u8; FrameLimits::control_only().max_limit() as usize + 1];
    assert!(matches!(
        path.send_frame(&too_large).await,
        Err(PathError::Protocol(
            phoneconnect::v1::ProtocolError::FrameTooLarge { .. }
        ))
    ));
    assert!(encode_frame(&too_large, &FrameLimits::default()).is_err());
}

#[tokio::test]
async fn a_path_configuration_without_a_usable_direct_limit_is_refused() {
    let harness = Harness::new(SESSION).await;
    let (relay, _probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(5)))
        .await;
    let identity = harness.identity(PeerRole::Client);
    let epoch = unique_epoch();
    for limit in [0, 60_001] {
        let error = ConnectedPath::relay_only(RelayOnlyPath {
            relay: Arc::clone(&relay),
            identity: &identity,
            peer_identity: harness.device_identity.public_key(),
            session_id: SESSION,
            device_id: DEVICE_ID,
            role: TicketRole::Client,
            epoch: &epoch,
            config: PathConfig {
                direct_frame_limit: limit,
                ..PathConfig::default()
            },
        })
        .expect_err("an unusable direct limit is refused");
        assert!(matches!(error, PathError::InvalidConfig { .. }), "{error}");
    }
}

#[tokio::test]
async fn a_relay_that_answers_409_is_unavailable_not_retryable() {
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let attempts = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&attempts);

    let server = tokio::spawn(async move {
        let (mut socket, _) = listener.accept().await.expect("one handshake");
        observed.fetch_add(1, Ordering::SeqCst);
        use tokio::io::AsyncWriteExt;
        let _ = socket
            .write_all(
                b"HTTP/1.1 409 Conflict\r\ncontent-type: application/json\r\ncontent-length: 27\r\nconnection: close\r\n\r\n{\"error\":\"relay_unavailable\"}",
            )
            .await;
        let _ = socket.shutdown().await;
    });

    let error = match phoneconnect_transport::WebSocketRelay::connect(
        &format!("ws://{address}/api/sessions/{SESSION}/relay"),
        "pcsess_test",
        1024,
    )
    .await
    {
        Ok(_) => panic!("a 409 is not a usable relay"),
        Err(error) => error,
    };
    assert_eq!(error, RelayError::Unavailable);
    assert!(error.is_terminal(), "the session id cannot be retried");
    assert_eq!(attempts.load(Ordering::SeqCst), 1);

    server.await.expect("server task finishes");
}

#[tokio::test]
async fn the_websocket_relay_measures_its_own_round_trip() {
    use phoneconnect_server::AppState;
    use phoneconnect_server::auth::{generate_secret, hash_secret};
    use phoneconnect_server::build_router;

    let store = Arc::new(SqliteStore::in_memory().expect("in-memory store"));
    let clock = Arc::new(ManualClock::new(NOW_MS));
    let device_identity = IdentityKey::generate().expect("device identity");
    let client_identity = IdentityKey::generate().expect("client identity");
    store
        .insert_enrollment_token(EnrollmentTokenRecord {
            token_hash: "rtt-enrollment".to_owned(),
            owner_id: "user-a".to_owned(),
            created_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + 900_000,
        })
        .await
        .expect("token");
    store
        .consume_enrollment_token(
            "rtt-enrollment",
            NOW_MS,
            NewDevice {
                device_id: DEVICE_ID.to_owned(),
                credential_hash: "credential-hash".to_owned(),
                identity_public_key: device_identity.public_key().as_str(),
                enrolled_at_ms: NOW_MS,
            },
        )
        .await
        .expect("device");
    let capability = generate_secret("pcsess_").expect("capability");
    let record = SessionRecord {
        session_id: SESSION.to_owned(),
        device_id: DEVICE_ID.to_owned(),
        owner_id: "user-a".to_owned(),
        capability_hash: hash_secret(&capability),
        client_identity_key: client_identity.public_key().as_str(),
        device_identity_key: device_identity.public_key().as_str(),
        created_at_ms: NOW_MS,
        expires_at_ms: NOW_MS + 300_000,
        revoked_at_ms: None,
    };
    store.insert_session(record.clone()).await.expect("session");

    let state = Arc::new(
        AppState::new(
            store,
            "rtt-admin",
            RELAY_ENDPOINT,
            RelayLimits::default(),
            clock,
        )
        .expect("app state"),
    );
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
        .await
        .expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, build_router(state)).await;
    });

    let relay = phoneconnect_transport::WebSocketRelay::connect(
        &format!("ws://{address}/api/sessions/{SESSION}/relay"),
        &capability,
        1024 * 1024,
    )
    .await
    .expect("relay attaches");

    let measured = relay
        .latency()
        .expect("the attach handshake measures the relay round trip instead of guessing 50 ms");
    assert!(
        measured < Duration::from_secs(1),
        "a loopback relay round trip cannot take {measured:?}"
    );

    // The configured estimate is only the fallback: a measured value replaces it.
    let identity = client_identity.clone();
    let epoch = unique_epoch();
    let path = ConnectedPath::relay_only(RelayOnlyPath {
        relay,
        identity: &identity,
        peer_identity: device_identity.public_key(),
        session_id: SESSION,
        device_id: DEVICE_ID,
        role: TicketRole::Client,
        epoch: &epoch,
        config: PathConfig::default(),
    })
    .expect("relay path");
    assert_eq!(path.path_kind(), PathKind::Relay);

    path.shutdown().await.expect("shutdown");
    server.abort();
}

#[tokio::test]
async fn a_round_rotation_during_upgrade_keeps_one_reader_and_loses_no_frames() {
    let harness = Harness::new(SESSION).await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    let device_socket = socket().await;
    let client_addr = client_socket.local_addr().expect("client addr");
    let device_addr = device_socket.local_addr().expect("device addr");

    let (client_ticket, device_ticket) = harness.peer_tickets();
    let client_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            device_addr,
            RELAY_ENDPOINT,
            &device_ticket.nonce,
        ),
        vec![client_addr],
    )
    .expect("client candidates");
    let device_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            client_addr,
            RELAY_ENDPOINT,
            &client_ticket.nonce,
        ),
        vec![device_addr],
    )
    .expect("device candidates");
    let (client_relay, _probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(60)))
        .await;
    let (device_relay, _probe) = harness
        .relay_channel(PeerRole::Device, Some(Duration::from_millis(60)))
        .await;
    let (client_path, device_path) = tokio::join!(
        PathController::connect(
            client_ticket,
            client_candidates.clone(),
            client_setup(client_socket, &harness)
                .with_relay(client_relay)
                .with_config(config(fast_probes()))
                .at(NOW_MS)
        ),
        PathController::connect(
            device_ticket,
            device_candidates.clone(),
            device_setup(device_socket, &harness)
                .with_relay(device_relay)
                .with_config(config(fast_probes()))
                .at(NOW_MS)
        ),
    );
    let client_path = Arc::new(client_path.expect("client connects"));
    let device_path = Arc::new(device_path.expect("device connects"));
    assert_eq!(client_path.path_kind(), PathKind::Direct);
    let first_round = client_path
        .probe_round_id()
        .await
        .expect("the direct socket reports its round");

    // A redeemed ticket makes the next `GET /ticket` start a new rendezvous round, which is
    // the normal production path. Rotating the key must not start a second reader on the
    // same socket: a second reader would consume the new round's packets with the old
    // authenticator and drop frames.
    // Both peers register (which redeems their tickets, exactly as `POST /candidates`
    // does); the next round then serves fresh nonces and a fresh probe key.
    for role in [PeerRole::Client, PeerRole::Device] {
        let registered = harness
            .authority
            .issue(&harness.record, role, NOW_MS)
            .expect("ticket issued");
        harness
            .authority
            .redeem(&registered, SESSION, role, NOW_MS)
            .expect("ticket redeems");
    }
    harness
        .authority
        .start_round(&harness.record.session_id)
        .expect("round rotates");
    let (client_ticket2, device_ticket2) = harness.peer_tickets();
    let client_candidates2 = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            device_addr,
            RELAY_ENDPOINT,
            &device_ticket2.nonce,
        ),
        vec![client_addr],
    )
    .expect("client candidates");
    let device_candidates2 = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            client_addr,
            RELAY_ENDPOINT,
            &client_ticket2.nonce,
        ),
        vec![device_addr],
    )
    .expect("device candidates");

    let sender = tokio::spawn({
        let client_path = Arc::clone(&client_path);
        async move {
            let mut sent = Vec::new();
            for index in 0..8 {
                let frame = envelope(&format!("req-rotate-{index}"), b"during rotation");
                client_path
                    .send_frame(&frame)
                    .await
                    .expect("send during rotation");
                sent.push(frame);
                tokio::time::sleep(Duration::from_millis(12)).await;
            }
            sent
        }
    });
    let receiver = tokio::spawn({
        let device_path = Arc::clone(&device_path);
        async move {
            let mut received = Vec::new();
            for _ in 0..8 {
                received.push(recv(&device_path).await);
            }
            received
        }
    });
    let upgrades = async {
        let (client, device) = tokio::join!(
            client_path.upgrade_with(&client_ticket2, &client_candidates2, NOW_MS),
            device_path.upgrade_with(&device_ticket2, &device_candidates2, NOW_MS),
        );
        (
            client.expect("client upgrades"),
            device.expect("device upgrades"),
        )
    };

    let (sent, received, upgraded) = tokio::join!(sender, receiver, upgrades);
    assert_eq!(upgraded, (PathKind::Direct, PathKind::Direct));
    assert_eq!(
        received.expect("receiver"),
        sent.expect("sender"),
        "no frame may be lost while the probe key rotates"
    );
    let second_round = client_path
        .probe_round_id()
        .await
        .expect("the direct socket still exists");
    assert_ne!(
        first_round, second_round,
        "the socket was re-keyed to the new round in place"
    );
    assert_eq!(
        second_round,
        device_path.probe_round_id().await.expect("device round id"),
        "both peers rotated to the same round key"
    );
}

#[tokio::test]
async fn a_pinned_peer_identity_fails_closed_before_any_frame() {
    let harness = Harness::new(SESSION).await;
    let key = harness.verification_key();
    let candidates = CandidateSet::discover(
        rendezvous_only(SESSION, &key, RELAY_ENDPOINT, "peer-nonce"),
        vec![],
    )
    .expect("candidates");
    let (relay, _probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(5)))
        .await;

    // Peer identity otherwise arrives through the server-signed ticket, so a compromised
    // rendezvous server could substitute it. A caller that pinned the identity out of band
    // must fail closed.
    let impostor = IdentityKey::generate().expect("impostor identity");
    let error = PathController::connect(
        harness.ticket(PeerRole::Client),
        candidates.clone(),
        client_setup(socket().await, &harness)
            .with_expected_peer_identity(impostor.public_key())
            .with_relay(Arc::clone(&relay))
            .at(NOW_MS),
    )
    .await
    .expect_err("a substituted peer identity is refused");
    assert!(
        matches!(
            error,
            PathError::Ticket(TicketError::PeerIdentityMismatch { .. })
        ),
        "{error}"
    );

    // The pinned identity that matches the ticket is accepted.
    let path = PathController::connect(
        harness.ticket(PeerRole::Client),
        candidates,
        client_setup(socket().await, &harness)
            .with_expected_peer_identity(harness.device_identity.public_key())
            .with_relay(relay)
            .at(NOW_MS),
    )
    .await
    .expect("the pinned identity matches");
    assert_eq!(path.path_kind(), PathKind::Relay);
}

/// Forwards direct-path datagrams between two peers and drops every switch acknowledgement
/// travelling from the device to the client, which is what asymmetric loss looks like.
struct AckLossProxy {
    socket: UdpSocket,
    client: SocketAddr,
    device: SocketAddr,
    client_credentials: ProbeCredentials,
    dropped: Arc<AtomicUsize>,
    /// Drop every switch acknowledgement from the device to the client.
    drop_switch_acks: bool,
}

impl AckLossProxy {
    async fn run(self, stop: Arc<AtomicBool>) {
        let mut buffer = vec![0u8; 65_535];
        while !stop.load(Ordering::SeqCst) {
            let received = tokio::time::timeout(
                Duration::from_millis(50),
                self.socket.recv_from(&mut buffer),
            )
            .await;
            let Ok(Ok((length, from))) = received else {
                continue;
            };
            let to = if from == self.client {
                self.device
            } else if from == self.device {
                self.client
            } else {
                continue;
            };
            if self.drop_switch_acks
                && from == self.device
                && matches!(
                    ProbePacket::decode(&buffer[..length], &self.client_credentials),
                    Ok(ProbePacket::SwitchAck { .. })
                )
            {
                self.dropped.fetch_add(1, Ordering::SeqCst);
                continue;
            }
            let _ = self.socket.send_to(&buffer[..length], to).await;
        }
    }
}

#[tokio::test]
async fn asymmetric_ack_loss_never_commits_one_peer_and_keeps_delivering() {
    let harness = Harness::new(SESSION).await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    let device_socket = socket().await;
    let client_addr = client_socket.local_addr().expect("client addr");
    let device_addr = device_socket.local_addr().expect("device addr");

    let proxy = UdpSocket::bind("127.0.0.1:0").await.expect("proxy socket");
    let proxy_addr = proxy.local_addr().expect("proxy addr");
    let dropped = Arc::new(AtomicUsize::new(0));
    let stop = Arc::new(AtomicBool::new(false));
    let proxy_task = tokio::spawn(
        AckLossProxy {
            socket: proxy,
            client: client_addr,
            device: device_addr,
            client_credentials: harness.credentials(PeerRole::Client),
            dropped: Arc::clone(&dropped),
            drop_switch_acks: true,
        }
        .run(Arc::clone(&stop)),
    );

    let (client_ticket, device_ticket) = harness.peer_tickets();
    let client_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            proxy_addr,
            RELAY_ENDPOINT,
            &device_ticket.nonce,
        ),
        vec![client_addr],
    )
    .expect("client candidates");
    let device_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            proxy_addr,
            RELAY_ENDPOINT,
            &client_ticket.nonce,
        ),
        vec![device_addr],
    )
    .expect("device candidates");
    let (client_relay, _probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(10)))
        .await;
    let (device_relay, _probe) = harness
        .relay_channel(PeerRole::Device, Some(Duration::from_millis(10)))
        .await;

    let switch = SwitchConfig {
        retries: 3,
        timeout: Duration::from_millis(60),
        confirmation_timeout: Duration::from_millis(300),
    };
    let (client_path, device_path) = tokio::join!(
        PathController::connect(
            client_ticket,
            client_candidates,
            client_setup(client_socket, &harness)
                .with_relay(client_relay)
                .with_config(PathConfig {
                    probe: fast_probes(),
                    switch,
                    ..PathConfig::default()
                })
                .at(NOW_MS)
        ),
        PathController::connect(
            device_ticket,
            device_candidates,
            device_setup(device_socket, &harness)
                .with_relay(device_relay)
                .with_config(PathConfig {
                    probe: fast_probes(),
                    switch,
                    ..PathConfig::default()
                })
                .at(NOW_MS)
        ),
    );
    let client_path = client_path.expect("client connects");
    let device_path = device_path.expect("device connects");

    assert!(
        dropped.load(Ordering::SeqCst) > 0,
        "the proxy really dropped the device's acknowledgements"
    );
    assert_eq!(
        client_path.path_kind(),
        PathKind::Relay,
        "a side whose acknowledgement was lost never commits"
    );
    assert_eq!(
        device_path.path_kind(),
        PathKind::Relay,
        "and neither does the side that never got the peer's confirmation"
    );

    // Delivery continues over the relay: no frame is black-holed on a path only one side
    // would have used.
    let frame = envelope("req-asymmetric", b"still delivered");
    client_path.send_frame(&frame).await.expect("relay send");
    assert_eq!(recv(&device_path).await, frame);

    stop.store(true, Ordering::SeqCst);
    proxy_task.await.expect("proxy stops");
}

#[tokio::test]
async fn a_direct_path_that_stops_delivering_falls_back_to_the_relay() {
    let harness = Harness::new(SESSION).await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    let device_socket = socket().await;
    let client_addr = client_socket.local_addr().expect("client addr");
    let device_addr = device_socket.local_addr().expect("device addr");

    // The direct path runs through a proxy, so the test can cut it without touching the
    // relay.
    let proxy = UdpSocket::bind("127.0.0.1:0").await.expect("proxy socket");
    let proxy_addr = proxy.local_addr().expect("proxy addr");
    let stop = Arc::new(AtomicBool::new(false));
    let proxy_task = tokio::spawn(
        AckLossProxy {
            socket: proxy,
            client: client_addr,
            device: device_addr,
            client_credentials: harness.credentials(PeerRole::Client),
            dropped: Arc::new(AtomicUsize::new(0)),
            drop_switch_acks: false,
        }
        .run(Arc::clone(&stop)),
    );

    let (client_ticket, device_ticket) = harness.peer_tickets();
    let client_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            proxy_addr,
            RELAY_ENDPOINT,
            &device_ticket.nonce,
        ),
        vec![client_addr],
    )
    .expect("client candidates");
    let device_candidates = CandidateSet::discover(
        rendezvous(
            SESSION,
            &key,
            proxy_addr,
            RELAY_ENDPOINT,
            &client_ticket.nonce,
        ),
        vec![device_addr],
    )
    .expect("device candidates");
    let (client_relay, _probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(10)))
        .await;
    let (device_relay, _probe) = harness
        .relay_channel(PeerRole::Device, Some(Duration::from_millis(10)))
        .await;
    let config = PathConfig {
        probe: fast_probes(),
        switch: fast_switch(),
        direct_health_timeout: Duration::from_millis(150),
        ..PathConfig::default()
    };
    let (client_path, device_path) = tokio::join!(
        PathController::connect(
            client_ticket,
            client_candidates,
            client_setup(client_socket, &harness)
                .with_relay(client_relay)
                .with_config(config.clone())
                .at(NOW_MS)
        ),
        PathController::connect(
            device_ticket,
            device_candidates,
            device_setup(device_socket, &harness)
                .with_relay(device_relay)
                .with_config(config)
                .at(NOW_MS)
        ),
    );
    let client_path = client_path.expect("client connects");
    let device_path = device_path.expect("device connects");
    assert_eq!(client_path.path_kind(), PathKind::Direct);

    let first = envelope("req-health-1", b"on direct");
    client_path.send_frame(&first).await.expect("direct send");
    assert_eq!(recv(&device_path).await, first);

    // Cut the direct path: no datagram reaches either side any more.
    stop.store(true, Ordering::SeqCst);
    proxy_task.await.expect("proxy stops");
    tokio::time::sleep(Duration::from_millis(250)).await;

    assert_eq!(
        client_path.path_kind(),
        PathKind::Direct,
        "the kind is only demoted when the next frame is sent or received"
    );
    let second = envelope("req-health-2", b"after the path died");
    client_path
        .send_frame(&second)
        .await
        .expect("a dead direct path must not black-hole");
    assert_eq!(
        client_path.path_kind(),
        PathKind::Relay,
        "the path demoted itself to the relay"
    );
    assert_eq!(
        recv(&device_path).await,
        second,
        "the peer received it over the relay"
    );
}
