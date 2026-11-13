//! Direct-path transport contract.
//!
//! Every test here drives real loopback UDP sockets and the server's bounded relay, so a
//! path is only reported as validated when an authenticated peer actually answered and a
//! frame actually crossed it.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use async_trait::async_trait;
use phoneconnect::v1::{
    DeviceId, Envelope, FrameLimits, RequestId, SessionId, StreamKind, encode_frame,
};
use phoneconnect_server::PeerRole;
use phoneconnect_server::relay::{Relay, RelayClose, RelayLimits, RelayPeer};
use phoneconnect_server::rendezvous::TicketAuthority;
use phoneconnect_server::store::{
    DeviceStore, EnrollmentTokenRecord, ManualClock, NewDevice, SessionRecord, SqliteStore,
};
use phoneconnect_transport::{
    CandidateKind, CandidateSet, ConnectedPath, HolePunchError, PathConfig, PathController,
    PathError, PathKind, PathSetup, ProbeAuthenticator, ProbeConfig, ProbePacket, RelayChannel,
    RelayError, RendezvousCandidates, Ticket, TicketError,
};
use serde_json::json;
use tokio::net::UdpSocket;
use tokio::time::timeout;

const NOW_MS: i64 = 1_760_000_000_000;
const DEVICE_ID: &str = "dev_transport";
const RELAY_ENDPOINT: &str = "http://relay.test/api/sessions";

// --------------------------------------------------------------------------------------
// Server-side rendezvous and relay fixtures. The transport crate deliberately has no
// server dependency, so the tests supply the server side the way the real server does:
// signed tickets from `TicketAuthority` and bounded relay handles from `Relay`.
// --------------------------------------------------------------------------------------

struct Harness {
    relay: Arc<Relay>,
    authority: Arc<TicketAuthority>,
    record: SessionRecord,
}

impl Harness {
    async fn new(session_id: &str) -> Self {
        let store = Arc::new(SqliteStore::in_memory().expect("in-memory store"));
        let clock = Arc::new(ManualClock::new(NOW_MS));
        let record = SessionRecord {
            session_id: session_id.to_owned(),
            device_id: DEVICE_ID.to_owned(),
            owner_id: "user-a".to_owned(),
            capability_hash: "capability-hash".to_owned(),
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
                    enrolled_at_ms: NOW_MS,
                },
            )
            .await
            .expect("device persists");
        store
            .insert_session(record.clone())
            .await
            .expect("session persists");
        let relay = Arc::new(Relay::new(
            RELAY_ENDPOINT,
            RelayLimits::default(),
            store.clone(),
            clock,
        ));
        Self {
            relay,
            authority: Arc::new(TicketAuthority::new().expect("ticket authority")),
            record,
        }
    }

    fn verification_key(&self) -> String {
        self.authority.verification_key().to_owned()
    }

    /// Issues a ticket the way `POST /api/sessions` and the device ticket route do, then
    /// round-trips it through JSON so the transport type must stay wire-compatible.
    fn ticket(&self, role: PeerRole) -> Ticket {
        let issued = self
            .authority
            .issue(&self.record, role, NOW_MS)
            .expect("ticket issued");
        serde_json::from_value(serde_json::to_value(issued).expect("ticket json"))
            .expect("transport accepts the server ticket shape")
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
}

impl RelayProbe {
    fn sends(&self) -> usize {
        self.sends.load(Ordering::SeqCst)
    }

    fn closed(&self) -> bool {
        self.closed.load(Ordering::SeqCst)
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
) -> RendezvousCandidates {
    serde_json::from_value(json!({
        "session_id": session_id,
        "expires_at": NOW_MS + 300_000,
        "verification_key": verification_key,
        "candidates": [
            { "kind": "server_observed", "endpoint": peer.to_string(), "priority": 150 },
            { "kind": "relay", "endpoint": relay, "priority": 100 }
        ]
    }))
    .expect("server candidate shape")
}

fn rendezvous_only(session_id: &str, verification_key: &str, relay: &str) -> RendezvousCandidates {
    serde_json::from_value(json!({
        "session_id": session_id,
        "expires_at": NOW_MS + 300_000,
        "verification_key": verification_key,
        "candidates": [{ "kind": "relay", "endpoint": relay, "priority": 100 }]
    }))
    .expect("server candidate shape")
}

fn fast_probes() -> ProbeConfig {
    ProbeConfig {
        attempt_timeout: Duration::from_millis(40),
        max_attempts: 3,
    }
}

fn config(probe: ProbeConfig) -> PathConfig {
    PathConfig {
        probe,
        ..PathConfig::default()
    }
}

fn envelope(request: &str, payload: &[u8]) -> Envelope {
    let device = DeviceId::new(DEVICE_ID).expect("device id");
    let session = SessionId::new("sess_direct").expect("session id");
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

// --------------------------------------------------------------------------------------
// Candidate discovery.
// --------------------------------------------------------------------------------------

#[test]
fn discovery_covers_local_server_observed_and_relay_candidates() {
    let local_one: SocketAddr = "10.0.0.7:51000".parse().expect("addr");
    let local_two: SocketAddr = "192.168.1.20:51000".parse().expect("addr");
    let observed: SocketAddr = "203.0.113.9:62000".parse().expect("addr");

    let set = CandidateSet::discover(
        rendezvous("sess_direct", "key", observed, RELAY_ENDPOINT),
        vec![local_one, local_two],
    )
    .expect("candidates discovered");

    assert_eq!(set.session_id(), "sess_direct");
    assert_eq!(set.expires_at(), NOW_MS + 300_000);
    assert_eq!(set.verification_key(), "key");

    let kinds: Vec<CandidateKind> = set.candidates().iter().map(|item| item.kind).collect();
    assert!(kinds.contains(&CandidateKind::Local), "{kinds:?}");
    assert!(kinds.contains(&CandidateKind::ServerObserved), "{kinds:?}");
    assert!(kinds.contains(&CandidateKind::Relay), "{kinds:?}");

    // Direct candidates are ordered by priority: local before server-observed.
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
        "session_id": "sess_direct",
        "expires_at": NOW_MS - 1,
        "verification_key": "key",
        "candidates": [{ "kind": "relay", "endpoint": RELAY_ENDPOINT, "priority": 100 }]
    }))
    .expect("shape");
    let set = CandidateSet::discover(expired, vec![]).expect("shape accepted at discovery");
    assert!(
        set.is_expired(NOW_MS),
        "the caller must reject expired rendezvous data"
    );

    let malformed: RendezvousCandidates = serde_json::from_value(json!({
        "session_id": "sess_direct",
        "expires_at": NOW_MS + 1000,
        "verification_key": "key",
        "candidates": [{ "kind": "server_observed", "endpoint": "not-an-address", "priority": 150 }]
    }))
    .expect("shape");
    assert!(CandidateSet::discover(malformed, vec![]).is_err());
}

// --------------------------------------------------------------------------------------
// Ticket authentication and nonce binding.
// --------------------------------------------------------------------------------------

#[test]
fn ticket_signature_binds_session_role_and_nonce() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let harness = runtime.block_on(Harness::new("sess_direct"));
    let key = harness.verification_key();
    let ticket = harness.ticket(PeerRole::Client);

    let credentials = ticket
        .verify(&key, NOW_MS)
        .expect("server-signed ticket verifies");
    assert_eq!(credentials.session_id(), "sess_direct");

    let mut swapped_nonce = ticket.clone();
    swapped_nonce.nonce = harness.ticket(PeerRole::Client).nonce;
    // The freshly issued ticket shares the session nonce, so change a signed field the
    // attacker controls instead: the signature must not cover the mutated value.
    swapped_nonce.device_id = "dev_someone_else".to_owned();
    assert_eq!(
        swapped_nonce.verify(&key, NOW_MS),
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

#[test]
fn replayed_probes_are_rejected_before_a_path_is_established() {
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let harness = runtime.block_on(Harness::new("sess_direct"));
    let key = harness.verification_key();

    let client = harness.ticket(PeerRole::Client);
    let device = harness.ticket(PeerRole::Device);
    assert_eq!(
        client.nonce, device.nonce,
        "both peers share one rendezvous nonce for the session"
    );

    let device_credentials = device.verify(&key, NOW_MS).expect("device ticket");
    let client_credentials = client.verify(&key, NOW_MS).expect("client ticket");

    let probe = ProbePacket::probe(7);
    let datagram = probe.encode(&device_credentials);
    let authenticator = ProbeAuthenticator::new(&client_credentials);

    assert!(matches!(
        authenticator.accept(&datagram),
        Ok(ProbePacket::Probe { seq: 7, .. })
    ));
    assert_eq!(
        authenticator.accept(&datagram),
        Err(HolePunchError::Replayed),
        "a byte-identical probe replay never validates a second path"
    );

    // A newer probe advances the window; the original replay stays rejected.
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

    // A probe minted for a different ticket nonce fails authentication outright.
    let other_session = runtime.block_on(Harness::new("sess_other"));
    let other = other_session
        .ticket(PeerRole::Device)
        .verify(&other_session.verification_key(), NOW_MS)
        .expect("other ticket");
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
    let harness = Harness::new("sess_direct").await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    let device_socket = socket().await;
    let client_addr = client_socket.local_addr().expect("client addr");
    let device_addr = device_socket.local_addr().expect("device addr");

    let client_candidates = CandidateSet::discover(
        rendezvous("sess_direct", &key, device_addr, RELAY_ENDPOINT),
        vec![client_addr],
    )
    .expect("client candidates");
    let device_candidates = CandidateSet::discover(
        rendezvous("sess_direct", &key, client_addr, RELAY_ENDPOINT),
        vec![device_addr],
    )
    .expect("device candidates");

    let (client_relay, client_probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(120)))
        .await;
    let (device_relay, _device_probe) = harness
        .relay_channel(PeerRole::Device, Some(Duration::from_millis(120)))
        .await;

    let client_setup = PathSetup::new(Arc::clone(&client_socket))
        .with_relay(client_relay)
        .with_config(config(fast_probes()))
        .at(NOW_MS);
    let device_setup = PathSetup::new(Arc::clone(&device_socket))
        .with_relay(device_relay)
        .with_config(config(fast_probes()))
        .at(NOW_MS);

    let (client_path, device_path) = tokio::join!(
        PathController::connect(
            harness.ticket(PeerRole::Client),
            client_candidates,
            client_setup
        ),
        PathController::connect(
            harness.ticket(PeerRole::Device),
            device_candidates,
            device_setup
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
    let harness = Harness::new("sess_direct").await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    // The device holds a UDP socket but never answers, which is what a restrictive
    // firewall or symmetric NAT looks like to the probing peer.
    let silent_device = UdpSocket::bind("127.0.0.1:0").await.expect("device socket");
    let device_addr = silent_device.local_addr().expect("device addr");
    let client_addr = client_socket.local_addr().expect("client addr");

    let client_candidates = CandidateSet::discover(
        rendezvous("sess_direct", &key, device_addr, RELAY_ENDPOINT),
        vec![client_addr],
    )
    .expect("client candidates");
    let (client_relay, client_probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(10)))
        .await;
    let device_peer = harness.relay_peer(PeerRole::Device).await;

    let client_path = PathController::connect(
        harness.ticket(PeerRole::Client),
        client_candidates,
        PathSetup::new(client_socket)
            .with_relay(client_relay)
            .with_config(config(ProbeConfig {
                attempt_timeout: Duration::from_millis(20),
                max_attempts: 2,
            }))
            .at(NOW_MS),
    )
    .await
    .expect("relay fallback");

    assert_eq!(client_path.path_kind(), PathKind::Relay);
    assert_eq!(client_probe.sends(), 0, "no frame is relayed until sent");

    let frame = envelope("req-relay-1", b"relayed payload");
    client_path.send_frame(&frame).await.expect("relay send");
    assert_eq!(
        device_peer.recv_frame().await.expect("relay delivers"),
        frame,
        "the relay path carries the same envelope the direct path would"
    );
    assert_eq!(client_probe.sends(), 1);
    assert!(!client_probe.closed(), "a fallback path stays open");
}

#[tokio::test]
async fn direct_negotiation_fails_explicitly_without_a_relay() {
    let harness = Harness::new("sess_direct").await;
    let key = harness.verification_key();
    let client_socket = socket().await;

    // No peer-reported endpoint and no local discovery: there is nothing direct to try.
    let candidates =
        CandidateSet::discover(rendezvous_only("sess_direct", &key, RELAY_ENDPOINT), vec![])
            .expect("candidates");

    let started = Instant::now();
    let error = PathController::connect(
        harness.ticket(PeerRole::Client),
        candidates,
        PathSetup::new(client_socket)
            .with_config(PathConfig {
                probe: ProbeConfig {
                    attempt_timeout: Duration::from_millis(20),
                    max_attempts: 2,
                },
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
    let harness = Harness::new("sess_direct").await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    let silent = UdpSocket::bind("127.0.0.1:0").await.expect("device socket");

    let candidates = CandidateSet::discover(
        rendezvous(
            "sess_direct",
            &key,
            silent.local_addr().expect("device addr"),
            RELAY_ENDPOINT,
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
        harness.ticket(PeerRole::Client),
        candidates,
        PathSetup::new(client_socket)
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
    let harness = Harness::new("sess_direct").await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    let device_socket = socket().await;
    let client_addr = client_socket.local_addr().expect("client addr");
    let device_addr = device_socket.local_addr().expect("device addr");

    let client_candidates = CandidateSet::discover(
        rendezvous("sess_direct", &key, device_addr, RELAY_ENDPOINT),
        vec![client_addr],
    )
    .expect("client candidates");
    let device_candidates = CandidateSet::discover(
        rendezvous("sess_direct", &key, client_addr, RELAY_ENDPOINT),
        vec![device_addr],
    )
    .expect("device candidates");

    let (client_relay, client_probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(10)))
        .await;
    let (device_relay, device_probe) = harness
        .relay_channel(PeerRole::Device, Some(Duration::from_millis(10)))
        .await;

    // First contact happens over the relay while direct negotiation is impossible.
    let client_path = PathController::connect(
        harness.ticket(PeerRole::Client),
        client_candidates,
        PathSetup::new(Arc::clone(&client_socket))
            .with_relay(client_relay)
            .with_config(config(ProbeConfig {
                attempt_timeout: Duration::from_millis(10),
                max_attempts: 1,
            }))
            .at(NOW_MS),
    )
    .await
    .expect("relay path");
    let device_path = PathController::connect(
        harness.ticket(PeerRole::Device),
        device_candidates,
        PathSetup::new(Arc::clone(&device_socket))
            .with_relay(device_relay)
            .with_config(config(ProbeConfig {
                attempt_timeout: Duration::from_millis(10),
                max_attempts: 1,
            }))
            .at(NOW_MS),
    )
    .await
    .expect("relay path");
    assert_eq!(client_path.path_kind(), PathKind::Relay);
    assert_eq!(device_path.path_kind(), PathKind::Relay);

    let first = envelope("req-migrate-1", b"over relay");
    client_path.send_frame(&first).await.expect("relay send");
    assert_eq!(recv(&device_path).await, first);

    // Both sides repeat negotiation and upgrade without a new session or a new ticket.
    let (client_upgrade, device_upgrade) =
        tokio::join!(client_path.try_upgrade(), device_path.try_upgrade(),);
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
    let harness = Harness::new("sess_direct").await;
    let key = harness.verification_key();
    let client_socket = socket().await;
    let silent = UdpSocket::bind("127.0.0.1:0").await.expect("device socket");

    let candidates = CandidateSet::discover(
        rendezvous(
            "sess_direct",
            &key,
            silent.local_addr().expect("device addr"),
            RELAY_ENDPOINT,
        ),
        vec![],
    )
    .expect("candidates");

    let relay = Arc::new(UnavailableRelay::default());
    let path = PathController::connect(
        harness.ticket(PeerRole::Client),
        candidates,
        PathSetup::new(client_socket)
            .with_relay(relay.clone())
            .with_config(config(ProbeConfig {
                attempt_timeout: Duration::from_millis(10),
                max_attempts: 1,
            }))
            .at(NOW_MS),
    )
    .await
    .expect("relay path");

    // A relay that already failed before any frame is sent reports the terminal state.
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
    let harness = Harness::new("sess_direct").await;

    // Even with no path available, the configured limits are the control-only profile,
    // so an oversized control frame is refused from its length prefix.
    assert_eq!(
        PathConfig::default().frame_limits.max_limit(),
        FrameLimits::control_only().max_limit()
    );

    let (relay, _probe) = harness
        .relay_channel(PeerRole::Client, Some(Duration::from_millis(5)))
        .await;
    let path = ConnectedPath::relay_only(relay, PathConfig::default());

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
async fn a_relay_that_answers_409_is_unavailable_not_retryable() {
    // A relay that has already answered `409 relay_unavailable` is terminal for that
    // session id. The client must surface that and must not attempt a second handshake.
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
        &format!("ws://{address}/api/sessions/sess_direct/relay"),
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
