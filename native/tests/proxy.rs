//! Loopback proxy contract.
//!
//! Every test drives real loopback TCP sockets and a real `ConnectedPath`; the peer is a
//! device-side stub that echoes `StreamKind::Proxy` envelopes, which is the shape the Android
//! agent's TCP bridge will implement. Nothing here claims an Android endpoint exists: the
//! stub is the peer and the relay is in-process, so these tests prove the native half only.

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use phoneconnect::v1::{DeviceId, Envelope, RequestId, SessionId, StreamKind};
use phoneconnect_native::proxy::{
    LocalEndpoint, ProxyAllocator, ProxyCapability, ProxyError, ProxyLimits, ProxySummary,
};
use phoneconnect_native::session_client::{SessionClient, SessionPath};
use phoneconnect_transport::{
    ConnectedPath, Epoch, HolePunchError, IdentityKey, PathConfig, PathError, PathKind,
    RelayChannel, RelayError, RelayOnlyPath, TicketRole,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

const DEVICE: &str = "dev_native";
const STREAM: &str = "adb";
const CLIENT_NONCE: &str = "client-nonce";
const DEVICE_NONCE: &str = "device-nonce";

// --------------------------------------------------------------------------------------
// In-process relay: two ends, each writing what the other reads.
// --------------------------------------------------------------------------------------

struct RelayEnd {
    inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    outbound: mpsc::Sender<Vec<u8>>,
}

impl RelayEnd {
    fn pair(capacity: usize) -> (Arc<Self>, Arc<Self>) {
        let (client_to_device, device_inbound) = mpsc::channel(capacity);
        let (device_to_client, client_inbound) = mpsc::channel(capacity);
        let client = Arc::new(Self {
            inbound: tokio::sync::Mutex::new(client_inbound),
            outbound: client_to_device,
        });
        let device = Arc::new(Self {
            inbound: tokio::sync::Mutex::new(device_inbound),
            outbound: device_to_client,
        });
        (client, device)
    }
}

#[async_trait]
impl RelayChannel for RelayEnd {
    async fn send_frame(&self, frame: &[u8]) -> Result<(), RelayError> {
        self.outbound
            .send(frame.to_vec())
            .await
            .map_err(|_| RelayError::Closed {
                reason: "peer is gone".to_owned(),
            })
    }

    async fn recv_frame(&self) -> Result<Vec<u8>, RelayError> {
        self.inbound
            .lock()
            .await
            .recv()
            .await
            .ok_or(RelayError::Closed {
                reason: "peer is gone".to_owned(),
            })
    }

    async fn close(&self) -> Result<(), RelayError> {
        Ok(())
    }

    fn latency(&self) -> Option<Duration> {
        Some(Duration::from_millis(5))
    }
}

/// A relay that refuses every send, so a failed send must be reported rather than hidden.
struct RefusingRelay;

#[async_trait]
impl RelayChannel for RefusingRelay {
    async fn send_frame(&self, _frame: &[u8]) -> Result<(), RelayError> {
        Err(RelayError::Closed {
            reason: "relay closed the transport".to_owned(),
        })
    }

    async fn recv_frame(&self) -> Result<Vec<u8>, RelayError> {
        std::future::pending().await
    }

    async fn close(&self) -> Result<(), RelayError> {
        Ok(())
    }
}

/// A relay that stalls on the first send, counting attempts so the test can see how much the
/// proxy buffered while the transport was blocked.
struct StalledRelay {
    attempts: AtomicUsize,
}

#[async_trait]
impl RelayChannel for StalledRelay {
    async fn send_frame(&self, _frame: &[u8]) -> Result<(), RelayError> {
        self.attempts.fetch_add(1, Ordering::SeqCst);
        std::future::pending().await
    }

    async fn recv_frame(&self) -> Result<Vec<u8>, RelayError> {
        std::future::pending().await
    }

    async fn close(&self) -> Result<(), RelayError> {
        Ok(())
    }
}

// --------------------------------------------------------------------------------------
// Session fixtures.
// --------------------------------------------------------------------------------------

struct RelaySession {
    client: SessionPath,
    device: Arc<ConnectedPath>,
}

fn session_id(name: &str) -> SessionId {
    SessionId::new(format!("sess_{name}")).expect("valid session id")
}

fn epoch() -> Epoch {
    Epoch::new(CLIENT_NONCE, DEVICE_NONCE).expect("epoch")
}

fn relay_session(name: &str) -> RelaySession {
    let client_identity = IdentityKey::generate().expect("client identity");
    let device_identity = IdentityKey::generate().expect("device identity");
    let session = session_id(name);
    let (client_relay, device_relay) = RelayEnd::pair(8);

    let client = SessionClient::new()
        .connect_relay_only(RelayOnlyPath {
            relay: client_relay,
            identity: &client_identity,
            peer_identity: device_identity.public_key(),
            session_id: session.as_str(),
            device_id: DEVICE,
            role: TicketRole::Client,
            epoch: &epoch(),
            config: PathConfig::default(),
        })
        .expect("relay session");
    let device = Arc::new(
        ConnectedPath::relay_only(RelayOnlyPath {
            relay: device_relay,
            identity: &device_identity,
            peer_identity: client_identity.public_key(),
            session_id: session.as_str(),
            device_id: DEVICE,
            role: TicketRole::Device,
            epoch: &epoch(),
            config: PathConfig::default(),
        })
        .expect("device stub path"),
    );
    RelaySession { client, device }
}

fn refusing_session(name: &str) -> SessionPath {
    let identity = IdentityKey::generate().expect("identity");
    let peer = IdentityKey::generate().expect("peer identity");
    SessionClient::new()
        .connect_relay_only(RelayOnlyPath {
            relay: Arc::new(RefusingRelay),
            identity: &identity,
            peer_identity: peer.public_key(),
            session_id: session_id(name).as_str(),
            device_id: DEVICE,
            role: TicketRole::Client,
            epoch: &epoch(),
            config: PathConfig::default(),
        })
        .expect("refusing session")
}

fn stalled_session(name: &str) -> (SessionPath, Arc<StalledRelay>) {
    let identity = IdentityKey::generate().expect("identity");
    let peer = IdentityKey::generate().expect("peer identity");
    let relay = Arc::new(StalledRelay {
        attempts: AtomicUsize::new(0),
    });
    let session = SessionClient::new()
        .connect_relay_only(RelayOnlyPath {
            relay: Arc::clone(&relay) as Arc<dyn RelayChannel>,
            identity: &identity,
            peer_identity: peer.public_key(),
            session_id: session_id(name).as_str(),
            device_id: DEVICE,
            role: TicketRole::Client,
            epoch: &epoch(),
            config: PathConfig::default(),
        })
        .expect("stalled session");
    (session, relay)
}

/// The device-side stub: every proxy envelope is echoed with its request id intact, which is
/// all an ADB byte bridge has to do once the Android side lands.
fn spawn_echo(
    device: Arc<ConnectedPath>,
) -> (JoinHandle<()>, Arc<std::sync::Mutex<Vec<Envelope>>>) {
    let seen: Arc<std::sync::Mutex<Vec<Envelope>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let handle = tokio::spawn(async move {
        loop {
            match device.recv_frame().await {
                Ok(envelope) => {
                    recorded
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner())
                        .push(envelope.clone());
                    let request = RequestId::new(envelope.request_id.clone())
                        .expect("the request id the peer used is valid");
                    let mut reply = Envelope::new(
                        StreamKind::Proxy,
                        &DeviceId::new(envelope.device_id.clone()).expect("device id"),
                        &SessionId::new(envelope.session_id.clone()).expect("session id"),
                        &request,
                    );
                    reply.deadline_unix_ms = envelope.deadline_unix_ms;
                    reply.payload = envelope.payload.clone();
                    if device.send_frame(&reply).await.is_err() {
                        return;
                    }
                }
                // The relay is silent between requests; that is not a failure.
                Err(PathError::HolePunch(HolePunchError::ReceiveTimeout))
                | Err(PathError::FramesLost { .. }) => continue,
                Err(_) => return,
            }
        }
    });
    (handle, seen)
}

fn limits() -> ProxyLimits {
    ProxyLimits {
        max_chunk_bytes: 16 * 1024,
        send_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(10),
        frame_deadline: Duration::from_secs(10),
    }
}

fn capability(ttl: Duration) -> ProxyCapability {
    ProxyCapability::new(STREAM, Instant::now() + ttl).expect("valid capability")
}

fn port_of(endpoint: &LocalEndpoint) -> u16 {
    endpoint
        .url
        .rsplit(':')
        .next()
        .expect("endpoint URL has a port")
        .parse()
        .expect("endpoint URL port is numeric")
}

/// Binds one endpoint and serves one local connection over `session`.
async fn serve_one(
    allocator: Arc<ProxyAllocator>,
    session: SessionPath,
    limits: ProxyLimits,
) -> (JoinHandle<Result<ProxySummary, ProxyError>>, LocalEndpoint) {
    let endpoint = allocator
        .bind(DEVICE, capability(Duration::from_secs(30)))
        .await
        .expect("bind");
    let proxy = session
        .proxy_session(STREAM, limits)
        .expect("proxy session");
    let served = endpoint.clone();
    let handle = tokio::spawn(async move { allocator.serve(&served, proxy).await });
    (handle, endpoint)
}

/// Reads whatever the peer still delivered, then requires EOF or a reset within the timeout.
async fn read_until_closed(client: &mut TcpStream) {
    let mut buffer = [0u8; 4096];
    let deadline = tokio::time::Instant::now() + Duration::from_secs(2);
    loop {
        match tokio::time::timeout_at(deadline, client.read(&mut buffer)).await {
            Ok(Ok(0)) => return,
            Ok(Ok(_)) => continue,
            Ok(Err(error)) if error.kind() == std::io::ErrorKind::ConnectionReset => return,
            other => panic!("expected the proxy connection to close, got {other:?}"),
        }
    }
}

fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}

// --------------------------------------------------------------------------------------
// Allocation.
// --------------------------------------------------------------------------------------

#[tokio::test]
async fn an_endpoint_is_loopback_only_and_uses_an_unused_ephemeral_port() {
    let allocator = ProxyAllocator::new();
    let endpoint = allocator
        .bind(DEVICE, capability(Duration::from_secs(60)))
        .await
        .expect("bind");

    assert_eq!(endpoint.device_id, DEVICE);
    assert_eq!(endpoint.stream, STREAM);
    assert!(
        endpoint.url.starts_with("http://127.0.0.1:"),
        "an endpoint is a loopback HTTP URL, got {}",
        endpoint.url
    );
    assert_ne!(port_of(&endpoint), 0, "an ephemeral port was assigned");

    let address = allocator
        .local_addr(DEVICE, STREAM)
        .await
        .expect("the bound address is reported");
    assert!(address.ip().is_loopback(), "never bound to a routable IP");
    assert_eq!(address.port(), port_of(&endpoint));

    TcpStream::connect(address).await.expect("loopback connect");
}

#[tokio::test]
async fn concurrent_binds_never_share_a_port() {
    let allocator = Arc::new(ProxyAllocator::new());
    let mut tasks = Vec::new();
    for index in 0..32 {
        let allocator = Arc::clone(&allocator);
        tasks.push(tokio::spawn(async move {
            allocator
                .bind(
                    DEVICE,
                    ProxyCapability::new(
                        format!("stream-{index}"),
                        Instant::now() + Duration::from_secs(60),
                    )
                    .expect("capability"),
                )
                .await
                .expect("bind")
        }));
    }

    let mut ports = Vec::new();
    for task in tasks {
        ports.push(port_of(&task.await.expect("bind task")));
    }
    let count = ports.len();
    ports.sort_unstable();
    ports.dedup();
    assert_eq!(ports.len(), count, "every concurrent bind got its own port");
    assert_eq!(allocator.endpoints().await.len(), 32);
}

#[tokio::test]
async fn an_already_expired_capability_never_binds() {
    let allocator = ProxyAllocator::new();
    let expired = ProxyCapability::new(STREAM, Instant::now() - Duration::from_secs(1))
        .expect("a stream identifier");
    let error = allocator
        .bind(DEVICE, expired)
        .await
        .expect_err("an expired capability must not open a port");
    assert!(
        matches!(error, ProxyError::CapabilityExpired { .. }),
        "{error:?}"
    );
    assert!(allocator.endpoints().await.is_empty());
}

#[tokio::test]
async fn binding_one_stream_twice_is_refused() {
    let allocator = ProxyAllocator::new();
    allocator
        .bind(DEVICE, capability(Duration::from_secs(60)))
        .await
        .expect("first bind");
    let error = allocator
        .bind(DEVICE, capability(Duration::from_secs(60)))
        .await
        .expect_err("a second endpoint for one stream would be ambiguous");
    assert!(
        matches!(error, ProxyError::AlreadyBound { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_non_identifier_device_or_stream_is_refused() {
    let error = ProxyCapability::new("not a stream", Instant::now() + Duration::from_secs(30))
        .expect_err("a stream name must be an identifier");
    assert!(
        matches!(error, ProxyError::InvalidStream { .. }),
        "{error:?}"
    );

    let allocator = ProxyAllocator::new();
    let error = allocator
        .bind("not a device", capability(Duration::from_secs(30)))
        .await
        .expect_err("a device id must be an identifier");
    assert!(
        matches!(error, ProxyError::InvalidDevice { .. }),
        "{error:?}"
    );
}

// --------------------------------------------------------------------------------------
// Byte carriage.
// --------------------------------------------------------------------------------------

#[tokio::test]
async fn proxy_bytes_are_preserved_in_both_directions() {
    let session = relay_session("proxy_echo");
    assert_eq!(session.client.path_kind(), PathKind::Relay);
    let (echo, seen) = spawn_echo(Arc::clone(&session.device));
    let allocator = Arc::new(ProxyAllocator::new());
    let (server, endpoint) = serve_one(Arc::clone(&allocator), session.client, limits()).await;

    let mut client = TcpStream::connect(allocator.local_addr(DEVICE, STREAM).await.unwrap())
        .await
        .expect("local client connects");
    // Every byte value across several proxy frames, so a text-only path cannot pass.
    let payload: Vec<u8> = (0..70_000u32).map(|index| (index % 251) as u8).collect();
    client.write_all(&payload).await.expect("write");
    let mut echoed = vec![0u8; payload.len()];
    tokio::time::timeout(Duration::from_secs(10), client.read_exact(&mut echoed))
        .await
        .expect("echo arrives")
        .expect("read echo");
    assert_eq!(echoed, payload, "bytes survived the proxy untouched");

    let frames = seen.lock().unwrap_or_else(|p| p.into_inner()).clone();
    assert!(frames.len() >= 4, "the payload was split into frames");
    let now = unix_ms();
    for envelope in &frames {
        assert_eq!(envelope.stream_kind, i32::from(StreamKind::Proxy));
        assert_eq!(envelope.request_id, format!("proxy-{STREAM}"));
        assert!(
            envelope.deadline_unix_ms > now,
            "every proxy frame carries a live deadline, got {}",
            envelope.deadline_unix_ms
        );
        assert!(envelope.payload.len() <= limits().max_chunk_bytes);
    }
    assert_eq!(endpoint.stream, STREAM);

    drop(client);
    let summary = server.await.expect("session task").expect("clean close");
    assert_eq!(summary.path_kind, PathKind::Relay);
    assert_eq!(summary.bytes_up, payload.len() as u64);
    assert_eq!(summary.bytes_down, payload.len() as u64);
    echo.abort();
}

#[tokio::test]
async fn a_frame_for_another_stream_closes_the_session() {
    // The peer answers with the wrong request id: the session must not deliver those bytes
    // to the local client, because they belong to another mapped stream.
    let session = relay_session("proxy_wrong_stream");
    let device = Arc::clone(&session.device);
    let misdirected = tokio::spawn(async move {
        if let Ok(_envelope) = device.recv_frame().await {
            let request = RequestId::new("proxy-other").expect("request id");
            let mut reply = Envelope::new(
                StreamKind::Proxy,
                &DeviceId::new(DEVICE).expect("device id"),
                &session_id("proxy_wrong_stream"),
                &request,
            );
            reply.payload = b"not for you".to_vec();
            let _ = device.send_frame(&reply).await;
        }
    });
    let allocator = Arc::new(ProxyAllocator::new());
    let (server, _endpoint) = serve_one(Arc::clone(&allocator), session.client, limits()).await;

    let mut client = TcpStream::connect(allocator.local_addr(DEVICE, STREAM).await.unwrap())
        .await
        .expect("local client connects");
    client.write_all(b"hello").await.expect("write");
    read_until_closed(&mut client).await;

    let error = server
        .await
        .expect("session task")
        .expect_err("wrong stream is refused");
    assert!(
        matches!(error, ProxyError::UnexpectedFrame { .. }),
        "{error:?}"
    );
    misdirected.abort();
}

// --------------------------------------------------------------------------------------
// Deadlines, failure, expiry, and backpressure.
// --------------------------------------------------------------------------------------

#[tokio::test]
async fn a_failed_send_is_reported_and_closes_the_local_connection() {
    let allocator = Arc::new(ProxyAllocator::new());
    let (server, _endpoint) = serve_one(
        Arc::clone(&allocator),
        refusing_session("proxy_refused"),
        limits(),
    )
    .await;

    let mut client = TcpStream::connect(allocator.local_addr(DEVICE, STREAM).await.unwrap())
        .await
        .expect("local client connects");
    client.write_all(b"ping").await.expect("write");

    let error = server
        .await
        .expect("session task")
        .expect_err("a refused send is never reported as delivery");
    assert!(
        matches!(error, ProxyError::Transport { .. }),
        "the transport failure is surfaced, got {error:?}"
    );
    read_until_closed(&mut client).await;
}

#[tokio::test]
async fn a_stalled_transport_applies_backpressure_instead_of_buffering() {
    let (session, relay) = stalled_session("proxy_stalled");
    let allocator = Arc::new(ProxyAllocator::new());
    let (server, _endpoint) = serve_one(Arc::clone(&allocator), session, limits()).await;

    let mut client = TcpStream::connect(allocator.local_addr(DEVICE, STREAM).await.unwrap())
        .await
        .expect("local client connects");
    let writer = tokio::spawn(async move {
        let payload = vec![0x5au8; 1 << 20];
        let _ = client.write_all(&payload).await;
        client
    });

    tokio::time::sleep(Duration::from_millis(250)).await;
    let attempts = relay.attempts.load(Ordering::SeqCst);
    assert_eq!(
        attempts, 1,
        "only the chunk in flight may reach a stalled transport"
    );

    writer.abort();
    server.abort();
}

#[tokio::test]
async fn an_expired_capability_closes_the_endpoint_immediately() {
    let ttl = Duration::from_millis(150);
    let session = relay_session("proxy_expiry");
    let (echo, _seen) = spawn_echo(Arc::clone(&session.device));
    let allocator = Arc::new(ProxyAllocator::new());
    let endpoint = allocator.bind(DEVICE, capability(ttl)).await.expect("bind");
    let proxy = session
        .client
        .proxy_session(STREAM, limits())
        .expect("proxy session");
    let served = endpoint.clone();
    let allocator_for_task = Arc::clone(&allocator);
    let server = tokio::spawn(async move { allocator_for_task.serve(&served, proxy).await });

    let mut client = TcpStream::connect(allocator.local_addr(DEVICE, STREAM).await.unwrap())
        .await
        .expect("local client connects");
    client.write_all(b"hello").await.expect("write");

    let error = server
        .await
        .expect("session task")
        .expect_err("expiry ends the session");
    assert!(
        matches!(error, ProxyError::CapabilityExpired { .. }),
        "{error:?}"
    );
    read_until_closed(&mut client).await;

    assert!(
        allocator.endpoints().await.is_empty(),
        "an expired endpoint is no longer exposed"
    );
    let second = allocator
        .serve(
            &endpoint,
            session
                .client
                .proxy_session(STREAM, limits())
                .expect("proxy session"),
        )
        .await
        .expect_err("an expired endpoint cannot be served again");
    assert!(
        matches!(second, ProxyError::UnknownEndpoint { .. }),
        "{second:?}"
    );
    echo.abort();
}

#[tokio::test]
async fn an_idle_connection_is_closed_at_the_idle_deadline() {
    let session = relay_session("proxy_idle");
    let allocator = Arc::new(ProxyAllocator::new());
    let idle = Duration::from_millis(150);
    let (server, _endpoint) = serve_one(
        Arc::clone(&allocator),
        session.client,
        ProxyLimits {
            idle_timeout: idle,
            ..limits()
        },
    )
    .await;

    let mut client = TcpStream::connect(allocator.local_addr(DEVICE, STREAM).await.unwrap())
        .await
        .expect("local client connects");
    let started = Instant::now();
    let error = server.await.expect("session task").expect_err("idle ends");
    assert!(matches!(error, ProxyError::Idle { .. }), "{error:?}");
    assert!(started.elapsed() >= idle, "the deadline was honoured");
    read_until_closed(&mut client).await;
}

#[tokio::test]
async fn one_path_carries_one_proxy_stream_at_a_time() {
    let session = relay_session("proxy_claim");
    let first = session
        .client
        .proxy_session(STREAM, limits())
        .expect("first proxy session");
    let error = session
        .client
        .proxy_session(STREAM, limits())
        .expect_err("a second pump would interleave bytes");
    assert!(matches!(error, ProxyError::StreamInUse { .. }), "{error:?}");
    drop(first);
    session
        .client
        .proxy_session(STREAM, limits())
        .expect("the claim is released when the pump ends");
}

#[tokio::test]
async fn an_oversized_chunk_limit_is_refused_before_the_endpoint_exists() {
    let session = relay_session("proxy_limits");
    let error = session
        .client
        .proxy_session(
            STREAM,
            ProxyLimits {
                max_chunk_bytes: usize::MAX,
                ..limits()
            },
        )
        .expect_err("an unbounded chunk cannot be sealed");
    assert!(
        matches!(error, ProxyError::InvalidLimits { .. }),
        "{error:?}"
    );
}
