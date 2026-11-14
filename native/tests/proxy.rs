//! Loopback proxy contract.
//!
//! Every test drives real loopback TCP sockets and a real `ConnectedPath`; the peer is a
//! device-side stub that answers `StreamKind::Proxy` envelopes, which is the shape the Android
//! agent's TCP bridge will implement. Nothing here claims an Android endpoint exists.

mod support;

use std::sync::Arc;
use std::time::{Duration, Instant};

use phoneconnect_native::proxy::{
    LocalEndpoint, ProxyAllocator, ProxyCapability, ProxyError, ProxyLimits,
};
use phoneconnect_native::session_client::SessionPath;
use phoneconnect_transport::PathKind;
use support::{
    DEVICE, EchoMode, RelaySession, addr_of, limits, port_of, refusing_session, relay_session,
    spawn_echo, stalled_session,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio::task::JoinHandle;

fn capability(stream: &str, ttl: Duration) -> ProxyCapability {
    ProxyCapability::new(stream, Instant::now() + ttl).expect("valid capability")
}

async fn bind(allocator: &ProxyAllocator, stream: &str) -> LocalEndpoint {
    allocator
        .bind(DEVICE, capability(stream, Duration::from_secs(30)))
        .await
        .expect("bind")
}

/// Binds one endpoint and serves one local connection over `session`.
async fn serve_one(
    allocator: Arc<ProxyAllocator>,
    session: &SessionPath,
    stream: &str,
    limits: ProxyLimits,
) -> (
    JoinHandle<Result<phoneconnect_native::proxy::ProxySummary, ProxyError>>,
    LocalEndpoint,
) {
    let endpoint = bind(&allocator, stream).await;
    let proxy = session
        .proxy_session(stream, limits)
        .await
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

async fn echo_reply(client: &mut TcpStream, payload: &[u8], expected: &[u8], timeout: Duration) {
    client.write_all(payload).await.expect("write");
    let mut echoed = vec![0u8; expected.len()];
    tokio::time::timeout(timeout, client.read_exact(&mut echoed))
        .await
        .expect("echo arrives")
        .expect("read echo");
    assert_eq!(echoed, expected, "bytes survived the proxy untouched");
}

// --------------------------------------------------------------------------------------
// Allocation.
// --------------------------------------------------------------------------------------

#[tokio::test]
async fn an_endpoint_is_loopback_only_and_uses_an_unused_ephemeral_port() {
    let allocator = ProxyAllocator::new();
    let endpoint = allocator
        .bind(DEVICE, capability("adb", Duration::from_secs(60)))
        .await
        .expect("bind");

    assert_eq!(endpoint.device_id, DEVICE);
    assert_eq!(endpoint.stream, "adb");
    assert!(
        endpoint.url.starts_with("http://127.0.0.1:"),
        "an endpoint is a loopback HTTP URL, got {}",
        endpoint.url
    );
    assert_ne!(port_of(&endpoint), 0, "an ephemeral port was assigned");

    let address = allocator
        .local_addr(DEVICE, "adb")
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
async fn binding_one_stream_twice_is_refused() {
    let allocator = ProxyAllocator::new();
    bind(&allocator, "adb").await;
    let error = allocator
        .bind(DEVICE, capability("adb", Duration::from_secs(60)))
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
        .bind("not a device", capability("adb", Duration::from_secs(30)))
        .await
        .expect_err("a device id must be an identifier");
    assert!(
        matches!(error, ProxyError::InvalidDevice { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn an_already_expired_capability_never_binds() {
    let allocator = ProxyAllocator::new();
    let expired = ProxyCapability::new("adb", Instant::now() - Duration::from_secs(1))
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

// --------------------------------------------------------------------------------------
// Byte carriage and demultiplexing.
// --------------------------------------------------------------------------------------

#[tokio::test]
async fn proxy_bytes_are_preserved_in_both_directions() {
    let session = relay_session("proxy_echo");
    assert_eq!(session.client.path_kind(), PathKind::Relay);
    let (echo, seen) = spawn_echo(Arc::clone(&session.device), EchoMode::Plain);
    let allocator = Arc::new(ProxyAllocator::new());
    let (server, _endpoint) =
        serve_one(Arc::clone(&allocator), &session.client, "adb", limits()).await;

    let bound = allocator.endpoints().await;
    let mut client = TcpStream::connect(addr_of(&bound[0]))
        .await
        .expect("local client connects");
    // Every byte value across several proxy frames, so a text-only path cannot pass.
    let payload: Vec<u8> = (0..70_000u32).map(|index| (index % 251) as u8).collect();
    echo_reply(&mut client, &payload, &payload, Duration::from_secs(10)).await;

    let frames = seen.lock().unwrap_or_else(|p| p.into_inner()).clone();
    assert!(frames.len() >= 4, "the payload was split into frames");
    for (index, envelope) in frames.iter().enumerate() {
        assert_eq!(
            envelope.sequence,
            (index + 1) as u32,
            "every proxy frame carries a per-stream sequence"
        );
        assert!(
            envelope.deadline_unix_ms > support::unix_ms(),
            "every proxy frame carries a live deadline"
        );
        assert!(envelope.payload.len() <= 16 * 1024);
    }

    drop(client);
    let summary = server.await.expect("session task").expect("clean close");
    assert_eq!(summary.path_kind, PathKind::Relay);
    assert_eq!(summary.bytes_up, payload.len() as u64);
    assert_eq!(summary.bytes_down, payload.len() as u64);
    echo.abort();
}

#[tokio::test]
async fn two_streams_on_one_path_both_carry_bytes() {
    let session = relay_session("proxy_two_streams");
    let (echo, _seen) = spawn_echo(Arc::clone(&session.device), EchoMode::Plain);
    let allocator = Arc::new(ProxyAllocator::new());
    let (first, first_endpoint) =
        serve_one(Arc::clone(&allocator), &session.client, "adb", limits()).await;
    let (second, second_endpoint) =
        serve_one(Arc::clone(&allocator), &session.client, "screen", limits()).await;
    assert_ne!(first_endpoint.url, second_endpoint.url);

    let mut first_client = TcpStream::connect(addr_of(&first_endpoint))
        .await
        .expect("first client");
    let mut second_client = TcpStream::connect(addr_of(&second_endpoint))
        .await
        .expect("second client");
    echo_reply(
        &mut first_client,
        b"first stream",
        b"first stream",
        Duration::from_secs(5),
    )
    .await;
    echo_reply(
        &mut second_client,
        b"second stream",
        b"second stream",
        Duration::from_secs(5),
    )
    .await;

    drop(first_client);
    drop(second_client);
    first.await.expect("first task").expect("first clean close");
    second
        .await
        .expect("second task")
        .expect("second clean close");
    echo.abort();
}

#[tokio::test]
async fn an_interleaved_events_frame_does_not_disturb_the_tunnel() {
    let session = relay_session("proxy_events");
    let (echo, _seen) = spawn_echo(Arc::clone(&session.device), EchoMode::WithEvents);
    let allocator = Arc::new(ProxyAllocator::new());
    let (server, endpoint) =
        serve_one(Arc::clone(&allocator), &session.client, "adb", limits()).await;

    let mut client = TcpStream::connect(addr_of(&endpoint))
        .await
        .expect("local client connects");
    echo_reply(
        &mut client,
        b"survives an events frame",
        b"survives an events frame",
        Duration::from_secs(5),
    )
    .await;
    drop(client);
    server
        .await
        .expect("session task")
        .expect("an Events frame on the path is not a failure");
    echo.abort();
}

#[tokio::test]
async fn a_frame_for_another_stream_is_ignored() {
    let session = relay_session("proxy_foreign");
    let (echo, _seen) = spawn_echo(Arc::clone(&session.device), EchoMode::WithForeignFrame);
    let allocator = Arc::new(ProxyAllocator::new());
    let (server, endpoint) =
        serve_one(Arc::clone(&allocator), &session.client, "adb", limits()).await;

    let mut client = TcpStream::connect(addr_of(&endpoint))
        .await
        .expect("local client connects");
    // Two frames, so the stub emits the foreign request id between their echoes.
    let payload: Vec<u8> = (0..40_000u32).map(|index| (index % 241) as u8).collect();
    echo_reply(&mut client, &payload, &payload, Duration::from_secs(10)).await;
    drop(client);
    server
        .await
        .expect("session task")
        .expect("a frame for another stream must not tear this one down");
    echo.abort();
}

#[tokio::test]
async fn a_sequence_gap_closes_the_stream_with_an_explicit_error() {
    let session = relay_session("proxy_gap");
    let (echo, _seen) = spawn_echo(Arc::clone(&session.device), EchoMode::WithSequenceGap);
    let allocator = Arc::new(ProxyAllocator::new());
    let (server, endpoint) =
        serve_one(Arc::clone(&allocator), &session.client, "adb", limits()).await;

    let mut client = TcpStream::connect(addr_of(&endpoint))
        .await
        .expect("local client connects");
    // Two frames; the stub answers the second with sequence 3, so the client sees a hole.
    let payload: Vec<u8> = (0..40_000u32).map(|index| (index % 239) as u8).collect();
    client.write_all(&payload).await.expect("write");
    read_until_closed(&mut client).await;

    let error = server
        .await
        .expect("session task")
        .expect_err("a hole is never a successful close");
    assert!(matches!(error, ProxyError::SequenceGap { .. }), "{error:?}");
    echo.abort();
}

// --------------------------------------------------------------------------------------
// Deadlines, failure, expiry, and backpressure.
// --------------------------------------------------------------------------------------

#[tokio::test]
async fn a_failed_send_is_reported_and_closes_the_local_connection() {
    let allocator = Arc::new(ProxyAllocator::new());
    let session = refusing_session("proxy_refused");
    let (server, _endpoint) = serve_one(Arc::clone(&allocator), &session, "adb", limits()).await;

    let bound = allocator.endpoints().await;
    let mut client = TcpStream::connect(addr_of(&bound[0]))
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
    let (server, _endpoint) = serve_one(Arc::clone(&allocator), &session, "adb", limits()).await;

    let bound = allocator.endpoints().await;
    let mut client = TcpStream::connect(addr_of(&bound[0]))
        .await
        .expect("local client connects");
    let writer = tokio::spawn(async move {
        let payload = vec![0x5au8; 1 << 20];
        let _ = client.write_all(&payload).await;
        client
    });

    tokio::time::sleep(Duration::from_millis(250)).await;
    let attempts = relay.attempts.load(std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        attempts, 1,
        "only the chunk in flight may reach a stalled transport"
    );

    writer.abort();
    server.abort();
}

#[tokio::test]
async fn an_expired_capability_closes_the_endpoint_immediately() {
    let session = relay_session("proxy_expiry");
    let (echo, _seen) = spawn_echo(Arc::clone(&session.device), EchoMode::Plain);
    let allocator = Arc::new(ProxyAllocator::new());
    let endpoint = allocator
        .bind(
            DEVICE,
            ProxyCapability::new("adb", Instant::now() + Duration::from_millis(150))
                .expect("capability"),
        )
        .await
        .expect("bind");
    let proxy = session
        .client
        .proxy_session("adb", limits())
        .await
        .expect("proxy session");
    let served = endpoint.clone();
    let allocator_for_task = Arc::clone(&allocator);
    let server = tokio::spawn(async move { allocator_for_task.serve(&served, proxy).await });

    let mut client = TcpStream::connect(addr_of(&endpoint))
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
                .proxy_session("adb", limits())
                .await
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
async fn uplink_activity_keeps_an_idle_tunnel_alive() {
    // No echo task: only the local upload produces activity.
    let session = relay_session("proxy_idle_uplink");
    let allocator = Arc::new(ProxyAllocator::new());
    let idle = Duration::from_millis(300);
    let (server, _endpoint) = serve_one(
        Arc::clone(&allocator),
        &session.client,
        "adb",
        ProxyLimits {
            idle_timeout: idle,
            ..limits()
        },
    )
    .await;

    let bound = allocator.endpoints().await;
    let mut client = TcpStream::connect(addr_of(&bound[0]))
        .await
        .expect("local client connects");
    let started = Instant::now();
    while started.elapsed() < Duration::from_millis(1200) {
        client
            .write_all(b"still here")
            .await
            .expect("the tunnel stays writable");
        tokio::time::sleep(Duration::from_millis(100)).await;
        assert!(
            !server.is_finished(),
            "an upload keeps the tunnel alive without inbound frames"
        );
    }

    let error = server.await.expect("session task").expect_err("idle ends");
    assert!(matches!(error, ProxyError::Idle { .. }), "{error:?}");
    assert!(
        started.elapsed() > Duration::from_millis(1200),
        "an upload every 100 ms outlived a {idle:?} idle deadline"
    );
    read_until_closed(&mut client).await;
}

#[tokio::test]
async fn a_tunnel_with_no_traffic_closes_at_the_idle_deadline() {
    let session = relay_session("proxy_idle_silent");
    let allocator = Arc::new(ProxyAllocator::new());
    let idle = Duration::from_millis(150);
    let (server, _endpoint) = serve_one(
        Arc::clone(&allocator),
        &session.client,
        "adb",
        ProxyLimits {
            idle_timeout: idle,
            ..limits()
        },
    )
    .await;

    let bound = allocator.endpoints().await;
    let mut client = TcpStream::connect(addr_of(&bound[0]))
        .await
        .expect("local client connects");
    let started = Instant::now();
    let error = server.await.expect("session task").expect_err("idle ends");
    assert!(matches!(error, ProxyError::Idle { .. }), "{error:?}");
    assert!(started.elapsed() >= idle, "the deadline was honoured");
    read_until_closed(&mut client).await;
}

#[tokio::test]
async fn one_path_carries_one_pump_per_stream() {
    let session = relay_session("proxy_claim");
    let first = session
        .client
        .proxy_session("adb", limits())
        .await
        .expect("first proxy session");
    let error = session
        .client
        .proxy_session("adb", limits())
        .await
        .expect_err("a second pump for one stream would interleave bytes");
    assert!(matches!(error, ProxyError::StreamInUse { .. }), "{error:?}");
    // A different stream is a different route and is allowed.
    session
        .client
        .proxy_session("screen", limits())
        .await
        .expect("another stream");
    drop(first);
    session
        .client
        .proxy_session("adb", limits())
        .await
        .expect("the claim is released when the pump ends");
}

#[tokio::test]
async fn an_oversized_chunk_limit_is_refused_before_the_endpoint_exists() {
    let session = relay_session("proxy_limits");
    let error = session
        .client
        .proxy_session(
            "adb",
            ProxyLimits {
                max_chunk_bytes: usize::MAX,
                ..limits()
            },
        )
        .await
        .expect_err("an unbounded chunk cannot be sealed");
    assert!(
        matches!(error, ProxyError::InvalidLimits { .. }),
        "{error:?}"
    );
}

fn _relay_session_keeps_the_type(_: RelaySession) {}
