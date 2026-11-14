//! Endpoint lifecycle through the shell's endpoint API.
//!
//! `EndpointManager` is the body of the `open_endpoint`/`close_endpoint`/`local_endpoints`
//! Tauri commands, so these tests exercise the command-level path without a webview: a
//! session is adopted (as a negotiated session would be), an endpoint is opened through the
//! manager, it is reachable on 127.0.0.1, carries bytes to the device stub, and disappears
//! from `endpoints()` when closed or expired.

mod support;

use std::sync::Arc;
use std::time::Duration;

use phoneconnect_native::endpoints::{
    EndpointError, EndpointManager, EndpointPolicy, OpenEndpointRequest, SessionAccess,
};
use phoneconnect_native::proxy::ProxyLimits;
use phoneconnect_native::trust::{PIN_FILE_NAME, TicketTrust, TrustError};
use phoneconnect_transport::IdentityKey;
use phoneconnect_transport::candidates::WireCandidate;
use phoneconnect_transport::{CandidateKind, RendezvousCandidates};
use support::{DEVICE, EchoMode, addr_of, relay_session, session_id, spawn_echo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

const SERVER: &str = "http://127.0.0.1:8080";

fn manager() -> EndpointManager {
    EndpointManager::new(
        IdentityKey::generate().expect("identity"),
        ProxyLimits::default(),
        EndpointPolicy::new(url::Url::parse(SERVER).expect("server URL")),
        None,
    )
}

fn rendezvous(
    ticket: phoneconnect_transport::Ticket,
    candidates: RendezvousCandidates,
) -> OpenEndpointRequest {
    OpenEndpointRequest {
        device_id: DEVICE.to_owned(),
        stream: "adb".to_owned(),
        ttl_seconds: 30,
        session: SessionAccess::Rendezvous {
            capability: "capability".to_owned(),
            ticket: Box::new(ticket),
            candidates: Box::new(candidates),
        },
    }
}

fn ticket(device_id: &str, session: &str) -> phoneconnect_transport::Ticket {
    phoneconnect_transport::Ticket {
        session_id: session.to_owned(),
        device_id: device_id.to_owned(),
        role: phoneconnect_transport::TicketRole::Client,
        nonce: "nonce".to_owned(),
        probe_key: "probe".to_owned(),
        own_identity_key: "own".to_owned(),
        peer_identity_key: "peer".to_owned(),
        expires_at: i64::MAX,
        signature: "signature".to_owned(),
    }
}

fn candidates(relay: &str, verification_key: &str, direct: Option<&str>) -> RendezvousCandidates {
    let mut entries = vec![WireCandidate {
        kind: CandidateKind::Relay,
        endpoint: relay.to_owned(),
        priority: 100,
    }];
    if let Some(endpoint) = direct {
        entries.push(WireCandidate {
            kind: CandidateKind::ServerObserved,
            endpoint: endpoint.to_owned(),
            priority: 150,
        });
    }
    RendezvousCandidates {
        session_id: "sess_rendezvous".to_owned(),
        expires_at: i64::MAX,
        verification_key: verification_key.to_owned(),
        peer_nonce: Some("peer-nonce".to_owned()),
        candidates: entries,
    }
}

fn request(stream: &str, ttl_seconds: u64, session: &str) -> OpenEndpointRequest {
    OpenEndpointRequest {
        device_id: DEVICE.to_owned(),
        stream: stream.to_owned(),
        ttl_seconds,
        session: SessionAccess::Established {
            session_id: session.to_owned(),
        },
    }
}

#[tokio::test]
async fn an_opened_endpoint_is_reachable_and_carries_bytes() {
    let session = relay_session("endpoint_open");
    let (echo, _seen) = spawn_echo(Arc::clone(&session.device), EchoMode::Plain);
    let manager = manager();
    let session_key = session_id("endpoint_open");
    manager
        .adopt(DEVICE, session.client)
        .await
        .expect("adopt the session");

    let endpoint = manager
        .open(request("adb", 30, session_key.as_str()))
        .await
        .expect("open an endpoint through the shell API");
    assert_eq!(endpoint.device_id, DEVICE);
    assert_eq!(endpoint.stream, "adb");
    assert!(endpoint.url.starts_with("http://127.0.0.1:"));
    assert_eq!(manager.endpoints().await, vec![endpoint.clone()]);

    let mut client = TcpStream::connect(addr_of(&endpoint))
        .await
        .expect("the endpoint is reachable on loopback");
    client
        .write_all(b"through the shell API")
        .await
        .expect("write");
    let mut echoed = vec![0u8; "through the shell API".len()];
    tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echoed))
        .await
        .expect("echo arrives")
        .expect("read echo");
    assert_eq!(echoed, b"through the shell API");

    assert!(manager.close(DEVICE, "adb").await, "the endpoint was live");
    assert!(
        manager.endpoints().await.is_empty(),
        "closed endpoints disappear"
    );
    let mut closed = client;
    let mut buffer = [0u8; 1];
    let _ = tokio::time::timeout(Duration::from_secs(2), closed.read(&mut buffer)).await;
    assert!(
        TcpStream::connect(addr_of(&endpoint)).await.is_err(),
        "a closed endpoint refuses new connections"
    );
    echo.abort();
}

#[tokio::test]
async fn one_session_serves_two_endpoints_at_once() {
    let session = relay_session("endpoint_two");
    let (echo, _seen) = spawn_echo(Arc::clone(&session.device), EchoMode::Plain);
    let manager = manager();
    let session_key = session_id("endpoint_two");
    manager
        .adopt(DEVICE, session.client)
        .await
        .expect("adopt the session");

    let adb = manager
        .open(request("adb", 30, session_key.as_str()))
        .await
        .expect("first endpoint");
    let screen = manager
        .open(request("screen", 30, session_key.as_str()))
        .await
        .expect("second endpoint on the same device");
    assert_ne!(adb.url, screen.url);
    assert_eq!(manager.endpoints().await.len(), 2);

    for (endpoint, payload) in [(&adb, b"adb bytes".as_slice()), (&screen, b"screen bytes")] {
        let mut client = TcpStream::connect(addr_of(endpoint))
            .await
            .expect("connect");
        client.write_all(payload).await.expect("write");
        let mut echoed = vec![0u8; payload.len()];
        tokio::time::timeout(Duration::from_secs(5), client.read_exact(&mut echoed))
            .await
            .expect("echo arrives")
            .expect("read echo");
        assert_eq!(echoed, payload);
    }

    assert!(manager.close(DEVICE, "adb").await);
    assert!(manager.close(DEVICE, "screen").await);
    assert!(manager.endpoints().await.is_empty());
    echo.abort();
}

#[tokio::test]
async fn an_expired_endpoint_disappears_from_the_list() {
    let session = relay_session("endpoint_expiry");
    let manager = manager();
    let session_key = session_id("endpoint_expiry");
    manager
        .adopt(DEVICE, session.client)
        .await
        .expect("adopt the session");

    let endpoint = manager
        .open(request("adb", 1, session_key.as_str()))
        .await
        .expect("open");
    assert_eq!(manager.endpoints().await.len(), 1);

    tokio::time::sleep(Duration::from_millis(1200)).await;
    assert!(
        manager.endpoints().await.is_empty(),
        "an expired capability is no longer listed"
    );
    assert!(
        TcpStream::connect(addr_of(&endpoint)).await.is_err(),
        "an expired endpoint refuses new connections"
    );
    assert!(
        !manager.close(DEVICE, "adb").await,
        "expiry already removed it"
    );
}

#[tokio::test]
async fn a_request_without_an_adopted_session_is_refused() {
    let manager = manager();
    let error = manager
        .open(request("adb", 30, "sess_never_adopted"))
        .await
        .expect_err("no session means no endpoint");
    assert!(
        matches!(
            error,
            phoneconnect_native::endpoints::EndpointError::SessionNotFound { .. }
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn a_request_for_another_device_is_refused_before_any_network_work() {
    let manager = manager();
    let request = rendezvous(
        ticket("dev_someone_else", "sess_other_device"),
        candidates("http://127.0.0.1:8080/api/sessions", "key", None),
    );
    let error = manager
        .open(request)
        .await
        .expect_err("a ticket for another device must not open an endpoint here");
    assert!(
        matches!(error, EndpointError::DeviceMismatch { .. }),
        "{error:?}"
    );
}

#[tokio::test]
async fn an_endpoint_on_a_closed_session_is_refused() {
    let session = relay_session("endpoint_closed");
    session.client.shutdown().await.expect("shut the path down");
    let manager = manager();
    let session_key = session_id("endpoint_closed");
    manager
        .adopt(DEVICE, session.client)
        .await
        .expect("adopt the session");

    let error = manager
        .open(request("adb", 30, session_key.as_str()))
        .await
        .expect_err("a dead path must not open a port");
    assert!(
        matches!(
            error,
            phoneconnect_native::endpoints::EndpointError::SessionClosed { .. }
        ),
        "{error:?}"
    );
}

#[tokio::test]
async fn closing_an_unknown_endpoint_is_false() {
    let manager = manager();
    assert!(!manager.close(DEVICE, "adb").await);
}

#[tokio::test]
async fn an_invalid_stream_or_zero_ttl_is_refused() {
    let session = relay_session("endpoint_invalid");
    let manager = manager();
    let session_key = session_id("endpoint_invalid");
    manager
        .adopt(DEVICE, session.client)
        .await
        .expect("adopt the session");

    let error = manager
        .open(request("not a stream", 30, session_key.as_str()))
        .await
        .expect_err("a stream must be an identifier");
    assert!(
        matches!(
            error,
            phoneconnect_native::endpoints::EndpointError::Proxy(_)
        ),
        "{error:?}"
    );

    let error = manager
        .open(request("adb", 0, session_key.as_str()))
        .await
        .expect_err("a zero ttl would be dead on arrival");
    assert!(
        matches!(
            error,
            phoneconnect_native::endpoints::EndpointError::InvalidLifetime
        ),
        "{error:?}"
    );
}

/// A manager with a pre-seeded trust pin, so no fetch is needed and the pin is authoritative.
fn manager_with_pin(name: &str, pin_value: &str) -> (EndpointManager, std::path::PathBuf) {
    let directory = std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-state")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("test directory");
    let pin = directory.join(PIN_FILE_NAME);
    let origin = url::Url::parse(SERVER)
        .expect("server URL")
        .origin()
        .ascii_serialization();
    std::fs::write(&pin, format!("origin: {origin}\nkey: {pin_value}\n")).expect("seed the pin");
    let server = url::Url::parse(SERVER).expect("server URL");
    let trust = Arc::new(TicketTrust::new(server.clone(), pin));
    let manager = EndpointManager::new(
        IdentityKey::generate().expect("identity"),
        ProxyLimits::default(),
        EndpointPolicy::new(server),
        Some(trust),
    );
    (manager, directory)
}

async fn wait_until_no_endpoints(manager: &EndpointManager) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(3);
    loop {
        if manager.endpoints().await.is_empty() {
            return;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "the endpoint did not disappear"
        );
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test]
async fn a_persistent_endpoint_serves_a_second_connection() {
    let session = relay_session("endpoint_reconnect");
    let (echo, _seen) = spawn_echo(Arc::clone(&session.device), EchoMode::StaleAfterReconnect);
    let manager = manager();
    let session_key = session_id("endpoint_reconnect");
    manager
        .adopt(DEVICE, session.client)
        .await
        .expect("adopt the session");
    let endpoint = manager
        .open(request("adb", 30, session_key.as_str()))
        .await
        .expect("open");

    let mut first = TcpStream::connect(addr_of(&endpoint))
        .await
        .expect("first connection");
    first.write_all(b"first connection").await.expect("write");
    let mut first_echo = vec![0u8; b"first connection".len()];
    tokio::time::timeout(Duration::from_secs(5), first.read_exact(&mut first_echo))
        .await
        .expect("first echo arrives")
        .expect("read the first echo");
    assert_eq!(first_echo, b"first connection");
    drop(first);

    // The port stays open. The device emits a frame for the closed connection's request id
    // before answering this one; it must not enter this tunnel.
    let mut second = TcpStream::connect(addr_of(&endpoint))
        .await
        .expect("second connection");
    second.write_all(b"second connection").await.expect("write");
    let mut second_echo = vec![0u8; b"second connection".len()];
    tokio::time::timeout(Duration::from_secs(5), second.read_exact(&mut second_echo))
        .await
        .expect("second echo arrives")
        .expect("read the second echo");
    assert_eq!(
        second_echo, b"second connection",
        "a stale frame for the closed connection must not be delivered"
    );

    assert!(manager.close(DEVICE, "adb").await);
    echo.abort();
}

#[tokio::test]
async fn a_dead_session_is_not_reused_for_a_new_endpoint() {
    let session = relay_session("endpoint_dead");
    let manager = manager();
    let session_key = session_id("endpoint_dead");
    manager
        .adopt(DEVICE, session.client)
        .await
        .expect("adopt the session");
    let endpoint = manager
        .open(request("adb", 30, session_key.as_str()))
        .await
        .expect("open");
    assert_eq!(manager.endpoints().await, vec![endpoint.clone()]);

    // Kill the transport from the device side: the hub reader sees the relay close.
    drop(session.device);
    wait_until_no_endpoints(&manager).await;

    let error = manager
        .open(request("adb", 30, session_key.as_str()))
        .await
        .expect_err("a dead session must not hand back a bound port");
    assert!(
        matches!(error, EndpointError::SessionClosed { .. }),
        "{error:?}"
    );
    assert!(
        manager.endpoints().await.is_empty(),
        "no bound-but-dead endpoint is left"
    );
}

#[tokio::test]
async fn a_relay_outside_the_configured_origin_is_refused_through_open() {
    let (manager, directory) = manager_with_pin("endpoint-origin", "key");
    let request = rendezvous(
        ticket(DEVICE, "sess_rendezvous"),
        candidates("http://evil.example/api/sessions", "key", None),
    );
    let error = manager
        .open(request)
        .await
        .expect_err("the shell must not dial another origin");
    assert!(
        matches!(error, EndpointError::RelayOriginOutsideServer { .. }),
        "{error:?}"
    );
    assert!(manager.endpoints().await.is_empty());
    std::fs::remove_dir_all(&directory).ok();
}

#[tokio::test]
async fn a_page_chosen_verification_key_is_refused_by_the_pin() {
    let (manager, directory) = manager_with_pin("endpoint-pin", "pinned-key");
    let pin = directory.join(PIN_FILE_NAME);
    let relay = format!("{SERVER}/api/sessions");
    let error = manager
        .open(rendezvous(
            ticket(DEVICE, "sess_rendezvous"),
            candidates(&relay, "page-chosen-key", None),
        ))
        .await
        .expect_err("the pinned key wins over the page");
    match error {
        EndpointError::Trust(TrustError::PinChanged { remedy, .. }) => {
            assert!(remedy.contains("approve"), "{remedy}");
        }
        other => panic!("expected a pin change, got {other:?}"),
    }
    assert!(
        manager.endpoints().await.is_empty(),
        "a refused key binds no port"
    );
    let recorded = std::fs::read_to_string(&pin).expect("pin");
    assert!(
        recorded.contains("key: pinned-key"),
        "the pin is never replaced by a page value: {recorded}"
    );
    std::fs::remove_dir_all(&directory).ok();
}
