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
    EndpointError, EndpointManager, OpenEndpointRequest, SessionAccess,
};
use phoneconnect_native::proxy::ProxyLimits;
use phoneconnect_transport::IdentityKey;
use phoneconnect_transport::Ticket;
use support::{DEVICE, EchoMode, addr_of, relay_session, session_id, spawn_echo};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

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
    let manager = EndpointManager::new(
        IdentityKey::generate().expect("identity"),
        ProxyLimits::default(),
    );
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
    let manager = EndpointManager::new(
        IdentityKey::generate().expect("identity"),
        ProxyLimits::default(),
    );
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
    let manager = EndpointManager::new(
        IdentityKey::generate().expect("identity"),
        ProxyLimits::default(),
    );
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
    let manager = EndpointManager::new(
        IdentityKey::generate().expect("identity"),
        ProxyLimits::default(),
    );
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
    let manager = EndpointManager::new(
        IdentityKey::generate().expect("identity"),
        ProxyLimits::default(),
    );
    let ticket = Ticket {
        session_id: "sess_other_device".to_owned(),
        device_id: "dev_someone_else".to_owned(),
        role: phoneconnect_transport::TicketRole::Client,
        nonce: "nonce".to_owned(),
        probe_key: "probe".to_owned(),
        own_identity_key: "own".to_owned(),
        peer_identity_key: "peer".to_owned(),
        expires_at: i64::MAX,
        signature: "signature".to_owned(),
    };
    let mut request = request("adb", 30, "sess_other_device");
    request.session = SessionAccess::Rendezvous {
        capability: "capability".to_owned(),
        ticket: Box::new(ticket),
        candidates: Box::new(phoneconnect_transport::RendezvousCandidates {
            session_id: "sess_other_device".to_owned(),
            expires_at: i64::MAX,
            verification_key: String::new(),
            peer_nonce: Some("peer-nonce".to_owned()),
            candidates: Vec::new(),
        }),
    };
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
    let manager = EndpointManager::new(
        IdentityKey::generate().expect("identity"),
        ProxyLimits::default(),
    );
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
    let manager = EndpointManager::new(
        IdentityKey::generate().expect("identity"),
        ProxyLimits::default(),
    );
    assert!(!manager.close(DEVICE, "adb").await);
}

#[tokio::test]
async fn an_invalid_stream_or_zero_ttl_is_refused() {
    let session = relay_session("endpoint_invalid");
    let manager = EndpointManager::new(
        IdentityKey::generate().expect("identity"),
        ProxyLimits::default(),
    );
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
