//! Trust-on-first-use contract for the ticket verification key.
//!
//! The key is read from the configured origin (a local HTTP server here stands in for the
//! server's candidates route), persisted under the shell's config directory, and compared on
//! every later open. A change is refused with a remedy; the pin is never silently replaced.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::{Arc, Mutex};
use std::time::Duration;

use phoneconnect_native::trust::{PIN_FILE_NAME, TicketTrust, TrustError};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::task::JoinHandle;
use url::Url;

/// A loopback HTTP server that answers every request with a candidates view carrying the key.
struct KeyServer {
    addr: SocketAddr,
    key: Arc<Mutex<String>>,
    task: JoinHandle<()>,
}

impl KeyServer {
    async fn start(key: &str) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
        let addr = listener.local_addr().expect("address");
        let key = Arc::new(Mutex::new(key.to_owned()));
        let served = Arc::clone(&key);
        let task = tokio::spawn(async move {
            loop {
                let Ok((mut socket, _)) = listener.accept().await else {
                    return;
                };
                let key = served
                    .lock()
                    .unwrap_or_else(|poisoned| poisoned.into_inner())
                    .clone();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    let _ = socket.read(&mut buffer).await;
                    let body = format!(r#"{{"verification_key":"{key}","peer_nonce":"n"}}"#);
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\n\
                         content-length: {}\r\nconnection: close\r\n\r\n{body}",
                        body.len()
                    );
                    let _ = socket.write_all(response.as_bytes()).await;
                });
            }
        });
        Self { addr, key, task }
    }

    fn url(&self) -> Url {
        Url::parse(&format!("http://{}", self.addr)).expect("server URL")
    }

    fn rotate(&self, key: &str) {
        *self
            .key
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner()) = key.to_owned();
    }
}

impl Drop for KeyServer {
    fn drop(&mut self) {
        self.task.abort();
    }
}

fn pin_path(name: &str) -> PathBuf {
    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-state")
        .join(format!("{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    directory.join(PIN_FILE_NAME)
}

fn read_pin(path: &PathBuf) -> String {
    std::fs::read_to_string(path)
        .expect("the pin was persisted")
        .trim()
        .to_owned()
}

#[tokio::test]
async fn the_first_open_pins_the_server_key() {
    let server = KeyServer::start("server-key").await;
    let path = pin_path("trust-pin");
    let trust = TicketTrust::new(server.url(), path.clone());

    let pinned = trust
        .pinned_key("sess_trust", "capability")
        .await
        .expect("the first open pins");
    assert_eq!(pinned, "server-key");
    assert_eq!(read_pin(&path), "server-key");
    std::fs::remove_dir_all(path.parent().expect("directory")).ok();
}

#[tokio::test]
async fn the_pin_survives_a_restart_and_is_not_refetched() {
    let server = KeyServer::start("server-key").await;
    let path = pin_path("trust-restart");
    TicketTrust::new(server.url(), path.clone())
        .pinned_key("sess_restart", "capability")
        .await
        .expect("pin");
    let address = server.url();
    drop(server);

    // The server is gone; only the stored pin can answer.
    let restarted = TicketTrust::new(address, path.clone());
    let pinned = tokio::time::timeout(
        Duration::from_secs(2),
        restarted.pinned_key("sess_restart", "capability"),
    )
    .await
    .expect("reading the pin does not wait for the network")
    .expect("the pin survives a restart");
    assert_eq!(pinned, "server-key");
    std::fs::remove_dir_all(path.parent().expect("directory")).ok();
}

#[tokio::test]
async fn a_page_key_that_differs_is_refused_with_a_remedy() {
    let server = KeyServer::start("pinned-key").await;
    let path = pin_path("trust-page-key");
    let trust = TicketTrust::new(server.url(), path.clone());
    trust
        .pinned_key("sess_page", "capability")
        .await
        .expect("pin");

    let error = trust
        .verify_supplied("page-chosen-key", "sess_page", "capability")
        .await
        .expect_err("the page cannot choose the trust anchor");
    match &error {
        TrustError::PinChanged {
            expected,
            supplied,
            detail,
            remedy,
        } => {
            assert_eq!(expected, "pinned-key");
            assert_eq!(supplied, "page-chosen-key");
            assert!(
                detail.contains("still advertises the pinned"),
                "the shell checks the server: {detail}"
            );
            assert!(remedy.contains("delete"), "{remedy}");
            assert!(remedy.contains(&path.display().to_string()), "{remedy}");
        }
        other => panic!("expected a pin change, got {other:?}"),
    }
    assert_eq!(read_pin(&path), "pinned-key", "the pin is untouched");
    std::fs::remove_dir_all(path.parent().expect("directory")).ok();
}

#[tokio::test]
async fn a_rotated_server_key_is_refused_with_the_remedy() {
    let server = KeyServer::start("old-key").await;
    let path = pin_path("trust-rotated");
    let trust = TicketTrust::new(server.url(), path.clone());
    trust
        .pinned_key("sess_rotate", "capability")
        .await
        .expect("pin");

    server.rotate("new-key");
    let error = trust
        .verify_supplied("new-key", "sess_rotate", "capability")
        .await
        .expect_err("a rotated key is never silently accepted");
    match &error {
        TrustError::PinChanged {
            expected,
            detail,
            remedy,
            ..
        } => {
            assert_eq!(expected, "old-key");
            assert!(
                detail.contains("now advertises new-key"),
                "the error names the rotation: {detail}"
            );
            assert!(remedy.contains("delete"), "{remedy}");
        }
        other => panic!("expected a pin change, got {other:?}"),
    }
    assert_eq!(read_pin(&path), "old-key", "the pin is not replaced");
    std::fs::remove_dir_all(path.parent().expect("directory")).ok();
}

#[tokio::test]
async fn an_unreachable_server_without_a_pin_fails_closed() {
    // Reserve a port, then release it so nothing is listening.
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let addr = listener.local_addr().expect("address");
    drop(listener);
    let path = pin_path("trust-unreachable");
    let trust = TicketTrust::new(
        Url::parse(&format!("http://{addr}")).expect("server URL"),
        path.clone(),
    );

    let error = trust
        .pinned_key("sess_unreachable", "capability")
        .await
        .expect_err("no pin and no server is a refusal");
    assert!(matches!(error, TrustError::Fetch { .. }), "{error:?}");
    assert!(!path.exists(), "a failed fetch writes no pin");
    std::fs::remove_dir_all(path.parent().expect("directory")).ok();
}

#[tokio::test]
async fn reset_forgets_the_pin_so_the_next_open_pins_again() {
    let server = KeyServer::start("first-key").await;
    let path = pin_path("trust-reset");
    let trust = TicketTrust::new(server.url(), path.clone());
    trust
        .pinned_key("sess_reset", "capability")
        .await
        .expect("pin");

    trust.reset().expect("reset");
    assert!(!path.exists(), "reset deletes the pin");

    server.rotate("second-key");
    assert_eq!(
        trust
            .pinned_key("sess_reset", "capability")
            .await
            .expect("pin again"),
        "second-key"
    );
    std::fs::remove_dir_all(path.parent().expect("directory")).ok();
}
