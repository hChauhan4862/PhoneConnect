//! Shared harness for the native proxy tests.
//!
//! Every fixture is real: loopback TCP sockets, a real `ConnectedPath` over an in-process
//! relay, and a device-side stub that answers proxy frames. Nothing here is a product code
//! path; the stub stands in for the Android TCP bridge that does not exist yet.

#![allow(dead_code)]

use std::collections::HashMap;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use async_trait::async_trait;
use phoneconnect::v1::{DeviceId, Envelope, RequestId, SessionId, StreamKind};
use phoneconnect_native::proxy::{LocalEndpoint, ProxyLimits};
use phoneconnect_native::session_client::{SessionClient, SessionPath};
use phoneconnect_transport::{
    ConnectedPath, Epoch, HolePunchError, IdentityKey, PathConfig, PathError, RelayChannel,
    RelayError, RelayOnlyPath, TicketRole,
};
use tokio::sync::mpsc;
use tokio::task::JoinHandle;

pub const DEVICE: &str = "dev_native";
pub const CLIENT_NONCE: &str = "client-nonce";
pub const DEVICE_NONCE: &str = "device-nonce";

/// Two ends of one in-process relay: each end writes what the other reads.
pub struct RelayEnd {
    inbound: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    outbound: mpsc::Sender<Vec<u8>>,
}

impl RelayEnd {
    pub fn pair(capacity: usize) -> (Arc<Self>, Arc<Self>) {
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
pub struct RefusingRelay;

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

/// A relay that stalls on the first send, counting attempts.
pub struct StalledRelay {
    pub attempts: AtomicUsize,
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

pub struct RelaySession {
    pub client: SessionPath,
    pub device: Arc<ConnectedPath>,
}

pub fn session_id(name: &str) -> SessionId {
    SessionId::new(format!("sess_{name}")).expect("valid session id")
}

pub fn epoch() -> Epoch {
    Epoch::new(CLIENT_NONCE, DEVICE_NONCE).expect("epoch")
}

pub fn relay_session(name: &str) -> RelaySession {
    let client_identity = IdentityKey::generate().expect("client identity");
    let device_identity = IdentityKey::generate().expect("device identity");
    let session = session_id(name);
    let (client_relay, device_relay) = RelayEnd::pair(16);

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

pub fn refusing_session(name: &str) -> SessionPath {
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

pub fn stalled_session(name: &str) -> (SessionPath, Arc<StalledRelay>) {
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

pub fn limits() -> ProxyLimits {
    ProxyLimits {
        max_chunk_bytes: 16 * 1024,
        send_timeout: Duration::from_secs(5),
        idle_timeout: Duration::from_secs(10),
        frame_deadline: Duration::from_secs(10),
    }
}

pub fn unix_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}

pub fn port_of(endpoint: &LocalEndpoint) -> u16 {
    endpoint
        .url
        .rsplit(':')
        .next()
        .expect("endpoint URL has a port")
        .parse()
        .expect("endpoint URL port is numeric")
}

pub fn addr_of(endpoint: &LocalEndpoint) -> std::net::SocketAddr {
    format!("127.0.0.1:{}", port_of(endpoint))
        .parse()
        .expect("endpoint address")
}

/// How the device stub answers proxy frames.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum EchoMode {
    /// Echo every proxy frame with the next sequence for that stream.
    Plain,
    /// Emit an unrelated Events frame before each echo, on the same path.
    WithEvents,
    /// Echo only the first frame, then send a wrong request id and the correct echo for the
    /// second frame.
    WithForeignFrame,
    /// Skip a sequence so the client can detect a hole.
    WithSequenceGap,
    /// After the first connection's request id is known, answer the next connection with a
    /// stale frame for the old id before echoing. A correct hub has no route for it.
    StaleAfterReconnect,
}

/// The device-side stub: echoes proxy frames, keeping a per-stream sequence.
pub fn spawn_echo(
    device: Arc<ConnectedPath>,
    mode: EchoMode,
) -> (JoinHandle<()>, Arc<std::sync::Mutex<Vec<Envelope>>>) {
    let seen: Arc<std::sync::Mutex<Vec<Envelope>>> = Arc::new(std::sync::Mutex::new(Vec::new()));
    let recorded = Arc::clone(&seen);
    let handle = tokio::spawn(async move {
        let mut sequences: HashMap<String, u32> = HashMap::new();
        let mut first_request: Option<String> = None;
        let mut echoes = 0u32;
        loop {
            let envelope = match device.recv_frame().await {
                Ok(envelope) => envelope,
                Err(PathError::HolePunch(HolePunchError::ReceiveTimeout))
                | Err(PathError::FramesLost { .. }) => continue,
                Err(_) => return,
            };
            recorded
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner())
                .push(envelope.clone());
            let device_id = DeviceId::new(envelope.device_id.clone()).expect("device id");
            let session_id = SessionId::new(envelope.session_id.clone()).expect("session id");

            if mode == EchoMode::StaleAfterReconnect {
                match &first_request {
                    None => first_request = Some(envelope.request_id.clone()),
                    Some(first) if first != &envelope.request_id => {
                        let stale = RequestId::new(first.clone()).expect("request id");
                        let mut frame =
                            Envelope::new(StreamKind::Proxy, &device_id, &session_id, &stale);
                        frame.sequence = 99;
                        frame.payload = b"stale bytes from a closed connection".to_vec();
                        if device.send_frame(&frame).await.is_err() {
                            return;
                        }
                    }
                    _ => {}
                }
            }
            if mode == EchoMode::WithEvents {
                let request = RequestId::new("event-heartbeat").expect("request id");
                let mut event =
                    Envelope::new(StreamKind::Events, &device_id, &session_id, &request);
                event.sequence = 1;
                event.payload = b"unrelated event".to_vec();
                if device.send_frame(&event).await.is_err() {
                    return;
                }
            }
            counts_check(&envelope.request_id);
            echoes += 1;
            if mode == EchoMode::WithForeignFrame && echoes == 2 {
                let foreign = RequestId::new("proxy-other").expect("request id");
                let mut frame = Envelope::new(StreamKind::Proxy, &device_id, &session_id, &foreign);
                frame.sequence = 1;
                frame.payload = b"not for this stream".to_vec();
                if device.send_frame(&frame).await.is_err() {
                    return;
                }
            }
            let sequence = {
                let next = sequences.entry(envelope.request_id.clone()).or_insert(0u32);
                *next = next.checked_add(1).expect("sequence");
                *next
            };
            let sequence = if mode == EchoMode::WithSequenceGap && sequence == 2 {
                3
            } else {
                sequence
            };
            let request = RequestId::new(envelope.request_id.clone()).expect("request id");
            let mut reply = Envelope::new(StreamKind::Proxy, &device_id, &session_id, &request);
            reply.sequence = sequence;
            reply.deadline_unix_ms = envelope.deadline_unix_ms;
            reply.payload = envelope.payload.clone();
            if device.send_frame(&reply).await.is_err() {
                return;
            }
        }
    });
    (handle, seen)
}

fn counts_check(_request_id: &str) {}
