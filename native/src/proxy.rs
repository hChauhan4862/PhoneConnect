//! Loopback proxy endpoints, the per-session frame demultiplexer, and the byte pump.
//!
//! Each mapped device stream gets one TCP listener on `127.0.0.1` with an ephemeral port.
//! A connected path is shared: one [`ProxyHub`] is the only reader of that path's inbound
//! frames and routes each `StreamKind::Proxy` frame to the stream that owns its `request_id`.
//! Frames of other kinds, and frames for a stream that is not open, belong to another
//! consumer and are ignored rather than disturbing a tunnel. The transport's single-reader
//! contract is therefore kept: the hub reads, and the pumps never call `recv_frame`.
//!
//! Every proxy frame carries a per-stream sequence and a deadline. A frame that arrives out
//! of sequence — or a `FramesLost` report, which means the path already discarded frames —
//! closes that tunnel with an explicit error, because a TCP stream cannot be resumed across
//! a hole. `bytes_down` counts bytes written, never bytes implied by a skipped frame.
//!
//! **A successful send is not proof of delivery.** [`ConnectedPath::send_frame`] returning
//! `Ok` means the frame was handed to the direct socket or the relay; neither acknowledges
//! the peer. [`ProxySummary`] therefore counts bytes *accepted by the transport*, and any
//! transport failure closes the local connection instead of leaving the client waiting.
//!
//! There is no Android TCP bridge yet, so an endpoint is useful only against a peer that
//! speaks the proxy stream (the tests use an echoing stub). The README states this.

use std::collections::HashMap;
use std::io;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};

use phoneconnect::v1::{DeviceId, Envelope, RequestId, SessionId, StreamKind};
use phoneconnect_transport::{ConnectedPath, HolePunchError, PathError, PathKind};
use serde::{Deserialize, Serialize};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::{Mutex, mpsc};

/// Every endpoint binds this address. Never `0.0.0.0`: a proxy port is a local capability,
/// not a network service.
pub const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// The port that asks the OS for an unused ephemeral port.
pub const EPHEMERAL_PORT: u16 = 0;
/// Largest payload one proxy frame may carry. A direct datagram carries at most 60,000
/// bytes including the sealed header, so this fits every path.
pub const MAX_PROXY_CHUNK_BYTES: usize = 32 * 1024;
/// Frames one stream may have queued for its local client before that stream is failed.
/// A slow local reader fails its own tunnel instead of stalling the shared path.
pub const STREAM_QUEUE_CHUNKS: usize = 8;
/// Default silence allowed on a proxied connection.
///
/// A byte tunnel is not a request/response protocol: `adb shell sleep 60` moves nothing for
/// a minute and is still healthy. Five minutes is long enough for that and short enough that
/// an abandoned port does not linger.
pub const DEFAULT_PROXY_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// A loopback endpoint the shell exposes back to the page.
///
/// This is the wire shape of `LocalEndpoint` in `web/src/host/hostContext.ts`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LocalEndpoint {
    pub device_id: String,
    pub stream: String,
    pub url: String,
}

/// The capability that authorizes one endpoint, and the instant it ends.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyCapability {
    pub stream: String,
    pub expires_at: Instant,
}

impl ProxyCapability {
    /// `stream` names what the endpoint tunnels (for example `adb`) and doubles as the proxy
    /// stream identifier, so it must be a valid protocol identifier.
    pub fn new(stream: impl Into<String>, expires_at: Instant) -> Result<Self, ProxyError> {
        let stream = stream.into();
        request_id_for(&stream)?;
        Ok(Self { stream, expires_at })
    }
}

/// Bounds applied to one proxied connection.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProxyLimits {
    /// Largest payload in one proxy frame, at most [`MAX_PROXY_CHUNK_BYTES`].
    pub max_chunk_bytes: usize,
    /// How long one send may take before the session fails instead of pretending delivery.
    pub send_timeout: Duration,
    /// Silence on the connection, in either direction, that ends it.
    pub idle_timeout: Duration,
    /// Deadline stamped on every proxy frame, so the peer can expire it.
    pub frame_deadline: Duration,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            max_chunk_bytes: 16 * 1024,
            send_timeout: Duration::from_secs(5),
            idle_timeout: DEFAULT_PROXY_IDLE_TIMEOUT,
            frame_deadline: Duration::from_secs(10),
        }
    }
}

impl ProxyLimits {
    pub fn validate(&self) -> Result<(), ProxyError> {
        if self.max_chunk_bytes == 0 || self.max_chunk_bytes > MAX_PROXY_CHUNK_BYTES {
            return Err(ProxyError::InvalidLimits {
                reason: format!(
                    "max_chunk_bytes must be between 1 and {MAX_PROXY_CHUNK_BYTES}, got {}",
                    self.max_chunk_bytes
                ),
            });
        }
        if self.send_timeout.is_zero()
            || self.idle_timeout.is_zero()
            || self.frame_deadline.is_zero()
        {
            return Err(ProxyError::InvalidLimits {
                reason: "send_timeout, idle_timeout, and frame_deadline must be non-zero"
                    .to_owned(),
            });
        }
        Ok(())
    }
}

/// Allocates loopback-only endpoints and serves one local connection at a time per endpoint.
#[derive(Debug, Default)]
pub struct ProxyAllocator {
    inner: Mutex<Vec<EndpointSlot>>,
}

#[derive(Debug)]
struct EndpointSlot {
    local: LocalEndpoint,
    listener: Arc<TcpListener>,
    capability: ProxyCapability,
}

impl ProxyAllocator {
    pub fn new() -> Self {
        Self::default()
    }

    /// Binds a new endpoint on loopback with an OS-assigned ephemeral port.
    pub async fn bind(
        &self,
        device_id: &str,
        capability: ProxyCapability,
    ) -> Result<LocalEndpoint, ProxyError> {
        let device = DeviceId::new(device_id).map_err(|error| ProxyError::InvalidDevice {
            device_id: device_id.to_owned(),
            reason: error.to_string(),
        })?;
        if capability.expires_at <= Instant::now() {
            return Err(ProxyError::CapabilityExpired {
                device_id: device_id.to_owned(),
                stream: capability.stream,
            });
        }
        let mut slots = self.inner.lock().await;
        let now = Instant::now();
        slots.retain(|slot| slot.capability.expires_at > now);
        if slots.iter().any(|slot| {
            slot.local.device_id == device.as_str() && slot.local.stream == capability.stream
        }) {
            return Err(ProxyError::AlreadyBound {
                device_id: device.as_str().to_owned(),
                stream: capability.stream,
            });
        }
        let listener = TcpListener::bind(SocketAddr::new(LOOPBACK, EPHEMERAL_PORT))
            .await
            .map_err(io_error("bind the loopback endpoint"))?;
        let address = listener
            .local_addr()
            .map_err(io_error("read the bound endpoint"))?;
        if !address.ip().is_loopback() {
            return Err(ProxyError::InvalidLimits {
                reason: format!("the OS bound {address}, which is not loopback"),
            });
        }
        let local = LocalEndpoint {
            device_id: device.as_str().to_owned(),
            stream: capability.stream.clone(),
            url: format!("http://{address}"),
        };
        slots.push(EndpointSlot {
            local: local.clone(),
            listener: Arc::new(listener),
            capability,
        });
        Ok(local)
    }

    /// Waits for one local connection on `endpoint` and pumps it until either side ends, the
    /// transport fails, the connection idles out, or the capability expires.
    pub async fn serve(
        &self,
        endpoint: &LocalEndpoint,
        session: ProxySession,
    ) -> Result<ProxySummary, ProxyError> {
        if endpoint.device_id != session.device_id.as_str() || endpoint.stream != session.stream {
            return Err(ProxyError::StreamMismatch {
                endpoint: format!("{}/{}", endpoint.device_id, endpoint.stream),
                session: format!("{}/{}", session.device_id, session.stream),
            });
        }
        let (listener, capability) = {
            let slots = self.inner.lock().await;
            let slot = slots
                .iter()
                .find(|slot| {
                    slot.local.device_id == endpoint.device_id
                        && slot.local.stream == endpoint.stream
                })
                .ok_or_else(|| ProxyError::UnknownEndpoint {
                    device_id: endpoint.device_id.clone(),
                    stream: endpoint.stream.clone(),
                })?;
            (Arc::clone(&slot.listener), slot.capability.clone())
        };
        if capability.expires_at <= Instant::now() {
            self.close(&endpoint.device_id, &endpoint.stream).await;
            return Err(ProxyError::CapabilityExpired {
                device_id: endpoint.device_id.clone(),
                stream: endpoint.stream.clone(),
            });
        }
        let connection = tokio::select! {
            accepted = listener.accept() => accepted.map_err(io_error("accept a local connection"))?.0,
            _ = tokio::time::sleep_until(capability.expires_at.into()) => {
                self.close(&endpoint.device_id, &endpoint.stream).await;
                return Err(ProxyError::CapabilityExpired {
                    device_id: endpoint.device_id.clone(),
                    stream: endpoint.stream.clone(),
                });
            }
        };
        let result = session.run(connection, capability.expires_at).await;
        if matches!(result, Err(ProxyError::CapabilityExpired { .. })) {
            self.close(&endpoint.device_id, &endpoint.stream).await;
        }
        result
    }

    /// The live endpoints, with expired ones removed so a page never lists a dead port.
    pub async fn endpoints(&self) -> Vec<LocalEndpoint> {
        let now = Instant::now();
        let mut slots = self.inner.lock().await;
        slots.retain(|slot| slot.capability.expires_at > now);
        slots.iter().map(|slot| slot.local.clone()).collect()
    }

    /// The address an endpoint is bound to, if it is still live.
    pub async fn local_addr(&self, device_id: &str, stream: &str) -> Option<SocketAddr> {
        let slots = self.inner.lock().await;
        slots
            .iter()
            .find(|slot| slot.local.device_id == device_id && slot.local.stream == stream)
            .and_then(|slot| slot.listener.local_addr().ok())
    }

    /// Stops an endpoint now; a connection it is not already serving cannot start.
    pub async fn close(&self, device_id: &str, stream: &str) -> bool {
        let now = Instant::now();
        let mut slots = self.inner.lock().await;
        // An endpoint whose capability already expired is closed, not "closed now".
        slots.retain(|slot| slot.capability.expires_at > now);
        let before = slots.len();
        slots.retain(|slot| !(slot.local.device_id == device_id && slot.local.stream == stream));
        slots.len() != before
    }
}

/// The single reader of one connected path, fanning proxy frames out to their streams.
///
/// The transport allows exactly one reader per path. Control, event, and file frames on that
/// path belong to other consumers and are ignored here; so is a proxy frame for a stream that
/// is not open. Nothing outside the owning stream is torn down.
#[derive(Debug)]
pub(crate) struct ProxyHub {
    inner: Arc<HubInner>,
}

#[derive(Debug)]
struct HubInner {
    path: Arc<ConnectedPath>,
    state: std::sync::Mutex<HubState>,
}

#[derive(Debug, Default)]
struct HubState {
    /// Live streams by request id.
    routes: HashMap<String, mpsc::Sender<HubEvent>>,
    /// Why a route was force-closed. Read by the pump once its channel ends.
    failures: HashMap<String, StreamFailure>,
    /// Set when the path itself fails; no new stream may start on it.
    closed: Option<String>,
    reader_running: bool,
}

#[derive(Debug)]
enum HubEvent {
    Bytes { sequence: u32, payload: Vec<u8> },
}

/// A failure that closes one stream. Split from [`ProxyError`] so it can be recorded without
/// an `io::Error` and cloned across the fan-out.
#[derive(Debug, Clone)]
enum StreamFailure {
    FramesLost { count: u32 },
    Transport { reason: String },
    Backpressure,
    SessionClosed,
}

impl StreamFailure {
    fn into_error(self, stream: &str) -> ProxyError {
        match self {
            Self::FramesLost { count } => ProxyError::FramesLost { count },
            Self::Transport { reason } => ProxyError::Transport { reason },
            Self::Backpressure => ProxyError::Backpressure {
                stream: stream.to_owned(),
            },
            Self::SessionClosed => ProxyError::SessionClosed {
                reason: "the session path closed".to_owned(),
            },
        }
    }
}

impl ProxyHub {
    pub(crate) fn new(path: Arc<ConnectedPath>) -> Self {
        Self {
            inner: Arc::new(HubInner {
                path,
                state: std::sync::Mutex::new(HubState::default()),
            }),
        }
    }

    /// Opens one stream on this path. A second pump for the same stream is refused; a
    /// different stream is independent and runs concurrently.
    pub(crate) async fn proxy_session(
        &self,
        device_id: &DeviceId,
        stream: &str,
        limits: ProxyLimits,
    ) -> Result<ProxySession, ProxyError> {
        limits.validate()?;
        let request_id = request_id_for(stream)?;
        let (sender, receiver) = mpsc::channel(STREAM_QUEUE_CHUNKS);
        {
            let mut state = self.lock();
            if let Some(reason) = &state.closed {
                return Err(ProxyError::SessionClosed {
                    reason: reason.clone(),
                });
            }
            if state.routes.contains_key(&request_id) {
                return Err(ProxyError::StreamInUse {
                    stream: stream.to_owned(),
                });
            }
            state.routes.insert(request_id.clone(), sender);
            if !state.reader_running {
                state.reader_running = true;
                let inner = Arc::clone(&self.inner);
                tokio::spawn(async move { inner.read_loop().await });
            }
        }
        Ok(ProxySession {
            path: Arc::clone(&self.inner.path),
            device_id: device_id.clone(),
            session_id: SessionId::new(self.inner.path.session_id())
                .expect("a connected path's session id was validated before it existed"),
            request_id: request_id.clone(),
            receiver,
            stream: stream.to_owned(),
            limits,
            route: RouteGuard {
                inner: Arc::clone(&self.inner),
                request_id,
            },
        })
    }

    fn lock(&self) -> std::sync::MutexGuard<'_, HubState> {
        self.inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

impl HubInner {
    async fn read_loop(self: Arc<Self>) {
        loop {
            match self.path.recv_frame().await {
                Ok(envelope) => {
                    if StreamKind::try_from(envelope.stream_kind).ok() != Some(StreamKind::Proxy) {
                        // Another consumer's frame on the shared path. Not ours.
                        continue;
                    }
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    let request_id = envelope.request_id.clone();
                    let Some(sender) = state.routes.get(&request_id) else {
                        // A stream that already ended (or never existed). Ignore its frame.
                        continue;
                    };
                    let event = HubEvent::Bytes {
                        sequence: envelope.sequence,
                        payload: envelope.payload,
                    };
                    match sender.try_send(event) {
                        Ok(()) => {}
                        Err(mpsc::error::TrySendError::Full(_)) => {
                            // The local client stopped reading. Fail its stream rather than
                            // stall the shared path or drop bytes silently.
                            state.fail_route(&request_id, StreamFailure::Backpressure);
                        }
                        Err(mpsc::error::TrySendError::Closed(_)) => {
                            state.routes.remove(&request_id);
                        }
                    }
                }
                // The relay is quiet between requests; that is not a failure.
                Err(PathError::HolePunch(HolePunchError::ReceiveTimeout)) => continue,
                Err(PathError::FramesLost { count }) => {
                    // The path already discarded inbound frames. Which stream lost bytes is
                    // not knowable, so every live stream is closed with an explicit error
                    // rather than writing a hole into a TCP tunnel. The path stays usable for
                    // new streams.
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.fail_all(StreamFailure::FramesLost { count });
                }
                Err(error) => {
                    let failure = if matches!(error, PathError::Shutdown) {
                        StreamFailure::SessionClosed
                    } else {
                        StreamFailure::Transport {
                            reason: error.to_string(),
                        }
                    };
                    let mut state = self
                        .state
                        .lock()
                        .unwrap_or_else(|poisoned| poisoned.into_inner());
                    state.fail_all(failure.clone());
                    state.closed = Some(match failure {
                        StreamFailure::SessionClosed => "the session path closed".to_owned(),
                        StreamFailure::Transport { reason } => reason,
                        _ => "the session path closed".to_owned(),
                    });
                    state.reader_running = false;
                    return;
                }
            }
        }
    }
}

impl HubState {
    /// Fails one stream: records why, then drops its sender so the pump sees the channel end
    /// after draining any bytes that arrived before the failure.
    fn fail_route(&mut self, request_id: &str, failure: StreamFailure) {
        if let Some(sender) = self.routes.remove(request_id) {
            self.failures.insert(request_id.to_owned(), failure);
            drop(sender);
        }
    }

    fn fail_all(&mut self, failure: StreamFailure) {
        let ids: Vec<String> = self.routes.keys().cloned().collect();
        for id in ids {
            self.fail_route(&id, failure.clone());
        }
    }
}

/// Removes a stream's route when its pump ends, so the stream can be opened again.
#[derive(Debug)]
struct RouteGuard {
    inner: Arc<HubInner>,
    request_id: String,
}

impl Drop for RouteGuard {
    fn drop(&mut self) {
        let mut state = self
            .inner
            .state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        state.routes.remove(&self.request_id);
        state.failures.remove(&self.request_id);
    }
}

/// One authenticated proxy stream carried by a connected path.
#[derive(Debug)]
pub struct ProxySession {
    path: Arc<ConnectedPath>,
    device_id: DeviceId,
    session_id: SessionId,
    request_id: String,
    receiver: mpsc::Receiver<HubEvent>,
    stream: String,
    limits: ProxyLimits,
    route: RouteGuard,
}

impl ProxySession {
    pub fn stream(&self) -> &str {
        &self.stream
    }

    pub fn path_kind(&self) -> PathKind {
        self.path.path_kind()
    }

    /// Pumps one local connection.
    ///
    /// The uplink reads one chunk, seals it with the next per-stream sequence, and only then
    /// reads again, so a stalled transport stops the local socket with TCP backpressure
    /// instead of growing a buffer. The downlink reads only this stream's demultiplexed
    /// frames and requires contiguous sequences.
    ///
    /// Either direction ending, any transport error, a lost-frame report, a sequence hole,
    /// the idle deadline (which both directions refresh), and capability expiry close the
    /// local socket before this returns.
    pub async fn run(
        self,
        connection: TcpStream,
        expires_at: Instant,
    ) -> Result<ProxySummary, ProxyError> {
        let ProxySession {
            path,
            device_id,
            session_id,
            request_id,
            mut receiver,
            stream,
            limits,
            // Keeping the guard until this function returns keeps the stream route claimed
            // for the whole pump, even while both tasks run.
            route,
        } = self;
        limits.validate()?;
        let (mut reader, mut writer) = connection.into_split();
        let bytes_up = Arc::new(AtomicU64::new(0));
        let bytes_down = Arc::new(AtomicU64::new(0));
        let activity = Arc::new(std::sync::Mutex::new(Instant::now()));
        let path_kind = path.path_kind();

        let uplink_limit = limits.clone();
        let uplink_path = Arc::clone(&path);
        let uplink_count = Arc::clone(&bytes_up);
        let uplink_activity = Arc::clone(&activity);
        let uplink_device = device_id.clone();
        let uplink_session = session_id.clone();
        let uplink_request = request_id.clone();
        let mut uplink = tokio::spawn(async move {
            let mut buffer = vec![0u8; uplink_limit.max_chunk_bytes];
            let mut sequence: u32 = 0;
            loop {
                let read = match reader.read(&mut buffer).await {
                    Ok(0) => return Ok(()),
                    Ok(read) => read,
                    Err(error) => {
                        return Err(ProxyError::Io {
                            operation: "read the local socket",
                            source: error,
                        });
                    }
                };
                sequence = sequence
                    .checked_add(1)
                    .ok_or(ProxyError::SequenceExhausted)?;
                let mut envelope = Envelope::new(
                    StreamKind::Proxy,
                    &uplink_device,
                    &uplink_session,
                    &uplink_request_id(&uplink_request),
                );
                envelope.sequence = sequence;
                envelope.deadline_unix_ms = unix_ms_after(uplink_limit.frame_deadline);
                envelope.payload = buffer[..read].to_vec();
                match tokio::time::timeout(
                    uplink_limit.send_timeout,
                    uplink_path.send_frame(&envelope),
                )
                .await
                {
                    Err(_) => {
                        return Err(ProxyError::SendTimedOut {
                            after: uplink_limit.send_timeout,
                        });
                    }
                    Ok(Err(error)) => {
                        return Err(ProxyError::Transport {
                            reason: error.to_string(),
                        });
                    }
                    Ok(Ok(())) => {
                        // Accepted by the transport, not proof of delivery.
                        uplink_count.fetch_add(read as u64, Ordering::SeqCst);
                        *uplink_activity.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
                    }
                }
            }
        });

        let downlink_limit = limits.clone();
        let downlink_activity = Arc::clone(&activity);
        let downlink_count = Arc::clone(&bytes_down);
        let downlink_stream = stream.clone();
        let failure_hub = Arc::clone(&route.inner);
        let failure_request = request_id.clone();
        let mut downlink = tokio::spawn(async move {
            let mut expected: u32 = 1;
            loop {
                let event = loop {
                    let deadline = *downlink_activity.lock().unwrap_or_else(|p| p.into_inner())
                        + downlink_limit.idle_timeout;
                    tokio::select! {
                        biased;
                        _ = tokio::time::sleep_until(deadline.into()) => {
                            // Uplink activity may have moved the deadline while we slept.
                            if *downlink_activity
                                .lock()
                                .unwrap_or_else(|p| p.into_inner())
                                + downlink_limit.idle_timeout
                                > Instant::now()
                            {
                                continue;
                            }
                            return Err(ProxyError::Idle {
                                after: downlink_limit.idle_timeout,
                            });
                        }
                        event = receiver.recv() => break event,
                    }
                };
                let HubEvent::Bytes { sequence, payload } = match event {
                    Some(event) => event,
                    None => {
                        return Err(take_failure(&failure_hub, &failure_request)
                            .map(|failure| failure.into_error(&downlink_stream))
                            .unwrap_or(ProxyError::SessionClosed {
                                reason: "the stream ended".to_owned(),
                            }));
                    }
                };
                if sequence != expected {
                    // A hole in a TCP byte stream cannot be delivered; failing closed is the
                    // only honest outcome.
                    return Err(ProxyError::SequenceGap {
                        expected,
                        found: sequence,
                    });
                }
                expected = expected
                    .checked_add(1)
                    .ok_or(ProxyError::SequenceExhausted)?;
                if payload.is_empty() {
                    continue;
                }
                match tokio::time::timeout(downlink_limit.idle_timeout, writer.write_all(&payload))
                    .await
                {
                    Err(_) => {
                        return Err(ProxyError::WriteTimedOut {
                            after: downlink_limit.idle_timeout,
                        });
                    }
                    Ok(Err(error)) => {
                        return Err(ProxyError::Io {
                            operation: "write the local socket",
                            source: error,
                        });
                    }
                    Ok(Ok(())) => {}
                }
                downlink_count.fetch_add(payload.len() as u64, Ordering::SeqCst);
                *downlink_activity.lock().unwrap_or_else(|p| p.into_inner()) = Instant::now();
            }
        });

        // Stop the other direction and wait for its half of the socket to drop, so the local
        // client sees the connection close before `serve` reports the outcome. A handle the
        // `select!` already completed is never awaited a second time.
        let outcome = tokio::select! {
            biased;
            _ = tokio::time::sleep_until(expires_at.into()) => {
                uplink.abort();
                downlink.abort();
                let _ = uplink.await;
                let _ = downlink.await;
                Err(ProxyError::CapabilityExpired {
                    device_id: device_id.to_string(),
                    stream: stream.clone(),
                })
            }
            finished = &mut uplink => {
                downlink.abort();
                let _ = downlink.await;
                task_result(finished)
            }
            finished = &mut downlink => {
                uplink.abort();
                let _ = uplink.await;
                task_result(finished)
            }
        };
        drop(route);

        outcome.map(|()| ProxySummary {
            bytes_up: bytes_up.load(Ordering::SeqCst),
            bytes_down: bytes_down.load(Ordering::SeqCst),
            path_kind,
        })
    }
}

fn take_failure(inner: &Arc<HubInner>, request_id: &str) -> Option<StreamFailure> {
    inner
        .state
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
        .failures
        .remove(request_id)
}

fn uplink_request_id(value: &str) -> RequestId {
    RequestId::new(value).expect("the request id was validated when the stream opened")
}

fn request_id_for(stream: &str) -> Result<String, ProxyError> {
    let request_id = format!("proxy-{stream}");
    RequestId::new(request_id.clone()).map_err(|error| ProxyError::InvalidStream {
        stream: stream.to_owned(),
        reason: error.to_string(),
    })?;
    Ok(request_id)
}

fn task_result(
    finished: Result<Result<(), ProxyError>, tokio::task::JoinError>,
) -> Result<(), ProxyError> {
    match finished {
        Ok(result) => result,
        Err(error) => Err(ProxyError::Io {
            operation: "run the proxy pump",
            source: io::Error::other(error),
        }),
    }
}

/// What one proxied connection moved, and which path carried it.
///
/// `bytes_up` is bytes **accepted by the transport**, not bytes the peer acknowledged; the
/// protocol has no delivery receipt. `bytes_down` is bytes written to the local client, in
/// sequence, never including a hole.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProxySummary {
    pub bytes_up: u64,
    pub bytes_down: u64,
    pub path_kind: PathKind,
}

fn unix_ms_after(after: Duration) -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
        + after.as_millis().min(i64::MAX as u128) as i64
}

fn io_error(operation: &'static str) -> impl Fn(io::Error) -> ProxyError {
    move |source| ProxyError::Io { operation, source }
}

/// Explicit proxy failures. A transport error is reported; it is never a silent close that
/// looks like a successful end of stream.
#[derive(Debug, thiserror::Error)]
pub enum ProxyError {
    #[error("stream {stream:?} is not a valid identifier: {reason}")]
    InvalidStream { stream: String, reason: String },
    #[error("device id {device_id:?} is not a valid identifier: {reason}")]
    InvalidDevice { device_id: String, reason: String },
    #[error("an endpoint is already bound for {device_id}/{stream}")]
    AlreadyBound { device_id: String, stream: String },
    #[error("no endpoint is bound for {device_id}/{stream}")]
    UnknownEndpoint { device_id: String, stream: String },
    #[error("the proxy capability for {device_id}/{stream} has expired")]
    CapabilityExpired { device_id: String, stream: String },
    #[error("endpoint {endpoint} cannot serve a {session} session")]
    StreamMismatch { endpoint: String, session: String },
    #[error("invalid proxy limits: {reason}")]
    InvalidLimits { reason: String },
    #[error("this session path already carries the {stream} proxy stream")]
    StreamInUse { stream: String },
    #[error("the local client for {stream} stopped reading; its queue is bounded")]
    Backpressure { stream: String },
    #[error("the connection carried nothing in either direction for {after:?}")]
    Idle { after: Duration },
    #[error("one send took longer than {after:?}")]
    SendTimedOut { after: Duration },
    #[error("the local client stopped reading for {after:?}")]
    WriteTimedOut { after: Duration },
    #[error("proxy frame sequence jumped from {found} (expected {expected})")]
    SequenceGap { expected: u32, found: u32 },
    #[error("the proxy stream exhausted its sequence space")]
    SequenceExhausted,
    #[error("the path dropped {count} inbound frame(s); the tunnel cannot resume across a hole")]
    FramesLost { count: u32 },
    #[error("the session path is closed: {reason}")]
    SessionClosed { reason: String },
    #[error("transport failed while carrying proxy bytes: {reason}")]
    Transport { reason: String },
    #[error("{operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn frames_lost_ends_every_live_stream_with_that_error() {
        let mut state = HubState::default();
        let (first, mut first_rx) = mpsc::channel(1);
        let (second, mut second_rx) = mpsc::channel(1);
        state.routes.insert("proxy-adb".to_owned(), first);
        state.routes.insert("proxy-screen".to_owned(), second);

        state.fail_all(StreamFailure::FramesLost { count: 3 });

        assert!(state.routes.is_empty(), "no route survives a reported loss");
        for receiver in [&mut first_rx, &mut second_rx] {
            assert!(
                matches!(
                    receiver.try_recv(),
                    Err(mpsc::error::TryRecvError::Disconnected)
                ),
                "the pump is told the stream ended"
            );
        }
        for id in ["proxy-adb", "proxy-screen"] {
            match state.failures.remove(id) {
                Some(StreamFailure::FramesLost { count }) => assert_eq!(count, 3),
                other => panic!("{id} did not record the loss: {other:?}"),
            }
        }
    }

    #[test]
    fn a_full_stream_queue_fails_only_that_stream() {
        let mut state = HubState::default();
        let (slow, _slow_rx) = mpsc::channel(1);
        let (healthy, mut healthy_rx) = mpsc::channel(1);
        state.routes.insert("proxy-slow".to_owned(), slow);
        state.routes.insert("proxy-healthy".to_owned(), healthy);
        // Fill the slow queue so the next delivery is refused.
        state
            .routes
            .get("proxy-slow")
            .expect("route")
            .try_send(HubEvent::Bytes {
                sequence: 1,
                payload: b"first".to_vec(),
            })
            .expect("the first event fits");

        state.fail_route("proxy-slow", StreamFailure::Backpressure);

        assert!(state.routes.contains_key("proxy-healthy"));
        assert!(
            healthy_rx.try_recv().is_err(),
            "the healthy stream is untouched"
        );
        assert!(matches!(
            state.failures.get("proxy-slow"),
            Some(StreamFailure::Backpressure)
        ));
    }
}
