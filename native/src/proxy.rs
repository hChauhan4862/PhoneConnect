//! Loopback proxy endpoints and the byte pump that carries them over one proxy stream.
//!
//! Each mapped device stream gets one TCP listener on `127.0.0.1` with an ephemeral port.
//! A local client that connects is pumped over the same authenticated `ConnectedPath` the
//! native client uses for control: every read becomes one `StreamKind::Proxy` envelope and
//! every proxy envelope becomes local bytes.
//!
//! **A successful send is not proof of delivery.** [`ConnectedPath::send_frame`] returning
//! `Ok` means the frame was handed to the direct socket or the relay; neither acknowledges
//! the peer. This module therefore never reports bytes as delivered: [`ProxySummary`] counts
//! bytes *accepted by the transport*, and any transport error closes the local connection
//! instead of leaving the browser waiting for bytes that will never arrive.
//!
//! There is no Android TCP bridge yet, so an endpoint is useful only against a peer that
//! speaks the proxy stream (the tests use an echoing stub). The README states this.

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
use tokio::sync::Mutex;

/// Every endpoint binds this address. Never `0.0.0.0`: a proxy port is a local capability,
/// not a network service.
pub const LOOPBACK: IpAddr = IpAddr::V4(Ipv4Addr::LOCALHOST);
/// The port that asks the OS for an unused ephemeral port.
pub const EPHEMERAL_PORT: u16 = 0;
/// Largest payload one proxy frame may carry. A direct datagram carries at most 60,000
/// bytes including the sealed header, so this fits every path.
pub const MAX_PROXY_CHUNK_BYTES: usize = 32 * 1024;

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
        RequestId::new(stream.clone()).map_err(|error| ProxyError::InvalidStream {
            stream: stream.clone(),
            reason: error.to_string(),
        })?;
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
    /// A connection that carries nothing in either direction for this long is closed.
    pub idle_timeout: Duration,
    /// Deadline stamped on every proxy frame, so the broker and peer can expire it.
    pub frame_deadline: Duration,
}

impl Default for ProxyLimits {
    fn default() -> Self {
        Self {
            max_chunk_bytes: 16 * 1024,
            send_timeout: Duration::from_secs(5),
            idle_timeout: Duration::from_secs(30),
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
        let mut slots = self.inner.lock().await;
        let before = slots.len();
        slots.retain(|slot| !(slot.local.device_id == device_id && slot.local.stream == stream));
        slots.len() != before
    }
}

/// The one proxy stream a session path may carry at a time.
///
/// Two pumps on one path would share the request id and interleave their bytes, so the second
/// claim is refused rather than silently corrupting the first.
#[derive(Debug, Clone, Default)]
pub(crate) struct StreamSlot(Arc<std::sync::Mutex<Option<String>>>);

impl StreamSlot {
    pub(crate) fn claim(&self, stream: &str) -> Result<StreamGuard, ProxyError> {
        let mut active = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if let Some(existing) = active.as_ref() {
            return Err(ProxyError::StreamInUse {
                stream: existing.clone(),
            });
        }
        *active = Some(stream.to_owned());
        Ok(StreamGuard(Arc::clone(&self.0)))
    }
}

/// Releases the slot when its pump ends.
#[derive(Debug)]
pub(crate) struct StreamGuard(Arc<std::sync::Mutex<Option<String>>>);

impl Drop for StreamGuard {
    fn drop(&mut self) {
        let mut active = self
            .0
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        *active = None;
    }
}

/// One authenticated proxy stream carried by a connected path.
#[derive(Debug)]
pub struct ProxySession {
    path: Arc<ConnectedPath>,
    request_id: RequestId,
    device_id: DeviceId,
    session_id: SessionId,
    stream: String,
    limits: ProxyLimits,
    _stream: StreamGuard,
}

impl ProxySession {
    /// Binds this session to one stream. The request id is derived from the stream, so a
    /// peer echoes it back and a frame for another stream is refused rather than written to
    /// the wrong local client.
    pub(crate) fn new(
        path: Arc<ConnectedPath>,
        device_id: DeviceId,
        stream: &str,
        limits: ProxyLimits,
        guard: StreamGuard,
    ) -> Result<Self, ProxyError> {
        limits.validate()?;
        let request_id = RequestId::new(format!("proxy-{stream}")).map_err(|error| {
            ProxyError::InvalidStream {
                stream: stream.to_owned(),
                reason: error.to_string(),
            }
        })?;
        let session_id = SessionId::new(path.session_id())
            .expect("a connected path's session id was validated before it existed");
        Ok(Self {
            path,
            request_id,
            device_id,
            session_id,
            stream: stream.to_owned(),
            limits,
            _stream: guard,
        })
    }

    pub fn stream(&self) -> &str {
        &self.stream
    }

    pub fn path_kind(&self) -> PathKind {
        self.path.path_kind()
    }

    /// Pumps one local connection.
    ///
    /// The uplink reads one chunk, seals it, and only then reads the next, so a stalled
    /// transport stops the local socket with TCP backpressure instead of growing a buffer.
    /// The downlink refuses a frame that is not this stream's. Either direction ending, any
    /// transport error, the idle deadline, and the capability expiry close the local socket
    /// before this returns.
    pub async fn run(
        self,
        connection: TcpStream,
        expires_at: Instant,
    ) -> Result<ProxySummary, ProxyError> {
        let ProxySession {
            path,
            request_id,
            device_id,
            session_id,
            stream,
            limits,
            // Holding the guard until this function returns keeps the stream slot claimed for
            // the whole pump, even while both tasks run.
            _stream,
        } = self;
        limits.validate()?;
        let (mut reader, mut writer) = connection.into_split();
        let bytes_up = Arc::new(AtomicU64::new(0));
        let bytes_down = Arc::new(AtomicU64::new(0));
        let path_kind = path.path_kind();

        let uplink_limit = limits.clone();
        let uplink_path = Arc::clone(&path);
        let uplink_count = Arc::clone(&bytes_up);
        let uplink_device = device_id.clone();
        let uplink_session = session_id.clone();
        let uplink_request = request_id.clone();
        let mut uplink = tokio::spawn(async move {
            let mut buffer = vec![0u8; uplink_limit.max_chunk_bytes];
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
                let mut envelope = Envelope::new(
                    StreamKind::Proxy,
                    &uplink_device,
                    &uplink_session,
                    &uplink_request,
                );
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
                    Ok(Err(error)) => return Err(ProxyError::Transport { source: error }),
                    Ok(Ok(())) => {
                        // Accepted by the transport, not proof of delivery: see the module doc.
                        uplink_count.fetch_add(read as u64, Ordering::SeqCst);
                    }
                }
            }
        });

        let downlink_limit = limits.clone();
        let downlink_path = Arc::clone(&path);
        let downlink_count = Arc::clone(&bytes_down);
        let downlink_device = device_id.clone();
        let downlink_session = session_id.clone();
        let downlink_request = request_id.clone();
        let downlink_stream = stream.clone();
        let mut downlink = tokio::spawn(async move {
            let mut idle_deadline = tokio::time::Instant::now() + downlink_limit.idle_timeout;
            loop {
                let received =
                    tokio::time::timeout_at(idle_deadline, downlink_path.recv_frame()).await;
                let envelope = match received {
                    Err(_) => {
                        return Err(ProxyError::Idle {
                            after: downlink_limit.idle_timeout,
                        });
                    }
                    // Local loss is not a peer fault: the next frame is still deliverable.
                    Ok(Err(PathError::FramesLost { .. })) => continue,
                    // The relay is simply quiet between requests; the idle deadline bounds it.
                    Ok(Err(PathError::HolePunch(HolePunchError::ReceiveTimeout))) => continue,
                    Ok(Err(error)) => return Err(ProxyError::Transport { source: error }),
                    Ok(Ok(envelope)) => envelope,
                };
                if StreamKind::try_from(envelope.stream_kind).ok() != Some(StreamKind::Proxy) {
                    return Err(ProxyError::UnexpectedFrame {
                        reason: format!(
                            "stream kind {} is not a proxy frame",
                            envelope.stream_kind
                        ),
                    });
                }
                if envelope.device_id != downlink_device.as_str()
                    || envelope.session_id != downlink_session.as_str()
                    || envelope.request_id != downlink_request.as_str()
                {
                    return Err(ProxyError::UnexpectedFrame {
                        reason: format!(
                            "frame for {}/{} is not stream {downlink_stream}",
                            envelope.device_id, envelope.request_id
                        ),
                    });
                }
                if envelope.payload.is_empty() {
                    continue;
                }
                match tokio::time::timeout(
                    downlink_limit.idle_timeout,
                    writer.write_all(&envelope.payload),
                )
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
                downlink_count.fetch_add(envelope.payload.len() as u64, Ordering::SeqCst);
                idle_deadline = tokio::time::Instant::now() + downlink_limit.idle_timeout;
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

        outcome.map(|()| ProxySummary {
            bytes_up: bytes_up.load(Ordering::SeqCst),
            bytes_down: bytes_down.load(Ordering::SeqCst),
            path_kind,
        })
    }
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
/// protocol has no delivery receipt.
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
    #[error("peer sent a frame this proxy stream cannot accept: {reason}")]
    UnexpectedFrame { reason: String },
    #[error("the connection carried nothing for {after:?}")]
    Idle { after: Duration },
    #[error("one send took longer than {after:?}")]
    SendTimedOut { after: Duration },
    #[error("the local client stopped reading for {after:?}")]
    WriteTimedOut { after: Duration },
    #[error("transport failed while carrying proxy bytes: {source}")]
    Transport {
        #[from]
        source: PathError,
    },
    #[error("{operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
}
