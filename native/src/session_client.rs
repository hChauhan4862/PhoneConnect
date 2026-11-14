//! One authenticated control-plane session, expressed as the transport path the proxy rides.
//!
//! The native client holds no privileged credentials: a session is authorized by the server
//! for the signed-in user, the ticket is verified by the shared transport, and this module
//! only chooses the path and reports which one won. The proxy then rides that path through
//! one demultiplexing reader ([`crate::proxy::ProxyHub`]), so several streams can share the
//! session without racing for `recv_frame`.

use std::sync::Arc;

use phoneconnect::v1::{DeviceId, FrameLimits, StreamKind};
use phoneconnect_transport::{
    CandidateSet, ConnectedPath, PathConfig, PathController, PathError, PathKind, PathSetup,
    RelayOnlyPath, Ticket,
};

use crate::proxy::{MAX_PROXY_CHUNK_BYTES, ProxyError, ProxyHub, ProxyLimits, ProxySession};

/// The transport seam the native client uses for every device session.
#[derive(Debug, Clone)]
pub struct SessionClient {
    config: PathConfig,
}

#[derive(Debug, thiserror::Error)]
pub enum SessionClientError {
    #[error("invalid session path configuration: {reason}")]
    InvalidConfig { reason: String },
    #[error("device id {device_id:?} is not a valid identifier: {reason}")]
    InvalidDevice { device_id: String, reason: String },
    #[error(transparent)]
    Path(#[from] PathError),
}

impl SessionClient {
    /// A client for data paths: file/media/proxy limits instead of the control-only profile.
    pub fn new() -> Self {
        Self {
            config: PathConfig {
                frame_limits: FrameLimits::new(),
                ..PathConfig::default()
            },
        }
    }

    /// A client with explicit path bounds. A frame profile that cannot carry a full proxy
    /// chunk is refused here rather than failing on the first frame.
    pub fn with_config(config: PathConfig) -> Result<Self, SessionClientError> {
        config
            .validate()
            .map_err(|error| SessionClientError::InvalidConfig {
                reason: error.to_string(),
            })?;
        let proxy_limit = config.frame_limits.limit_for(StreamKind::Proxy) as usize;
        if proxy_limit < MAX_PROXY_CHUNK_BYTES {
            return Err(SessionClientError::InvalidConfig {
                reason: format!(
                    "the proxy frame limit is {proxy_limit} bytes, but a proxy chunk may be \
                     {MAX_PROXY_CHUNK_BYTES} bytes; widen the proxy stream limit"
                ),
            });
        }
        Ok(Self { config })
    }

    pub fn config(&self) -> &PathConfig {
        &self.config
    }

    /// Verifies the ticket, negotiates direct against relay, and reports the chosen path.
    ///
    /// The client's configuration replaces whatever the setup carried, so one policy owns
    /// every session this client opens: probe bounds, frame profile, and timeouts.
    pub async fn connect(
        &self,
        ticket: Ticket,
        candidates: CandidateSet,
        setup: PathSetup,
    ) -> Result<SessionPath, SessionClientError> {
        let device_id = self.device_id(&ticket.device_id)?;
        let path =
            PathController::connect(ticket, candidates, setup.with_config(self.config.clone()))
                .await?;
        Ok(SessionPath::new(path, device_id))
    }

    /// The relay fallback, used when direct negotiation already failed or UDP is disabled.
    pub fn connect_relay_only(
        &self,
        setup: RelayOnlyPath<'_>,
    ) -> Result<SessionPath, SessionClientError> {
        let device_id = self.device_id(setup.device_id)?;
        let path = ConnectedPath::relay_only(RelayOnlyPath {
            relay: setup.relay,
            identity: setup.identity,
            peer_identity: setup.peer_identity,
            session_id: setup.session_id,
            device_id: device_id.as_str(),
            role: setup.role,
            epoch: setup.epoch,
            config: self.config.clone(),
        })?;
        Ok(SessionPath::new(path, device_id))
    }

    fn device_id(&self, device_id: &str) -> Result<DeviceId, SessionClientError> {
        DeviceId::new(device_id).map_err(|error| SessionClientError::InvalidDevice {
            device_id: device_id.to_owned(),
            reason: error.to_string(),
        })
    }
}

impl Default for SessionClient {
    fn default() -> Self {
        Self::new()
    }
}

/// A connected session: one path, one demultiplexing reader, and the streams that ride it.
#[derive(Debug)]
pub struct SessionPath {
    path: Arc<ConnectedPath>,
    device_id: DeviceId,
    hub: ProxyHub,
}

impl SessionPath {
    fn new(path: ConnectedPath, device_id: DeviceId) -> Self {
        let path = Arc::new(path);
        let hub = ProxyHub::new(Arc::clone(&path));
        Self {
            path,
            device_id,
            hub,
        }
    }

    /// The path path selection actually committed: direct or relay.
    pub fn path_kind(&self) -> PathKind {
        self.path.path_kind()
    }

    pub fn session_id(&self) -> &str {
        self.path.session_id()
    }

    pub fn device_id(&self) -> &DeviceId {
        &self.device_id
    }

    /// Builds the proxy pump for `stream`. One pump is active per stream at a time; different
    /// streams run concurrently through the session's single reader.
    pub async fn proxy_session(
        &self,
        stream: &str,
        limits: ProxyLimits,
    ) -> Result<ProxySession, ProxyError> {
        self.hub
            .proxy_session(&self.device_id, stream, limits)
            .await
    }

    /// True when the session can still carry frames: the path was not shut down and the
    /// hub's reader has not failed. A caller that keeps a session across endpoints checks
    /// this before reusing it.
    pub async fn is_usable(&self) -> bool {
        !self.path.is_closed().await && !self.hub.is_closed()
    }

    /// Resolves when the hub's reader fails, so a serving endpoint can stop instead of
    /// waiting for a connection it could never carry.
    pub async fn wait_closed(&self) {
        self.hub.wait_closed().await;
    }

    /// Tears the path down. The relay keepalive stops and the direct socket closes.
    pub async fn shutdown(&self) -> Result<(), PathError> {
        self.path.shutdown().await
    }
}
