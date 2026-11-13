//! PhoneConnect path transport.
//!
//! The transport carries the same PhoneConnect frames over the lowest-latency path that
//! both peers have authenticated: a direct UDP path established with authenticated hole
//! punching, or the server's bounded relay. It is platform-independent on purpose so the
//! native client and the Android agent (through its transport adapter) share one
//! implementation, and every I/O seam is either a Tokio socket or the [`RelayChannel`]
//! trait, which keeps the state machine testable without a network.
//!
//! Security properties this crate enforces:
//! - A ticket must carry a valid server signature over session, device, role, nonce,
//!   probe key, and expiry before any candidate is probed ([`Ticket::verify`]).
//! - Every direct datagram is authenticated with an HMAC keyed by the ticket's probe key
//!   and rendezvous nonce, so a probe or frame minted for another ticket never validates.
//! - Every accepted datagram advances a 64-entry replay window, so a captured probe,
//!   acknowledgement, or frame cannot validate a path or be redelivered.
//! - Probing is bounded in attempts and time per attempt; silence is reported as an
//!   explicit failure rather than an indefinite wait.
//! - Relay frames are bounded by [`FrameLimits`]; a control path uses
//!   [`FrameLimits::control_only`], which refuses an oversized frame from its length
//!   prefix before any body is buffered.

#![deny(unsafe_code)]

pub mod candidates;
pub mod hole_punch;
pub mod path;

use std::sync::Arc;

use futures_util::SinkExt;
use futures_util::stream::{SplitSink, SplitStream, StreamExt};
use tokio::sync::Mutex;
use tokio_tungstenite::MaybeTlsStream;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;

pub use candidates::{
    CandidateError, CandidateKind, CandidateSet, EndpointCandidate, RendezvousCandidates,
};
pub use hole_punch::{
    HolePunchError, ProbeAuthenticator, ProbeConfig, ProbeCredentials, ProbePacket, TicketRole,
};
pub use path::{
    ConnectedPath, PathConfig, PathController, PathError, PathKind, PathSetup, RelayChannel,
    RelayError, Ticket, TicketError,
};

/// Converts a server-advertised relay endpoint into the WebSocket URL a peer attaches to.
///
/// The server advertises `http(s)://…/api/sessions`, and one session's transport lives at
/// `<base>/<session_id>/relay`. A caller that already holds a `ws(s)://` URL passes it
/// through unchanged.
pub fn relay_url(endpoint: &str, session_id: &str) -> String {
    let base = endpoint.trim_end_matches('/');
    if base.ends_with(&format!("/{session_id}/relay")) {
        return base.to_owned();
    }
    format!("{base}/{session_id}/relay")
}

type WebSocket = WebSocketStream<MaybeTlsStream<tokio::net::TcpStream>>;

/// WebSocket implementation of [`RelayChannel`] against the server's relay route.
///
/// Each binary WebSocket message carries exactly one PhoneConnect frame, so the relay
/// forwards bytes it never rewrites. Text messages and oversized messages are refused.
pub struct WebSocketRelay {
    sink: Mutex<SplitSink<WebSocket, Message>>,
    stream: Mutex<SplitStream<WebSocket>>,
    max_frame_bytes: usize,
}

impl WebSocketRelay {
    /// Attaches to `url` with the caller's session capability or device credential.
    ///
    /// A relay that answers `409 relay_unavailable` is reported as
    /// [`RelayError::Unavailable`], which is terminal for that session id: the caller must
    /// create a new session rather than retry on the same one.
    pub async fn connect(
        url: &str,
        bearer: &str,
        max_frame_bytes: usize,
    ) -> Result<Arc<Self>, RelayError> {
        let mut request = self::request(url)?;
        request.headers_mut().insert(
            "authorization",
            format!("Bearer {bearer}")
                .parse()
                .map_err(|_| RelayError::Malformed {
                    reason: "bearer token is not a valid header value".to_owned(),
                })?,
        );
        let (socket, _response) = tokio_tungstenite::connect_async(request)
            .await
            .map_err(connect_error)?;
        let (sink, stream) = socket.split();
        Ok(Arc::new(Self {
            sink: Mutex::new(sink),
            stream: Mutex::new(stream),
            max_frame_bytes,
        }))
    }
}

#[async_trait::async_trait]
impl RelayChannel for WebSocketRelay {
    async fn send_frame(&self, frame: &[u8]) -> Result<(), RelayError> {
        if frame.len() > self.max_frame_bytes {
            return Err(RelayError::Malformed {
                reason: format!(
                    "frame of {} bytes exceeds the {}-byte relay limit",
                    frame.len(),
                    self.max_frame_bytes
                ),
            });
        }
        self.sink
            .lock()
            .await
            .send(Message::Binary(frame.to_vec().into()))
            .await
            .map_err(socket_error)
    }

    async fn recv_frame(&self) -> Result<Vec<u8>, RelayError> {
        loop {
            let message = self.stream.lock().await.next().await;
            match message {
                Some(Ok(Message::Binary(bytes))) => {
                    if bytes.len() > self.max_frame_bytes {
                        return Err(RelayError::Malformed {
                            reason: format!(
                                "relay sent {} bytes, over the {}-byte limit",
                                bytes.len(),
                                self.max_frame_bytes
                            ),
                        });
                    }
                    return Ok(bytes.to_vec());
                }
                Some(Ok(Message::Close(frame))) => {
                    return Err(RelayError::Closed {
                        reason: frame
                            .map(|frame| frame.reason.to_string())
                            .unwrap_or_default(),
                    });
                }
                Some(Ok(Message::Ping(_) | Message::Pong(_))) => {}
                Some(Ok(Message::Text(_))) => {
                    return Err(RelayError::Malformed {
                        reason: "relay sent a text message; PhoneConnect frames are binary"
                            .to_owned(),
                    });
                }
                Some(Ok(Message::Frame(_))) => {}
                Some(Err(error)) => return Err(socket_error(error)),
                None => {
                    return Err(RelayError::Closed {
                        reason: String::new(),
                    });
                }
            }
        }
    }

    async fn close(&self) -> Result<(), RelayError> {
        self.sink.lock().await.close().await.map_err(socket_error)
    }
}

fn request(
    url: &str,
) -> Result<tokio_tungstenite::tungstenite::handshake::client::Request, RelayError> {
    let normalized = normalize_ws_url(url)?;
    normalized
        .as_str()
        .into_client_request()
        .map_err(|error| RelayError::Malformed {
            reason: error.to_string(),
        })
}

fn normalize_ws_url(url: &str) -> Result<String, RelayError> {
    let trimmed = url.trim();
    let normalized = if let Some(rest) = trimmed.strip_prefix("https://") {
        format!("wss://{rest}")
    } else if let Some(rest) = trimmed.strip_prefix("http://") {
        format!("ws://{rest}")
    } else if trimmed.starts_with("ws://") || trimmed.starts_with("wss://") {
        trimmed.to_owned()
    } else {
        return Err(RelayError::Malformed {
            reason: format!("relay endpoint {trimmed} is not an http(s) or ws(s) URL"),
        });
    };
    Ok(normalized)
}

fn connect_error(error: tokio_tungstenite::tungstenite::Error) -> RelayError {
    use tokio_tungstenite::tungstenite::Error;
    match error {
        Error::Http(response) => match response.status().as_u16() {
            409 | 404 | 410 => RelayError::Unavailable,
            status => RelayError::Refused { status },
        },
        other => RelayError::Malformed {
            reason: other.to_string(),
        },
    }
}

fn socket_error(error: tokio_tungstenite::tungstenite::Error) -> RelayError {
    use tokio_tungstenite::tungstenite::Error;
    match error {
        Error::ConnectionClosed | Error::AlreadyClosed => RelayError::Closed {
            reason: String::new(),
        },
        other => RelayError::Malformed {
            reason: other.to_string(),
        },
    }
}
