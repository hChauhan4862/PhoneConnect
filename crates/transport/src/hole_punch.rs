//! Authenticated UDP hole punching and the direct data path that follows it.
//!
//! Every datagram carries the rendezvous round id and an HMAC-SHA256 tag over the whole
//! packet. The key is derived from the round's shared probe key, the session id, and the
//! sender's role, so a packet minted for another session, another round, or the opposite
//! role never authenticates. Authentication happens before any sequence is
//! accepted, and a 64-entry replay window rejects a captured probe, acknowledgement, or
//! frame instead of validating a path with it.
//!
//! One task owns every socket read ([`DirectSocket`]). Probes, acknowledgements, frames,
//! and switch requests are dispatched by kind, so a concurrent upgrade can never steal the
//! peer's acknowledgement or drop a data frame: frames always reach the frame queue.
//!
//! A direct path pins the peer's address. Frames sent to an address that no longer reaches
//! the peer are still reported as sent; delivery is confirmed by the peer's frames and by
//! the switch handshake, never by `send_to` succeeding.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;
use tokio::sync::{broadcast, mpsc};

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8] = b"PCPROBE1";
/// magic + kind + role + seq + round id + body length.
const HEADER_LEN: usize = 8 + 1 + 1 + 4 + 32 + 2;
const MAC_LEN: usize = 32;
const NONCE_DIGEST_LEN: usize = 32;
const KEY_LABEL: &[u8] = b"phoneconnect-direct-path-v1";

/// Largest direct-path frame. A UDP datagram cannot carry more than 65 507 bytes of
/// payload; larger frames belong on the relay.
pub const MAX_DIRECT_FRAME_BYTES: usize = 60_000;

/// Frames a direct socket buffers for the reader before it applies backpressure.
pub const DIRECT_FRAME_QUEUE: usize = 64;

/// Switch/acknowledgement events a direct socket can hold for the path state machine.
const DIRECT_CONTROL_QUEUE: usize = 16;

/// Acks an in-flight punch can observe.
const DIRECT_ACK_FANOUT: usize = 64;

/// Which end of the session a peer is.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TicketRole {
    Client,
    Device,
}

impl TicketRole {
    pub fn opposite(self) -> Self {
        match self {
            Self::Client => Self::Device,
            Self::Device => Self::Client,
        }
    }

    fn byte(self) -> u8 {
        match self {
            Self::Client => 1,
            Self::Device => 2,
        }
    }

    fn from_byte(byte: u8) -> Option<Self> {
        match byte {
            1 => Some(Self::Client),
            2 => Some(Self::Device),
            _ => None,
        }
    }
}

/// Bounds for hole punching. Every attempt waits at most `attempt_timeout` and the whole
/// exchange stops after `max_attempts`, so silence is bounded in time.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProbeConfig {
    pub attempt_timeout: Duration,
    pub max_attempts: u32,
}

impl Default for ProbeConfig {
    fn default() -> Self {
        Self {
            attempt_timeout: Duration::from_millis(250),
            max_attempts: 4,
        }
    }
}

/// Explicit direct-path failures. A candidate is never reported as validated on an
/// assumption: each variant names the check that failed.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum HolePunchError {
    #[error("datagram is not a PhoneConnect probe")]
    Malformed,
    #[error("probe failed authentication")]
    Unauthenticated,
    #[error("probe was already seen; replay rejected")]
    Replayed,
    #[error("probe sequence is exhausted")]
    SequenceExhausted,
    #[error("no candidate answered {attempts} authenticated probes")]
    Timeout { attempts: u32 },
    #[error("direct path received no authenticated frame before its deadline")]
    ReceiveTimeout,
    #[error("direct frame of {length} bytes exceeds the {limit}-byte datagram limit")]
    FrameTooLarge { length: usize, limit: usize },
    #[error("the peer never confirmed the direct switch")]
    SwitchUnconfirmed,
    #[error("direct socket is closed")]
    Closed,
    #[error("socket operation failed: {reason}")]
    Io { reason: String },
}

/// The material one rendezvous round grants for the direct path.
///
/// Probes are bound to the round's shared probe key, not to a ticket's redemption nonce: a
/// peer that re-requests a ticket gets a new nonce but must still interoperate with the peer
/// that holds the older ticket from the same round.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCredentials {
    session_id: String,
    role: TicketRole,
    round_id: [u8; NONCE_DIGEST_LEN],
    probe_key: Vec<u8>,
    expires_at: i64,
}

impl ProbeCredentials {
    pub fn new(
        session_id: impl Into<String>,
        role: TicketRole,
        probe_key: Vec<u8>,
        expires_at: i64,
    ) -> Result<Self, HolePunchError> {
        if probe_key.len() != 32 {
            return Err(HolePunchError::Unauthenticated);
        }
        let round_id: [u8; NONCE_DIGEST_LEN] = Sha256::digest(&probe_key).into();
        Ok(Self {
            session_id: session_id.into(),
            role,
            round_id,
            probe_key,
            expires_at,
        })
    }

    pub fn session_id(&self) -> &str {
        &self.session_id
    }

    pub fn role(&self) -> TicketRole {
        self.role
    }

    /// Identifier of the rendezvous round this peer probes on, derived from the round key.
    pub fn round_id(&self) -> String {
        self.round_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    pub fn expires_at(&self) -> i64 {
        self.expires_at
    }

    pub fn is_expired(&self, now_ms: i64) -> bool {
        now_ms >= self.expires_at
    }

    fn key_for(&self, role: TicketRole) -> [u8; 32] {
        let mut mac =
            HmacSha256::new_from_slice(&self.probe_key).expect("HMAC accepts a 32-byte key");
        mac.update(KEY_LABEL);
        mac.update(self.session_id.as_bytes());
        mac.update(&[0]);
        mac.update(&self.round_id);
        mac.update(&[role.byte()]);
        let tag = mac.finalize().into_bytes();
        let mut key = [0u8; 32];
        key.copy_from_slice(&tag);
        key
    }
}

/// One authenticated datagram on the direct path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProbePacket {
    /// A hole-punch probe awaiting an acknowledgement.
    Probe { seq: u32 },
    /// An acknowledgement. `seq` is the acknowledger's own counter and `echo` is the probe
    /// it answers, so acknowledgements never share a sequence space with probes.
    Ack { seq: u32, echo: u32 },
    /// One sealed PhoneConnect frame.
    Frame { seq: u32, payload: Vec<u8> },
    /// "I validated this path; commit to it."
    Switch { seq: u32 },
    /// "I validated this path too; both sides may commit."
    SwitchAck { seq: u32, echo: u32 },
    /// "I have validated this path and will read it." A side only sends this after its own
    /// switch completed, so the peer commits only when the sender really is reading.
    Confirm { seq: u32 },
}

const KIND_PROBE: u8 = 1;
const KIND_ACK: u8 = 2;
const KIND_FRAME: u8 = 3;
const KIND_SWITCH: u8 = 4;
const KIND_SWITCH_ACK: u8 = 5;
const KIND_CONFIRM: u8 = 6;

impl ProbePacket {
    pub fn probe(seq: u32) -> Self {
        Self::Probe { seq }
    }

    pub fn ack(seq: u32, echo: u32) -> Self {
        Self::Ack { seq, echo }
    }

    pub fn frame(seq: u32, payload: Vec<u8>) -> Result<Self, HolePunchError> {
        if payload.len() > MAX_DIRECT_FRAME_BYTES {
            return Err(HolePunchError::FrameTooLarge {
                length: payload.len(),
                limit: MAX_DIRECT_FRAME_BYTES,
            });
        }
        Ok(Self::Frame { seq, payload })
    }

    pub fn switch(seq: u32) -> Self {
        Self::Switch { seq }
    }

    pub fn switch_ack(seq: u32, echo: u32) -> Self {
        Self::SwitchAck { seq, echo }
    }

    pub fn confirm(seq: u32) -> Self {
        Self::Confirm { seq }
    }

    pub fn seq(&self) -> u32 {
        match self {
            Self::Probe { seq }
            | Self::Ack { seq, .. }
            | Self::Frame { seq, .. }
            | Self::Switch { seq }
            | Self::SwitchAck { seq, .. }
            | Self::Confirm { seq } => *seq,
        }
    }

    /// Serializes the packet and authenticates it with the sender's credentials.
    pub fn encode(&self, credentials: &ProbeCredentials) -> Vec<u8> {
        let (kind, body): (u8, Vec<u8>) = match self {
            Self::Probe { .. } => (KIND_PROBE, Vec::new()),
            Self::Ack { echo, .. } => (KIND_ACK, echo.to_be_bytes().to_vec()),
            Self::Frame { payload, .. } => (KIND_FRAME, payload.clone()),
            Self::Switch { .. } => (KIND_SWITCH, Vec::new()),
            Self::SwitchAck { echo, .. } => (KIND_SWITCH_ACK, echo.to_be_bytes().to_vec()),
            Self::Confirm { .. } => (KIND_CONFIRM, Vec::new()),
        };
        let mut datagram = Vec::with_capacity(HEADER_LEN + body.len() + MAC_LEN);
        datagram.extend_from_slice(MAGIC);
        datagram.push(kind);
        datagram.push(credentials.role.byte());
        datagram.extend_from_slice(&self.seq().to_be_bytes());
        datagram.extend_from_slice(&credentials.round_id);
        datagram.extend_from_slice(&(body.len() as u16).to_be_bytes());
        datagram.extend_from_slice(&body);

        let mut mac = HmacSha256::new_from_slice(&credentials.key_for(credentials.role))
            .expect("HMAC accepts a 32-byte key");
        mac.update(&datagram);
        datagram.extend_from_slice(&mac.finalize().into_bytes());
        datagram
    }

    /// Verifies and parses a datagram received by `credentials`' peer. Every rejection is
    /// [`HolePunchError::Malformed`] or [`HolePunchError::Unauthenticated`]; nothing about
    /// a failed tag is exposed.
    pub fn decode(datagram: &[u8], credentials: &ProbeCredentials) -> Result<Self, HolePunchError> {
        if datagram.len() < HEADER_LEN + MAC_LEN || &datagram[..MAGIC.len()] != MAGIC {
            return Err(HolePunchError::Malformed);
        }
        let kind = datagram[8];
        let sender_role =
            TicketRole::from_byte(datagram[9]).ok_or(HolePunchError::Unauthenticated)?;
        if sender_role == credentials.role {
            // A peer never authenticates its own role: a reflected packet must not
            // validate a path.
            return Err(HolePunchError::Unauthenticated);
        }
        let seq = u32::from_be_bytes([datagram[10], datagram[11], datagram[12], datagram[13]]);
        if datagram[14..HEADER_LEN - 2] != credentials.round_id {
            return Err(HolePunchError::Unauthenticated);
        }
        let body_len =
            u16::from_be_bytes([datagram[HEADER_LEN - 2], datagram[HEADER_LEN - 1]]) as usize;
        if datagram.len() != HEADER_LEN + body_len + MAC_LEN {
            return Err(HolePunchError::Malformed);
        }
        let body = &datagram[HEADER_LEN..HEADER_LEN + body_len];

        let mut mac = HmacSha256::new_from_slice(&credentials.key_for(sender_role))
            .expect("HMAC accepts a 32-byte key");
        mac.update(&datagram[..HEADER_LEN + body_len]);
        mac.verify_slice(&datagram[HEADER_LEN + body_len..])
            .map_err(|_| HolePunchError::Unauthenticated)?;

        let echo = || -> Result<u32, HolePunchError> {
            if body.len() != 4 {
                return Err(HolePunchError::Malformed);
            }
            Ok(u32::from_be_bytes([body[0], body[1], body[2], body[3]]))
        };
        match kind {
            KIND_PROBE if body.is_empty() => Ok(Self::Probe { seq }),
            KIND_ACK => Ok(Self::Ack { seq, echo: echo()? }),
            KIND_FRAME => {
                if body.is_empty() {
                    return Err(HolePunchError::Malformed);
                }
                Ok(Self::Frame {
                    seq,
                    payload: body.to_vec(),
                })
            }
            KIND_SWITCH if body.is_empty() => Ok(Self::Switch { seq }),
            KIND_SWITCH_ACK => Ok(Self::SwitchAck { seq, echo: echo()? }),
            KIND_CONFIRM if body.is_empty() => Ok(Self::Confirm { seq }),
            _ => Err(HolePunchError::Malformed),
        }
    }
}

/// A 64-datagram sliding replay window. A sequence number is accepted at most once, in
/// any order, and anything older than the window is refused rather than guessed at.
#[derive(Debug, Default)]
struct ReplayWindow {
    highest: Option<u32>,
    bitmap: u64,
}

impl ReplayWindow {
    fn check_and_advance(&mut self, seq: u32) -> bool {
        match self.highest {
            None => {
                self.highest = Some(seq);
                self.bitmap = 1;
                true
            }
            Some(highest) if seq > highest => {
                let shift = seq - highest;
                self.bitmap = if shift >= 64 {
                    1
                } else {
                    (self.bitmap << shift) | 1
                };
                self.highest = Some(seq);
                true
            }
            Some(highest) => {
                let offset = highest - seq;
                if offset >= 64 {
                    return false;
                }
                let bit = 1u64 << offset;
                if self.bitmap & bit != 0 {
                    return false;
                }
                self.bitmap |= bit;
                true
            }
        }
    }
}

/// Verifies inbound datagrams and enforces the replay window for one peer.
#[derive(Debug)]
pub struct ProbeAuthenticator {
    credentials: ProbeCredentials,
    window: Mutex<ReplayWindow>,
}

impl ProbeAuthenticator {
    pub fn new(credentials: &ProbeCredentials) -> Self {
        Self {
            credentials: credentials.clone(),
            window: Mutex::new(ReplayWindow::default()),
        }
    }

    /// Authenticates `datagram` and advances the replay window. Authentication happens
    /// before replay state is touched, so a forged packet cannot burn a sequence number.
    pub fn accept(&self, datagram: &[u8]) -> Result<ProbePacket, HolePunchError> {
        let packet = ProbePacket::decode(datagram, &self.credentials)?;
        let mut window = self.window();
        if !window.check_and_advance(packet.seq()) {
            return Err(HolePunchError::Replayed);
        }
        Ok(packet)
    }

    fn window(&self) -> MutexGuard<'_, ReplayWindow> {
        self.window
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }
}

/// Outcome of a successful hole punch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HolePunchOutcome {
    pub peer: SocketAddr,
    pub rtt: Duration,
}

/// Control traffic the path state machine has to see for itself.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DirectEvent {
    /// The peer validated the path and asks to commit to it.
    Switch { from: SocketAddr, echo: u32 },
    /// The peer confirmed our switch request.
    SwitchAck { from: SocketAddr, echo: u32 },
    /// The peer says it is reading the direct path.
    Confirmed { from: SocketAddr },
}

#[derive(Debug, Clone, Copy)]
struct AckEvent {
    from: SocketAddr,
    echo: u32,
}

struct DirectInner {
    socket: Arc<UdpSocket>,
    credentials: std::sync::RwLock<ProbeCredentials>,
    authenticators: std::sync::RwLock<AuthenticatorRing>,
    seq: AtomicU32,
    peer: Mutex<Option<SocketAddr>>,
    acks: broadcast::Sender<AckEvent>,
    events: broadcast::Sender<DirectEvent>,
    frames: mpsc::Sender<Vec<u8>>,
    closed: AtomicBool,
}

/// One authenticated UDP socket, with exactly one task reading it.
///
/// The reader owns `recv_from`; `punch`, `send_frame`, and `recv_frame` only ever wait on
/// queues the reader feeds. That is what makes a concurrent upgrade safe: an
/// acknowledgement cannot be stolen by the data path, and a data frame that arrives while
/// a punch is running is queued rather than discarded.
pub struct DirectSocket {
    inner: Arc<DirectInner>,
    frames: tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>,
    reader: Mutex<Option<tokio::task::JoinHandle<()>>>,
    responder: tokio::task::JoinHandle<()>,
}

impl std::fmt::Debug for DirectSocket {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("DirectSocket")
            .field("session_id", &self.credentials().session_id().to_owned())
            .field("role", &self.credentials().role())
            .field("peer", &self.peer())
            .finish_non_exhaustive()
    }
}

impl DirectSocket {
    /// Starts the single reader for `socket`. The reader lives until the socket errors or
    /// every handle is dropped.
    pub async fn open(
        socket: Arc<UdpSocket>,
        credentials: ProbeCredentials,
    ) -> Result<Self, HolePunchError> {
        let (acks, _) = broadcast::channel(DIRECT_ACK_FANOUT);
        let (events, _) = broadcast::channel(DIRECT_CONTROL_QUEUE);
        let (frames, frame_receiver) = mpsc::channel(DIRECT_FRAME_QUEUE);
        let inner = Arc::new(DirectInner {
            socket,
            authenticators: std::sync::RwLock::new(AuthenticatorRing::new(&credentials)),
            credentials: std::sync::RwLock::new(credentials),
            seq: AtomicU32::new(0),
            peer: Mutex::new(None),
            acks,
            events,
            frames,
            closed: AtomicBool::new(false),
        });
        let reader = tokio::spawn(read_loop(Arc::clone(&inner)));
        let responder = tokio::spawn(switch_responder(Arc::clone(&inner)));
        Ok(Self {
            inner,
            frames: tokio::sync::Mutex::new(frame_receiver),
            reader: Mutex::new(Some(reader)),
            responder,
        })
    }

    /// The round this socket currently sends on.
    pub fn round_id(&self) -> String {
        self.credentials().round_id()
    }

    /// Switches this socket to a new rendezvous round without starting a second reader.
    ///
    /// One task owns `recv_from` for the socket's whole lifetime; rotating the key in place
    /// is what keeps that true. The previous round's authenticator stays valid for a short
    /// overlap so in-flight datagrams are still accepted.
    pub fn rekey(&self, credentials: ProbeCredentials) {
        if let Ok(mut ring) = self.inner.authenticators.write() {
            ring.rotate(&credentials);
        }
        if let Ok(mut current) = self.inner.credentials.write() {
            *current = credentials;
        }
    }

    fn credentials(&self) -> ProbeCredentials {
        self.inner
            .credentials
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .clone()
    }

    pub fn local_addr(&self) -> Result<SocketAddr, HolePunchError> {
        self.inner
            .socket
            .local_addr()
            .map_err(|error| HolePunchError::Io {
                reason: error.to_string(),
            })
    }

    /// The validated peer, once a punch succeeded.
    pub fn peer(&self) -> Option<SocketAddr> {
        *self.inner.peer()
    }

    fn set_peer(&self, peer: SocketAddr) {
        *self.inner.peer() = Some(peer);
    }

    pub fn is_closed(&self) -> bool {
        self.inner.closed.load(Ordering::SeqCst)
    }

    /// Stops the reader and the switch responder. Idempotent.
    pub fn close(&self) {
        self.inner.closed.store(true, Ordering::SeqCst);
        if let Some(reader) = self
            .reader
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .take()
        {
            reader.abort();
        }
        self.responder.abort();
    }

    pub fn next_seq(&self) -> Result<u32, HolePunchError> {
        self.inner.next_seq()
    }

    /// Probes every direct candidate until one returns an authenticated acknowledgement.
    ///
    /// Each attempt sends one probe per candidate and waits at most
    /// `config.attempt_timeout`; after `config.max_attempts` the exchange fails with
    /// [`HolePunchError::Timeout`]. Probes from the peer are acknowledged by the reader, so
    /// the opposite peer validates the path too.
    pub async fn punch(
        &self,
        candidates: &[SocketAddr],
        config: ProbeConfig,
    ) -> Result<HolePunchOutcome, HolePunchError> {
        if candidates.is_empty() {
            return Err(HolePunchError::Timeout { attempts: 0 });
        }
        let mut acks = self.inner.acks.subscribe();
        let mut attempts = 0;
        for _ in 0..config.max_attempts {
            attempts += 1;
            let seq = self.inner.next_seq()?;
            let credentials = self.credentials();
            let probe = ProbePacket::probe(seq).encode(&credentials);
            let sent_at = Instant::now();
            for candidate in candidates {
                self.inner.send_datagram(&probe, *candidate).await?;
            }

            let deadline = sent_at + config.attempt_timeout;
            loop {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                match tokio::time::timeout(deadline - now, acks.recv()).await {
                    Ok(Ok(event)) if event.echo == seq && candidates.contains(&event.from) => {
                        self.set_peer(event.from);
                        return Ok(HolePunchOutcome {
                            peer: event.from,
                            rtt: sent_at.elapsed(),
                        });
                    }
                    Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                    _ => break,
                }
            }
        }
        Err(HolePunchError::Timeout { attempts })
    }

    /// Commits both peers to this path.
    ///
    /// The caller has already validated the path locally. It asks the peer to commit and
    /// waits for the peer's confirmation, re-sending on a bounded retry schedule. A peer
    /// that has not validated the path never confirms, so a one-sided punch leaves both
    /// sides on the relay instead of black-holing frames on a path only one side uses.
    pub async fn negotiate_switch(
        &self,
        peer: SocketAddr,
        config: SwitchConfig,
    ) -> Result<(), HolePunchError> {
        let mut events = self.inner.events.subscribe();
        let deadline = Instant::now() + config.total_timeout();
        let mut next_request = Instant::now();
        let mut pending: Option<u32> = None;

        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(HolePunchError::SwitchUnconfirmed);
            }
            // Re-ask on the retry schedule: the peer may still be validating when the first
            // request arrives, and a request it ignored is not a refusal.
            if now >= next_request {
                let seq = self.inner.next_seq()?;
                self.inner
                    .send_datagram(&ProbePacket::switch(seq).encode(&self.credentials()), peer)
                    .await?;
                pending = Some(seq);
                next_request = now + config.retry_interval();
            }

            let wake_at = next_request.min(deadline);
            let remaining = wake_at.saturating_duration_since(Instant::now());
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Ok(DirectEvent::Switch { from, echo })) => {
                    // Both peers may ask at once; answer while waiting for our own answer.
                    let _ = self.accept_switch_if_validated(from, echo).await;
                }
                Ok(Ok(DirectEvent::SwitchAck { from, echo }))
                    if from == peer && pending == Some(echo) =>
                {
                    return Ok(());
                }
                Ok(Ok(DirectEvent::SwitchAck { .. } | DirectEvent::Confirmed { .. })) => {}
                Ok(Err(broadcast::error::RecvError::Lagged(_))) => {}
                Ok(Err(broadcast::error::RecvError::Closed)) => {
                    return Err(HolePunchError::Closed);
                }
                Err(_) => {}
            }
        }
    }

    /// Answers a peer's switch request, but only from the validated peer. An unvalidated
    /// peer stays silent, which is what makes the handshake two-sided.
    async fn accept_switch_if_validated(
        &self,
        from: SocketAddr,
        echo: u32,
    ) -> Result<(), HolePunchError> {
        if *self.inner.peer() != Some(from) {
            return Ok(());
        }
        let seq = self.inner.next_seq()?;
        self.inner
            .send_datagram(
                &ProbePacket::switch_ack(seq, echo).encode(&self.credentials()),
                from,
            )
            .await
    }

    /// Tells the peer this side now reads the direct path, after its own switch completed.
    pub async fn send_confirm(&self, peer: SocketAddr) -> Result<(), HolePunchError> {
        let seq = self.inner.next_seq()?;
        self.inner
            .send_datagram(&ProbePacket::confirm(seq).encode(&self.credentials()), peer)
            .await
    }

    /// Subscribes to switch and confirmation events. Subscribe *before* sending anything a
    /// peer may answer, so a fast answer is never missed.
    pub fn subscribe(&self) -> broadcast::Receiver<DirectEvent> {
        self.inner.events.subscribe()
    }

    /// Waits on an already-subscribed event stream for the peer's confirmation, bounded. A
    /// peer that is not reading the direct path never sends one, and the caller must keep
    /// the relay as the delivery path.
    pub async fn await_confirmation(
        &self,
        events: &mut broadcast::Receiver<DirectEvent>,
        peer: SocketAddr,
        timeout: Duration,
    ) -> bool {
        let deadline = Instant::now() + timeout;
        loop {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                return false;
            }
            match tokio::time::timeout(remaining, events.recv()).await {
                Ok(Ok(DirectEvent::Confirmed { from })) if from == peer => return true,
                Ok(Ok(_)) | Ok(Err(broadcast::error::RecvError::Lagged(_))) => continue,
                Ok(Err(broadcast::error::RecvError::Closed)) => return false,
                Err(_) => return false,
            }
        }
    }

    /// Acknowledges a peer's switch request after the local path state machine decided the
    /// peer is validated.
    pub async fn accept_switch(&self, from: SocketAddr, echo: u32) -> Result<(), HolePunchError> {
        self.accept_switch_if_validated(from, echo).await
    }

    /// Sends one sealed (already encrypted) frame to the validated peer.
    pub async fn send_frame(&self, peer: SocketAddr, sealed: &[u8]) -> Result<(), HolePunchError> {
        let packet = ProbePacket::frame(self.inner.next_seq()?, sealed.to_vec())?;
        self.inner
            .send_datagram(&packet.encode(&self.credentials()), peer)
            .await
    }

    /// Waits for one sealed frame from the validated peer. Probing and switch traffic never
    /// appears here, and a replay or a failed tag never surfaces as data.
    pub async fn recv_frame(&self, timeout: Duration) -> Result<Vec<u8>, HolePunchError> {
        let mut frames = self.frames.lock().await;
        match tokio::time::timeout(timeout, frames.recv()).await {
            Ok(Some(frame)) => {
                if self.inner.closed.load(Ordering::SeqCst) && frame.is_empty() {
                    return Err(HolePunchError::Closed);
                }
                Ok(frame)
            }
            Ok(None) => Err(HolePunchError::Closed),
            Err(_) => Err(HolePunchError::ReceiveTimeout),
        }
    }
}

impl Drop for DirectSocket {
    fn drop(&mut self) {
        self.close();
    }
}

/// Current round authenticator plus the previous one during a rotation overlap.
struct AuthenticatorRing {
    current: ProbeAuthenticator,
    previous: Option<(ProbeAuthenticator, Instant)>,
}

/// How long datagrams from the previous round are still accepted after a rotation.
const REKEY_OVERLAP: Duration = Duration::from_secs(2);

impl AuthenticatorRing {
    fn new(credentials: &ProbeCredentials) -> Self {
        Self {
            current: ProbeAuthenticator::new(credentials),
            previous: None,
        }
    }

    fn rotate(&mut self, credentials: &ProbeCredentials) {
        let next = ProbeAuthenticator::new(credentials);
        let previous = std::mem::replace(&mut self.current, next);
        self.previous = Some((previous, Instant::now() + REKEY_OVERLAP));
    }

    fn accept(&self, datagram: &[u8]) -> Result<ProbePacket, HolePunchError> {
        match self.current.accept(datagram) {
            Err(HolePunchError::Unauthenticated) => match &self.previous {
                Some((previous, retire_at)) if Instant::now() < *retire_at => {
                    previous.accept(datagram)
                }
                _ => Err(HolePunchError::Unauthenticated),
            },
            other => other,
        }
    }
}

impl DirectInner {
    fn accept(&self, datagram: &[u8]) -> Result<ProbePacket, HolePunchError> {
        self.authenticators
            .read()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accept(datagram)
    }

    fn peer(&self) -> MutexGuard<'_, Option<SocketAddr>> {
        self.peer
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
    }

    fn next_seq(&self) -> Result<u32, HolePunchError> {
        let mut current = self.seq.load(Ordering::SeqCst);
        loop {
            let next = current
                .checked_add(1)
                .ok_or(HolePunchError::SequenceExhausted)?;
            match self
                .seq
                .compare_exchange(current, next, Ordering::SeqCst, Ordering::SeqCst)
            {
                Ok(_) => return Ok(current),
                Err(actual) => current = actual,
            }
        }
    }

    async fn send_datagram(&self, datagram: &[u8], to: SocketAddr) -> Result<(), HolePunchError> {
        self.socket
            .send_to(datagram, to)
            .await
            .map(|_| ())
            .map_err(|error| HolePunchError::Io {
                reason: error.to_string(),
            })
    }
}

/// Bounded switch confirmation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SwitchConfig {
    pub retries: u32,
    pub timeout: Duration,
    /// How long this side waits for the peer's confirmation after both switches completed.
    pub confirmation_timeout: Duration,
}

impl Default for SwitchConfig {
    fn default() -> Self {
        Self {
            retries: 3,
            timeout: Duration::from_millis(150),
            confirmation_timeout: Duration::from_millis(750),
        }
    }
}

impl SwitchConfig {
    /// Whole handshake deadline, including every retry.
    pub fn total_timeout(&self) -> Duration {
        self.timeout.saturating_mul(self.retries.max(1))
    }

    /// Delay between the first request and a retry.
    pub fn retry_interval(&self) -> Duration {
        self.timeout
    }
}

/// Answers the peer's switch request once this side has validated the path.
///
/// It runs for the life of the socket, so a peer that asks to switch while the path is
/// carrying frames still gets an answer; an unvalidated peer never answers, which is what
/// keeps the handshake two-sided.
async fn switch_responder(inner: Arc<DirectInner>) {
    let mut events = inner.events.subscribe();
    loop {
        match events.recv().await {
            Ok(DirectEvent::Switch { from, echo }) => {
                if *inner.peer() != Some(from) {
                    continue;
                }
                if let Ok(seq) = inner.next_seq() {
                    let credentials = inner
                        .credentials
                        .read()
                        .map(|current| current.clone())
                        .unwrap_or_else(|poisoned| poisoned.into_inner().clone());
                    let ack = ProbePacket::switch_ack(seq, echo).encode(&credentials);
                    let _ = inner.socket.send_to(&ack, from).await;
                }
            }
            Ok(DirectEvent::SwitchAck { .. } | DirectEvent::Confirmed { .. }) => {}
            Err(broadcast::error::RecvError::Lagged(_)) => continue,
            Err(broadcast::error::RecvError::Closed) => return,
        }
        if inner.closed.load(Ordering::SeqCst) {
            return;
        }
    }
}

/// The only reader of the direct socket.
///
/// Authenticate before dispatch, and never let a probe or acknowledgement consume a frame:
/// each kind has one destination.
async fn read_loop(inner: Arc<DirectInner>) {
    let mut buffer = vec![0u8; 65_535];
    loop {
        let received = inner.socket.recv_from(&mut buffer).await;
        let (length, from) = match received {
            Ok(received) => received,
            Err(_) => {
                inner.closed.store(true, Ordering::SeqCst);
                return;
            }
        };
        match inner.accept(&buffer[..length]) {
            Ok(ProbePacket::Probe { seq }) => {
                let credentials = inner
                    .credentials
                    .read()
                    .map(|current| current.clone())
                    .unwrap_or_else(|poisoned| poisoned.into_inner().clone());
                let ack = inner
                    .next_seq()
                    .map(|own| ProbePacket::ack(own, seq).encode(&credentials));
                if let Ok(ack) = ack {
                    let _ = inner.socket.send_to(&ack, from).await;
                }
            }
            Ok(ProbePacket::Ack { echo, .. }) => {
                let _ = inner.acks.send(AckEvent { from, echo });
            }
            Ok(ProbePacket::Switch { seq }) => {
                let _ = inner.events.send(DirectEvent::Switch { from, echo: seq });
            }
            Ok(ProbePacket::SwitchAck { echo, .. }) => {
                let _ = inner.events.send(DirectEvent::SwitchAck { from, echo });
            }
            Ok(ProbePacket::Confirm { .. }) => {
                let _ = inner.events.send(DirectEvent::Confirmed { from });
            }
            Ok(ProbePacket::Frame { payload, .. }) => {
                let known = *inner.peer() == Some(from);
                if !known {
                    continue;
                }
                // Backpressure, not a silent drop: a full queue stalls the reader rather
                // than discarding a frame the session already handed to the path.
                if inner.frames.send(payload).await.is_err() {
                    return;
                }
            }
            Err(HolePunchError::Replayed | HolePunchError::Unauthenticated) => {}
            Err(_) => {}
        }
    }
}
