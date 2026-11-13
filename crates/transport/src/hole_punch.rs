//! Authenticated UDP hole punching and the direct data path that follows it.
//!
//! Every datagram carries the rendezvous nonce and an HMAC-SHA256 tag over the whole
//! packet. The key is derived from the ticket's probe key, the session id, the nonce, and
//! the sender's role, so a packet minted for another session, another ticket, or the
//! opposite role never authenticates. Authentication happens before any sequence is
//! accepted, and a 64-entry replay window rejects a captured probe, acknowledgement, or
//! frame instead of validating a path with it.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::net::UdpSocket;

type HmacSha256 = Hmac<Sha256>;

const MAGIC: &[u8] = b"PCPROBE1";
/// magic + kind + role + seq + nonce digest + body length.
const HEADER_LEN: usize = 8 + 1 + 1 + 4 + 32 + 2;
const MAC_LEN: usize = 32;
const NONCE_DIGEST_LEN: usize = 32;
const KEY_LABEL: &[u8] = b"phoneconnect-direct-path-v1";

/// Largest direct-path frame. A UDP datagram cannot carry more than 65 507 bytes of
/// payload; larger frames belong on the relay.
pub const MAX_DIRECT_FRAME_BYTES: usize = 60_000;

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
    #[error("socket operation failed: {reason}")]
    Io { reason: String },
}

/// The authenticated, nonce-bound material one ticket grants for the direct path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProbeCredentials {
    session_id: String,
    role: TicketRole,
    nonce: String,
    nonce_digest: [u8; NONCE_DIGEST_LEN],
    probe_key: Vec<u8>,
    expires_at: i64,
}

impl ProbeCredentials {
    pub fn new(
        session_id: impl Into<String>,
        role: TicketRole,
        nonce: impl Into<String>,
        probe_key: Vec<u8>,
        expires_at: i64,
    ) -> Result<Self, HolePunchError> {
        if probe_key.len() != 32 {
            return Err(HolePunchError::Unauthenticated);
        }
        let nonce = nonce.into();
        if nonce.is_empty() {
            return Err(HolePunchError::Unauthenticated);
        }
        let nonce_digest: [u8; NONCE_DIGEST_LEN] = Sha256::digest(nonce.as_bytes()).into();
        Ok(Self {
            session_id: session_id.into(),
            role,
            nonce,
            nonce_digest,
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

    pub fn nonce(&self) -> &str {
        &self.nonce
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
        mac.update(&self.nonce_digest);
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
    /// One framed PhoneConnect envelope.
    Frame { seq: u32, payload: Vec<u8> },
}

const KIND_PROBE: u8 = 1;
const KIND_ACK: u8 = 2;
const KIND_FRAME: u8 = 3;

impl ProbePacket {
    pub fn probe(seq: u32) -> Self {
        Self::Probe { seq }
    }

    pub fn ack(seq: u32, echo: u32) -> Self {
        Self::Ack { seq, echo }
    }

    pub fn frame(seq: u32, payload: Vec<u8>) -> Result<Self, HolePunchError> {
        if payload.len() > MAX_DIRECT_FRAME_BYTES {
            return Err(HolePunchError::Malformed);
        }
        Ok(Self::Frame { seq, payload })
    }

    pub fn seq(&self) -> u32 {
        match self {
            Self::Probe { seq } | Self::Ack { seq, .. } | Self::Frame { seq, .. } => *seq,
        }
    }

    /// Serializes the packet and authenticates it with the sender's credentials.
    pub fn encode(&self, credentials: &ProbeCredentials) -> Vec<u8> {
        let (kind, body): (u8, Vec<u8>) = match self {
            Self::Probe { .. } => (KIND_PROBE, Vec::new()),
            Self::Ack { echo, .. } => (KIND_ACK, echo.to_be_bytes().to_vec()),
            Self::Frame { payload, .. } => (KIND_FRAME, payload.clone()),
        };
        let mut datagram = Vec::with_capacity(HEADER_LEN + body.len() + MAC_LEN);
        datagram.extend_from_slice(MAGIC);
        datagram.push(kind);
        datagram.push(credentials.role.byte());
        datagram.extend_from_slice(&self.seq().to_be_bytes());
        datagram.extend_from_slice(&credentials.nonce_digest);
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
        if datagram[14..HEADER_LEN - 2] != credentials.nonce_digest {
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

        match kind {
            KIND_PROBE if body.is_empty() => Ok(Self::Probe { seq }),
            KIND_ACK if body.len() == 4 => Ok(Self::Ack {
                seq,
                echo: u32::from_be_bytes([body[0], body[1], body[2], body[3]]),
            }),
            KIND_FRAME => {
                if body.is_empty() {
                    return Err(HolePunchError::Malformed);
                }
                Ok(Self::Frame {
                    seq,
                    payload: body.to_vec(),
                })
            }
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

/// A validated direct path: the socket, the peer, the authenticator, and the outbound
/// sequence counter. Probing and framed traffic share one sequence space, so a probe
/// captured from the handshake can never be replayed as a frame.
pub struct HolePuncher {
    socket: Arc<UdpSocket>,
    credentials: ProbeCredentials,
    authenticator: ProbeAuthenticator,
    seq: AtomicU32,
}

impl std::fmt::Debug for HolePuncher {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("HolePuncher")
            .field("session_id", &self.credentials.session_id)
            .field("role", &self.credentials.role)
            .finish_non_exhaustive()
    }
}

/// Outcome of a successful hole punch.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HolePunchOutcome {
    pub peer: SocketAddr,
    pub rtt: Duration,
}

impl HolePuncher {
    pub fn new(socket: Arc<UdpSocket>, credentials: ProbeCredentials) -> Self {
        Self {
            socket,
            authenticator: ProbeAuthenticator::new(&credentials),
            credentials,
            seq: AtomicU32::new(0),
        }
    }

    pub fn credentials(&self) -> &ProbeCredentials {
        &self.credentials
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

    /// Probes every direct candidate until one returns an authenticated acknowledgement.
    ///
    /// Each attempt sends one probe per candidate and waits at most
    /// `config.attempt_timeout`; after `config.max_attempts` the exchange fails with
    /// [`HolePunchError::Timeout`]. Authenticated probes from the peer are acknowledged
    /// immediately, so the opposite peer validates the path too.
    pub async fn punch(
        &self,
        candidates: &[SocketAddr],
        config: ProbeConfig,
    ) -> Result<HolePunchOutcome, HolePunchError> {
        if candidates.is_empty() {
            return Err(HolePunchError::Timeout { attempts: 0 });
        }
        let mut buffered = vec![0u8; 65_535];
        let mut attempts = 0;
        for _ in 0..config.max_attempts {
            attempts += 1;
            let seq = self.next_seq()?;
            let probe = ProbePacket::probe(seq).encode(&self.credentials);
            let sent_at = Instant::now();
            for candidate in candidates {
                self.send_datagram(&probe, *candidate).await?;
            }

            let deadline = sent_at + config.attempt_timeout;
            loop {
                let now = Instant::now();
                if now >= deadline {
                    break;
                }
                let remaining = deadline - now;
                let received =
                    tokio::time::timeout(remaining, self.socket.recv_from(&mut buffered)).await;
                let Ok(Ok((length, from))) = received else {
                    break;
                };
                if !candidates.contains(&from) {
                    continue;
                }
                match self.authenticator.accept(&buffered[..length]) {
                    Ok(ProbePacket::Ack { echo, .. }) if echo == seq => {
                        return Ok(HolePunchOutcome {
                            peer: from,
                            rtt: sent_at.elapsed(),
                        });
                    }
                    Ok(ProbePacket::Probe { seq: peer_seq }) => {
                        let ack =
                            ProbePacket::ack(self.next_seq()?, peer_seq).encode(&self.credentials);
                        self.send_datagram(&ack, from).await?;
                    }
                    Ok(_) => {}
                    Err(HolePunchError::Replayed | HolePunchError::Unauthenticated) => {}
                    Err(error) => return Err(error),
                }
            }
        }
        Err(HolePunchError::Timeout { attempts })
    }

    /// Sends one framed envelope to the validated peer.
    pub async fn send_frame(&self, peer: SocketAddr, frame: &[u8]) -> Result<(), HolePunchError> {
        let seq = self.next_seq()?;
        let packet = ProbePacket::Frame {
            seq,
            payload: frame.to_vec(),
        }
        .encode(&self.credentials);
        self.send_datagram(&packet, peer).await
    }

    /// Waits for one authenticated frame from `peer`. Probes, acknowledgements, and
    /// datagrams from any other address are ignored; a replay or a failed tag never
    /// surfaces as data.
    pub async fn recv_frame(
        &self,
        peer: SocketAddr,
        timeout: Duration,
    ) -> Result<Vec<u8>, HolePunchError> {
        let mut buffered = vec![0u8; 65_535];
        let deadline = Instant::now() + timeout;
        loop {
            let now = Instant::now();
            if now >= deadline {
                return Err(HolePunchError::ReceiveTimeout);
            }
            let received =
                tokio::time::timeout(deadline - now, self.socket.recv_from(&mut buffered)).await;
            let Ok(Ok((length, from))) = received else {
                return Err(HolePunchError::ReceiveTimeout);
            };
            if from != peer {
                continue;
            }
            match self.authenticator.accept(&buffered[..length]) {
                Ok(ProbePacket::Frame { payload, .. }) => return Ok(payload),
                Ok(ProbePacket::Probe { seq }) => {
                    let ack = ProbePacket::ack(self.next_seq()?, seq).encode(&self.credentials);
                    self.send_datagram(&ack, from).await?;
                }
                Ok(ProbePacket::Ack { .. }) => {}
                Err(HolePunchError::Replayed | HolePunchError::Unauthenticated) => {}
                Err(error) => return Err(error),
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
