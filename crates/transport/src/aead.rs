//! End-to-end frame confidentiality.
//!
//! Every PhoneConnect frame is sealed before either path carries it, so the relay forwards
//! ciphertext it cannot interpret and a direct-path observer cannot read the session.
//!
//! Trust model: two static identity keys — the device's, registered at enrollment, and the
//! client's, registered when the session is authorized — agree on a shared secret with
//! X25519. HKDF-SHA256 splits the secret into one key per direction, salted with the session
//! id and a per-connection epoch (both tickets' single-use nonces). The server holds only
//! public identity keys, so it can neither derive a traffic key nor decrypt a frame. The
//! server-issued probe key authenticates hole-punch datagrams only; it is deliberately not
//! used here.
//!
//! Peer identity is trust-on-first-use through the rendezvous service: the ticket that names
//! the peer's public key is server-signed, so a malicious server can substitute it and MITM.
//! Callers authenticate the server over TLS and may pin the peer identity out of band
//! (`PathSetup::with_expected_peer_identity`). The epoch gives fresh keys per connection, not
//! forward secrecy, because the identity keys are long-lived.
//!
//! Each frame uses a fresh 96-bit nonce built from the sender's direction byte and a
//! monotonic counter, and authenticates a header that binds the key id, direction, counter,
//! stream kind, and sequence, together with the session id, as associated data. A captured
//! frame cannot be replayed, a lower counter is a regression, a reflected frame carries the
//! wrong direction, and a frame for another identity pair carries an unknown key id.

use std::collections::HashMap;
use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Mutex, OnceLock};

use base64::Engine;
use base64::engine::general_purpose::URL_SAFE_NO_PAD;
use chacha20poly1305::aead::{Aead, Payload};
use chacha20poly1305::{ChaCha20Poly1305, KeyInit, Nonce};
use hkdf::Hkdf;
use phoneconnect::v1::{Envelope, ProtocolError, StreamKind};
use prost::Message;
use sha2::{Digest, Sha256};
use x25519_dalek::{PublicKey, StaticSecret};

use crate::hole_punch::TicketRole;

/// Bytes in an X25519 identity key.
pub const IDENTITY_KEY_LEN: usize = 32;

/// Bytes of key id carried in a sealed frame and used for lookup.
pub const KEY_ID_LEN: usize = SealedHeader::KEY_ID_LEN;

/// Bytes of the Poly1305 tag appended to every sealed frame.
pub const TAG_LEN: usize = SealedHeader::TAG_LEN;

const AEAD_LABEL: &[u8] = b"phoneconnect-aead-v1";
const KEY_ID_LABEL: &[u8] = b"phoneconnect-key-id-v1";

/// The header layout is a wire contract shared with the relay and the Kotlin port, so it is
/// defined in `phoneconnect` and re-exported here.
pub use phoneconnect::{SEALED_VERSION, SealedHeader};

/// Explicit confidentiality failures. Nothing degrades into plaintext or a silent retry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AeadError {
    #[error("identity key material is invalid")]
    InvalidKeyMaterial,
    #[error("the agreed key is degenerate; refusing to use it")]
    WeakKey,
    #[error("connection epoch is missing or empty; re-register with rendezvous")]
    InvalidEpoch,
    #[error(
        "this connection epoch was already used for this session and role; a new path needs fresh tickets"
    )]
    EpochReused,
    #[error("sealed frame is malformed: {reason}")]
    Malformed { reason: String },
    #[error("sealed frame carries key id {found}; this session uses {expected}")]
    UnknownKeyId { found: String, expected: String },
    #[error("sealed frame was sent in the wrong direction")]
    WrongDirection,
    #[error("frame authentication failed: the ciphertext or its header was changed")]
    Authentication,
    #[error("frame counter {counter} was already received")]
    Replayed { counter: u64 },
    #[error("frame counter {counter} regressed outside the replay window (highest {highest})")]
    CounterRegression { counter: u64, highest: u64 },
    #[error("frame counter space is exhausted; the session must be re-established")]
    CounterExhausted,
    #[error("sealed frame does not contain a valid envelope: {reason}")]
    InvalidEnvelope { reason: String },
    #[error("sealed header declares {header:?} but the envelope it delivers is {envelope:?}")]
    StreamKindMismatch {
        header: StreamKind,
        envelope: StreamKind,
    },
}

impl From<ProtocolError> for AeadError {
    fn from(error: ProtocolError) -> Self {
        Self::InvalidEnvelope {
            reason: error.to_string(),
        }
    }
}

/// A static X25519 identity private key held only by the peer itself.
///
/// The device's key is created at enrollment and the client's when its session is
/// authorized; neither private half is ever sent to the server.
#[derive(Clone)]
pub struct IdentityKey {
    secret: StaticSecret,
}

impl fmt::Debug for IdentityKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("IdentityKey")
            .field("public_key", &self.public_key().as_str())
            .finish_non_exhaustive()
    }
}

impl IdentityKey {
    pub fn generate() -> Result<Self, AeadError> {
        let mut bytes = [0u8; IDENTITY_KEY_LEN];
        getrandom::fill(&mut bytes).map_err(|_| AeadError::InvalidKeyMaterial)?;
        Ok(Self::from_bytes(bytes))
    }

    pub fn from_bytes(bytes: [u8; IDENTITY_KEY_LEN]) -> Self {
        Self {
            secret: StaticSecret::from(bytes),
        }
    }

    /// Parses a 32-byte key from unpadded base64url.
    pub fn parse(value: &str) -> Result<Self, AeadError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value.trim().as_bytes())
            .map_err(|_| AeadError::InvalidKeyMaterial)?;
        let array: [u8; IDENTITY_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| AeadError::InvalidKeyMaterial)?;
        Ok(Self::from_bytes(array))
    }

    /// Unpadded base64url of the private half. Persist it in the platform keystore; never
    /// send it to the server.
    pub fn to_secret_string(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.secret.to_bytes())
    }

    pub fn public_key(&self) -> IdentityPublicKey {
        IdentityPublicKey(PublicKey::from(&self.secret).to_bytes())
    }
}

/// The public half of a peer identity, pinned outside the session.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct IdentityPublicKey([u8; IDENTITY_KEY_LEN]);

impl IdentityPublicKey {
    pub fn parse(value: &str) -> Result<Self, AeadError> {
        let bytes = URL_SAFE_NO_PAD
            .decode(value.trim().as_bytes())
            .map_err(|_| AeadError::InvalidKeyMaterial)?;
        let array: [u8; IDENTITY_KEY_LEN] = bytes
            .try_into()
            .map_err(|_| AeadError::InvalidKeyMaterial)?;
        Ok(Self(array))
    }

    pub fn as_str(&self) -> String {
        URL_SAFE_NO_PAD.encode(self.0)
    }

    pub fn as_bytes(&self) -> &[u8; IDENTITY_KEY_LEN] {
        &self.0
    }
}

impl fmt::Display for IdentityPublicKey {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.as_str())
    }
}

/// One direction of a session. Numbers are on the wire: never reuse them.
fn direction_byte(role: TicketRole) -> u8 {
    match role {
        TicketRole::Client => 1,
        TicketRole::Device => 2,
    }
}

/// The frame counter of a sealed frame addressed to this peer, when its header is readable.
/// Every check here repeats a check in [`SessionCipher::open`], which is where a frame that
/// fails one of them is diagnosed; this only has to say what `open` would read.
fn peer_counter(sealed: &[u8], key_id: &[u8; KEY_ID_LEN], peer_direction: u8) -> Option<u64> {
    if sealed.len() < SealedHeader::MIN_LEN
        || sealed[SealedHeader::VERSION_OFFSET] != SEALED_VERSION
        || sealed[SealedHeader::KEY_ID_OFFSET..SealedHeader::DIRECTION_OFFSET] != *key_id
        || sealed[SealedHeader::DIRECTION_OFFSET] != peer_direction
    {
        return None;
    }
    let counter = u64::from_be_bytes(
        sealed[SealedHeader::COUNTER_OFFSET..SealedHeader::STREAM_KIND_OFFSET]
            .try_into()
            .ok()?,
    );
    (counter != 0).then_some(counter)
}

/// The per-connection epoch mixed into key derivation.
///
/// The identity keys are static, so the same session id would otherwise produce the same
/// keys — and the same ChaCha20-Poly1305 nonces — for every connection. Each connection
/// exchanges the two peers' single-use ticket nonces through rendezvous; both sides mix the
/// same pair, in role order, into the HKDF salt. A reconnecting peer re-registers with a
/// fresh ticket and therefore derives fresh keys, and a second `ConnectedPath` for one
/// session id can never reuse a nonce.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Epoch {
    client_nonce: String,
    device_nonce: String,
}

impl Epoch {
    pub fn new(
        client_nonce: impl Into<String>,
        device_nonce: impl Into<String>,
    ) -> Result<Self, AeadError> {
        let epoch = Self {
            client_nonce: client_nonce.into(),
            device_nonce: device_nonce.into(),
        };
        if epoch.client_nonce.is_empty() || epoch.device_nonce.is_empty() {
            return Err(AeadError::InvalidEpoch);
        }
        Ok(epoch)
    }

    /// Orders this peer's own nonce and the opposite peer's nonce by role, which is what
    /// makes both sides derive the same salt.
    pub fn split(own_nonce: &str, peer_nonce: &str, role: TicketRole) -> Result<Self, AeadError> {
        match role {
            TicketRole::Client => Self::new(own_nonce, peer_nonce),
            TicketRole::Device => Self::new(peer_nonce, own_nonce),
        }
    }

    pub fn client_nonce(&self) -> &str {
        &self.client_nonce
    }

    pub fn device_nonce(&self) -> &str {
        &self.device_nonce
    }

    fn salt(&self, session_id: &str) -> Vec<u8> {
        let mut salt = Vec::with_capacity(
            session_id.len() + self.client_nonce.len() + self.device_nonce.len() + 3,
        );
        salt.extend_from_slice(session_id.as_bytes());
        salt.push(0);
        salt.extend_from_slice(self.client_nonce.as_bytes());
        salt.push(0);
        salt.extend_from_slice(self.device_nonce.as_bytes());
        salt
    }
}

/// Per-frame secrecy and authentication for one session connection.
pub struct SessionCipher {
    session_id: String,
    role: TicketRole,
    key_id: [u8; KEY_ID_LEN],
    send_cipher: ChaCha20Poly1305,
    recv_cipher: ChaCha20Poly1305,
    peer_direction: u8,
    send_counter: AtomicU64,
    recv_state: Mutex<ReplayWindow>,
}

/// Replay window for authenticated frames.
///
/// A strict high-water mark would turn a legitimate UDP reorder into a fatal
/// `CounterRegression`. The window accepts any not-yet-seen counter within
/// [`AEAD_REPLAY_WINDOW`] of the highest one, refuses a repeat as [`AeadError::Replayed`],
/// and reports a counter below the window as [`AeadError::CounterRegression`] so a caller can
/// tell a reorder from a fatal regression.
const AEAD_REPLAY_WINDOW: u64 = 64;

#[derive(Default)]
struct ReplayWindow {
    highest: Option<u64>,
    seen: u64,
}

impl ReplayWindow {
    fn accept(&mut self, counter: u64) -> Result<(), AeadError> {
        match self.highest {
            None => {
                self.highest = Some(counter);
                self.seen = 1;
                Ok(())
            }
            Some(highest) if counter > highest => {
                let shift = counter - highest;
                self.seen = if shift >= AEAD_REPLAY_WINDOW {
                    1
                } else {
                    (self.seen << shift) | 1
                };
                self.highest = Some(counter);
                Ok(())
            }
            Some(highest) => {
                let offset = highest - counter;
                if offset >= AEAD_REPLAY_WINDOW {
                    return Err(AeadError::CounterRegression { counter, highest });
                }
                let bit = 1u64 << offset;
                if self.seen & bit != 0 {
                    return Err(AeadError::Replayed { counter });
                }
                self.seen |= bit;
                Ok(())
            }
        }
    }
}

impl fmt::Debug for SessionCipher {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("SessionCipher")
            .field("session_id", &self.session_id)
            .field("key_id", &self.key_id_hex())
            .finish_non_exhaustive()
    }
}

impl SessionCipher {
    /// Agrees on the session keys from the caller's identity key and the pinned peer
    /// identity key. The server is not part of this computation.
    pub fn new(
        own: &IdentityKey,
        peer: IdentityPublicKey,
        session_id: &str,
        role: TicketRole,
        epoch: &Epoch,
    ) -> Result<Self, AeadError> {
        if session_id.is_empty() {
            return Err(AeadError::InvalidKeyMaterial);
        }
        // Two paths for one session with the same epoch would reuse a ChaCha20-Poly1305
        // nonce, so the second is refused rather than silently repeating keystream.
        claim_epoch(session_id, role, epoch)?;
        let peer_public = PublicKey::from(*peer.as_bytes());
        let shared = own.secret.diffie_hellman(&peer_public);
        if shared.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(AeadError::WeakKey);
        }

        let mut okm = [0u8; 64];
        let salt = epoch.salt(session_id);
        Hkdf::<Sha256>::new(Some(&salt), shared.as_bytes())
            .expand(AEAD_LABEL, &mut okm)
            .map_err(|_| AeadError::WeakKey)?;
        let client_to_device = &okm[..32];
        let device_to_client = &okm[32..];
        let (send_key, recv_key) = match role {
            TicketRole::Client => (client_to_device, device_to_client),
            TicketRole::Device => (device_to_client, client_to_device),
        };

        let own_public = own.public_key();
        let (client_public, device_public) = match role {
            TicketRole::Client => (own_public, peer),
            TicketRole::Device => (peer, own_public),
        };

        Ok(Self {
            session_id: session_id.to_owned(),
            role,
            key_id: key_id(session_id, client_public, device_public, epoch),
            send_cipher: ChaCha20Poly1305::new_from_slice(send_key)
                .map_err(|_| AeadError::InvalidKeyMaterial)?,
            recv_cipher: ChaCha20Poly1305::new_from_slice(recv_key)
                .map_err(|_| AeadError::InvalidKeyMaterial)?,
            peer_direction: direction_byte(role.opposite()),
            send_counter: AtomicU64::new(1),
            recv_state: Mutex::new(ReplayWindow::default()),
        })
    }

    /// Hex key id shared by both peers of this identity pair and session.
    pub fn key_id(&self) -> String {
        self.key_id_hex()
    }

    fn key_id_hex(&self) -> String {
        self.key_id
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect()
    }

    /// Seals one envelope. The caller sends the returned bytes; nothing else on the wire
    /// describes the frame's contents.
    pub fn seal(&self, envelope: &Envelope) -> Result<Vec<u8>, AeadError> {
        let stream_kind = envelope.validate()?;
        self.seal_with_kind(envelope, stream_kind)
    }

    /// Seals `envelope` with a header label that must equal the envelope's own kind.
    ///
    /// The relay and the receiver both pin that equality, so a sender that labels a frame
    /// differently produces a frame every hop refuses.
    fn seal_with_kind(
        &self,
        envelope: &Envelope,
        stream_kind: StreamKind,
    ) -> Result<Vec<u8>, AeadError> {
        let counter = self.next_counter()?;

        let mut header = [0u8; SealedHeader::LEN];
        header[SealedHeader::VERSION_OFFSET] = SEALED_VERSION;
        header[SealedHeader::KEY_ID_OFFSET..SealedHeader::DIRECTION_OFFSET]
            .copy_from_slice(&self.key_id);
        header[SealedHeader::DIRECTION_OFFSET] = direction_byte(self.role);
        header[SealedHeader::COUNTER_OFFSET..SealedHeader::STREAM_KIND_OFFSET]
            .copy_from_slice(&counter.to_be_bytes());
        header[SealedHeader::STREAM_KIND_OFFSET] = stream_kind as u8;
        header[SealedHeader::SEQUENCE_OFFSET..SealedHeader::LEN]
            .copy_from_slice(&envelope.sequence.to_be_bytes());

        let aad = associated_data(&self.session_id, &header);
        let nonce = frame_nonce(header[SealedHeader::DIRECTION_OFFSET], counter);
        let ciphertext = self
            .send_cipher
            .encrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &envelope.encode_to_vec(),
                    aad: &aad,
                },
            )
            .map_err(|_| AeadError::Authentication)?;

        let mut sealed = Vec::with_capacity(SealedHeader::LEN + ciphertext.len());
        sealed.extend_from_slice(&header);
        sealed.extend_from_slice(&ciphertext);
        Ok(sealed)
    }

    /// True when [`Self::open`] would still accept this frame's counter, i.e. the frame has
    /// not fallen out of the replay window behind the frames already received.
    ///
    /// The header is read, never decrypted and never recorded, so a caller that has been
    /// holding a frame can decide whether it is still deliverable instead of discovering it as
    /// a [`AeadError::CounterRegression`]. A frame this method cannot read is reported as
    /// still deliverable: [`Self::open`] is where a malformed frame is diagnosed.
    pub fn within_replay_window(&self, sealed: &[u8]) -> bool {
        let Some(counter) = peer_counter(sealed, &self.key_id, self.peer_direction) else {
            return true;
        };
        let highest = self
            .recv_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .highest;
        match highest {
            // A counter ahead of the window is always acceptable.
            Some(highest) => counter > highest || highest - counter < AEAD_REPLAY_WINDOW,
            None => true,
        }
    }

    /// Opens one sealed frame. Authenticates first, then applies the bounded replay window,
    /// so a forged frame can never burn a counter and a reordered frame is still delivered.
    pub fn open(&self, sealed: &[u8]) -> Result<Envelope, AeadError> {
        if sealed.len() < SealedHeader::MIN_LEN {
            return Err(AeadError::Malformed {
                reason: format!("sealed frame is {} bytes", sealed.len()),
            });
        }
        if sealed[SealedHeader::VERSION_OFFSET] != SEALED_VERSION {
            return Err(AeadError::Malformed {
                reason: format!(
                    "unsupported sealed-frame version {}",
                    sealed[SealedHeader::VERSION_OFFSET]
                ),
            });
        }
        let found: [u8; KEY_ID_LEN] = sealed
            [SealedHeader::KEY_ID_OFFSET..SealedHeader::DIRECTION_OFFSET]
            .try_into()
            .expect("the header length is checked");
        if found != self.key_id {
            return Err(AeadError::UnknownKeyId {
                found: found.iter().map(|byte| format!("{byte:02x}")).collect(),
                expected: self.key_id_hex(),
            });
        }
        let direction = sealed[SealedHeader::DIRECTION_OFFSET];
        if direction != self.peer_direction {
            return Err(AeadError::WrongDirection);
        }
        let counter = u64::from_be_bytes(
            sealed[SealedHeader::COUNTER_OFFSET..SealedHeader::STREAM_KIND_OFFSET]
                .try_into()
                .expect("the header length is checked"),
        );
        if counter == 0 {
            return Err(AeadError::Malformed {
                reason: "frame counter 0 is reserved".to_owned(),
            });
        }

        let header: [u8; SealedHeader::LEN] = sealed[..SealedHeader::LEN]
            .try_into()
            .expect("the header length is checked");
        let aad = associated_data(&self.session_id, &header);
        let nonce = frame_nonce(direction, counter);
        let plaintext = self
            .recv_cipher
            .decrypt(
                Nonce::from_slice(&nonce),
                Payload {
                    msg: &sealed[SealedHeader::LEN..],
                    aad: &aad,
                },
            )
            .map_err(|_| AeadError::Authentication)?;

        self.recv_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .accept(counter)?;

        let envelope =
            Envelope::decode(plaintext.as_slice()).map_err(|error| AeadError::InvalidEnvelope {
                reason: error.to_string(),
            })?;
        let envelope_kind = envelope.validate()?;
        // The header is authenticated too, but authentication alone does not tie it to the
        // envelope it delivers: a peer that holds the key controls both. Pin the kind so a
        // control envelope cannot arrive inside a frame labelled as events, or the reverse.
        let header_kind = SealedHeader::stream_kind(sealed).ok_or(AeadError::Malformed {
            reason: "sealed frame has no readable stream kind".to_owned(),
        })?;
        if header_kind != envelope_kind {
            return Err(AeadError::StreamKindMismatch {
                header: header_kind,
                envelope: envelope_kind,
            });
        }
        Ok(envelope)
    }

    fn next_counter(&self) -> Result<u64, AeadError> {
        let mut current = self.send_counter.load(Ordering::SeqCst);
        loop {
            let next = current.checked_add(1).ok_or(AeadError::CounterExhausted)?;
            match self.send_counter.compare_exchange(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => return Ok(current),
                Err(actual) => current = actual,
            }
        }
    }
}

/// Epochs this process has already used, per session and role.
///
/// A reconnect must bring fresh tickets; reusing a ticket pair would derive the same keys,
/// which is the one thing AEAD cannot survive. The registry is process-local: after a restart
/// the rendezvous service has minted fresh nonces anyway.
/// Session, role, and the two ticket nonces.
type ClaimedEpoch = (String, u8, String, String);

/// How long a claimed epoch is remembered; it only has to outlive the session's lifetime.
const CLAIMED_EPOCH_TTL: std::time::Duration = std::time::Duration::from_secs(600);

/// Largest number of claimed epochs remembered; the oldest are pruned first.
const MAX_CLAIMED_EPOCHS: usize = 8192;

fn claimed_epochs() -> &'static Mutex<HashMap<ClaimedEpoch, std::time::Instant>> {
    static CLAIMED: OnceLock<Mutex<HashMap<ClaimedEpoch, std::time::Instant>>> = OnceLock::new();
    CLAIMED.get_or_init(|| Mutex::new(HashMap::new()))
}

fn claim_epoch(session_id: &str, role: TicketRole, epoch: &Epoch) -> Result<(), AeadError> {
    let key = (
        session_id.to_owned(),
        direction_byte(role),
        epoch.client_nonce().to_owned(),
        epoch.device_nonce().to_owned(),
    );
    let mut claimed = claimed_epochs()
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner());
    let now = std::time::Instant::now();
    claimed.retain(|_, seen| now.duration_since(*seen) < CLAIMED_EPOCH_TTL);
    if claimed.len() >= MAX_CLAIMED_EPOCHS
        && let Some(oldest) = claimed
            .iter()
            .min_by_key(|(_, seen)| **seen)
            .map(|(key, _)| key.clone())
    {
        claimed.remove(&oldest);
    }
    if claimed.insert(key, now).is_some() {
        return Err(AeadError::EpochReused);
    }
    Ok(())
}

fn associated_data(session_id: &str, header: &[u8; SealedHeader::LEN]) -> Vec<u8> {
    let mut aad = Vec::with_capacity(AEAD_LABEL.len() + 2 + session_id.len() + header.len());
    aad.extend_from_slice(AEAD_LABEL);
    aad.extend_from_slice(&(session_id.len() as u16).to_be_bytes());
    aad.extend_from_slice(session_id.as_bytes());
    aad.extend_from_slice(header);
    aad
}

fn frame_nonce(direction: u8, counter: u64) -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce[0] = direction;
    nonce[1..9].copy_from_slice(&counter.to_be_bytes());
    nonce
}

fn key_id(
    session_id: &str,
    client_public: IdentityPublicKey,
    device_public: IdentityPublicKey,
    epoch: &Epoch,
) -> [u8; KEY_ID_LEN] {
    let mut first = client_public.0;
    let mut second = device_public.0;
    if first > second {
        std::mem::swap(&mut first, &mut second);
    }
    let mut hasher = Sha256::new();
    hasher.update(KEY_ID_LABEL);
    hasher.update((session_id.len() as u16).to_be_bytes());
    hasher.update(session_id.as_bytes());
    hasher.update(first);
    hasher.update(second);
    hasher.update(epoch.salt(session_id));
    let digest = hasher.finalize();
    let mut id = [0u8; KEY_ID_LEN];
    id.copy_from_slice(&digest[..KEY_ID_LEN]);
    id
}

#[cfg(test)]
mod tests {
    use super::*;
    use phoneconnect::v1::{DeviceId, RequestId, SessionId};

    fn cipher_pair() -> (SessionCipher, SessionCipher) {
        let client_identity = IdentityKey::from_bytes([0x11; IDENTITY_KEY_LEN]);
        let device_identity = IdentityKey::from_bytes([0x22; IDENTITY_KEY_LEN]);
        let epoch = Epoch::new("client-kind-nonce", "device-kind-nonce").expect("epoch");
        let client = SessionCipher::new(
            &client_identity,
            device_identity.public_key(),
            "sess_kind",
            TicketRole::Client,
            &epoch,
        )
        .expect("client cipher");
        let device = SessionCipher::new(
            &device_identity,
            client_identity.public_key(),
            "sess_kind",
            TicketRole::Device,
            &epoch,
        )
        .expect("device cipher");
        (client, device)
    }

    fn control_envelope() -> Envelope {
        let device = DeviceId::new("dev_kind").expect("device id");
        let session = SessionId::new("sess_kind").expect("session id");
        let request = RequestId::new("req-kind").expect("request id");
        let mut envelope = Envelope::new(StreamKind::Control, &device, &session, &request);
        envelope.sequence = 1;
        envelope
    }

    /// A sealed frame whose header says one kind and whose plaintext envelope says another is
    /// exactly how a read-only client could smuggle a control command past a relay that only
    /// sees the routing label. The receiver must refuse it, not dispatch the envelope.
    #[test]
    fn a_sealed_header_kind_must_match_the_envelope_it_delivers() {
        let (client, device) = cipher_pair();
        let sealed = client
            .seal_with_kind(&control_envelope(), StreamKind::Events)
            .expect("seal with a relabelled header");

        assert_eq!(
            device.open(&sealed).err(),
            Some(AeadError::StreamKindMismatch {
                header: StreamKind::Events,
                envelope: StreamKind::Control,
            })
        );
    }
}
