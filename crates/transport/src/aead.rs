//! End-to-end frame confidentiality.
//!
//! Every PhoneConnect frame is sealed before either path carries it, so the relay forwards
//! ciphertext it cannot interpret and a direct-path observer cannot read the session.
//!
//! Trust model: two static identity keys — the device's, registered at enrollment, and the
//! client's, registered when the session is authorized — agree on a shared secret with
//! X25519. HKDF-SHA256, salted with the session id, splits the secret into one key per
//! direction. The server holds only public identity keys, so it can neither derive a
//! traffic key nor decrypt a frame. The server-issued probe key authenticates hole-punch
//! datagrams only; it is deliberately not used here.
//!
//! Each frame uses a fresh 96-bit nonce built from the sender's direction byte and a
//! monotonic counter, and authenticates a header that binds the key id, direction, counter,
//! stream kind, and sequence, together with the session id, as associated data. A captured
//! frame cannot be replayed, a lower counter is a regression, a reflected frame carries the
//! wrong direction, and a frame for another identity pair carries an unknown key id.

use std::fmt;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};

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
pub const KEY_ID_LEN: usize = 8;

/// Bytes of the Poly1305 tag appended to every sealed frame.
pub const TAG_LEN: usize = 16;

const SEALED_VERSION: u8 = 1;
const AEAD_LABEL: &[u8] = b"phoneconnect-aead-v1";
const KEY_ID_LABEL: &[u8] = b"phoneconnect-key-id-v1";

/// Layout of the authenticated sealed-frame header.
///
/// The header is not secret: it lets a receiver find the key and reject a replay before it
/// spends work on decryption. Every byte of it is authenticated as associated data, so a
/// changed header is a failed tag, never a different frame.
pub struct SealedHeader;

impl SealedHeader {
    pub const VERSION_OFFSET: usize = 0;
    pub const KEY_ID_OFFSET: usize = 1;
    pub const DIRECTION_OFFSET: usize = Self::KEY_ID_OFFSET + KEY_ID_LEN;
    pub const COUNTER_OFFSET: usize = Self::DIRECTION_OFFSET + 1;
    pub const STREAM_KIND_OFFSET: usize = Self::COUNTER_OFFSET + 8;
    pub const SEQUENCE_OFFSET: usize = Self::STREAM_KIND_OFFSET + 1;
    /// version + key id + direction + counter + stream kind + sequence.
    pub const LEN: usize = Self::SEQUENCE_OFFSET + 4;

    /// Smallest accepted sealed frame: a header plus a tag.
    pub const MIN_LEN: usize = Self::LEN + TAG_LEN;

    /// Stream kind carried by a sealed frame, so a relay can apply the right frame limit.
    pub fn stream_kind(sealed: &[u8]) -> Option<StreamKind> {
        if sealed.len() < Self::MIN_LEN {
            return None;
        }
        StreamKind::try_from(i32::from(sealed[Self::STREAM_KIND_OFFSET])).ok()
    }
}

/// Explicit confidentiality failures. Nothing degrades into plaintext or a silent retry.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum AeadError {
    #[error("identity key material is invalid")]
    InvalidKeyMaterial,
    #[error("the agreed key is degenerate; refusing to use it")]
    WeakKey,
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
    #[error("frame counter {counter} regressed below {highest}")]
    CounterRegression { counter: u64, highest: u64 },
    #[error("frame counter space is exhausted; the session must be re-established")]
    CounterExhausted,
    #[error("sealed frame does not contain a valid envelope: {reason}")]
    InvalidEnvelope { reason: String },
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

/// Per-frame secrecy and authentication for one session.
pub struct SessionCipher {
    session_id: String,
    role: TicketRole,
    key_id: [u8; KEY_ID_LEN],
    send_cipher: ChaCha20Poly1305,
    recv_cipher: ChaCha20Poly1305,
    peer_direction: u8,
    send_counter: AtomicU64,
    recv_state: Mutex<RecvState>,
}

#[derive(Default)]
struct RecvState {
    highest: u64,
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
    ) -> Result<Self, AeadError> {
        if session_id.is_empty() {
            return Err(AeadError::InvalidKeyMaterial);
        }
        let peer_public = PublicKey::from(*peer.as_bytes());
        let shared = own.secret.diffie_hellman(&peer_public);
        if shared.as_bytes().iter().all(|byte| *byte == 0) {
            return Err(AeadError::WeakKey);
        }

        let mut okm = [0u8; 64];
        Hkdf::<Sha256>::new(Some(session_id.as_bytes()), shared.as_bytes())
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
            key_id: key_id(session_id, client_public, device_public),
            send_cipher: ChaCha20Poly1305::new_from_slice(send_key)
                .map_err(|_| AeadError::InvalidKeyMaterial)?,
            recv_cipher: ChaCha20Poly1305::new_from_slice(recv_key)
                .map_err(|_| AeadError::InvalidKeyMaterial)?,
            peer_direction: direction_byte(role.opposite()),
            send_counter: AtomicU64::new(1),
            recv_state: Mutex::new(RecvState::default()),
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

    /// Opens one sealed frame. Authenticates first, then rejects a replayed or regressed
    /// counter, so a forged frame can never burn a counter.
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

        let mut state = self
            .recv_state
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner());
        if counter == state.highest {
            return Err(AeadError::Replayed { counter });
        }
        if counter < state.highest {
            return Err(AeadError::CounterRegression {
                counter,
                highest: state.highest,
            });
        }
        state.highest = counter;
        drop(state);

        let envelope =
            Envelope::decode(plaintext.as_slice()).map_err(|error| AeadError::InvalidEnvelope {
                reason: error.to_string(),
            })?;
        envelope.validate()?;
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
    let digest = hasher.finalize();
    let mut id = [0u8; KEY_ID_LEN];
    id.copy_from_slice(&digest[..KEY_ID_LEN]);
    id
}
