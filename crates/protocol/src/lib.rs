//! PhoneConnect wire protocol.
//!
//! The crate name is `phoneconnect-protocol`; the library is `phoneconnect` so that every
//! component speaks the same path: `phoneconnect::v1::*`.
//!
//! Frames are a four-byte big-endian length prefix followed by an encoded [`v1::Envelope`].
//! The length prefix describes the envelope body only. Decoders check the prefix against a
//! configured limit *before* allocating or reading the body, so a peer can never force an
//! unbounded allocation.

#![deny(unsafe_code)]

use prost::Message;

/// Wire protocol version this build speaks. Frames carrying any other value are rejected.
pub const PROTOCOL_VERSION: u32 = 1;

/// Bytes in the big-endian length prefix that precedes every encoded envelope.
pub const LENGTH_PREFIX_LEN: usize = 4;

/// Maximum frame body size for control and event streams: 1 MiB.
pub const CONTROL_FRAME_LIMIT: u32 = 1024 * 1024;

/// Default maximum frame body size for file, media, and proxy streams: 4 MiB.
pub const STREAM_FRAME_LIMIT: u32 = 4 * 1024 * 1024;

/// Maximum accepted length of a device, session, or request identifier.
pub const MAX_IDENTIFIER_LEN: usize = 128;

pub mod v1 {
    //! `phoneconnect.v1` protobuf types and their protocol helpers.
    include!(concat!(env!("OUT_DIR"), "/phoneconnect.v1.rs"));

    pub use super::{
        CONTROL_FRAME_LIMIT, DecodedFrame, DeviceId, FrameLimits, LENGTH_PREFIX_LEN,
        MAX_IDENTIFIER_LEN, PROTOCOL_VERSION, ProtocolError, RequestId, STREAM_FRAME_LIMIT,
        SessionId, decode_frame, encode_frame, read_frame_length,
    };
}

use v1::{Envelope, StreamKind};

/// Explicit protocol failures. There are no success-shaped fallbacks: a frame either
/// decodes into a validated envelope or the caller receives one of these errors.
#[derive(Debug, ::thiserror::Error)]
pub enum ProtocolError {
    #[error("truncated frame prefix: only {available} of 4 length bytes are buffered")]
    TruncatedPrefix { available: usize },
    #[error("truncated frame: body declares {declared} bytes but only {available} are buffered")]
    TruncatedFrame { declared: usize, available: usize },
    #[error("frame too large: {length} bytes exceeds the {limit}-byte limit for {stream_kind:?}")]
    FrameTooLarge {
        stream_kind: Option<StreamKind>,
        length: usize,
        limit: usize,
    },
    #[error("unknown stream kind {value}")]
    UnknownStreamKind { value: i32 },
    #[error("envelope is missing a stream kind")]
    MissingStreamKind,
    #[error("unsupported protocol version {found}; this build speaks {supported}")]
    UnsupportedVersion { found: u32, supported: u32 },
    #[error("sequence {sequence} cannot be advanced; the stream must be re-established")]
    SequenceExhausted { sequence: u32 },
    #[error("invalid {kind}: {reason}")]
    InvalidIdentifier {
        kind: &'static str,
        reason: &'static str,
    },
    #[error("invalid frame limit {limit} for {stream_kind:?} streams")]
    InvalidFrameLimit { stream_kind: StreamKind, limit: u32 },
    #[error(
        "frame limits apply to concrete stream kinds; Unspecified cannot be configured (limit {limit})"
    )]
    UnspecifiedStreamKindLimit { limit: u32 },
    #[error("malformed protobuf frame: {0}")]
    Decode(#[from] prost::DecodeError),
    #[error("could not encode protobuf frame: {0}")]
    Encode(#[from] prost::EncodeError),
}

/// Per-stream-kind frame body limits. Control and event streams default to 1 MiB;
/// file, media, and proxy streams default to 4 MiB and are configured independently.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct FrameLimits {
    control: u32,
    file: u32,
    media: u32,
    proxy: u32,
}

impl Default for FrameLimits {
    fn default() -> Self {
        Self {
            control: CONTROL_FRAME_LIMIT,
            file: STREAM_FRAME_LIMIT,
            media: STREAM_FRAME_LIMIT,
            proxy: STREAM_FRAME_LIMIT,
        }
    }
}

impl FrameLimits {
    /// The default limits: 1 MiB control/event frames, 4 MiB file/media/proxy frames.
    pub fn new() -> Self {
        Self::default()
    }

    /// Profile for control-only connections: every stream kind is capped at
    /// [`CONTROL_FRAME_LIMIT`], so an oversized frame is refused from its length prefix
    /// before any body is buffered or decoded.
    ///
    /// Use this for connections that carry only control and event streams. It is the
    /// required profile for control-only connections; default limits cap the prefix at
    /// the 4 MiB stream limit, which would let a peer force up to 4 MiB of buffering
    /// before the stream kind is known.
    pub const fn control_only() -> Self {
        Self {
            control: CONTROL_FRAME_LIMIT,
            file: CONTROL_FRAME_LIMIT,
            media: CONTROL_FRAME_LIMIT,
            proxy: CONTROL_FRAME_LIMIT,
        }
    }

    /// Limit for `stream_kind`. Unspecified kinds are held to the control limit; their
    /// frames are rejected by validation anyway.
    pub const fn limit_for(&self, stream_kind: StreamKind) -> u32 {
        match stream_kind {
            StreamKind::Unspecified | StreamKind::Control | StreamKind::Events => self.control,
            StreamKind::File => self.file,
            StreamKind::Media => self.media,
            StreamKind::Proxy => self.proxy,
        }
    }

    /// Largest limit across every stream kind: the cap a decoder may apply to a length
    /// prefix before the stream kind is known.
    pub const fn max_limit(&self) -> u32 {
        let mut max = self.control;
        if self.file > max {
            max = self.file;
        }
        if self.media > max {
            max = self.media;
        }
        if self.proxy > max {
            max = self.proxy;
        }
        max
    }

    /// Overrides the limit for one concrete stream kind. Control and events share one
    /// limit; [`StreamKind::Unspecified`] is refused because
    /// its frames are never valid and aliasing it to control would hide a caller mistake.
    pub fn with_stream_limit(
        mut self,
        stream_kind: StreamKind,
        limit: u32,
    ) -> Result<Self, ProtocolError> {
        if limit == 0 {
            return Err(ProtocolError::InvalidFrameLimit { stream_kind, limit });
        }
        match stream_kind {
            StreamKind::Unspecified => Err(ProtocolError::UnspecifiedStreamKindLimit { limit }),
            StreamKind::Control | StreamKind::Events => {
                self.control = limit;
                Ok(self)
            }
            StreamKind::File => {
                self.file = limit;
                Ok(self)
            }
            StreamKind::Media => {
                self.media = limit;
                Ok(self)
            }
            StreamKind::Proxy => {
                self.proxy = limit;
                Ok(self)
            }
        }
    }
}

/// Wire version of the sealed-frame header.
pub const SEALED_VERSION: u8 = 1;

/// Layout of the authenticated sealed-frame header.
///
/// The sealed frame is the ciphertext of one envelope: a fixed header followed by the
/// ChaCha20-Poly1305 body and tag. The header is not secret — it lets a receiver find the key
/// and reject a replay before spending work on decryption — and every byte of it is
/// authenticated as associated data, so a changed header is a failed tag.
///
/// It lives here because three independent implementations must agree on it: the relay reads
/// the kind byte to bound and authorize a frame without decrypting it, and both transports
/// (Rust and Kotlin) read it to bind the frame they open.
pub struct SealedHeader;

impl SealedHeader {
    pub const VERSION_OFFSET: usize = 0;
    pub const KEY_ID_OFFSET: usize = 1;
    /// Bytes of key id carried in a sealed frame.
    pub const KEY_ID_LEN: usize = 8;
    pub const DIRECTION_OFFSET: usize = Self::KEY_ID_OFFSET + Self::KEY_ID_LEN;
    pub const COUNTER_OFFSET: usize = Self::DIRECTION_OFFSET + 1;
    pub const STREAM_KIND_OFFSET: usize = Self::COUNTER_OFFSET + 8;
    pub const SEQUENCE_OFFSET: usize = Self::STREAM_KIND_OFFSET + 1;
    /// version + key id + direction + counter + stream kind + sequence.
    pub const LEN: usize = Self::SEQUENCE_OFFSET + 4;

    /// Bytes of the Poly1305 tag appended to every sealed frame.
    pub const TAG_LEN: usize = 16;

    /// Smallest accepted sealed frame: a header plus a tag.
    pub const MIN_LEN: usize = Self::LEN + Self::TAG_LEN;

    /// Stream kind declared by a sealed frame's header. `None` when the frame is too short or
    /// the byte is not a known kind: a frame no honest sender produces.
    pub fn stream_kind(sealed: &[u8]) -> Option<StreamKind> {
        if sealed.len() < Self::MIN_LEN {
            return None;
        }
        StreamKind::try_from(i32::from(sealed[Self::STREAM_KIND_OFFSET])).ok()
    }
}

/// A decoded frame plus the number of bytes it occupied in the input buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DecodedFrame {
    pub envelope: Envelope,
    pub consumed: usize,
}

/// Encodes `envelope` as a length-delimited frame after validating version, stream kind,
/// identifiers, and the stream-kind frame limit.
pub fn encode_frame(envelope: &Envelope, limits: &FrameLimits) -> Result<Vec<u8>, ProtocolError> {
    let stream_kind = envelope.validate()?;
    let length = envelope.encoded_len();
    let limit = limits.limit_for(stream_kind) as usize;
    if length > limit {
        return Err(ProtocolError::FrameTooLarge {
            stream_kind: Some(stream_kind),
            length,
            limit,
        });
    }
    let declared = u32::try_from(length).map_err(|_| ProtocolError::FrameTooLarge {
        stream_kind: Some(stream_kind),
        length,
        limit,
    })?;

    let mut frame = Vec::with_capacity(LENGTH_PREFIX_LEN + length);
    frame.extend_from_slice(&declared.to_be_bytes());
    envelope.encode(&mut frame)?;
    Ok(frame)
}

/// Validates a four-byte length prefix against the largest configured limit and returns
/// the announced body length. Callers that read frames from a socket use this to bound
/// their read buffer before touching peer-provided lengths.
pub fn read_frame_length(
    prefix: [u8; LENGTH_PREFIX_LEN],
    limits: &FrameLimits,
) -> Result<usize, ProtocolError> {
    let declared = u32::from_be_bytes(prefix) as usize;
    let limit = limits.max_limit() as usize;
    if declared > limit {
        return Err(ProtocolError::FrameTooLarge {
            stream_kind: None,
            length: declared,
            limit,
        });
    }
    Ok(declared)
}

/// Decodes the first frame in `buffer`, returning the validated envelope and how many
/// bytes it consumed. Trailing bytes are left for the caller, so a buffered stream of
/// frames can be drained in order.
pub fn decode_frame(buffer: &[u8], limits: &FrameLimits) -> Result<DecodedFrame, ProtocolError> {
    let (declared, body) = split_frame(buffer, limits)?;
    let envelope = Envelope::decode(body)?;
    let stream_kind = envelope.validate()?;
    let limit = limits.limit_for(stream_kind) as usize;
    if declared > limit {
        return Err(ProtocolError::FrameTooLarge {
            stream_kind: Some(stream_kind),
            length: declared,
            limit,
        });
    }
    Ok(DecodedFrame {
        envelope,
        consumed: LENGTH_PREFIX_LEN + declared,
    })
}

fn split_frame<'a>(
    buffer: &'a [u8],
    limits: &FrameLimits,
) -> Result<(usize, &'a [u8]), ProtocolError> {
    if buffer.len() < LENGTH_PREFIX_LEN {
        return Err(ProtocolError::TruncatedPrefix {
            available: buffer.len(),
        });
    }
    let declared = read_frame_length([buffer[0], buffer[1], buffer[2], buffer[3]], limits)?;
    let available = buffer.len() - LENGTH_PREFIX_LEN;
    if available < declared {
        return Err(ProtocolError::TruncatedFrame {
            declared,
            available,
        });
    }
    Ok((
        declared,
        &buffer[LENGTH_PREFIX_LEN..LENGTH_PREFIX_LEN + declared],
    ))
}

impl Envelope {
    /// Builds an envelope for `stream_kind` at the current protocol version with sequence 0.
    pub fn new(
        stream_kind: StreamKind,
        device_id: &DeviceId,
        session_id: &SessionId,
        request_id: &RequestId,
    ) -> Self {
        Self {
            protocol_version: PROTOCOL_VERSION,
            stream_kind: i32::from(stream_kind),
            request_id: request_id.as_str().to_owned(),
            device_id: device_id.as_str().to_owned(),
            session_id: session_id.as_str().to_owned(),
            sequence: 0,
            deadline_unix_ms: 0,
            payload: Vec::new(),
        }
    }

    /// Sets the stream kind from the typed enum instead of the raw wire `i32`.
    pub fn set_kind(&mut self, stream_kind: StreamKind) {
        self.stream_kind = i32::from(stream_kind);
    }

    /// Checks the fields a relay or peer must not trust and returns the decoded stream kind.
    pub fn validate(&self) -> Result<StreamKind, ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion {
                found: self.protocol_version,
                supported: PROTOCOL_VERSION,
            });
        }
        let stream_kind = StreamKind::try_from(self.stream_kind).map_err(|_| {
            ProtocolError::UnknownStreamKind {
                value: self.stream_kind,
            }
        })?;
        if stream_kind == StreamKind::Unspecified {
            return Err(ProtocolError::MissingStreamKind);
        }
        validate_identifier("device_id", &self.device_id)?;
        if !self.session_id.is_empty() {
            validate_identifier("session_id", &self.session_id)?;
        }
        if !self.request_id.is_empty() {
            validate_identifier("request_id", &self.request_id)?;
        }
        Ok(stream_kind)
    }

    /// Advances the per-stream sequence counter, refusing to wrap.
    pub fn advance_sequence(&mut self) -> Result<u32, ProtocolError> {
        let next = self
            .sequence
            .checked_add(1)
            .ok_or(ProtocolError::SequenceExhausted {
                sequence: self.sequence,
            })?;
        self.sequence = next;
        Ok(next)
    }
}

fn validate_identifier(kind: &'static str, value: &str) -> Result<(), ProtocolError> {
    if value.is_empty() {
        return Err(ProtocolError::InvalidIdentifier {
            kind,
            reason: "must not be empty",
        });
    }
    if value.len() > MAX_IDENTIFIER_LEN {
        return Err(ProtocolError::InvalidIdentifier {
            kind,
            reason: "must be at most 128 bytes",
        });
    }
    let valid = value.bytes().all(|byte| {
        byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'_' | b'.' | b':' | b'=')
    });
    if !valid {
        return Err(ProtocolError::InvalidIdentifier {
            kind,
            reason: "may only contain ASCII letters, digits, and '-', '_', '.', ':', '='",
        });
    }
    Ok(())
}

macro_rules! identifier {
    ($(#[$meta:meta])* $name:ident, $label:literal) => {
        $(#[$meta])*
        #[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord)]
        pub struct $name(String);

        impl $name {
            /// Validates `value` and wraps it.
            pub fn new(value: impl Into<String>) -> Result<Self, ProtocolError> {
                let value = value.into();
                validate_identifier($label, &value)?;
                Ok(Self(value))
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl std::fmt::Display for $name {
            fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                formatter.write_str(&self.0)
            }
        }

        impl std::str::FromStr for $name {
            type Err = ProtocolError;

            fn from_str(value: &str) -> Result<Self, Self::Err> {
                Self::new(value)
            }
        }

        impl TryFrom<&str> for $name {
            type Error = ProtocolError;

            fn try_from(value: &str) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl TryFrom<String> for $name {
            type Error = ProtocolError;

            fn try_from(value: String) -> Result<Self, Self::Error> {
                Self::new(value)
            }
        }

        impl AsRef<str> for $name {
            fn as_ref(&self) -> &str {
                &self.0
            }
        }
    };
}

identifier!(
    /// Identifier of an enrolled device as issued by the server.
    DeviceId,
    "device_id"
);
identifier!(
    /// Identifier of an authorized device session.
    SessionId,
    "session_id"
);
identifier!(
    /// Identifier correlating a request with its response.
    RequestId,
    "request_id"
);
