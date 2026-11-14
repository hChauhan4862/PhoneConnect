//! Trust-on-first-use pin for the rendezvous ticket verification key.
//!
//! The page supplies a candidates view, and the transport verifies each ticket against the
//! Ed25519 key in that view. If the page chose the key, the signature check would only prove
//! self-consistency: a compromised page could mint its own key, sign a ticket with it, and
//! have the shell dial a relay it controls. The shell therefore pins the server's key itself.
//!
//! On the first rendezvous open the shell reads the key from the configured origin over the
//! configured scheme (`GET <server>/api/sessions/<id>/candidates` with the session capability)
//! and stores it under the shell's config directory. Afterwards a page-supplied key must equal
//! the pin. When it does not, the shell asks the origin once more to say whether the server
//! rotated its key or the page presented a key the server does not use, and refuses with an
//! explicit trust action either way. A pin is never silently replaced.
//!
//! A rotation is accepted only by [`TicketTrust::accept_rotation`], which a user confirms with
//! the value the shell showed them; the shell has no code path that trusts a new key on its
//! own. Pins are scoped to one origin, redirects are refused so the anchor can only come from
//! the configured origin, and on Unix a symlinked pin is refused rather than followed.

use std::io;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use phoneconnect::v1::SessionId;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use url::Url;

/// How long the key fetch may take before the open fails instead of hanging.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// Base file name; the path adds an origin tag so two servers never share a pin.
pub const PIN_FILE_NAME: &str = "ticket-verification-key";

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

/// Trust-on-first-use store for one server origin.
#[derive(Debug)]
pub struct TicketTrust {
    server: Url,
    pin_path: PathBuf,
    http: reqwest::Client,
}

/// A rotation the shell can show a user before they accept it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PendingRotation {
    pub pinned: String,
    pub current: String,
}

#[derive(Debug, thiserror::Error)]
pub enum TrustError {
    #[error("the pin file {path} could not be read: {source}")]
    ReadPin {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the pin file {path} could not be written: {source}")]
    WritePin {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the pin file {path} is a symlink; refusing to follow it")]
    PinSymlink { path: PathBuf },
    #[error("the pin file {path} records origin {recorded}, not the configured {expected}")]
    PinOriginMismatch {
        path: PathBuf,
        recorded: String,
        expected: String,
    },
    #[error("the pin file {path} is not a PhoneConnect pin: {reason}")]
    PinCorrupt { path: PathBuf, reason: String },
    #[error("no ticket verification key is pinned yet")]
    NoPin,
    #[error("session id {session_id:?} cannot be used to fetch the key: {reason}")]
    InvalidSession { session_id: String, reason: String },
    #[error("the session capability is not a valid bearer token")]
    InvalidCapability,
    #[error("could not fetch the ticket verification key from {url}: {reason}")]
    Fetch { url: String, reason: String },
    #[error("the key endpoint {url} answered HTTP {status}")]
    Refused { url: String, status: u16 },
    #[error("the key endpoint {url} returned no verification key")]
    MissingKey { url: String },
    #[error(
        "the ticket verification key changed: pinned {expected}, presented {supplied} ({detail}); \
         {remedy}"
    )]
    PinChanged {
        expected: String,
        supplied: String,
        detail: String,
        remedy: String,
    },
    #[error(
        "the server key changed again: confirmed {confirmed}, now {current}; ask for the new key \
         before trusting it"
    )]
    RotationMoved { confirmed: String, current: String },
}

impl TicketTrust {
    pub fn new(server: Url, pin_path: PathBuf) -> Self {
        let http = reqwest::Client::builder()
            // The anchor must come from the configured origin; a redirect is another origin.
            .redirect(reqwest::redirect::Policy::none())
            .timeout(FETCH_TIMEOUT)
            .build()
            .expect("the HTTP client builds with a static configuration");
        Self {
            server,
            pin_path,
            http,
        }
    }

    pub fn pin_path(&self) -> &Path {
        &self.pin_path
    }

    /// The pinned key, fetching and persisting it when no pin exists yet.
    pub async fn pinned_key(
        &self,
        session_id: &str,
        capability: &str,
    ) -> Result<String, TrustError> {
        if let Some(pin) = self.read_pin()? {
            return Ok(pin.key);
        }
        let fetched = self.fetch_key(session_id, capability).await?;
        self.write_pin(&fetched)?;
        Ok(fetched)
    }

    /// Requires `supplied` (from the page's candidates view) to equal the pin.
    ///
    /// On a mismatch the configured origin is asked once more, so the error can say whether
    /// the server rotated its key or the page presented one the server does not use.
    pub async fn verify_supplied(
        &self,
        supplied: &str,
        session_id: &str,
        capability: &str,
    ) -> Result<String, TrustError> {
        let pinned = self.pinned_key(session_id, capability).await?;
        if supplied == pinned {
            return Ok(pinned);
        }
        let detail = match self.fetch_key(session_id, capability).await {
            Ok(current) if current == supplied => {
                format!("the server now advertises {current}")
            }
            Ok(current) if current == pinned => {
                format!("the server still advertises the pinned {current}")
            }
            Ok(current) => format!("the server advertises {current}"),
            Err(error) => format!("the server could not be asked ({error})"),
        };
        Err(TrustError::PinChanged {
            expected: pinned,
            supplied: supplied.to_owned(),
            detail,
            remedy: self.remedy(),
        })
    }

    /// The rotation a user may confirm: the pinned key and the key the server advertises now.
    pub async fn pending_rotation(
        &self,
        session_id: &str,
        capability: &str,
    ) -> Result<PendingRotation, TrustError> {
        let pinned = self.read_pin()?.ok_or(TrustError::NoPin)?.key;
        let current = self.fetch_key(session_id, capability).await?;
        Ok(PendingRotation { pinned, current })
    }

    /// Replaces the pin with `confirmed_current`, which the user saw and accepted.
    ///
    /// The key is fetched again first: if the server changed since the user looked, this
    /// refuses (`RotationMoved`) instead of pinning a key nobody confirmed.
    pub async fn accept_rotation(
        &self,
        confirmed_current: &str,
        session_id: &str,
        capability: &str,
    ) -> Result<(), TrustError> {
        let current = self.fetch_key(session_id, capability).await?;
        if current != confirmed_current {
            return Err(TrustError::RotationMoved {
                confirmed: confirmed_current.to_owned(),
                current,
            });
        }
        self.write_pin(&current)
    }

    /// Deletes the pin. The next open pins again.
    pub fn reset(&self) -> Result<(), TrustError> {
        match std::fs::remove_file(&self.pin_path) {
            Ok(()) => Ok(()),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(TrustError::WritePin {
                path: self.pin_path.clone(),
                source,
            }),
        }
    }

    fn remedy(&self) -> String {
        format!(
            "confirm the new key with the server operator and accept it in the PhoneConnect \
             shell; the pin is {}",
            self.pin_path.display()
        )
    }

    fn read_pin(&self) -> Result<Option<RecordedPin>, TrustError> {
        match std::fs::symlink_metadata(&self.pin_path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                return Err(TrustError::PinSymlink {
                    path: self.pin_path.clone(),
                });
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(source) => {
                return Err(TrustError::ReadPin {
                    path: self.pin_path.clone(),
                    source,
                });
            }
        }
        let contents =
            std::fs::read_to_string(&self.pin_path).map_err(|source| TrustError::ReadPin {
                path: self.pin_path.clone(),
                source,
            })?;
        let recorded = parse_pin(&self.pin_path, &contents)?;
        let expected = self.server.origin().ascii_serialization();
        if recorded.origin != expected {
            return Err(TrustError::PinOriginMismatch {
                path: self.pin_path.clone(),
                recorded: recorded.origin,
                expected,
            });
        }
        Ok(Some(recorded))
    }

    fn write_pin(&self, key: &str) -> Result<(), TrustError> {
        if std::fs::symlink_metadata(&self.pin_path)
            .map(|metadata| metadata.file_type().is_symlink())
            .unwrap_or(false)
        {
            return Err(TrustError::PinSymlink {
                path: self.pin_path.clone(),
            });
        }
        let parent = self.pin_path.parent().ok_or_else(|| TrustError::WritePin {
            path: self.pin_path.clone(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "the pin has no directory"),
        })?;
        std::fs::create_dir_all(parent).map_err(|source| TrustError::WritePin {
            path: self.pin_path.clone(),
            source,
        })?;
        let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::SeqCst);
        let temporary = self
            .pin_path
            .with_extension(format!("tmp-{}-{sequence}", std::process::id()));
        let mut options = std::fs::OpenOptions::new();
        // `create_new` refuses an existing path, so a pre-created temp file (or symlink) can
        // never be followed or truncated.
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let contents = format!(
            "origin: {}\nkey: {key}\n",
            self.server.origin().ascii_serialization()
        );
        let write = || -> io::Result<()> {
            use std::io::Write;
            let mut file = options.open(&temporary)?;
            file.write_all(contents.as_bytes())?;
            file.sync_all()
        };
        let result = write()
            .map_err(|source| TrustError::WritePin {
                path: temporary.clone(),
                source,
            })
            .and_then(|()| {
                std::fs::rename(&temporary, &self.pin_path).map_err(|source| TrustError::WritePin {
                    path: self.pin_path.clone(),
                    source,
                })
            });
        if result.is_err() {
            let _ = std::fs::remove_file(&temporary);
        }
        result
    }

    async fn fetch_key(&self, session_id: &str, capability: &str) -> Result<String, TrustError> {
        SessionId::new(session_id).map_err(|error| TrustError::InvalidSession {
            session_id: session_id.to_owned(),
            reason: error.to_string(),
        })?;
        if capability.is_empty()
            || capability
                .bytes()
                .any(|byte| byte.is_ascii_control() || byte == b' ')
        {
            return Err(TrustError::InvalidCapability);
        }
        let url = self
            .server
            .join(&format!("/api/sessions/{session_id}/candidates"))
            .map_err(|error| TrustError::Fetch {
                url: self.server.to_string(),
                reason: error.to_string(),
            })?;
        let response = self
            .http
            .get(url.clone())
            .bearer_auth(capability)
            .send()
            .await
            .map_err(|error| TrustError::Fetch {
                url: url.to_string(),
                reason: error.to_string(),
            })?;
        if !response.status().is_success() {
            // Includes a redirect: the anchor may only come from the configured origin.
            return Err(TrustError::Refused {
                url: url.to_string(),
                status: response.status().as_u16(),
            });
        }
        let body = response.text().await.map_err(|error| TrustError::Fetch {
            url: url.to_string(),
            reason: error.to_string(),
        })?;
        let view: KeyView = serde_json::from_str(&body).map_err(|error| TrustError::Fetch {
            url: url.to_string(),
            reason: error.to_string(),
        })?;
        if view.verification_key.trim().is_empty() {
            return Err(TrustError::MissingKey {
                url: url.to_string(),
            });
        }
        Ok(view.verification_key.trim().to_owned())
    }
}

#[derive(Deserialize)]
struct KeyView {
    verification_key: String,
}

struct RecordedPin {
    origin: String,
    key: String,
}

fn parse_pin(path: &Path, contents: &str) -> Result<RecordedPin, TrustError> {
    let mut origin = None;
    let mut key = None;
    for line in contents.lines() {
        let line = line.trim();
        if let Some(value) = line.strip_prefix("origin:") {
            origin = Some(value.trim().to_owned());
        } else if let Some(value) = line.strip_prefix("key:") {
            key = Some(value.trim().to_owned());
        }
    }
    match (origin, key) {
        (Some(origin), Some(key)) if !key.is_empty() => Ok(RecordedPin { origin, key }),
        _ => Err(TrustError::PinCorrupt {
            path: path.to_path_buf(),
            reason: "expected `origin: <origin>` and `key: <verification key>` lines".to_owned(),
        }),
    }
}

/// The shell's config directory for the pin.
///
/// macOS: `~/Library/Application Support/PhoneConnect`; Windows: `%APPDATA%\PhoneConnect`;
/// other Unix: `$XDG_CONFIG_HOME/phoneconnect` or `~/.config/phoneconnect`.
fn config_directory() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")?;
        Some(PathBuf::from(home).join("Library/Application Support/PhoneConnect"))
    }
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("APPDATA")?;
        Some(PathBuf::from(base).join("PhoneConnect"))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
        Some(base.join("phoneconnect"))
    }
}

/// The pin path for one server origin.
///
/// The file name carries a hash of the origin so switching servers cannot reuse (or misread)
/// the previous pin; the file also records the origin and a foreign one is refused.
pub fn default_pin_path(server: &Url) -> Option<PathBuf> {
    let tag: String = Sha256::digest(server.origin().ascii_serialization().as_bytes())
        .iter()
        .take(8)
        .map(|byte| format!("{byte:02x}"))
        .collect();
    Some(config_directory()?.join(format!("{PIN_FILE_NAME}-{tag}")))
}
