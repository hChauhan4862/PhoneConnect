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
//! rotated its key or the page presented a key the server does not use, and refuses with the
//! reset procedure either way. A pin is never silently replaced.
//!
//! The server currently generates its ticket signing key at process start, so a server
//! restart rotates it; the remedy is to delete the pin file after confirming the new key.

use std::io;
use std::path::{Path, PathBuf};
use std::time::Duration;

use phoneconnect::v1::SessionId;
use serde::Deserialize;
use url::Url;

/// How long the key fetch may take before the open fails instead of hanging.
const FETCH_TIMEOUT: Duration = Duration::from_secs(10);

/// File name of the pin inside the shell's config directory.
pub const PIN_FILE_NAME: &str = "ticket-verification-key";

/// Trust-on-first-use store for one server origin.
#[derive(Debug)]
pub struct TicketTrust {
    server: Url,
    pin_path: PathBuf,
    http: reqwest::Client,
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
}

impl TicketTrust {
    pub fn new(server: Url, pin_path: PathBuf) -> Self {
        let http = reqwest::Client::builder()
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
            return Ok(pin);
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

    /// Deletes the pin. The next open pins again; this is the documented reset after a server
    /// rotates its signing key.
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
            "confirm the new key with the server operator, then delete {} and reopen the endpoint",
            self.pin_path.display()
        )
    }

    fn read_pin(&self) -> Result<Option<String>, TrustError> {
        match std::fs::read_to_string(&self.pin_path) {
            Ok(contents) => {
                let trimmed = contents.trim();
                Ok(if trimmed.is_empty() {
                    None
                } else {
                    Some(trimmed.to_owned())
                })
            }
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(source) => Err(TrustError::ReadPin {
                path: self.pin_path.clone(),
                source,
            }),
        }
    }

    fn write_pin(&self, key: &str) -> Result<(), TrustError> {
        let parent = self.pin_path.parent().ok_or_else(|| TrustError::WritePin {
            path: self.pin_path.clone(),
            source: io::Error::new(io::ErrorKind::InvalidInput, "the pin has no directory"),
        })?;
        std::fs::create_dir_all(parent).map_err(|source| TrustError::WritePin {
            path: self.pin_path.clone(),
            source,
        })?;
        // Write beside the pin and rename, so a crash cannot leave a truncated trust anchor.
        let temporary = self.pin_path.with_extension("tmp");
        let mut options = std::fs::OpenOptions::new();
        options.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let write = || -> io::Result<()> {
            use std::io::Write;
            let mut file = options.open(&temporary)?;
            file.write_all(key.as_bytes())?;
            file.write_all(b"\n")?;
            file.sync_all()
        };
        write().map_err(|source| TrustError::WritePin {
            path: temporary.clone(),
            source,
        })?;
        std::fs::rename(&temporary, &self.pin_path).map_err(|source| TrustError::WritePin {
            path: self.pin_path.clone(),
            source,
        })
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

/// The shell's config directory for the pin.
///
/// macOS: `~/Library/Application Support/PhoneConnect`; Windows: `%APPDATA%\PhoneConnect`;
/// other Unix: `$XDG_CONFIG_HOME/phoneconnect` or `~/.config/phoneconnect`.
pub fn default_pin_path() -> Option<PathBuf> {
    #[cfg(target_os = "macos")]
    {
        let home = std::env::var_os("HOME")?;
        Some(
            PathBuf::from(home)
                .join("Library/Application Support/PhoneConnect")
                .join(PIN_FILE_NAME),
        )
    }
    #[cfg(target_os = "windows")]
    {
        let base = std::env::var_os("APPDATA")?;
        Some(PathBuf::from(base).join("PhoneConnect").join(PIN_FILE_NAME))
    }
    #[cfg(all(unix, not(target_os = "macos")))]
    {
        let base = std::env::var_os("XDG_CONFIG_HOME")
            .map(PathBuf::from)
            .or_else(|| std::env::var_os("HOME").map(|home| PathBuf::from(home).join(".config")))?;
        Some(base.join("phoneconnect").join(PIN_FILE_NAME))
    }
}
