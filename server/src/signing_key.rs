//! The server's persisted ticket signing key.
//!
//! The key must survive a restart: the native shell pins the verification key it advertises
//! (trust on first use), so a key regenerated on every boot would make every pinned client
//! refuse until an operator resets the pin. The key is read from a file or created once, and
//! an existing file is never overwritten — a corrupt one stops startup instead of silently
//! rotating every client's trust anchor.

use std::io::{self, Write};
use std::path::{Path, PathBuf};

use ed25519_dalek::SigningKey;

/// Environment variable naming the key file.
pub const TICKET_KEY_PATH_ENV: &str = "PHONECONNECT_TICKET_KEY_PATH";

/// Default key file, beside the database on the data volume.
pub const DEFAULT_TICKET_KEY_PATH: &str = "/data/ticket-signing-key";

/// Bytes in an Ed25519 signing key.
const KEY_LEN: usize = 32;

#[derive(Debug, thiserror::Error)]
pub enum SigningKeyError {
    #[error("the ticket signing key file {path} is a symlink; refusing to use it")]
    Symlink { path: PathBuf },
    #[error("the ticket signing key file {path} must contain {KEY_LEN} bytes as hex: {reason}")]
    InvalidFormat { path: PathBuf, reason: String },
    #[error("could not read the ticket signing key file {path}: {source}")]
    Read {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("could not create the ticket signing key file {path}: {source}")]
    Write {
        path: PathBuf,
        #[source]
        source: io::Error,
    },
    #[error("the system random source failed: {0}")]
    Random(String),
}

/// Loads the key at `path`, creating it once if it does not exist.
///
/// Creation uses `create_new` with mode `0600` on Unix, so two processes cannot generate
/// competing keys and an existing file (or symlink) is never replaced. A file that exists but
/// cannot be parsed stops startup; it is never regenerated.
pub fn load_or_create(path: &Path) -> Result<SigningKey, SigningKeyError> {
    match std::fs::symlink_metadata(path) {
        Ok(metadata) => {
            if metadata.file_type().is_symlink() {
                return Err(SigningKeyError::Symlink {
                    path: path.to_path_buf(),
                });
            }
            read_key(path)
        }
        Err(error) if error.kind() == io::ErrorKind::NotFound => create_key(path),
        Err(source) => Err(SigningKeyError::Read {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn read_key(path: &Path) -> Result<SigningKey, SigningKeyError> {
    let contents = std::fs::read_to_string(path).map_err(|source| SigningKeyError::Read {
        path: path.to_path_buf(),
        source,
    })?;
    let trimmed = contents.trim();
    let bytes = decode_hex(trimmed).ok_or_else(|| SigningKeyError::InvalidFormat {
        path: path.to_path_buf(),
        reason: format!(
            "expected {} hex characters, found {}",
            KEY_LEN * 2,
            trimmed.len()
        ),
    })?;
    Ok(SigningKey::from_bytes(&bytes))
}

fn create_key(path: &Path) -> Result<SigningKey, SigningKeyError> {
    let mut secret = [0u8; KEY_LEN];
    getrandom::fill(&mut secret).map_err(|error| SigningKeyError::Random(error.to_string()))?;
    if let Some(parent) = path.parent()
        && !parent.as_os_str().is_empty()
    {
        std::fs::create_dir_all(parent).map_err(|source| SigningKeyError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    match options.open(path) {
        Ok(mut file) => {
            let text = format!("{}\n", encode_hex(&secret));
            file.write_all(text.as_bytes())
                .and_then(|()| file.sync_all())
                .map_err(|source| SigningKeyError::Write {
                    path: path.to_path_buf(),
                    source,
                })?;
            Ok(SigningKey::from_bytes(&secret))
        }
        // Another process won the race; use the key it created rather than replacing it.
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => read_key(path),
        Err(source) => Err(SigningKeyError::Write {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn encode_hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

fn decode_hex(value: &str) -> Option<[u8; KEY_LEN]> {
    if value.len() != KEY_LEN * 2 {
        return None;
    }
    let mut bytes = [0u8; KEY_LEN];
    for (index, chunk) in value.as_bytes().chunks_exact(2).enumerate() {
        bytes[index] = u8::from_str_radix(std::str::from_utf8(chunk).ok()?, 16).ok()?;
    }
    Some(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::relay::PeerRole;
    use crate::rendezvous::TicketAuthority;
    use crate::store::SessionRecord;

    const NOW_MS: i64 = 1_760_000_000_000;
    const SESSION: &str = "sess_key";

    fn test_directory(name: &str) -> PathBuf {
        let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
            .join("target/test-state")
            .join(format!("{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&directory);
        std::fs::create_dir_all(&directory).expect("test directory");
        directory
    }

    fn session() -> SessionRecord {
        SessionRecord {
            session_id: SESSION.to_owned(),
            device_id: "dev_key".to_owned(),
            owner_id: "user-key".to_owned(),
            capability_hash: "capability-hash".to_owned(),
            client_identity_key: "a".repeat(64),
            device_identity_key: "b".repeat(64),
            created_at_ms: NOW_MS,
            expires_at_ms: NOW_MS + 300_000,
            revoked_at_ms: None,
            control: false,
        }
    }

    #[test]
    fn a_ticket_issued_before_a_restart_still_verifies() {
        let directory = test_directory("signing-key-restart");
        let path = directory.join("ticket-signing-key");

        let first = TicketAuthority::from_signing_key(load_or_create(&path).expect("create"));
        let ticket = first
            .issue(&session(), PeerRole::Client, NOW_MS)
            .expect("issue a ticket");
        let verification_key = first.verification_key().to_owned();
        drop(first);

        let second = TicketAuthority::from_signing_key(load_or_create(&path).expect("reload"));
        assert_eq!(
            second.verification_key(),
            verification_key,
            "a restart must not rotate the advertised key"
        );
        second
            .verify(&ticket, SESSION, PeerRole::Client, NOW_MS + 1)
            .expect("a ticket issued before the restart still verifies");

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path)
                .expect("key metadata")
                .permissions()
                .mode()
                & 0o777;
            assert_eq!(mode, 0o600, "the key is private to its owner");
        }
        assert_eq!(
            std::fs::read_to_string(&path)
                .expect("key file")
                .trim()
                .len(),
            KEY_LEN * 2,
            "stored as hex"
        );
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn an_existing_key_is_never_regenerated() {
        let directory = test_directory("signing-key-stable");
        let path = directory.join("ticket-signing-key");
        let first = encode_hex(&load_or_create(&path).expect("create").to_bytes());
        let second = encode_hex(&load_or_create(&path).expect("reload").to_bytes());
        assert_eq!(first, second);
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn a_corrupt_key_file_stops_startup_and_is_not_overwritten() {
        let directory = test_directory("signing-key-corrupt");
        let path = directory.join("ticket-signing-key");
        std::fs::write(&path, "not-a-key\n").expect("write");
        let error = load_or_create(&path).expect_err("a corrupt key is not a fresh key");
        assert!(
            matches!(error, SigningKeyError::InvalidFormat { .. }),
            "{error:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("file"),
            "not-a-key\n",
            "the file is untouched"
        );
        std::fs::remove_dir_all(&directory).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_symlinked_key_file_is_refused() {
        let directory = test_directory("signing-key-symlink");
        let target = directory.join("elsewhere");
        std::fs::write(&target, encode_hex(&[7u8; KEY_LEN])).expect("target");
        let path = directory.join("ticket-signing-key");
        std::os::unix::fs::symlink(&target, &path).expect("symlink");
        let error = load_or_create(&path).expect_err("a symlink is refused");
        assert!(
            matches!(error, SigningKeyError::Symlink { .. }),
            "{error:?}"
        );
        std::fs::remove_dir_all(&directory).ok();
    }
}
