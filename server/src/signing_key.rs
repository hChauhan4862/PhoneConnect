//! The server's persisted ticket signing key.
//!
//! The key must survive a restart: the native shell pins the verification key it advertises
//! (trust on first use), so a key regenerated on every boot would make every pinned client
//! refuse until an operator resets the pin. The key is read from a file or created once, and
//! an existing file is never overwritten — a corrupt one stops startup instead of silently
//! rotating every client's trust anchor.

use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU64, Ordering};

use ed25519_dalek::SigningKey;

/// Environment variable naming the key file.
pub const TICKET_KEY_PATH_ENV: &str = "PHONECONNECT_TICKET_KEY_PATH";

/// Default key file, beside the database on the data volume.
pub const DEFAULT_TICKET_KEY_PATH: &str = "/data/ticket-signing-key";

/// Bytes in an Ed25519 signing key.
const KEY_LEN: usize = 32;

static TEMP_SEQUENCE: AtomicU64 = AtomicU64::new(0);

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
    tighten_permissions(path)?;
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
    let parent = path
        .parent()
        .filter(|parent| !parent.as_os_str().is_empty());
    if let Some(parent) = parent {
        std::fs::create_dir_all(parent).map_err(|source| SigningKeyError::Write {
            path: parent.to_path_buf(),
            source,
        })?;
    }
    // Write a complete key to a private temporary file first, then publish it without
    // overwriting. A crash can only leave the temporary behind, never a truncated key at the
    // real path, and a racing process either publishes first or reads the winner's complete
    // file.
    let temporary = temporary_path(path);
    write_secret(&temporary, &secret)?;
    let published = std::fs::hard_link(&temporary, path);
    let _ = std::fs::remove_file(&temporary);
    match published {
        Ok(()) => {
            sync_directory(parent);
            Ok(SigningKey::from_bytes(&secret))
        }
        Err(error) if error.kind() == io::ErrorKind::AlreadyExists => read_key(path),
        Err(source) => Err(SigningKeyError::Write {
            path: path.to_path_buf(),
            source,
        }),
    }
}

fn temporary_path(path: &Path) -> PathBuf {
    let sequence = TEMP_SEQUENCE.fetch_add(1, Ordering::SeqCst);
    path.with_extension(format!("tmp-{}-{sequence}", std::process::id()))
}

fn write_secret(path: &Path, secret: &[u8; KEY_LEN]) -> Result<(), SigningKeyError> {
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let result = (|| -> io::Result<()> {
        let mut file = options.open(path)?;
        file.write_all(format!("{}\n", encode_hex(secret)).as_bytes())?;
        file.sync_all()
    })();
    result.map_err(|source| {
        let _ = std::fs::remove_file(path);
        SigningKeyError::Write {
            path: path.to_path_buf(),
            source,
        }
    })
}

/// On Unix, a key readable by group or others is tightened to `0600`.
fn tighten_permissions(path: &Path) -> Result<(), SigningKeyError> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let metadata = std::fs::metadata(path).map_err(|source| SigningKeyError::Read {
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.permissions().mode() & 0o077 == 0 {
            return Ok(());
        }
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).map_err(
            |source| SigningKeyError::Write {
                path: path.to_path_buf(),
                source,
            },
        )?;
        eprintln!(
            "phoneconnect: tightened {} to 0600; it was readable by group or others",
            path.display()
        );
    }
    #[cfg(not(unix))]
    {
        let _ = path;
    }
    Ok(())
}

/// Flushes the directory entry so a published key survives a crash.
#[cfg(unix)]
fn sync_directory(parent: Option<&Path>) {
    if let Some(parent) = parent
        && let Ok(directory) = std::fs::File::open(parent)
    {
        let _ = directory.sync_all();
    }
}

#[cfg(not(unix))]
fn sync_directory(_parent: Option<&Path>) {}

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

    #[test]
    fn an_empty_key_file_is_not_a_valid_key() {
        let directory = test_directory("signing-key-empty");
        let path = directory.join("ticket-signing-key");
        std::fs::write(&path, "").expect("write");
        let error = load_or_create(&path).expect_err("an empty file is never a key");
        assert!(
            matches!(error, SigningKeyError::InvalidFormat { .. }),
            "{error:?}"
        );
        assert_eq!(
            std::fs::read_to_string(&path).expect("file"),
            "",
            "the file is untouched"
        );
        std::fs::remove_dir_all(&directory).ok();
    }

    #[test]
    fn concurrent_creations_all_see_one_complete_key() {
        let directory = test_directory("signing-key-race");
        let path = directory.join("ticket-signing-key");
        let keys: Vec<[u8; KEY_LEN]> = std::thread::scope(|scope| {
            let handles: Vec<_> = (0..8)
                .map(|_| {
                    scope.spawn(|| {
                        load_or_create(&path)
                            .expect("every creator or reader gets a key")
                            .to_bytes()
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|handle| handle.join().expect("thread"))
                .collect()
        });
        assert!(
            keys.iter().all(|key| *key == keys[0]),
            "racing processes must agree on one key"
        );
        let contents = std::fs::read_to_string(&path).expect("key file");
        assert_eq!(
            contents.len(),
            KEY_LEN * 2 + 1,
            "only a complete hex key plus a newline is ever published: {contents:?}"
        );
        let mut names: Vec<String> = std::fs::read_dir(&directory)
            .expect("directory")
            .map(|entry| {
                entry
                    .expect("entry")
                    .file_name()
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert_eq!(
            names,
            vec!["ticket-signing-key".to_owned()],
            "no temporary file is left behind"
        );
        std::fs::remove_dir_all(&directory).ok();
    }

    #[cfg(unix)]
    #[test]
    fn a_group_readable_key_is_tightened_to_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let directory = test_directory("signing-key-mode");
        let path = directory.join("ticket-signing-key");
        let created = encode_hex(&load_or_create(&path).expect("create").to_bytes());
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o644)).expect("chmod");

        let reloaded = encode_hex(&load_or_create(&path).expect("reload").to_bytes());
        assert_eq!(reloaded, created, "the key itself is unchanged");
        assert_eq!(
            std::fs::metadata(&path)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600,
            "a group/world readable key is tightened"
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
