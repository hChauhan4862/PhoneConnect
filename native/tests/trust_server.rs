//! The trust pin against the real server route.
//!
//! The fake server in `tests/trust.rs` proves the trust logic; this test proves the coupling:
//! an in-process PhoneConnect server issues a session, the shell fetches the verification key
//! from the server's own candidates route, and the pin equals the key the server advertised in
//! the session response. A second read reuses the pin instead of rewriting it.

use std::net::SocketAddr;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;

use phoneconnect_native::trust::{PIN_FILE_NAME, TicketTrust};
use phoneconnect_server::relay::RelayLimits;
use phoneconnect_server::store::{ManualClock, SqliteStore};
use phoneconnect_server::{AppState, build_router};
use phoneconnect_transport::IdentityKey;
use serde_json::{Value, json};
use tokio::net::TcpListener;
use url::Url;

const ADMIN_TOKEN: &str = "trust-coupling-admin-token";
const NOW_MS: i64 = 1_760_000_000_000;

#[tokio::test]
async fn the_pin_matches_the_key_the_real_server_advertises() {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind");
    let address: SocketAddr = listener.local_addr().expect("address");
    let base = format!("http://{address}");
    let store = Arc::new(SqliteStore::in_memory().expect("store"));
    let clock = Arc::new(ManualClock::new(NOW_MS));
    let state = Arc::new(
        AppState::new(
            store,
            ADMIN_TOKEN,
            format!("{base}/api/sessions"),
            RelayLimits::default(),
            clock,
        )
        .expect("app state"),
    );
    let router = build_router(Arc::clone(&state));
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, router).await;
    });

    let http = reqwest::Client::new();
    let token: Value = http
        .post(format!("{base}/api/enrollment-tokens"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&json!({"owner_id": "user-a", "expires_in_seconds": 900}))
        .send()
        .await
        .expect("token request")
        .json()
        .await
        .expect("token body");
    let device_identity = IdentityKey::generate().expect("device identity");
    let enrolled: Value = http
        .post(format!("{base}/api/devices/enroll"))
        .json(&json!({
            "token": token["token"],
            "identity_key": device_identity.public_key().to_string(),
        }))
        .send()
        .await
        .expect("enrollment")
        .json()
        .await
        .expect("enrollment body");
    let client_identity = IdentityKey::generate().expect("client identity");
    let session: Value = http
        .post(format!("{base}/api/sessions"))
        .bearer_auth(ADMIN_TOKEN)
        .json(&json!({
            "device_id": enrolled["device_id"],
            "client_identity_key": client_identity.public_key().to_string(),
        }))
        .send()
        .await
        .expect("session")
        .json()
        .await
        .expect("session body");

    let session_id = session["session_id"].as_str().expect("session id");
    let capability = session["capability"].as_str().expect("capability");
    let advertised = session["verification_key"]
        .as_str()
        .expect("verification key");

    let directory = PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("target/test-state")
        .join(format!("trust-server-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&directory);
    std::fs::create_dir_all(&directory).expect("test directory");
    let path = directory.join(PIN_FILE_NAME);
    let trust = TicketTrust::new(Url::parse(&base).expect("server URL"), path.clone());

    let pinned = trust
        .pinned_key(session_id, capability)
        .await
        .expect("the key comes from the real server route");
    assert_eq!(pinned, advertised, "the pin is the server's own key");
    let recorded = std::fs::read_to_string(&path).expect("pin file");
    assert!(
        recorded.contains(&format!("key: {advertised}")),
        "{recorded}"
    );

    // A second read uses the pin: the file is not rewritten.
    let first_modified = std::fs::metadata(&path)
        .expect("pin metadata")
        .modified()
        .expect("modification time");
    tokio::time::sleep(Duration::from_millis(30)).await;
    let again = trust
        .pinned_key(session_id, capability)
        .await
        .expect("the pin answers again");
    assert_eq!(again, advertised);
    assert_eq!(
        std::fs::metadata(&path)
            .expect("pin metadata")
            .modified()
            .expect("modification time"),
        first_modified,
        "an existing pin is not rewritten"
    );

    server.abort();
    std::fs::remove_dir_all(&directory).ok();
}
