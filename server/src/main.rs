//! PhoneConnect server entry point.
//!
//! Configuration is environment-only so the same image runs in compose, a VM, or a
//! single-node deployment: the bootstrap admin token is required, the database path and
//! listen address are optional, and the relay endpoint is advertised to peers.

use std::path::Path;
use std::sync::Arc;

use phoneconnect_server::auth::{ADMIN_TOKEN_ENV, admin_token_from_env};
use phoneconnect_server::config::{PUBLIC_URL_ENV, relay_endpoint_for};
use phoneconnect_server::relay::RelayLimits;
use phoneconnect_server::rendezvous::TicketAuthority;
use phoneconnect_server::retention::{DEFAULT_RETENTION_INTERVAL, RetentionJob};
use phoneconnect_server::signing_key::{
    DEFAULT_TICKET_KEY_PATH, TICKET_KEY_PATH_ENV, load_or_create,
};
use phoneconnect_server::store::{DeviceStore, SqliteStore, SystemClock};
use phoneconnect_server::web::{WebUi, router_with_web_ui};
use phoneconnect_server::{AppState, build_router};

const LISTEN_ADDR_ENV: &str = "PHONECONNECT_LISTEN_ADDR";
const DATABASE_PATH_ENV: &str = "PHONECONNECT_DATABASE_PATH";
const WEB_ROOT_ENV: &str = "PHONECONNECT_WEB_ROOT";

const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_DATABASE_PATH: &str = "/data/phoneconnect.sqlite3";
const DEFAULT_WEB_ROOT: &str = "web/dist";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let admin_token = admin_token_from_env()
        .map_err(|_| format!("{ADMIN_TOKEN_ENV} must be set to a non-empty admin token"))?;
    let listen_addr = environment_or(LISTEN_ADDR_ENV, DEFAULT_LISTEN_ADDR);
    let database_path = environment_or(DATABASE_PATH_ENV, DEFAULT_DATABASE_PATH);
    // One origin, not two settings: the relay base peers receive is derived from it, so a
    // native shell that loaded this origin can always dial the relay it is told about.
    let public_url = environment_or(
        PUBLIC_URL_ENV,
        phoneconnect_server::config::DEFAULT_PUBLIC_URL,
    );
    let relay_endpoint = relay_endpoint_for(&public_url);
    let web_root = environment_or(WEB_ROOT_ENV, DEFAULT_WEB_ROOT);

    // The signing key persists, so a restart does not rotate the verification key a native
    // client pinned on first use. A corrupt key file stops startup; it is never regenerated.
    let ticket_key_path = environment_or(TICKET_KEY_PATH_ENV, DEFAULT_TICKET_KEY_PATH);
    let tickets = Arc::new(TicketAuthority::from_signing_key(load_or_create(
        Path::new(&ticket_key_path),
    )?));

    let store: Arc<dyn DeviceStore> = Arc::new(SqliteStore::open(&database_path)?);
    let state = Arc::new(AppState::with_tickets(
        store,
        admin_token,
        relay_endpoint,
        RelayLimits::default(),
        Arc::new(SystemClock),
        tickets,
    )?);

    // The browser and the native shell load the same server URL; there is no second bundle.
    let router = match WebUi::load(&web_root) {
        Ok(ui) => {
            println!("phoneconnect-server serving the web UI from {web_root}");
            router_with_web_ui(Arc::clone(&state), ui)
        }
        Err(error) => {
            eprintln!("phoneconnect: web UI unavailable ({error}); serving the API only");
            build_router(state.clone())
        }
    };

    // 30-day retention: once at startup, then on the interval. No scheduler daemon.
    let retention = Arc::new(RetentionJob::new(
        Arc::clone(&state.store),
        Arc::clone(&state.telemetry),
        Arc::clone(&state.clock),
    ));
    let _retention = retention.spawn_interval(DEFAULT_RETENTION_INTERVAL);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    println!("phoneconnect-server listening on {listen_addr}");
    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await?;
    Ok(())
}

fn environment_or(key: &str, fallback: &str) -> String {
    match std::env::var(key) {
        Ok(value) if !value.trim().is_empty() => value,
        _ => fallback.to_owned(),
    }
}

async fn shutdown_signal() {
    let _ = tokio::signal::ctrl_c().await;
}
