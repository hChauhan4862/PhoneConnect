//! PhoneConnect server entry point.
//!
//! Configuration is environment-only so the same image runs in compose, a VM, or a
//! single-node deployment: the bootstrap admin token is required, the database path and
//! listen address are optional, and the relay endpoint is advertised to peers.

use std::sync::Arc;

use phoneconnect_server::auth::{ADMIN_TOKEN_ENV, admin_token_from_env};
use phoneconnect_server::relay::RelayLimits;
use phoneconnect_server::store::{DeviceStore, SqliteStore, SystemClock};
use phoneconnect_server::{AppState, build_router};

const LISTEN_ADDR_ENV: &str = "PHONECONNECT_LISTEN_ADDR";
const DATABASE_PATH_ENV: &str = "PHONECONNECT_DATABASE_PATH";
const RELAY_ENDPOINT_ENV: &str = "PHONECONNECT_RELAY_ENDPOINT";

const DEFAULT_LISTEN_ADDR: &str = "0.0.0.0:8080";
const DEFAULT_DATABASE_PATH: &str = "/data/phoneconnect.sqlite3";
const DEFAULT_RELAY_ENDPOINT: &str = "http://localhost:8080/api/relay";

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let admin_token = admin_token_from_env()
        .map_err(|_| format!("{ADMIN_TOKEN_ENV} must be set to a non-empty admin token"))?;
    let listen_addr = environment_or(LISTEN_ADDR_ENV, DEFAULT_LISTEN_ADDR);
    let database_path = environment_or(DATABASE_PATH_ENV, DEFAULT_DATABASE_PATH);
    let relay_endpoint = environment_or(RELAY_ENDPOINT_ENV, DEFAULT_RELAY_ENDPOINT);

    let store: Arc<dyn DeviceStore> = Arc::new(SqliteStore::open(&database_path)?);
    let state = Arc::new(AppState::new(
        store,
        admin_token,
        relay_endpoint,
        RelayLimits::default(),
        Arc::new(SystemClock),
    )?);

    let listener = tokio::net::TcpListener::bind(&listen_addr).await?;
    println!("phoneconnect-server listening on {listen_addr}");
    axum::serve(listener, build_router(state))
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
