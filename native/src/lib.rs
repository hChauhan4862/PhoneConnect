//! PhoneConnect native client.
//!
//! There is exactly one UI: the React app the server serves at `/`. This crate is the thin
//! desktop shell around it, plus the loopback proxy that lets a native client expose a
//! connected device as a local endpoint.
//!
//! - [`web_shell`] — URL policy, the injected host context, tray and window bookkeeping.
//! - [`proxy`] — loopback endpoint allocation, the per-session frame demux, and the byte
//!   pump over one proxy stream.
//! - [`endpoints`] — the endpoint lifecycle behind the shell's commands.
//! - [`session_client`] — the authenticated transport path the proxy rides.
//!
//! `src/main.rs` is only the Tauri wiring, compiled with `--features shell`, so the logic
//! above is tested without a webview or a display.

pub mod endpoints;
pub mod proxy;
pub mod session_client;
pub mod web_shell;
