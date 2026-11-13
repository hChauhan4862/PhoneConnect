//! Generates the Tauri ACL for the desktop shell build.
//!
//! The shell exposes exactly four application commands. Declaring them here makes
//! tauri-build generate `allow-*`/`deny-*` permissions for each, so the capability file can
//! grant them to the remote server origin explicitly instead of relying on a default.
//!
//! The build script is inert for a plain `cargo test -p phoneconnect-native`: the proxy and
//! URL policy are platform-independent, and compiling a webview toolchain to test them would
//! make the logic untestable on a headless machine.

fn main() {
    if std::env::var_os("CARGO_FEATURE_SHELL").is_none() {
        return;
    }
    tauri_build::try_build(tauri_build::Attributes::new().app_manifest(
        tauri_build::AppManifest::new().commands(&[
            "open_window",
            "set_tray_status",
            "local_endpoints",
            "notify",
        ]),
    ))
    .expect("generate the Tauri ACL");
}
