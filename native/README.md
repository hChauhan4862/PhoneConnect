# PhoneConnect native shell

Placeholder: this directory will hold the thin Tauri/Rust tray process for macOS, Windows,
and Linux.

Its intended responsibility is to open the server-served web UI URL in a webview, inject a
documented host-context bridge (separate OS windows, tray state, notifications, local
endpoints, external links), carry native transport when a peer is directly reachable,
otherwise fall back to the authenticated server relay, allocate collision-safe loopback
proxy ports per mapped stream, and verify/roll back its own updates.

It deliberately contains no product screens: there is exactly one UI implementation, and
native-only behavior is additive through the host adapter rather than a forked UI tree.
