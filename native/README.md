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

## Transport

Direct-path and relay transport live in the shared `crates/transport` crate
(`phoneconnect-transport`), not in this shell, so the native client and the Android agent
run the same negotiation:

- `CandidateSet::discover` merges the relay route with locally discovered and
  server-observed endpoints.
- `PathController::connect` verifies the signed rendezvous ticket, probes direct candidates
  with bounded authenticated UDP, and selects the lower-latency validated path against the
  relay.
- `ConnectedPath` carries bounded frames over either path, with `try_upgrade` for migrating
  a relay session to direct while keeping the relay as the fallback, and
  `fallback_to_relay` for path degradation. A migration never closes the relay session.
- `WebSocketRelay` attaches to the server's framed relay route. A `409 relay_unavailable`
  is terminal for that session id: create a new session, never retry on the old one, and
  read revocation from the stream close reason rather than from the lease status.

`docker/transport-e2e/run.sh` runs the cross-process fallback test with the server and both
peer stubs in Docker.
