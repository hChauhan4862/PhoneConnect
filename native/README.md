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

- `SessionCipher` seals every frame with ChaCha20-Poly1305 keys agreed from the two pinned
  identity keys (X25519 + HKDF-SHA256 over the session id and a per-connection epoch built
  from both tickets' single-use nonces). The relay and a direct-path observer only ever see
  ciphertext, and the server cannot derive the keys.

## Trust model

- The identity keys are the trust anchor: only the two peers hold private halves, and the
  peer's public half is pinned by the server-signed ticket. This is TOFU through rendezvous:
  a malicious or compromised rendezvous server can substitute a peer key and MITM, so TLS
  authenticity to the server is assumed. A caller that learned the peer identity out of band
  pins it with `PathSetup::with_expected_peer_identity`, and `connect` then fails closed.
- The epoch makes every connection use fresh keys, so a second `ConnectedPath` for one
  session id never reuses a ChaCha20-Poly1305 nonce. It is not forward secrecy: the static
  identity keys are long-lived.
- `CandidateSet::discover` merges the relay route with locally discovered and
  server-observed endpoints.
- `PathController::connect` verifies the signed rendezvous ticket, probes direct candidates
  with bounded authenticated UDP, and selects the lower-latency validated path against the
  relay. Relay latency is measured on attach, not assumed, and the configured estimate is
  only the fallback.
- A direct path commits only after both peers confirm the switch, so a one-sided punch
  leaves the session on the relay instead of black-holing frames.
- `ConnectedPath` carries bounded frames over either path, with `upgrade_with(ticket,
  candidates, now)` for migrating a relay session to direct while keeping the relay as the
  fallback, and `fallback_to_relay` for path degradation. A migration never closes the relay
  session.
- `WebSocketRelay` attaches to the server's framed relay route. A `409 relay_unavailable`
  is terminal for that session id: create a new session, never retry on the old one, and
  read revocation from the stream close reason rather than from the lease status.

A direct path pins the peer's address for this milestone: `send_to` succeeding is not
delivery, and a peer that changed NAT mapping is only noticed by the absence of its frames.
Treat direct delivery as best-effort until the reconnect work renegotiates it.

`docker/transport-e2e/run.sh` runs the cross-process fallback test with the server and both
peer stubs in Docker.
