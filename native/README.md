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
- A freshly committed or re-promoted direct path duplicates every frame onto the relay until
  a direct frame proves the peer reads direct. The duplication is bounded in time
  (`PathConfig::transition_timeout`) and frames (`PathConfig::transition_max_frames`), and a
  relay that refuses a copy — `Backpressure`, or the close the server sends instead when a
  peer queue fills — ends it early: an unbounded transition would fill the relay's peer queue
  until the server closed the sender's socket, destroying the fallback.
- The transition bound ends the *duplication*, never the relay. A path that has a relay reads
  it for the rest of its life, in every state, so a peer that demoted still reaches us; only
  relay *sends* are limited, because they are what fills the bounded relay queue. A
  relay-origin frame is proof the peer reads the relay, so it moves our sends there, and the
  next direct frame moves them back. That is what makes a one-way outage degrade instead of
  dying: our datagrams are lost, the peer demotes to the relay and sends there, we read the
  relay and follow it, and the session keeps delivering until a fresh `upgrade_with` restores
  a direct path.
- A committed direct path is demoted only when the peer stops answering keepalives, never
  because the application happened to be blocked in `recv_frame`. A receive longer than
  `direct_health_timeout` keeps a live path direct, and a direct frame that arrives while
  the relay is being read re-promotes the path and is surfaced to the caller. Every receive
  is bounded by `PathConfig::recv_timeout`, including the relay wait. While a path is
  duplicating, a relay frame waits up to `PathConfig::relay_frame_grace` for its own direct
  copy, so a low-latency relay does not talk a healthy direct path out of the data it is
  already delivering.
- Loss is reported, not hidden: `ConnectedPath::dropped_frames` counts frames the bounded
  inbound ring dropped for a stalled reader (monotonic, including after shutdown), and the
  next receive reports the gap as `PathError::FramesLost { count }` — non-fatal and local,
  never as the `CounterRegression` a broken peer would produce. `relay_backpressure_events`
  counts relay copies the relay refused.
- `WebSocketRelay` attaches to the server's framed relay route. A `409 relay_unavailable`
  is terminal for that session id: create a new session, never retry on the old one, and
  read revocation from the stream close reason rather than from the lease status.

A direct path pins the peer's address for this milestone: `send_to` succeeding is not
delivery, and a peer that changed NAT mapping is only noticed by the absence of its frames
(keepalives make that bounded, and a path with a relay demotes back to it automatically).
Treat direct delivery as best-effort until the reconnect work renegotiates it.

Every `connect` needs a fresh ticket and freshly read candidates: the ticket's single-use
nonce is half the connection key epoch, and a ticket already used by this process is refused
instead of silently reusing keys.

`docker/transport-e2e/run.sh` runs the cross-process fallback test with the server and both
peer stubs in Docker.
