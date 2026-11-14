# PhoneConnect transport

The shared path layer beneath every PhoneConnect component. It carries already-sealed
PhoneConnect frames over the lowest-latency path both peers have authenticated: a direct UDP
path established with authenticated hole punching, or the server's bounded relay. It is
platform-independent so the native shell and the Android agent's future port share one
implementation, and every I/O seam is a Tokio socket or the `RelayChannel` trait.

## Frame sealing

Each peer holds a static X25519 identity key: the device's is registered at enrollment, the
client's when its session is authorized. `SessionCipher` runs X25519 between them and expands
the shared secret with HKDF-SHA256 into 64 bytes — 32 for client-to-device and 32 for
device-to-client — and each role uses one half to send and the other to receive.

The HKDF salt is the session id, a NUL, the client's single-use ticket nonce, a NUL, and the
device's single-use ticket nonce, in that role order. Both peers therefore derive the same
keys from the same rendezvous round. Because the identity keys are long-lived, a fresh ticket
round is what gives a connection fresh keys: reusing one epoch for a session and role in the
same process is refused (`AeadError::EpochReused`) instead of repeating a nonce.

Every frame is sealed with ChaCha20-Poly1305 under a 96-bit nonce of the sender's direction
byte (1 = client, 2 = device) followed by an 8-byte big-endian counter. The counter starts at
1 and never wraps; exhaustion ends the session with `CounterExhausted`.

The associated data binds the frame to its session and its readable header. It is the
`phoneconnect-aead-v1` label, the session id with a two-byte length prefix, then the sealed
header: version, key id, direction, counter, stream kind, and sequence. The header's stream
kind must equal the kind of the envelope inside; the relay and the receiver both pin that
equality (`StreamKindMismatch`), so a sender cannot relabel a control envelope as events.

The key id is derived from the session id, both identity public keys, and the epoch. A frame
for another identity pair carries an unknown key id and is refused. The server holds only the
public halves and can derive no traffic key. The server-issued probe key authenticates
hole-punch datagrams only; it never keys frame encryption.

Peer identity is trust-on-first-use through the rendezvous service, because the ticket that
names the peer's key is server-signed. A caller that learned the peer's identity by another
route pins it with `PathSetup::with_expected_peer_identity`, and a ticket naming a different
key fails closed. The epoch gives fresh keys per connection, not forward secrecy.

### Replay window

`SessionCipher` keeps a 64-entry sliding window per receiving direction. Any not-yet-seen
counter within 64 of the highest is accepted, so a reordered frame is still delivered. A
repeat is `AeadError::Replayed`; a counter below the window is `CounterRegression`, which
lets a caller tell a reorder from a fatal regression. A reflected frame carries the wrong
direction, and a changed header or ciphertext fails authentication.

Separately, each direct socket keeps its own 64-datagram replay window for probes,
acknowledgements, switch requests, and frames.

## Hole punching and candidate exchange

`CandidateSet::discover` merges the two views of the opposite peer into one ordered,
de-duplicated set and validates each endpoint before anything is probed:

- locally discovered direct endpoints, priority 200;
- an endpoint the server observed for the peer, priority 150;
- the relay, priority 100. Direct candidates outrank it, but the wire priority the server
  sends is preserved.

Before any probe, `Ticket::verify` checks the server's Ed25519 signature over the session id,
device id, role, rendezvous nonce, probe key, both pinned identity keys, and the expiry. A
tampered, expired, wrong-role, or already-used ticket is an explicit `TicketError`; nothing
degrades into "assume trusted".

Every direct datagram carries a round id and an HMAC-SHA256 tag over the whole packet. The
key is derived from the round's shared probe key, the session id, and the sender's role, so a
packet minted for another session, round, or role never authenticates. Authentication happens
before any sequence is accepted. One task owns every socket read and dispatches by kind, so a
concurrent upgrade cannot steal the peer's acknowledgement or drop a data frame.

Probing is bounded: each attempt waits at most 250 ms and the exchange stops after four
attempts by default. A direct frame is at most 60,000 bytes; larger frames belong on the
relay.

## Path selection, upgrade, and fallback

`PathController::connect` verifies the ticket, agrees the traffic key, probes the direct
candidates, and commits only after the peer confirms the switch. It then selects the lower of
the two validated round trips (`PathController::select`); a tie goes to the direct path, and
`None` means no path validated. The relay's round trip is measured at attach with a ping/pong
and falls back to a configured estimate when the measurement fails. `RelayOnlyPath` is the
alternative when UDP is unavailable.

`ConnectedPath::upgrade_with` repeats negotiation with a fresh ticket and moves the same path
to a direct channel when it validates, the peer confirms, and it is not slower than the relay.
Request ids, sequence numbers, and the relay lease are untouched, and the relay stays
attached: migration is reversible and fallback must not need a new session. An expired ticket
is a ticket error and explicitly not terminal, so the caller may fetch another and try again.

The relay is never closed by a path change. A freshly committed or re-promoted direct path
duplicates every frame onto the relay, bounded by `transition_timeout` (default 1 s) and
`transition_max_frames` (default 16), until a direct frame proves the peer reads direct. The
transition bound ends the duplication, never the relay.

Two state rules keep a healthy path from being demoted and a demotion from being a one-way
trip. A path is demoted only when the peer stops answering keepalives, never because the
application blocked in `recv_frame`, and a direct frame that arrives while the relay is being
read re-promotes it. Once a path has a relay it reads it for the rest of its life, in every
state, so a peer that demoted — or that we demoted ourselves onto — still reaches us. Only
relay *sends* are limited, because they are what can fill the relay's bounded queue. A
relay-origin frame proves the peer reads the relay, so it moves our sends there; the next
direct frame moves them back.

A direct path pins the peer's address for this milestone: a peer that moved behind a new NAT
mapping is detected only by the absence of its frames, so callers treat the direct path as
best-effort until a reconnect renegotiates it.

## Relay keepalive

The server closes a relay socket whose *direction* has carried nothing for 30 seconds
(`RELAY_IDLE_TIMEOUT`) with `idle_timeout`. A healthy direct path sends the relay nothing at
all, so without a keepalive the fallback would quietly disappear about thirty seconds into an
otherwise healthy session.

`PathConfig::relay_keepalive_interval` must be non-zero and shorter than that 30-second
timeout — `PathConfig::validate` refuses one that is not — and defaults to 10 seconds. The
keepalive is a WebSocket ping: the relay answers it itself and never forwards it, so it costs
no frame slot, no queue depth, and no sequence number. `idle_timeout` closes the relay, not the
session; the transport reports the loss of the relay only to a send that actually needs it.

The relay carries exactly one PhoneConnect frame per binary WebSocket message. Text messages
and oversized messages are refused before a frame is decoded. A relay that answers
`409 relay_unavailable` is terminal for that session id: create a new session and never retry
on the old one.

## Frame limits

`FrameLimits` bounds every frame before it is buffered. The default profile
(`FrameLimits::new`) allows 1 MiB on control and events and 4 MiB on file, media, and proxy.

`FrameLimits::control_only()` caps every stream kind at 1 MiB. Use it for control-only
connections: the default profile caps a length prefix at the 4 MiB stream limit, which would
let a peer force up to 4 MiB of buffering before the stream kind is known. With the
control-only profile an oversized frame is refused from its length prefix. `PathConfig`
defaults to that profile, and `direct_frame_limit` may not exceed 60,000 bytes.

## Delivery semantics

**A successful send does not prove delivery.** `ConnectedPath::send_frame` returning `Ok`
means the sealed frame was handed to the direct socket or the relay; neither acknowledges the
peer. Delivery is confirmed only by the peer's frames and by the switch handshake — never by
`send_to` succeeding.

A direct send to an address that no longer reaches the peer is still reported as sent. A relay
that refuses a copy — because the peer's bounded queue is full or the session closed — is
reported, and the transport treats any relay refusal as the signal that the copy did not
reach the peer. Frames the direct socket's bounded ring drops, or relay frames that fall out
of the replay window, surface as `PathError::FramesLost`. Callers that count bytes count bytes
*accepted by the transport*, never bytes delivered.

## Per-request-id sequence contract

`Envelope.sequence` is a monotonic counter **per request id**, not per session. It never
wraps; exhaustion ends the stream. A request id names one conversation — the loopback proxy
uses `proxy-<stream>-<n>`, one per local connection — and its sequence starts at 1 and ends
with that request.

The transport carries the sequence sealed inside the envelope and never renumbers or reorders
frames. Consumers that resume a byte stream (the loopback proxy's `ProxyHub`) require
contiguous sequences per request id: a gap, or a `FramesLost` report, closes that stream with
`SequenceGap` / `FramesLost` rather than writing a hole into a TCP stream. A re-established
session restarts the counter at 1, and a late frame for a closed request id must be dropped by
the peer rather than answered or carried into the next connection.

The transport allows exactly one reader per `ConnectedPath`. A consumer that fans frames out
(control, events, proxy) must own that reader and route by request id, because a second
concurrent reader would steal frames from the first.

## Tests

`crates/protocol/build.rs` runs `protoc`, so install it before any Cargo command:
`brew install protobuf` on macOS, `sudo apt-get install -y protobuf-compiler` on
Debian/Ubuntu.

```sh
cargo test -p phoneconnect-transport
```

`tests/aead.rs` covers sealing, tamper, replay, regression, direction, and key-id failures;
`tests/path_upgrade.rs` drives real loopback UDP sockets and the server relay through
validation, selection, upgrade, demotion, and fallback; `tests/kotlin_fixtures.rs` holds
byte-for-byte compatibility vectors for the Android port; and
`docker/transport-e2e/run.sh` proves a control frame crosses the relay between two containers
when direct probing cannot succeed.
