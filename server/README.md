# PhoneConnect server

The control plane for PhoneConnect: it authorizes sessions, serves rendezvous data, and
operates the bounded relay fallback. Frames are sealed end to end by the peers, so the relay
carries ciphertext it cannot read: this process holds only public identity keys and can
derive no traffic key. It never exposes ADB and never interprets a payload.

## Binary and crate layout

- crate `phoneconnect-server`, library `phoneconnect_server`, binary `phoneconnect-server`.
- `src/lib.rs` — `AppState`, the API error envelope, and the router.
- `src/auth.rs` — credential classes, hashing, constant-time comparison, authorization checks.
- `src/store.rs` — `DeviceStore` trait plus the SQLite implementation and the clock.
- `src/enrollment.rs` — one-time enrollment tokens and device enrollment.
- `src/rendezvous.rs` — session capabilities, signed rendezvous tickets, ticket
  redemption, and candidate exchange.
- `src/relay.rs` — bounded relay sessions, limits, explicit close reasons, and the framed
  relay transport route.
- `src/leases.rs` — control leases: one holder per device, explicit grant and handoff,
  read-only secondary access, and revocation that closes the lease's streams.
- `src/management.rs` — the device management channel: one authenticated WebSocket per
  device, the in-memory command table, deadlines, and bounded results.
- `src/commands.rs` — the command HTTP surface: authorization, dispatch, polling, and the
  audit rows written for every attempt and every command that ends without an answer.
- `src/audit.rs` — the read-only audit surface (`GET /api/audit`) and the revocation rows
  the admin and lease routes append. A row carries identity, action, outcome, and an error
  code; never an argument, a path, a file byte, or an image.
- `src/telemetry.rs` — bounded per-device telemetry aggregation, explicit freshness, and
  30-day aggregate deletion.
- `src/status.rs` — the status surface the web UI renders: device, session, path evidence,
  lease, and telemetry.
- `src/retention.rs` — the callable 30-day retention job (startup + interval hook).
- `src/web.rs` — serves the built web app at `/` with SPA fallback and a strict CSP.
- `src/admin.rs` — admin-guarded revocation of tokens, devices, and sessions.
- `src/main.rs` — environment-driven configuration and process startup.

## Endpoints

| Method | Path | Credential | Purpose |
|---|---|---|---|
| `GET` | `/health` | none | Liveness plus `audit_write_failures`, the best-effort dispatch audit writes that failed since startup. Never touches sessions. |
| `POST` | `/api/enrollment-tokens` | admin | `{token, expires_at}` for one owner. |
| `POST` | `/api/devices/enroll` | enrollment token | Consumes the token once; body is `{token, identity_key}` and the response is `{device_id, credential}`. The device's X25519 identity public key is pinned here. |
| `POST` | `/api/sessions` | admin | Authorizes a device session; body is `{device_id, client_identity_key, control?, user_id?}`, response `{session_id, capability, expires_at, ticket, verification_key}`. `control: true` requires a live lease held by `user_id`; the default session is read-only. |
| `GET` | `/api/sessions/{id}/ticket` | session capability or owning device credential | Fresh short-lived ticket for the calling role. |
| `GET` | `/api/sessions/{id}/candidates` | session capability or owning device credential | Relay route plus the endpoint observed for the opposite peer. |
| `POST` | `/api/sessions/{id}/candidates` | session capability or owning device credential | Redeems a ticket, records this peer's observed endpoint, returns the peer's view. |
| `POST` | `/api/sessions/{id}/relay` | session capability or owning device credential | Bounded relay lease with explicit limits. |
| `GET` (upgrade) | `/api/sessions/{id}/relay` | session capability (client end) or owning device credential (device end) | The framed relay transport: a WebSocket carrying one PhoneConnect frame per binary message. |
| `POST` | `/api/enrollment-tokens/{token}/revoke` | admin | Revokes one unused enrollment token; idempotent. |
| `POST` | `/api/devices/{id}/revoke` | admin | Revokes a device and its live sessions; closes their relays. |
| `POST` | `/api/sessions/{id}/revoke` | admin | Revokes one session; closes its relay. |
| `GET` | `/api/devices` | admin | Enrolled devices, oldest first. No credential is ever returned. |
| `GET` | `/api/devices/{id}/status?user_id=` | admin | The status surface: enrollment, the live session (or the newest ended one when none is live) with path evidence, lease, telemetry freshness. |
| `GET` | `/api/devices/{id}/lease?user_id=` | admin | The active lease and one user's access (`is_owner`, `role`, `can_control`). |
| `POST` | `/api/devices/{id}/lease` | admin | The owner grants control while the device is free; body is `{actor_id, expires_in_seconds?}`. |
| `POST` | `/api/devices/{id}/lease/handoff` | admin | Explicit transfer of control; body is `{actor_id, to_user_id, expires_in_seconds?}`. Returns the new lease and the replaced one's revocation event. |
| `POST` | `/api/leases/{id}/revoke` | admin | Immediate revocation; body is `{actor_id}`. Returns the revocation event, including the stream capabilities it invalidated. Idempotent. |
| `GET` | `/api/devices/{id}/sessions/next` | device credential | The newest live session for this device, with a device ticket and a `control` flag; `204` when there is none. |
| `POST` | `/api/devices/{id}/telemetry` | device credential matching `{id}` | One bounded telemetry report; the response is the bounded aggregate. |
| `GET` (upgrade) | `/api/devices/{id}/control` | device credential matching `{id}` | The management channel: a WebSocket carrying JSON telemetry and commands. A new connection replaces the old one with a `replaced` close. |
| `POST` | `/api/devices/{id}/commands?user_id=` | admin | Dispatches one command; body is `{name, args?, timeout_ms?}` and the response is `202 {command_id}`. Refusals are `403 lease_read_only`, `409 device_offline`, `409 device_revoked`, `429 command_capacity`, `400 invalid_timeout`. |
| `GET` | `/api/commands/{id}?user_id=` | admin | One command's state: `pending`, `ok`, `error`, or `timeout`, with `output`, `error`, `message`, and timestamps. |
| `GET` | `/api/audit?device_id=&limit=` | admin | Newest-first durable audit rows (`at_ms`, `actor`, `action`, `device_id`, `outcome`, `error`). `device_id` is an exact filter; an unknown device is an empty list. `limit` defaults to 50 and is capped at 200. Read-only: no endpoint changes a row. |
| `POST` | `/api/devices/{id}/files/list?user_id=` | admin | Forwards `files.list`; body is `{path}`. Responds `202 {command_id}`, polled like any command. |
| `POST` | `/api/devices/{id}/files/read?user_id=` | admin | Forwards `files.read`; body is `{path, offset?, length?}`. |
| `POST` | `/api/devices/{id}/files/write?user_id=` | admin | Forwards `files.write`; body is `{path, data_base64, append?}`. A write whose body decodes past 1 MiB is refused with `413 too_large` before it is dispatched; `400 invalid_base64` otherwise. |
| `POST` | `/api/devices/{id}/files/mkdir?user_id=` | admin | Forwards `files.mkdir`; body is `{path}`. |
| `POST` | `/api/devices/{id}/files/delete?user_id=` | admin | Forwards `files.delete`; body is `{path}`. The device removes a file or an empty directory only. |
| `POST` | `/api/devices/{id}/files/rename?user_id=` | admin | Forwards `files.rename`; body is `{from, to}`. |
| `POST` | `/api/devices/{id}/apps/list?user_id=` | admin | Forwards `apps.list`; the body is ignored (an object or `null`). Responds `202 {command_id}`, polled like any command. |
| `POST` | `/api/devices/{id}/apps/launch?user_id=` | admin | Forwards `apps.launch`; body is `{package}`. The device answers `launch_blocked` or `no_launch_activity` when its platform refuses. |
| `POST` | `/api/devices/{id}/apps/stop?user_id=` | admin | Forwards `apps.stop`; body is `{package}`. The device reports `kill_requested`, not a confirmed stop. |
| `POST` | `/api/devices/{id}/apps/clear?user_id=` | admin | Forwards `apps.clear`; body is `{package}`. The device refuses it as `not_permitted` (it needs a signature-level permission). |
| `POST` | `/api/devices/{id}/apps/set_enabled?user_id=` | admin | Forwards `apps.set_enabled`; body is `{package, enabled}`. The device refuses it as `not_permitted` (it needs a signature-level permission). |
| `POST` | `/api/devices/{id}/screen/snapshot?user_id=` | admin | Forwards `screen.snapshot` with no arguments; the body must be an object or `null`. The device answers `consent_required` unless the user enabled screen capture on its setup screen. A result over the 2 MiB cap is refused `result_too_large`. |
| `POST` | `/api/devices/{id}/console/props?user_id=` | admin | Forwards `system.props`; body is `{}` or `{keys:[...]}` (at most 32 names of at most 64 bytes). The device reports its documented allowlist and answers `not_permitted` for a name outside it; a platform reader failure is `props_unavailable`. |
| `POST` | `/api/devices/{id}/console/shell?user_id=` | admin | Forwards `shell.exec`; the body must be an object or `null`. The device always answers `not_permitted`: a shell needs the ADB/root UID. |
| `POST` | `/api/devices/{id}/console/logcat?user_id=` | admin | Forwards `logcat.tail`; the body must be an object or `null`. The device always answers `not_permitted`: `READ_LOGS` is signature-level. |
| `POST` | `/api/devices/{id}/control/get?user_id=` | admin | Forwards `control.get` with no arguments; the body must be an object or `null`. The device reports each reading or `null` plus its constant reason in `unavailable`, and names every key it refuses to change. |
| `POST` | `/api/devices/{id}/control/set?user_id=` | admin | Forwards `control.set`; body is `{key, value}` where `value` is an integer or a boolean (at most 32 bytes of key; no NUL). The device owns the ranges and answers `invalid_args`, `not_permitted` with a machine reason, `not_applied`, or `unconfirmed`, with `platform_read_failed` when it cannot read the stream max; every reason token or message arrives verbatim. |
| `POST` | `/api/devices/{id}/control/reboot?user_id=` | admin | Forwards `control.reboot`; the body must be an object or `null`. The device always answers `not_permitted` / `reboot_requires_privilege`: `REBOOT` is signature-level. |

The file routes are commands with a typed front door: the same authorization, capacity,
deadline, and audit row as `POST /commands`, and the same refusals (`403 lease_read_only`,
`409 device_offline`, `429 command_capacity`). The device's `PathGuard` is the safety
authority; the server's own checks are structural (`invalid_request`) plus the write size cap.
Whatever a forwarded command can and cannot do is the device's answer, not the server's
decision: `../docs/capabilities.md` is the single device-side matrix of every command, its
refusal code and reason, and whether it was verified on the emulator or only in a unit test.
The app routes follow the same pattern. The server's own checks are structural
(`invalid_request`: a missing, non-string, blank, NUL-containing, or over-255-byte package, or
a non-boolean `enabled`); every capability decision is the device's, so `launch_blocked`,
`no_launch_activity`, `unknown_package`, and `not_permitted` arrive verbatim and are never
translated into a success. Nothing about an app list is persisted.

File bytes are never written to disk, stored in the database, or logged: an accepted write is
forwarded as the caller's own base64, and the command record keeps only the device's answer
(`bytes_written`, entries, or one read chunk) in the bounded in-memory table.

The screen and console routes are the same pattern, and the honest half of this milestone:

- `screen/snapshot` forwards `{}` and nothing else. The device captures only with the
  `MediaProjection` consent the user granted on its setup screen; without it the answer is
  `consent_required`, and the server never asks the device to prompt. A frame is bounded by the
  device (base64 under 2 MiB) and by the server: an answer over the result cap becomes
  `result_too_large`, never a stored oversized payload. Nothing about a frame is written
  anywhere.
- `console/props` forwards an optional key list and lets the device decide what its allowlist
  permits; `not_permitted` and `props_unavailable` arrive verbatim.
- `console/shell` and `console/logcat` exist so a caller receives the device's constant
  `not_permitted` (with its reason) instead of `unknown_command`. Neither can succeed for an
  ordinary installed app, and the server never fabricates output for them. There is no
  streaming endpoint: one answer per accepted command.

The control routes follow the same pattern and keep the same honesty:

- `control/get` forwards `{}` and passes the device's reading map through untouched. A reading
  the platform refuses is `null` with a reason in `unavailable`; the server never fills a
  missing value in.
- `control/set` checks only what it could not forward — a missing, non-string, blank,
  NUL-containing, or over-32-byte key, or a value that is neither an integer nor a boolean
  (`400 invalid_request`) — and forwards `{key, value}` verbatim. The device decides the range
  (`invalid_args`), whether a grant is missing (`not_permitted` with `write_settings_required`
  or `policy_access_required`), whether a write stuck (`not_applied`), and whether the device
  could confirm it (`unconfirmed`); a volume stream whose max it cannot read is
  `platform_read_failed`. Every code and reason message arrives verbatim.
- `control/reboot` is forwarded so the device's constant `not_permitted` /
  `reboot_requires_privilege` reaches the caller instead of `unknown_command`. The server has no
  reboot path of its own.
- Nothing about a reading or a control value is persisted: the bounded in-memory command record
  keeps the device's answer and nothing else.
| `GET` | `/` and any non-API route | none | The built web app, with SPA fallback for its routes. |

An unknown `/api/...` path is always a JSON 404 (`api_not_found`); it never returns the SPA
document, including when the slash is percent-encoded (`/api%2Fnope`), because the path is
classified after decoding. A path that names a file but does not resolve is a 404 too, so a missing asset is
never served as HTML labelled as JavaScript. Every web response carries
`Content-Security-Policy: default-src 'self'; ... object-src 'none'; base-uri 'none';
frame-ancestors 'none'`, `X-Content-Type-Options: nosniff`, and `Referrer-Policy:
no-referrer`. Assets are immutable-cached; the app shell is `no-cache`. The built app is
served from `PHONECONNECT_WEB_ROOT` (default `web/dist`), read once at startup; a missing
build is reported on stderr and the API is served without it.

The UI is **not live**. There is no server-to-client push channel, so a screen shows the
snapshot it last read: another user's handoff, a revocation, or a new session appears only
after a refresh. The status and telemetry screens say so next to their refresh controls.

Errors are always `{"error": "<code>"}` with a non-2xx status; there are no
success-shaped fallbacks. Revocation returns `{"revoked": true, "revoked_at": <unix ms>}`
and is idempotent, so an operator can retry it safely. Revoking a device or session also
closes that relay in the running process before the response is sent.

Revocation by enrollment token takes the raw token in the URL path, which reverse proxies
often log. Hash it before lookup (this server does not store the raw token) and configure
access logging to drop that path, or revoke through a control plane that does not log it.

## Credential classes

1. Admin bearer token from `PHONECONNECT_ADMIN_TOKEN`. It mints enrollment tokens and
   authorizes sessions; local password and MFA login arrive with the production-ops plan.
2. Device credential (`pcdev_...`) issued once at enrollment.
3. Session capability (`pcsess_...`) minted per authorized session, valid for 5 minutes.

Secrets are stored only as SHA-256 hashes and compared in constant time. Enrollment tokens
are single-use and consumed in the same transaction that creates the device.

## Frame encryption and identity keys

Frame confidentiality is end to end: each peer holds a static X25519 identity key — the
device's is registered at enrollment, the client's when its session is authorized, which is
the login-equivalent registration until local password login lands. The two peers agree a
secret with X25519 and split it with HKDF-SHA256 salted by the session id into one key per
direction. Every frame is sealed with ChaCha20-Poly1305, a per-direction nonce built from
the direction byte and a monotonic counter, and associated data that binds the session id,
stream kind, sequence, counter, and key id.

The server only ever receives the public halves. It cannot derive a traffic key from what it
stores, so it cannot read a frame even though it carries it. The server-issued probe key
authenticates hole-punch datagrams only; it never keys encryption. A tampered frame, an
unknown key id, a reflected frame, a replayed counter, and a counter regression are refused
explicitly, while a reordered frame inside the replay window is still delivered.

Each connection mixes a fresh epoch (both tickets' single-use nonces) into the key
derivation, so a reconnecting peer derives new keys and never reuses a ChaCha20-Poly1305
nonce.

The trust model is explicit: peer identity is trust-on-first-use through this rendezvous
service, because the ticket that names the peer's key is signed by the server. A malicious
or compromised server can substitute a peer key and MITM, so clients must authenticate the
server over TLS and may pin the peer identity out of band. The protocol gives fresh keys per
connection but not forward secrecy.

## Rendezvous tickets and direct-path candidate exchange

Each peer receives a signed, short-lived ticket: an Ed25519 signature over the session id,
device id, role, rendezvous nonce, 256-bit probe key, both pinned identity public keys, and
a 30-second expiry that never outlives the session. The public verification key travels with the ticket
(`verification_key`) so a peer verifies the signature itself; only the server holds the
private half, and the key is persisted at `PHONECONNECT_TICKET_KEY_PATH`, so a restart keeps
the same verification key and outstanding tickets stay valid.

Both roles of one rendezvous round receive the same nonce and probe key — that shared value
is what authenticates direct-path probes — while each ticket is signed for its own role.
Redemption is single-use per role: a replayed ticket answers `409 ticket_replayed`, a
tampered or unsigned ticket `401 ticket_invalid`, an expired one `401 ticket_expired`, and
a ticket presented by the wrong role or session `401 ticket_scope_mismatch`. None of these
reaches candidate exchange, so a replayed ticket never establishes a path. Re-requesting a
ticket after a redemption starts a new rendezvous round, so a peer that lost its ticket can
always re-register instead of being told its own nonce is a replay.

`POST /api/sessions/{id}/candidates` redeems the caller's ticket and records the endpoint
that peer reports for itself. `GET /api/sessions/{id}/candidates` (and the response to the
`POST`) returns the relay route plus a `server_observed` candidate for the opposite peer
once that peer has reported one. The relay route is `<PHONECONNECT_PUBLIC_URL>/api/sessions/
{session_id}/relay`.

## Relay transport and live authorization

`POST /api/sessions/{id}/relay` returns a lease whose `endpoint` is the live transport route
for that session. An HTTP `GET` upgrade on the same path is the framed relay transport: each
binary WebSocket message is exactly one PhoneConnect frame, authorization is re-checked
before the upgrade, and each peer attaches with the credential it holds (a session capability
is the client end, a device credential is the device end). The advertised `expires_at` and
`limits` fields bound the session.

The relay re-reads authorization while a session is attached: every send and receive
consults the clock and the store, and a blocked peer polls on a bounded interval. A session
stops forwarding as soon as it expires, its session is revoked, its owning device is
revoked, or its store record disappears. Each case reports a distinct close reason
(`SessionExpired`, `SessionRevoked`, `DeviceRevoked`, `UnknownSession`, and
`StoreUnavailable` when authorization state cannot be read, which fails closed).

A relay session is leased once. If its relay closes — the session byte budget is exhausted,
the transport closes it, or revocation ends it — the same session id cannot be leased again
until the session expires: the close reason is sticky and the per-session byte budget counts
every byte forwarded under that session, not every byte forwarded under one lease. Asking for
a new lease or a transport upgrade returns 409 `relay_unavailable`, which is terminal for
that session id: create a new session and never retry on the old one.

A transport that ends because of revocation or expiry sends a WebSocket close frame with a
stable code (`device_revoked`, `session_revoked`, `session_expired`, `idle_timeout`,
`backpressure`, and so on). Peers learn revocation from that stream error, not from the
status the lease reported when it was issued. A full peer queue is one of those closes: a
sender that overruns it never sees a per-frame "backpressure" response, it sees the stream
close, which is why the transport treats any relay refusal as the signal that the copy did
not reach the peer. Closed relay state is dropped when the session expires, so memory stays bounded by
sessions from the last five minutes.

A peer's socket is closed with `idle_timeout` when nothing has crossed it in either direction
for 30 seconds. Anything the peer sends proves it is still there, including a WebSocket ping
and a pong — a ping is answered by the relay itself and is never forwarded, so it costs no
frame slot, no queue depth, and no sequence number. That is the keepalive the transport uses:
a session whose traffic is entirely direct sends the relay nothing, so without a periodic
ping the fallback would be closed about thirty seconds into an otherwise healthy session.

`idle_timeout` closes the *relay*, not the session. A peer whose direct path is delivering
should keep using it: the transport reports the loss of the relay only to a send that actually
needs it, and never as the result of an otherwise idle read. Reserve "create a new session" for
`409 relay_unavailable` on a *new* lease, or for a `device_revoked`, `session_revoked`, or
`session_expired` close.

## Control leases

A device has at most one active control lease. The owner grants it while the device is free
(`POST /api/devices/{id}/lease`) and may hand it to another user explicitly
(`.../lease/handoff`); a held lease is never displaced silently, not even by the owner, and
handoff is atomic in the store. The holder may pass control on or revoke it. A user without
the lease is a secondary viewer: status and telemetry read normally, and every control
admission is refused `403 lease_read_only` instead of quietly succeeding.

A control session (`POST /api/sessions` with `control: true` and a `user_id`) is authorized
by the lease, linked to it, and never outlives it. The device learns the flag from
`/sessions/next`, so it refuses a control frame on a read-only session even if the frame
reaches it. Revoking a lease or handing it off
revokes those sessions in the store *and* closes their relay transports with the
`lease_revoked` close reason **in the same request**, so an attached peer learns immediately
rather than at the next liveness poll. Revocation returns the event naming every invalidated
session.

Read-only is enforced per frame, not only at admission. The session record persists whether a
lease authorized control; the relay refuses a `STREAM_KIND_CONTROL` frame from the client end
of a read-only session with `control_not_authorized`, without ending the stream, so a viewer
that keeps receiving telemetry stays connected. Over the WebSocket the refused frame is
dropped and the socket stays open (the transport has no per-frame error), and the server
counts the refusal in the status surface's `control_refusals`, which the UI shows. A control
session's frames are accepted, and revocation ends the stream before the next frame can be
sent.

The relay decides all of that from the **sealed frame's own header**, never from the routing
label the sender chooses. A relay payload must carry a readable sealed header
(`SealedHeader::stream_kind`), the payload must fit the limit that header declares (so a
larger routing label cannot buy a bigger cap for a control frame), and the routing label must
equal the header's kind — otherwise the frame is refused `stream_kind_mismatch`. A receiver
pins the same equality between the header and the envelope it decrypts, so a key holder that
labels a control envelope as events is refused at the relay *and* at the peer. The device also
learns whether its session is a control session from `/sessions/next` and refuses an inbound
control frame locally when it is not.

Leases are **not yet an authorization boundary in the security sense**: with no local password
login or MFA, the admin-token holder asserts `actor_id`/`user_id` in the request. The lease
rules constrain what a client may do once its identity is accepted; they do not authenticate
that identity. Local accounts and MFA (production-ops plan) turn them into a real boundary.

Revoking a lease stops **new** commands; it does not cancel one already delivered. A lease may
be granted for as little as a second while a command's deadline may be 60 s, and the management
channel has no cancel frame, so a command dispatched just before revocation can still run and
answer after it. The device is the one bound that helps: it refuses to start a frame whose
absolute `expires_at_ms` has already passed. Treat `lease_read_only` as the guarantee and
revocation as a gate on future dispatches, not a kill signal.

## Management channel and commands

Besides the sealed peer relay, every enrolled device keeps a management WebSocket at
`/api/devices/{id}/control`, authorized by its device credential. It carries JSON the server
reads — this is the deliberate, documented trade that gives the one web UI any device feature
at all; relay frames stay ciphertext.

Frames are fixed:

- device → server `{"type":"hello","model","android_version","sdk"}`,
  `{"type":"telemetry","sample":…}`, and
  `{"type":"result","request_id","status":"ok"|"error","output","error","message"}`;
- server → device `{"type":"command","request_id","name","args","deadline_ms","expires_at_ms"}`,
  where `deadline_ms` is a duration the device may spend and `expires_at_ms` is the same
  deadline as absolute server time. A device that dequeues a frame after `expires_at_ms` must
  refuse to start it and answer `timeout`: a duration alone would let a command queued behind
  a slow handler run after the caller was already told it timed out. `args` is a JSON object or
  null; any other type is refused `error: invalid_args`.

One connection per device: a second connection replaces the first, which is closed with the
`replaced` code and whose in-flight commands complete as `error`/`device_offline`. Revoking the
device closes its open channel in the same request with the `device_revoked` code, so it stops
refreshing telemetry; until the socket observes that close, frames from a revoked device are
dropped rather than ingested. A frame that is not valid JSON closes the channel with
`malformed_frame`; an invalid telemetry *value* is dropped and surfaces as stale telemetry
instead.

Commands live in memory only: at most 64 in flight per device, a 10 s default and 60 s
maximum deadline, and at most 2 MiB per result (an oversized result refuses the command with
`result_too_large`). Retained records are bounded by count **and** by the bytes of their
answers: the whole table keeps at most 32 MiB of retained answer (the serialized `output` plus
the `message` and `error` text — a `files.read` chunk is ~350 KiB, so a count-only cap would
allow over a gigabyte), and the oldest completed records are dropped once either bound is
crossed — a trimmed command reads as `command_unknown`, the same as one past the count cap.
Each `message`/`error` is itself kept to 4 KiB (its beginning plus an ellipsis) so one result
cannot spend the budget on prose, and one budget serves every device, so a large fleet cannot
multiply the ceiling. The channel is rate-limited per device, not just bounded: 20 inbound
frames/s and 4 MiB/s, with an over-budget channel closed as `rate_limited`; command creation —
and every attempt that can be traced, including a refused one — is throttled at 10/s per device
(burst 20) and answers `429 rate_limited` with `Retry-After`. The throttle is checked at the
attempt's entry, before any other decision, because it is also the bound on audit growth: an
attempt it refuses is not traced. The per-device bucket table is capped (4 096 ids), because an
attempt may name an id that matches no device and is still traced; past the cap a new name is
refused rather than remembered.
The bursts are sized from the caps, not guessed: at least one result frame per in-flight
command, and enough bytes for a full-size result from each of them, so a device that fell
behind can always deliver what it owes. The same per-device ingress budget is charged by
`POST /api/devices/{id}/telemetry`, which feeds the same ingest mutex — a flood through either
door is refused `429 rate_limited`. Buckets are keyed by device, so reconnecting does not reset
them. The numbers live in one `management::limits` block. A command whose deadline passes reads as `timeout`
and appends its `command.outcome` row; nothing pending is ever left looking successful. The device owns the command vocabulary: the server forwards any
name, and an unimplemented one comes back as `unknown_command`.

Dispatch requires the admin token *and* the actor's access to the device (its owner, or the
active lease holder); the actor is the `user_id` query parameter because the admin token
carries no identity. Every attempt the creation throttle admits writes one `command.dispatch`
row with actor, action, device, outcome, and error code — written best-effort after enqueue, and
**`accepted` means the frame reached the device's channel, not that the device executed it**. A command that then
ends without a device answer appends a second `command.outcome` row (`timeout` or
`device_offline`); see [Audit](#audit).

## Audit

Two actions describe a command's life. Every attempt that gets past the per-device creation
throttle writes one durable `command.dispatch` row: `at_ms`, `actor`, `action`, `device_id`,
`outcome` (`accepted` or `refused`), and the machine `error` code when there is one. An attempt
the throttle refuses answers `429 rate_limited` and appends nothing — tracing it would let a
flood write rows through the very limit that is meant to bound the log. A command that then ends **without
a device answer** writes one more row with action `command.outcome` and outcome `timeout` (its
deadline passed) or `device_offline` (the device's channel ended first). When both are true —
the deadline passed while nothing observed the table, then the channel ended — `timeout` wins,
because it happened first; every terminal path settles passed deadlines before it fails the
rest. Nothing else writes an
outcome row: an answered command — `ok` or `error`, including `result_too_large` — keeps only
its `command.dispatch` row and its in-memory record, and a refused dispatch never became a
command, so it has no outcome row. `accepted` therefore means *delivered to the device's
channel*, not executed, and the trace separates "accepted and executed" (no `command.outcome`
row) from "accepted and never answered" (one).

Both rows are written **after the attempt is resolved**: accepted attempts are enqueued first,
refusals before the response, and outcomes when the registry settles a deadline or a channel.
The outcome rows are written by the registry itself, from facts copied out of the in-memory
command table after its lock is released, so a database call never stalls a device's channel.
Every one of these writes is best-effort: a failed write is logged at error level, counted as
`audit_write_failures` in `GET /health`, and never changes the caller's outcome or the
command's state. The counter is an upper bound on untraced events: it counts a missing refusal
or outcome row too. A non-zero value means at least one event has no durable row.

**The actor is asserted, not authenticated.** `actor` is the `user_id` query parameter (or a
lease body's `actor_id`), which any admin-token holder can set to any string, because the
bootstrap token carries no identity of its own. A row is therefore attribution, not
non-repudiation: it records what the server did for *someone claiming* that identity, not who
did it. Accounts and MFA turn it into a real boundary.

What the server does enforce is the **order and classification** of the decision. Access to the
named device is decided first, and a refusal is classified by that decision: an unauthorized
attempt is still traced, against the device it named, with the authorization code
(`lease_read_only`, `device_revoked`, `device_unknown`) rather than whatever code its request
body would otherwise have produced. Only a caller that has access has its request-shape code
recorded (`invalid_request`, `too_large`, …). So a caller cannot choose the code on its row, but
it can always name itself anything, and access to one device says nothing about another. The
refusal row is deliberately *not* withheld from an unauthorized attempt — that is the order in
this code, and the docs describe it so a later change does not "fix" the code to match a
stronger claim.

Every revocation writes its row **inside the same store transaction** that performs it, so a
revocation can never commit untraced. If the audit row cannot be written, the whole revocation
rolls back and the request answers `500 store_failure`: the device, session, or lease stays
active until the store is repaired. That is the deliberate trade — a revocation that cannot be
traced does not happen. The row is stamped with the effective revocation time and the
affected device, and these endpoints are idempotent: a retried `device.revoke`,
`session.revoke`, or `lease.revoke` keeps the first time and appends nothing, so a retry can
never claim a later event or another actor. `lease.handoff` records the replaced lease and the
actor that granted it; a handoff that replaces nothing writes no row. A session revocation is
keyed by the session's device; the actor of a device or session revocation is `admin` because
the bootstrap token carries no user identity. An enrollment-token revocation precedes any
device, has no `device_id`, and is therefore not an audit row.

`GET /api/audit` is read-only and admin-authenticated: there is no endpoint that writes,
changes, or deletes a row. Rows carry no command arguments, file path, file bytes, or image
data — a refused `files.write` records that it was refused and its code (`device_offline`,
`too_large`), not the path or the content. The `device_id` filter is an exact match, so an
unknown device id is an empty list rather than another device's history. `limit` defaults to
50 and is capped at 200; `0`, a negative number, or a non-number is `400 invalid_request`
rather than a silently widened page.

## Telemetry

`POST /api/devices/{id}/telemetry` and the management channel's `telemetry` frames each
accept one report and keep a bounded window per device: at most 16 retained samples and one small aggregate (min/max/mean plus the latest value), for
at most 200 devices. A 201st device is refused `429 telemetry_capacity` rather than evicting a
tracked device. A non-finite CPU reading, a battery outside 0-100, memory usage above the
reported total, or a `connectivity` value that is not printable ASCII or longer than 64 bytes is
refused `400 invalid_sample`. The `connectivity` bound matters for memory, not tidiness: 16
samples are retained per device, so an unbounded string would let one agent pin megabytes of the
aggregator. Aggregates live in memory only: no raw sample
log, file, or media byte is persisted, and unknown JSON fields are dropped rather than
retained. **Telemetry history does not survive a server restart** — the aggregate is rebuilt
from the reports that arrive after it starts.

Freshness is explicit: `fresh` inside 90 seconds (three missed 30-second reports), `stale`
after that, `missing` when no report has ever arrived. The status surface reports the state
it knows; a stale reading keeps its value and is labelled stale.

## Retention

`RetentionJob::run(now_ms)` is deterministic and deletes session records, control leases, and
lease links that ended more than 30 days earlier, and audit rows written more than 30 days
earlier. `main` runs it once at startup and then every six hours through `spawn_interval`;
there is no separate scheduler daemon. A failed run is logged and retried on the next tick.

Age is the only bound on the audit log, and the per-device creation throttle sets its worst case.
Every traced attempt — accepted, refused for want of access, or refused for its shape — charges
that bucket, and only an attempt the bucket admits writes rows, so the rate is a real ceiling
rather than an estimate for accepted dispatches. At 10/s per device (burst 20) and at most two
rows per attempt (one `command.dispatch`, one `command.outcome`), one device can append at most
**about 1.7 million rows a day and 51.8 million rows per 30-day window**; the 200-device ceiling
makes that roughly **10.4 billion rows** (order 1 TB at ~100 bytes a row) if every device
attempted at full throttle, unanswered, for the whole window. Real deployments sit far below it —
an outcome row appears only for a command no device answered, and a device that answers writes
one row — but there is no count cap, so size the database for the window you actually retain.
The other row writers are revocation rows (idempotent: a retried revoke appends nothing), a
`lease.handoff` row per successful handoff, and nothing at all for an enrollment-token
revocation; handoffs are the one action bounded only by admin request rate.

The 30-day window applies to leases, session records, and the audit log. Telemetry aggregates
are a separate, in-memory concern: they are not persisted at all, the job's aggregate purge
only bounds memory, and a restart clears them regardless of age. Device records and enrollment
tokens are not aged out, because deleting an enrolled device would orphan a live device.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PHONECONNECT_ADMIN_TOKEN` | required | Bootstrap admin bearer token. Compose refuses to start without it. |
| `PHONECONNECT_LISTEN_ADDR` | `0.0.0.0:8080` | Listen address. |
| `PHONECONNECT_DATABASE_PATH` | `/data/phoneconnect.sqlite3` | SQLite file; mount a volume here. |
| `PHONECONNECT_PUBLIC_URL` | `http://127.0.0.1:8080` | The origin clients use. The relay base is derived as `<origin>/api/sessions` and one session appends `/{session_id}/relay`, so the advertised relay is always on the origin a native client loaded. Set it to the public HTTPS origin behind a TLS proxy. |
| `PHONECONNECT_TICKET_KEY_PATH` | `/data/ticket-signing-key` | Ed25519 ticket signing key. Created `0600` on first start and reused afterwards, so a restart does not rotate the verification key native clients pinned. It is written to a private temporary file, synced, then published with a hard link (never overwriting), so a reader only ever sees a complete key; a stale `*.tmp-*` leftover is removed on the next start. On filesystems without hard links it is published with `create_new`, which also never truncates, but a crash there can leave an empty file that startup refuses rather than regenerating. A corrupt, empty, or symlinked file stops startup; it is never regenerated or followed. Tightening an existing group/world-readable file to `0600` is best-effort: a read-only mount or a key owned by another user still loads, with a warning. |
| `PHONECONNECT_WEB_ROOT` | `web/dist` | Directory of the built web app, served at `/` (the image uses `/app/web`). |

A peer that reconnects fetches a fresh ticket and re-reads its candidates: each ticket's
single-use nonce is half of that connection's key epoch, and the transport refuses to open a
second path with a ticket it already used.

The ticket signing key is persisted (`PHONECONNECT_TICKET_KEY_PATH`), so a restart keeps the
advertised verification key and native clients keep their pin. Replacing the key file—or
pointing a deployment at a different one—rotates the key: a pinned client then refuses with
the remedy `native/README.md` documents and can accept the new key through the shell's
explicit, user-confirmed trust action; it never accepts a rotation silently. Identity keys are
per device and per client and are stored as public values only. A multi-replica deployment
needs the same key file on every replica.

Terminate TLS at a reverse proxy; all public endpoints require TLS in production.

## Persistence and retention

The store keeps enrollment tokens, devices, sessions, control leases, the lease-to-session
links, and the audit log: identifiers, credential hashes, expiry, revocation, who may control
what, and one trace row per command attempt. Stream payloads, files, and media are never
persisted and never queued beyond the bounded relay limits; a command's arguments are not
persisted either. Relay state is dropped as sessions expire, so memory stays proportional to live
sessions. Telemetry aggregates are bounded in memory, not stored per sample.

The SQLite adapter serializes writes on one connection. That concurrency limit is
intentional for single-node deployments; a PostgreSQL adapter can implement the same
`DeviceStore` trait without leaking backend types through it.

## Running

`cargo` builds `crates/protocol`, whose `build.rs` shells out to `protoc`, so every Cargo
command in this workspace needs it:

```sh
brew install protobuf                          # macOS
sudo apt-get install -y protobuf-compiler      # Debian/Ubuntu
```

```sh
cargo test -p phoneconnect-server

PHONECONNECT_ADMIN_TOKEN="$(openssl rand -base64 32)" cargo run -p phoneconnect-server
```

Compose requires an admin token: it uses `${PHONECONNECT_ADMIN_TOKEN:?...}`, so
`docker compose config` and `up` refuse to start when the variable is unset. There is no
built-in default token. The published port is bound to loopback only
(`127.0.0.1:8080:8080`); expose the server through a TLS-terminating reverse proxy.

```sh
openssl rand -base64 32 > .admin-token          # keep this file out of version control
export PHONECONNECT_ADMIN_TOKEN="$(cat .admin-token)"

docker compose -f docker/compose.yaml config    # fails without the token, by design
docker compose -f docker/compose.yaml up --build
curl -fsS http://127.0.0.1:8080/health

PHONECONNECT_ADMIN_TOKEN="$(cat .admin-token)" docker compose -f docker/compose.yaml down -v
```

Compose interpolates the file for every subcommand, so `ps`, `logs`, and `down` also need
the variable in the environment (or in an untracked `.env` next to the compose file, which
compose reads automatically).

The container runs as a non-root user with a read-only root filesystem; `/data` is the only
writable volume.
