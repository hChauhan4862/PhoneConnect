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
- `src/admin.rs` — admin-guarded revocation of tokens, devices, and sessions.
- `src/main.rs` — environment-driven configuration and process startup.

## Endpoints

| Method | Path | Credential | Purpose |
|---|---|---|---|
| `GET` | `/health` | none | Liveness only; never touches sessions. |
| `POST` | `/api/enrollment-tokens` | admin | `{token, expires_at}` for one owner. |
| `POST` | `/api/devices/enroll` | enrollment token | Consumes the token once; body is `{token, identity_key}` and the response is `{device_id, credential}`. The device's X25519 identity public key is pinned here. |
| `POST` | `/api/sessions` | admin | Authorizes a device session; body is `{device_id, client_identity_key}`, response `{session_id, capability, expires_at, ticket, verification_key}`. |
| `GET` | `/api/sessions/{id}/ticket` | session capability or owning device credential | Fresh short-lived ticket for the calling role. |
| `GET` | `/api/sessions/{id}/candidates` | session capability or owning device credential | Relay route plus the endpoint observed for the opposite peer. |
| `POST` | `/api/sessions/{id}/candidates` | session capability or owning device credential | Redeems a ticket, records this peer's observed endpoint, returns the peer's view. |
| `POST` | `/api/sessions/{id}/relay` | session capability or owning device credential | Bounded relay lease with explicit limits. |
| `GET` (upgrade) | `/api/sessions/{id}/relay` | session capability (client end) or owning device credential (device end) | The framed relay transport: a WebSocket carrying one PhoneConnect frame per binary message. |
| `POST` | `/api/enrollment-tokens/{token}/revoke` | admin | Revokes one unused enrollment token; idempotent. |
| `POST` | `/api/devices/{id}/revoke` | admin | Revokes a device and its live sessions; closes their relays. |
| `POST` | `/api/sessions/{id}/revoke` | admin | Revokes one session; closes its relay. |

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
private half, and the key is generated at startup, which invalidates outstanding tickets
across a restart.

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
once that peer has reported one. The relay route is `<PHONECONNECT_RELAY_ENDPOINT base>
/{session_id}/relay`.

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
status the lease reported when it was issued. Closed relay state is dropped when the session expires, so memory stays bounded by
sessions from the last five minutes.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PHONECONNECT_ADMIN_TOKEN` | required | Bootstrap admin bearer token. Compose refuses to start without it. |
| `PHONECONNECT_LISTEN_ADDR` | `0.0.0.0:8080` | Listen address. |
| `PHONECONNECT_DATABASE_PATH` | `/data/phoneconnect.sqlite3` | SQLite file; mount a volume here. |
| `PHONECONNECT_RELAY_ENDPOINT` | `http://localhost:8080/api/sessions` | Relay route base advertised to peers; one session appends `/{session_id}/relay`. |

A peer that reconnects fetches a fresh ticket and re-reads its candidates: each ticket's
single-use nonce is half of that connection's key epoch, and the transport refuses to open a
second path with a ticket it already used.

The ticket signing key is generated at process start, so a restart invalidates outstanding
tickets (30 s) and a multi-replica deployment would need shared key material. Identity keys
are per device and per client and are stored as public values only.

Terminate TLS at a reverse proxy; all public endpoints require TLS in production.

## Persistence and retention

The store keeps enrollment tokens, devices, and sessions: identifiers, credential hashes,
expiry, and revocation only. Stream payloads, files, and media are never persisted and
never queued beyond the bounded relay limits. Relay state is dropped as sessions expire, so
memory stays proportional to live sessions.

The SQLite adapter serializes writes on one connection. That concurrency limit is
intentional for single-node deployments; a PostgreSQL adapter can implement the same
`DeviceStore` trait without leaking backend types through it.

## Running

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
