# PhoneConnect server

The control plane for PhoneConnect: it authorizes sessions, serves rendezvous data, and
operates the bounded end-to-end encrypted relay fallback. It never exposes ADB and never
interprets relayed payloads.

## Binary and crate layout

- crate `phoneconnect-server`, library `phoneconnect_server`, binary `phoneconnect-server`.
- `src/lib.rs` — `AppState`, the API error envelope, and the router.
- `src/auth.rs` — credential classes, hashing, constant-time comparison, authorization checks.
- `src/store.rs` — `DeviceStore` trait plus the SQLite implementation and the clock.
- `src/enrollment.rs` — one-time enrollment tokens and device enrollment.
- `src/rendezvous.rs` — session capabilities, rendezvous tickets, candidate endpoints.
- `src/relay.rs` — bounded relay sessions, limits, and explicit close reasons.
- `src/admin.rs` — admin-guarded revocation of tokens, devices, and sessions.
- `src/main.rs` — environment-driven configuration and process startup.

## Endpoints

| Method | Path | Credential | Purpose |
|---|---|---|---|
| `GET` | `/health` | none | Liveness only; never touches sessions. |
| `POST` | `/api/enrollment-tokens` | admin | `{token, expires_at}` for one owner. |
| `POST` | `/api/devices/enroll` | enrollment token | Consumes the token once, returns `{device_id, credential}`. |
| `POST` | `/api/sessions` | admin | Authorizes a device session; returns `{session_id, capability, expires_at, ticket}`. |
| `GET` | `/api/sessions/{id}/candidates` | session capability or owning device credential | Authenticated endpoint candidates. |
| `POST` | `/api/sessions/{id}/relay` | session capability or owning device credential | Bounded relay lease with explicit limits. |
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

## Relay lease and live authorization

`POST /api/sessions/{id}/relay` returns a lease whose `endpoint` is a **transport
contract**, not a live route. Task 2 serves nothing at that URL; the transport task binds
it. The `expires_at` and `limits` fields are authoritative now.

The relay re-reads authorization while a session is attached: every send and receive
consults the clock and the store, and a blocked peer polls on a bounded interval. A session
stops forwarding as soon as it expires, its session is revoked, its owning device is
revoked, or its store record disappears. Each case reports a distinct close reason
(`SessionExpired`, `SessionRevoked`, `DeviceRevoked`, `UnknownSession`, and
`StoreUnavailable` when authorization state cannot be read, which fails closed).

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PHONECONNECT_ADMIN_TOKEN` | required | Bootstrap admin bearer token. Compose refuses to start without it. |
| `PHONECONNECT_LISTEN_ADDR` | `0.0.0.0:8080` | Listen address. |
| `PHONECONNECT_DATABASE_PATH` | `/data/phoneconnect.sqlite3` | SQLite file; mount a volume here. |
| `PHONECONNECT_RELAY_ENDPOINT` | `http://localhost:8080/api/relay` | Relay URL advertised to peers. |

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
