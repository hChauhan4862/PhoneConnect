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

Errors are always `{"error": "<code>"}` with a non-2xx status; there are no
success-shaped fallbacks.

## Credential classes

1. Admin bearer token from `PHONECONNECT_ADMIN_TOKEN`. It mints enrollment tokens and
   authorizes sessions; local password and MFA login arrive with the production-ops plan.
2. Device credential (`pcdev_...`) issued once at enrollment.
3. Session capability (`pcsess_...`) minted per authorized session, valid for 5 minutes.

Secrets are stored only as SHA-256 hashes and compared in constant time. Enrollment tokens
are single-use and consumed in the same transaction that creates the device.

## Configuration

| Variable | Default | Meaning |
|---|---|---|
| `PHONECONNECT_ADMIN_TOKEN` | required | Bootstrap admin bearer token. |
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

PHONECONNECT_ADMIN_TOKEN=change-me cargo run -p phoneconnect-server

docker compose -f docker/compose.yaml up --build
curl -fsS http://127.0.0.1:8080/health
```

The container runs as a non-root user with a read-only root filesystem; `/data` is the only
writable volume.
