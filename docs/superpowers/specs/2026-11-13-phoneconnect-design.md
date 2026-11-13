# PhoneConnect — Initial Product Design

## Intent

PhoneConnect is a self-hosted, multi-user system for securely connecting managed
Android devices to web and native clients over local or remote networks. It combines
device management, low-latency interaction, and an optional localhost proxy that lets
native clients expose a connected phone as a local endpoint.

The first release must prove that an Android device can enroll, remain connected after
the UI is closed and after reboot where the OS permits it, recover from network
interruptions, and be controlled by an authorized user without repeated manual setup.

## Goals

- Provide a Docker-distributed server with web UI, API, authentication, authorization,
  device enrollment, eventing, update metadata, and optional relay transport.
- Support multiple users, device ownership, and explicit device sharing.
- Provide an Android agent that maintains a resilient authenticated connection on
  ordinary user-installed phones, with optional managed-device support later.
- Keep up to 200 enrolled devices connected in the background for telemetry and
  health monitoring, including CPU, memory, battery, connectivity, and extensible
  device metrics.
- Define a versioned PhoneConnect protocol for control commands, device events, files,
  media streams, and future transports; do not make ADB the runtime wire protocol.
- Provide native macOS, Windows, and Linux clients with a tray process, embedded web UI,
  local device ports, and optional remote proxying.
- Preserve low latency through direct connections where possible, bounded relay
  buffering, binary framing, backpressure, reconnect/resume, and observability.
- Support signed updates for the server, Android agent, and native clients.
- Support up to 10 users in the first release, with one organization per deployment.
- Support local password authentication with MFA.
- Retain operational and audit data for 30 days by default.
- Allow device owners to grant control to another user through an explicit handoff;
  revocation must terminate active sessions immediately.

## Non-goals for the first release

- iOS device control or an always-on iOS agent. iOS will require a separately scoped,
  reduced-capability product because general background sockets and ADB-like control are
  not available to ordinary apps.
- Arbitrary unauthenticated ADB exposure to the public internet.
- Server-side APK generation and arbitrary user-defined package identities in the
  connectivity MVP.
- Root access, privilege escalation, or bypassing Android security controls.
- Guaranteeing persistence on unmanaged consumer phones. Android and OEM policy can
  still stop an ordinary app; the product must expose connection health and recovery
  rather than promise that it can never be killed.

## Anti-goals

- Do not route all traffic through the server when a secure direct path is available.
- Do not use a browser as the only transport for high-rate media or byte streams.
- Do not silently weaken TLS, authentication, device isolation, or update verification
  to make pairing easier.
- Do not claim that battery settings alone make an ordinary Android app unkillable.

## Constraints

- Ordinary Android enrollment must work through a normal APK install and a one-time
  pairing flow. Device-owner provisioning may be added later for deployments that need
  stronger policy control and can accept enterprise enrollment requirements.
- The Android agent must use supported foreground-service, boot, network, and device
  policy APIs; OEM behavior must be detected and surfaced rather than hidden.
- The Android agent uses one foreground service and one persistent notification for
  connection, telemetry, and recovery. It must not create one notification per device,
  stream, or reconnect attempt.
- The server must run in a single Docker image for the initial distribution, with
  persistent storage externalized through a documented volume.
- Public signup must be controlled by one server configuration flag and must default to
  disabled for new deployments.
- All public endpoints require TLS in production. Device and user credentials must be
  scoped, revocable, rotated, and stored as hashes or platform-protected secrets.
- The first native-client target is macOS 26+ on Apple Silicon and Intel where the
  toolchain permits, Windows 10+, and current mainstream Linux distributions on x64
  and arm64 where packaging support is practical. The web client targets current
  Chromium, Firefox, and Safari releases.

## Approaches considered

### A. Reuse an existing local-first desktop client and add a remote transport

This would preserve the existing Tauri/Rust/React implementation and add a server
relay. It is the fastest route to feature parity, but its process model and ADB-centric
assumptions would constrain a new multi-user protocol and managed-agent lifecycle.

### B. Server-centric browser control

The Android agent would stream all control and media through the server, and native
clients would mostly embed the web UI. This simplifies centralized authorization but
increases bandwidth, latency, operating cost, and privacy exposure.

### C. New PhoneConnect protocol and clients — selected

PhoneConnect will define its own versioned, authenticated protocol and shared domain
model. It will use a Tailscale-like path strategy: the server is the control plane,
authorization authority, rendezvous service, and encrypted relay; peers first exchange
candidate endpoints through the relay, attempt authenticated UDP hole punching, and
upgrade to a direct path when possible. Native clients own local proxy ports and
translate local protocol traffic into authenticated PhoneConnect streams. This costs
more initially but gives the required control over latency, security, reconnect
behavior, and future non-ADB transports.

## System shape

### Components

1. **Server**
   - Web UI and REST API.
   - User authentication, signup policy, sessions, roles, device ownership, sharing,
     pairing, audit events, and revocation.
   - Device rendezvous and capability negotiation.
   - Optional encrypted relay for control, file, media, and proxy streams.
   - Long-lived device telemetry ingestion with bounded sampling and aggregation so
     200 connected devices do not create an unbounded event log.
   - Update manifest and release-channel policy.
   - PostgreSQL-compatible production persistence is preferred; SQLite may be supported
     for small self-hosted installations if concurrency limits are explicit.

2. **Android agent**
   - Ordinary APK enrollment package with a future device-owner extension.
   - One foreground connection service with one visible status notification.
   - Boot/network recovery, exponential reconnect, protocol version negotiation, and
     local queue limits.
   - Setup wizard that checks notification permission, battery policy, network, boot
     behavior, and update prerequisites; it explains that OEM restrictions can still
     interrupt ordinary apps.
   - Periodic and event-driven telemetry for CPU, memory, battery, storage, network,
     process health, and agent diagnostics, with configurable intervals and backoff.
   - Feature adapters for shell-like commands, files, apps, input, display, audio, and
     diagnostics where Android policy permits them.
   - ADB is an enrollment/bootstrap mechanism, not the long-term identity or transport.

3. **Native client**
   - Tauri/Rust tray process for macOS, Windows, and Linux.
   - A thin shell that loads the same server-served web UI URL; it does not
     reimplement screens or maintain a second UI tree.
   - Supplies host capabilities to the web UI (separate OS windows, tray state,
     notifications, local endpoints, external links) through one documented bridge.
   - Direct transport when reachable, otherwise authenticated server relay.
   - Localhost port allocator and proxy. Each mapped device/stream receives a
     collision-safe ephemeral port bound to loopback only by default.
   - Client-side update verification and rollback-safe installation.

4. **Web client**
   - Responsive device dashboard, enrollment flow, permissions/capabilities, command
     console, files/apps, mirror/control, audit, and update status.
   - WebSocket/WebTransport use is limited to browser-suitable streams; native clients
     handle the full proxy and high-rate paths.

### User interface

- There is exactly one UI implementation: the React web app served by the server. The
  native clients embed that same origin and URL in a webview, whether the server is
  remote or self-hosted locally.
- Screens are not forked per host. A single `HostAdapter` abstraction changes behavior
  only where the environment differs:
  - Browser: navigate within the SPA, use in-page tabs and modals, no tray or OS windows.
  - Native: may open a detached OS window for a long-lived view (mirror, console, file
    transfer), update the tray, show native notifications, and expose local proxy
    endpoints back to the page.
- Adapter selection is explicit: the native shell injects a host-context object and the
  page falls back to browser behavior when it is absent. The UI must remain fully usable
  in a plain browser without the native shell.
- Native-only affordances are additive and degrade to in-page equivalents; a web user
  never sees a dead control that only works in a native window.
- The same URL, session cookies, and authorization checks apply to both hosts. The
  native shell must not bypass server authentication or embed privileged credentials in
  the page.

### Protocol

- Versioned binary envelope with explicit stream type, request ID, device ID, session
  ID, sequence number, deadline, payload length, and integrity/authentication context.
- Separate logical streams for control RPC, events, files, media, and proxy bytes.
- Per-stream flow control, bounded queues, cancellation, deadlines, and keepalive.
- Mutual device authentication using an enrollment credential and rotated session keys.
- User authorization is checked by the server before issuing a capability-limited session
  token; the Android agent never trusts a user-provided device ID by itself.
- Resume tokens are scoped to a session and expire; replayed commands must be rejected.
- Protocol errors are explicit and observable; no success-shaped fallback responses.

### Connectivity

1. Android agent and native client maintain authenticated control connections to the
   server rendezvous service.
2. Native client requests a device session; the server authorizes the user and gives
   both endpoints short-lived rendezvous data and candidate endpoints.
3. Both peers exchange endpoint candidates and use authenticated UDP hole punching with
   STUN-like endpoint discovery. They continuously probe candidates and upgrade from
   relay to the lowest-latency validated direct path when possible.
4. If direct negotiation fails because of symmetric NAT, CGNAT, restrictive firewalls,
   or unavailable UDP, both sides use the server relay. Relay traffic remains
   end-to-end encrypted and the relay does not interpret privileged payloads.
5. On network change or path degradation, peers repeat candidate discovery and can fall
   back to relay without requiring user re-pairing.
6. Native client exposes only loopback ports and closes them when the capability or
   session expires.

### Sharing and control

- A device has one current control lease at a time.
- The owner grants a lease to another authorized user with an explicit expiry or
  revokes it immediately.
- Secondary viewers may receive read-only telemetry and streams when permitted but
  cannot issue control commands without the active lease.
- Lease acquisition, handoff, expiry, and revocation are server-authoritative and
  emitted as protocol events to every affected client.
- Revocation closes active control streams and invalidates their short-lived tokens;
  the Android agent must reject further commands from those streams.

### Enrollment and updates

- Initial enrollment may use USB/ADB and a pairing code, but runtime sessions use the
  PhoneConnect protocol.
- Ordinary production enrollment uses a server-issued one-time enrollment token with
  expiry and revocation. A future managed-device mode may add device-owner provisioning
  for stronger policy enforcement.
- Server, Android, and native releases publish signed manifests with minimum supported
  protocol versions and rollback metadata.
- The server may notify clients of updates, but each component verifies signatures and
  compatibility before installation.
- APK customization is deferred until a separate signing/provisioning design defines
  tenant keys, package namespace ownership, icon validation, build isolation, and
  artifact retention.

### Persistence and retention

- Audit events, device metadata, telemetry aggregates, session records, and diagnostics
  are retained for 30 days by default and deleted by a scheduled retention job.
- Raw high-rate telemetry is sampled/aggregated rather than retained indefinitely.
- Files, recordings, and media are streamed by default and are not persisted by the
  server unless a future feature explicitly requests storage with its own retention
  policy.

## Reliability and performance

- Target reconnect detection within seconds, bounded by configurable heartbeat and
  backoff values.
- Never buffer unbounded media or proxy data in memory or durable queues.
- Measure handshake time, direct-vs-relay selection, round-trip latency, dropped frames,
  reconnects, queue depth, relay throughput, and command deadlines.
- Add protocol-level fault tests for token revocation, stale sessions, replay, stream
  cancellation, partial writes, reconnect, backpressure, and relay failure before
  claiming production readiness.

## Security and operations

- Default-deny signup, device sharing, command capabilities, and relay access.
- Role-based authorization with per-device ownership and explicit grants.
- Audit enrollment, login, sharing, command, file, update, and revocation events.
- Rate-limit pairing, login, signup, command creation, and relay allocation.
- Document reverse proxy/TLS, secret storage, backups, migrations, health checks, and
  upgrade/rollback procedures for Docker deployments.

## Open decisions for implementation

- Exact protocol framing and cryptographic channel construction.
- Server language/runtime and database baseline.
- Direct transport mechanism and NAT traversal scope for the first release.
- Android feature capability matrix and minimum supported API/OEM set.
- Device-owner enrollment UX and whether a non-managed diagnostic mode is included.
- Native proxy protocol compatibility target beyond a localhost ADB-shaped endpoint.
- Release signing ownership, update channels, and artifact hosting.
