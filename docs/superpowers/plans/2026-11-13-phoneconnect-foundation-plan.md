# PhoneConnect Foundation Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build and verify the first PhoneConnect foundation: a versioned protocol, authenticated rendezvous/relay, resilient ordinary Android connection service, and a native transport proof that upgrades from relay to direct peer connectivity when possible.

**Architecture:** Use Kotlin for the Android agent, Rust for the server transport core and native-client transport core, and a small React web surface only for pairing/session status. The server is the authorization and rendezvous control plane plus an encrypted relay fallback; peers use ICE-style endpoint discovery and authenticated UDP hole punching, then carry PhoneConnect framed streams over the selected path. Runtime traffic is never exposed as raw public ADB.

**Tech Stack:** Kotlin/Android, Rust, Tokio, Tauri-compatible Rust library boundaries, React/TypeScript for the minimal status UI, Protobuf schema generation for stable envelopes, SQLite for development tests, PostgreSQL-compatible repository interfaces for production, Docker Compose for local integration.

**Spec:** [2026-11-13-phoneconnect-design.md](/Volumes/wise/HARENDRA/MobileConnect/PhoneConnect/docs/superpowers/specs/2026-11-13-phoneconnect-design.md)

## Global Constraints

- The first native-client target is macOS 26+ on Apple Silicon and Intel where the toolchain permits, Windows 10+, and current mainstream Linux distributions on x64 and arm64 where packaging support is practical.
- The Android agent uses one foreground service and one persistent notification for connection, telemetry, and recovery.
- Ordinary production enrollment uses a server-issued one-time enrollment token with expiry and revocation.
- Relay traffic remains end-to-end encrypted and the relay does not interpret privileged payloads.
- A device has one current control lease at a time; revocation closes active control streams and invalidates their short-lived tokens.
- Never buffer unbounded media or proxy data in memory or durable queues.
- Files, recordings, and media are streamed by default and are not persisted by the server.
- Audit events, device metadata, telemetry aggregates, session records, and diagnostics are retained for 30 days by default.
- There is exactly one UI implementation, served by the server; native clients embed that same URL and differ only through `HostAdapter` behavior.

## Review Focus

- **Replayed or revoked enrollment/session token:** must be rejected before a stream is accepted; test in Task 2.
- **Relay receives malformed, oversized, or unauthenticated frames:** must close only the offending session without interpreting or forwarding the payload; test in Task 2.
- **Direct-path negotiation fails or changes network:** must fall back to relay and later retry direct without re-pairing; test in Task 3.
- **Android process is backgrounded, rebooted, or disconnected:** one service/notification must recover with bounded backoff and no duplicate notifications; test in Task 4.
- **Control lease is revoked during an active stream:** existing commands must stop immediately and the Android side must reject subsequent commands; test in Task 5.
- **The same screen is opened in a browser and inside the native shell:** both must remain fully usable, with native-only actions degrading to in-page equivalents and no dead controls; test in Task 5.

---

### Task 1: Repository and shared protocol foundation

**Files:**
- Create: `PhoneConnect/Cargo.toml`
- Create: `PhoneConnect/crates/protocol/Cargo.toml`
- Create: `PhoneConnect/crates/protocol/src/lib.rs`
- Create: `PhoneConnect/proto/phoneconnect/v1/envelope.proto`
- Create: `PhoneConnect/proto/phoneconnect/v1/session.proto`
- Create: `PhoneConnect/crates/protocol/tests/codec.rs`
- Create: `PhoneConnect/android/README.md`
- Create: `PhoneConnect/server/README.md`
- Create: `PhoneConnect/native/README.md`

**Interfaces:**
- Produces `phoneconnect::v1::Envelope`, `StreamKind`, `SessionId`, `DeviceId`,
  `RequestId`, and `ProtocolError` plus length-delimited encode/decode functions.
- The envelope carries `protocol_version`, `stream_kind`, `request_id`, `device_id`,
  `session_id`, `sequence`, `deadline_unix_ms`, and `payload`.
- Maximum decoded frame size is 1 MiB for control/events and is configurable separately
  for file/media/proxy streams; oversized frames fail closed.

- [ ] **Step 1: Write failing codec tests** for round-trip envelopes, unknown stream kinds, truncated frames, sequence overflow, and the 1 MiB control-frame limit.
- [ ] **Step 2: Run `cargo test -p phoneconnect-protocol`** and confirm the new tests fail because the crate and codec are not implemented.
- [ ] **Step 3: Implement the Protobuf schema and Rust codec** with checked length prefixes, explicit version validation, and typed errors; do not use unbounded allocation from a peer-provided length.
- [ ] **Step 4: Run `cargo test -p phoneconnect-protocol`** and confirm all codec tests pass.
- [ ] **Step 5: Commit** with `git add proto crates/protocol Cargo.toml android/README.md server/README.md native/README.md && git commit -m "feat: add PhoneConnect protocol foundation"`.

### Task 2: Server identity, enrollment, rendezvous, and relay contract

**Files:**
- Create: `PhoneConnect/server/Cargo.toml`
- Create: `PhoneConnect/server/src/main.rs`
- Create: `PhoneConnect/server/src/auth.rs`
- Create: `PhoneConnect/server/src/enrollment.rs`
- Create: `PhoneConnect/server/src/rendezvous.rs`
- Create: `PhoneConnect/server/src/relay.rs`
- Create: `PhoneConnect/server/src/store.rs`
- Create: `PhoneConnect/server/tests/security.rs`
- Create: `PhoneConnect/server/tests/relay.rs`
- Create: `PhoneConnect/docker/Dockerfile`
- Create: `PhoneConnect/docker/compose.yaml`

**Interfaces:**
- `POST /api/enrollment-tokens` returns `{token, expires_at}` for an authorized user.
- `POST /api/devices/enroll` consumes a token once and returns a device credential.
- `POST /api/sessions` returns a short-lived session capability and rendezvous ticket.
- `GET /api/sessions/{id}/candidates` returns authenticated endpoint candidates.
- `POST /api/sessions/{id}/relay` upgrades an authorized session to a bounded relay.
- Relay frame handler consumes `Envelope` and returns explicit close reasons; it never
  dispatches privileged payloads or stores stream data.
- Device credential hashes, enrollment expiry, revocation, session expiry, and one-time
  token use are persisted behind `DeviceStore`.

- [ ] **Step 1: Write failing security tests** for one-time enrollment, expiry, revoked credentials, user/device isolation, session expiry, and immediate revocation.
- [ ] **Step 2: Write failing relay tests** for authenticated peers, malformed frames, oversized frames, backpressure, half-close, and bounded idle timeout.
- [ ] **Step 3: Run `cargo test -p phoneconnect-server --test security --test relay`** and confirm failure.
- [ ] **Step 4: Implement the store and auth/enrollment endpoints** using hashed secrets, constant-time credential comparison, explicit authorization checks, and transactionally consumed enrollment tokens.
- [ ] **Step 5: Implement rendezvous tickets and the relay** using Tokio tasks with per-session byte/frame limits, cancellation, deadlines, and no durable payload buffering.
- [ ] **Step 6: Run the targeted server tests** and confirm all pass.
- [ ] **Step 7: Build the Docker image and run a health check** with `docker compose -f docker/compose.yaml up --build --abort-on-container-exit`; expect a successful `/health` response and no stored stream payloads.
- [ ] **Step 8: Commit** with `git add server docker && git commit -m "feat: add enrollment rendezvous and relay"`.

### Task 3: Direct-path transport upgrade

**Files:**
- Create: `PhoneConnect/crates/transport/Cargo.toml`
- Create: `PhoneConnect/crates/transport/src/lib.rs`
- Create: `PhoneConnect/crates/transport/src/candidates.rs`
- Create: `PhoneConnect/crates/transport/src/hole_punch.rs`
- Create: `PhoneConnect/crates/transport/src/path.rs`
- Create: `PhoneConnect/crates/transport/tests/path_upgrade.rs`
- Modify: `PhoneConnect/server/src/rendezvous.rs`
- Modify: `PhoneConnect/server/src/relay.rs`

**Interfaces:**
- `CandidateSet::discover()` produces local, server-observed, and relay candidates.
- `PathController::connect(ticket, candidates) -> ConnectedPath` races authenticated
  direct UDP candidates against relay setup, selects the lowest-latency validated path,
  and preserves the same session identity across upgrades.
- `ConnectedPath` exposes bounded `send_frame`, `recv_frame`, `shutdown`, and
  `path_kind()` methods.

- [ ] **Step 1: Write failing transport tests** using loopback peers for direct success, relay fallback, direct failure, path migration, replayed probe rejection, and bounded probe timeouts.
- [ ] **Step 2: Run `cargo test -p phoneconnect-transport --test path_upgrade`** and confirm failure.
- [ ] **Step 3: Implement candidate exchange and authenticated probes** with short-lived tickets, nonce replay protection, bounded retries, and explicit direct/relay state transitions.
- [ ] **Step 4: Implement path upgrade and migration** so a relay session can move to a validated direct path without changing request IDs or control leases.
- [ ] **Step 5: Run the targeted transport tests** and confirm all pass.
- [ ] **Step 6: Add an integration test** that runs server, Android-side transport stub, and native-side transport stub in Docker with a forced direct failure; expect transparent relay fallback.
- [ ] **Step 7: Commit** with `git add crates/transport server/src/rendezvous.rs server/src/relay.rs && git commit -m "feat: add direct path upgrade with relay fallback"`.

### Task 4: Android ordinary-app connection service

**Files:**
- Create: `PhoneConnect/android/settings.gradle.kts`
- Create: `PhoneConnect/android/app/build.gradle.kts`
- Create: `PhoneConnect/android/app/src/main/AndroidManifest.xml`
- Create: `PhoneConnect/android/app/src/main/java/com/phoneconnect/agent/ConnectionService.kt`
- Create: `PhoneConnect/android/app/src/main/java/com/phoneconnect/agent/NotificationController.kt`
- Create: `PhoneConnect/android/app/src/main/java/com/phoneconnect/agent/EnrollmentStore.kt`
- Create: `PhoneConnect/android/app/src/main/java/com/phoneconnect/agent/ReconnectPolicy.kt`
- Create: `PhoneConnect/android/app/src/test/java/com/phoneconnect/agent/ConnectionServiceTest.kt`
- Create: `PhoneConnect/android/app/src/test/java/com/phoneconnect/agent/NotificationControllerTest.kt`

**Interfaces:**
- `ConnectionService` owns one foreground service instance and one notification ID for
  control, telemetry, reconnect, and session streams.
- `EnrollmentStore` stores only the device credential protected by Android Keystore.
- `ReconnectPolicy.nextDelay(attempt, reason)` returns bounded exponential backoff with
  jitter and resets after a healthy connection.
- `NotificationController.update(state)` updates the same notification rather than
  creating a new notification.

- [ ] **Step 1: Write failing JVM tests** for one notification ID, no duplicate service start, credential encryption boundary, reconnect backoff cap, and state reset after recovery.
- [ ] **Step 2: Run `./gradlew :app:testDebugUnitTest`** and confirm failure.
- [ ] **Step 3: Implement the foreground service** with one persistent notification, boot/network recovery hooks, cancellation-safe coroutine scopes, and bounded reconnect.
- [ ] **Step 4: Implement enrollment persistence** using Android Keystore-backed encryption and clear revocation/unenrollment behavior.
- [ ] **Step 5: Implement the Android transport and enrollment path** — port the sealed channel (X25519 + HKDF + ChaCha20-Poly1305, per-direction counters, replay window) from `crates/transport`, add the relay WebSocket client, a `SessionRunner` that establishes a live session, an enrollment HTTP client, and a minimal setup activity that enrolls the device and requests `POST_NOTIFICATIONS`. The service must be able to reach `Connected`, not only `ActionRequired`; map server revocation to immediate stream closure.
- [ ] **Step 6: Run unit tests, build the APK, and run the emulator instrumentation smoke test where an emulator exists**; expect one notification channel/ID and recovery after force-stop/start, with OEM-kill limitations reported rather than hidden. If no emulator/device is available, record the step as unverified with the reason instead of omitting it.
- [ ] **Step 7: Commit** with `git add android && git commit -m "feat: add resilient Android connection service"`.

### Task 5: Control leases, telemetry, and shared web UI host adapter

**Files:**
- Create: `PhoneConnect/server/src/leases.rs`
- Create: `PhoneConnect/server/src/telemetry.rs`
- Create: `PhoneConnect/server/tests/leases.rs`
- Create: `PhoneConnect/server/tests/telemetry.rs`
- Create: `PhoneConnect/web/package.json`
- Create: `PhoneConnect/web/src/api.ts`
- Create: `PhoneConnect/web/src/host/HostAdapter.ts`
- Create: `PhoneConnect/web/src/host/browserHost.ts`
- Create: `PhoneConnect/web/src/host/nativeHost.ts`
- Create: `PhoneConnect/web/src/host/hostContext.ts`
- Create: `PhoneConnect/web/src/App.tsx`
- Create: `PhoneConnect/web/src/App.test.tsx`
- Create: `PhoneConnect/web/src/host/HostAdapter.test.ts`
- Create: `PhoneConnect/server/src/web.rs`
- Create: `PhoneConnect/server/tests/web.rs`

**Interfaces:**
- `LeaseStore.acquire(device_id, user_id, expires_at) -> ControlLease` succeeds only
  when no active lease exists or the owner explicitly hands it off.
- `LeaseStore.revoke(lease_id, actor) -> RevocationEvent` invalidates all active
  stream capabilities for the lease.
- `TelemetryAggregator.ingest(device_id, sample)` keeps bounded recent aggregates and
  exposes 30-day retention deletion.
- `HostAdapter` is the only place host differences live:
  `kind: "browser" | "native"`,
  `openView(route: string, options: { detached: boolean }): Promise<void>`,
  `setTrayStatus(status: TrayStatus): Promise<void>`,
  `localEndpoints(): Promise<LocalEndpoint[]>`,
  `notify(input: { title: string; body: string }): Promise<void>`.
- `createHostAdapter(context?: NativeHostContext): HostAdapter` returns `nativeHost`
  when the shell injected a context and `browserHost` otherwise.
- `browserHost.openView` navigates in the SPA and ignores `detached`;
  `nativeHost.openView` opens a separate OS window for `detached` and otherwise
  navigates the embedded webview to the same route.
- The status UI shows enrollment/session state, direct vs relay path, one active
  controller, telemetry freshness, and explicit reconnect/permission errors.

- [ ] **Step 1: Write failing lease tests** for owner grant, controlled handoff, secondary read-only access, expiry, immediate revocation, and command rejection after revocation.
- [ ] **Step 2: Write failing telemetry tests** for bounded sampling, 200-device aggregation, stale-device detection, and 30-day deletion.
- [ ] **Step 3: Run targeted server tests** and confirm failure.
- [ ] **Step 4: Implement lease authorization and revocation events** across server sessions and Android stream handlers.
- [ ] **Step 5: Implement telemetry aggregation** without persisting raw high-rate samples or files/media.
- [ ] **Step 6: Implement `HostAdapter` and its two implementations**; tests must prove a screen renders and works with `browserHost`, degrades native-only controls to in-page equivalents, and calls `openView(..., {detached:true})` exactly once under `nativeHost`.
- [ ] **Step 7: Implement the minimal status UI** and test that it renders direct/relay state, active lease, stale telemetry, and errors without success-shaped fallbacks; the same component tree must pass under both adapters.
- [ ] **Step 8: Serve the built web UI from the server** at `/` with SPA fallback and a strict CSP, so the browser and the native shell load the identical URL; tests must prove a deep route returns the SPA document, an unknown API path returns 404 (not the SPA), and assets are served with the right content type. A native shell must be able to load `<server>/` unchanged.
- [ ] **Step 9: Run server and web tests** and confirm all pass.
- [ ] **Step 10: Commit** with `git add server web && git commit -m "feat: add leases telemetry and shared web UI host adapter"`.

### Task 6: Native shell embedding the shared web UI and localhost proxy

**Files:**
- Create: `PhoneConnect/native/Cargo.toml`
- Create: `PhoneConnect/native/src/main.rs`
- Create: `PhoneConnect/native/src/web_shell.rs`
- Create: `PhoneConnect/native/src/proxy.rs`
- Create: `PhoneConnect/native/src/session_client.rs`
- Create: `PhoneConnect/native/tests/proxy.rs`
- Create: `PhoneConnect/native/README.md`

**Interfaces:**
- `ProxyAllocator::bind(device_id, capability) -> LocalEndpoint` binds loopback only
  and chooses an unused ephemeral port.
- `ProxySession` translates local byte reads/writes into one authenticated PhoneConnect
  proxy stream with deadlines, backpressure, and immediate close on capability expiry.
- `SessionClient` uses `PathController` and reports the selected direct/relay path.
- `web_shell::resolve_url(configured_server_url) -> Result<Url>` accepts only `https://`
  (or `http://127.0.0.1`/`http://localhost` for development) and loads that exact URL in
  the Tauri webview; it must not rewrite paths or inject a separate UI bundle.
- `web_shell::host_context(server_url) -> NativeHostContext` supplies
  `{ kind: "native", serverUrl, proxyCapabilities }` to the page via the injected
  `window.__PHONECONNECT_HOST__` object.

- [ ] **Step 1: Write failing proxy tests** for loopback-only binding, concurrent port allocation, byte preservation, backpressure, capability expiry, and relay fallback.
- [ ] **Step 2: Write failing web-shell tests** for URL validation, rejection of non-loopback plain HTTP, and host-context shape.
- [ ] **Step 3: Run `cargo test -p phoneconnect-native --test proxy`** and confirm failure.
- [ ] **Step 4: Implement the proxy and session client** using the shared transport crate; never bind `0.0.0.0` by default and never accept unauthenticated remote clients.
- [ ] **Step 5: Implement the Tauri shell** to load the configured server URL, inject the host context, expose tray/notification commands used by `nativeHost`, and expose local proxy endpoints to the page.
- [ ] **Step 6: Run proxy, web-shell, and the end-to-end Docker transport tests**; expect `127.0.0.1:<ephemeral-port>` to remain usable across relay/direct path selection, and the shell loading the server-served UI rather than a bundled copy.
- [ ] **Step 7: Commit** with `git add native && git commit -m "feat: add native shell embedding shared web UI and proxy"`.

## Follow-up plans

After this foundation is accepted, create separate plans for:

1. Android feature adapters and parity with the evaluated prototypes: files, apps,
   input, display/mirroring, audio, diagnostics, and capability negotiation.
2. Full web dashboard for every feature (the single UI), then the thin native shell's
   tray, detached-window, notification, and updater polish.
3. Docker production operations, migrations, signup/MFA administration, backups, and
   30-day retention jobs.
4. Signed update channels for server, Android, and native clients.
5. Optional generated APK provisioning, package/signing policy, and future iOS scope.

## Verification gate

The foundation is not complete until:

- Rust protocol, server, transport, and native tests pass.
- Android unit tests and emulator smoke tests pass.
- Docker integration proves enrollment, relay fallback, direct-path upgrade, revocation,
  lease handoff, and bounded telemetry.
- No test stores raw stream payloads or creates duplicate Android foreground notifications.
- A report records which direct-NAT scenarios were tested and which remain relay-only.
