# PhoneConnect Device Features Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Turn the reviewed transport/server/agent foundation into a usable device manager: a device reaches the server, reports real telemetry, and can be inspected and operated (files, apps, screen, console, toggles) from the one web UI — the feature surface the evaluated prototypes provide.

**Architecture:** Add the server-mediated management channel described in the design's "Two channels, two confidentiality rules": an authenticated device WebSocket carrying JSON commands and telemetry, and server HTTP endpoints the web UI calls. The sealed peer channel is untouched and keeps carrying proxy/media ciphertext only.

**Tech Stack:** Rust (axum, tokio, tokio-tungstenite) server + transport reuse; Kotlin/OkHttp Android agent; React/TypeScript web UI; Vitest + JUnit/Robolectric tests.

**Spec:** [2026-11-13-phoneconnect-design.md](../specs/2026-11-13-phoneconnect-design.md)

## Global Constraints

- Management payloads are JSON on a TLS WebSocket; the server may read them. Sealed peer frames stay unreadable by the server. Never move peer media/proxy bytes onto the management channel.
- Every management command requires an active control lease or ownership of the device; read-only sessions never dispatch commands.
- Every command has a deadline (default 10 s, max 60 s), a bounded result, and an explicit `ok` / `error` / `timeout` outcome. No success-shaped fallbacks.
- Bounded everywhere: at most 200 tracked devices, at most 16 recent telemetry samples per device, at most 64 in-flight commands per device, no persisted file or media payloads.
- The Android agent keeps exactly one foreground service and one notification. The management channel shares that service and notification.
- Commands the device does not recognize return `error` with `unknown_command`; a device that is offline returns `error` with `device_offline` immediately rather than hanging.
- File operations are confined to the paths the platform permits (app-accessible storage, shared storage the app can read) and reject traversal; every path is validated before use.
- Tests must not require a physical device: Android behaviour is unit-tested with fakes; server behaviour is tested in-process; web behaviour is tested with mocked fetch.

## Review Focus

- **A command arrives for a device with no control lease or a revoked lease:** must be refused before touching the device; test in Task 1.
- **The device disconnects mid-command:** the caller must get `device_offline`, never a hung pending row; test in Task 1.
- **A command result is oversized or malformed:** must be rejected and bounded, never stored unbounded; test in Task 1.
- **Paths containing `..`, symlinks, or absolute escapes:** must be refused before any file operation; test in Task 2.
- **Screen capture or logcat floods the channel:** must be bounded by frames/bytes and closed with an explicit reason; test in Task 4.

---

### Task 1: Management channel, telemetry, and the command backbone

**Files:**
- Create: `server/src/management.rs` (WebSocket `/api/devices/{device_id}/control`, device registry, command dispatch, deadlines, results)
- Create: `server/src/commands.rs` (`POST /api/devices/{device_id}/commands`, `GET /api/commands/{command_id}`, authorization, audit rows)
- Create: `server/tests/management.rs`
- Create: `server/tests/commands.rs`
- Modify: `server/src/lib.rs` (routes, state, module wiring)
- Modify: `server/src/store.rs` (audit table + insert/list, additive migration)
- Create: `android/app/src/main/java/com/phoneconnect/agent/net/DeviceControlChannel.kt`
- Create: `android/app/src/main/java/com/phoneconnect/agent/control/CommandDispatcher.kt`
- Create: `android/app/src/main/java/com/phoneconnect/agent/control/DeviceInfoHandler.kt`
- Create: `android/app/src/main/java/com/phoneconnect/agent/telemetry/TelemetrySampler.kt`
- Create: `android/app/src/test/java/com/phoneconnect/agent/TelemetrySamplerTest.kt`
- Create: `android/app/src/test/java/com/phoneconnect/agent/CommandDispatcherTest.kt`
- Modify: `android/app/src/main/java/com/phoneconnect/agent/ConnectionService.kt`, `ConnectionSupervisor.kt`, `ConnectionStatus.kt`
- Create: `web/src/routes/CommandsRoute.tsx`, `web/src/components/CommandPanel.tsx`, `web/src/components/CommandPanel.test.tsx`
- Modify: `web/src/api.ts`, `web/src/routing.ts`

**Interfaces:**
- Device → server frames (JSON text): `{"type":"hello","model":str,"android_version":str,"sdk":int}`, `{"type":"telemetry","sample":TelemetrySample}`, `{"type":"result","request_id":str,"status":"ok"|"error","output":json|null,"error":str|null,"message":str|null}`.
- Server → device frames: `{"type":"command","request_id":str,"name":str,"args":json,"deadline_ms":int}`.
- `POST /api/devices/{device_id}/commands` body `{"name":str,"args":json|null,"timeout_ms":int|null}` → `202 {"command_id":str}`; `GET /api/commands/{command_id}` → `{"command_id","device_id","name","status":"pending"|"ok"|"error"|"timeout","output","error","message","created_at_ms","completed_at_ms"}`.
- Authorization: admin bearer token (this milestone) AND `LeaseStore` says the actor owns the device or holds the active lease; a revoked device is `409 device_revoked`; an offline device is `409 device_offline`.
- Command names in this task: `device.info`, `device.ping`, `telemetry.now`.
- `TelemetrySampler.sample()` returns `TelemetrySample` with `cpu_percent`, `memory_used_bytes`, `memory_total_bytes`, `battery_percent`, `battery_charging`, `connectivity`; missing metrics are `null`, never zero-filled.
- `CommandDispatcher.dispatch(name, args) -> Result<JsonObject, CommandError>`; unknown name → `unknown_command`.

Steps:
- [ ] **Step 1: Write failing server tests** for: control channel rejects a bad device credential; a command with no lease is refused; a command to an offline device is `device_offline`; a command times out as `timeout`; a valid command round-trips `device.info`; a revoked device is refused; results are bounded (a 2 MiB result is refused).
- [ ] **Step 2: Run `cargo test -p phoneconnect-server --test management --test commands`** and confirm failure.
- [ ] **Step 3: Implement the store audit table and `commands.rs`** with the authorization and deadline rules above.
- [ ] **Step 4: Implement `management.rs`** — WebSocket upgrade (device credential in the `Authorization` header), device registry keyed by device id with one connection per device (a new connection replaces the old), per-device in-flight cap of 64, a 10 s default / 60 s max deadline, and explicit close reasons.
- [ ] **Step 5: Run the server tests** and confirm they pass.
- [ ] **Step 6: Write failing Android tests** for: sampler maps BatteryManager/ActivityManager values and leaves unsupported metrics null; dispatcher routes `device.info`/`device.ping`/`telemetry.now`; unknown name is `unknown_command`; a channel reconnect backoff is bounded.
- [ ] **Step 7: Implement `TelemetrySampler`, `CommandDispatcher`, `DeviceInfoHandler`, `DeviceControlChannel`** and wire the channel into `ConnectionService` under the existing single notification (the channel is a second connection inside the same service, not a second service).
- [ ] **Step 8: Write failing web tests** for: a command panel posts a command and renders `ok` output; `device_offline` renders as an explicit error; a pending command never renders as success.
- [ ] **Step 9: Implement `CommandPanel` + `CommandsRoute`** and register the route.
- [ ] **Step 10: Run all suites** (`cargo test --workspace`, Android unit tests, `npm test`, typecheck, lint) and commit.

### Task 2: Files

**Files:**
- Create: `android/.../control/FileHandler.kt`, `android/.../control/PathGuard.kt`, tests `FileHandlerTest.kt`, `PathGuardTest.kt`
- Create: `server/src/files.rs`, `server/tests/files.rs`
- Create: `web/src/routes/FilesRoute.tsx`, `web/src/components/FileList.tsx`, tests
- Modify: `server/src/lib.rs`, `android/.../control/CommandDispatcher.kt`, `web/src/api.ts`, `web/src/routing.ts`

**Interfaces:**
- Commands: `files.list {path}` → `{entries:[{name,path,is_dir,size_bytes,modified_ms}]}`; `files.read {path,offset?,length?}` → `{data_base64,truncated,name}` (max 256 KiB per chunk); `files.write {path,data_base64,append?}` → `{bytes_written}`; `files.mkdir {path}`; `files.delete {path}` (file or empty dir only); `files.rename {from,to}`.
- `PathGuard.resolve(root, requested) -> Result<PathBuf, PathError>` rejects `..`, absolute escapes, symlinks that leave the root, and NUL; the root is a single configured directory (`Environment.getExternalStorageDirectory()`-equivalent or app external files dir), never `/`.
- Server routes pass commands through; no file bytes are stored server-side.
- `409 device_offline` when the device is not connected; `413` when a write exceeds 1 MiB after decoding.

Steps:
- [ ] **Step 1: failing tests** for PathGuard (traversal, symlink escape, NUL, legit nested path), FileHandler (list/read/write/mkdir/delete/rename, read truncation, write size cap), server passthrough and size refusal, web list/render/error states.
- [ ] **Step 2: run and confirm failure.**
- [ ] **Step 3: implement PathGuard and FileHandler.**
- [ ] **Step 4: implement server routes and tests.**
- [ ] **Step 5: implement the web Files route.**
- [ ] **Step 6: run all suites and commit.**

### Task 3: Apps

**Files:**
- Create: `android/.../control/AppsHandler.kt` + test
- Create: `server/src/apps.rs`, `server/tests/apps.rs`
- Create: `web/src/routes/AppsRoute.tsx`, `web/src/components/AppList.tsx` + tests
- Modify: `CommandDispatcher.kt`, `server/src/lib.rs`, `web/src/api.ts`, `web/src/routing.ts`

**Interfaces:**
- Commands: `apps.list {}` → `{apps:[{package,label,version_name,version_code,system,enabled,updated_ms}]}`; `apps.launch {package}`; `apps.stop {package}`; `apps.clear {package}`; `apps.set_enabled {package,enabled}`.
- Label resolution uses `PackageManager`; an unresolvable label falls back to the package name (never invents a name).
- Only packages visible to the app's UID are listed; a package the app cannot touch returns `error: not_permitted`.

Steps: mirror Task 2's cycle (tests → implement Android → server → web → verify → commit).

### Task 4: Screen snapshot, console, and logcat

**Files:**
- Create: `android/.../control/ScreenHandler.kt`, `LogcatHandler.kt`, `ShellHandler.kt` + tests
- Create: `server/src/screen.rs`, `server/src/console.rs`, tests
- Create: `web/src/routes/ScreenRoute.tsx`, `ConsoleRoute.tsx` + tests
- Modify: `CommandDispatcher.kt`, `server/src/lib.rs`, `web/src/api.ts`, `web/src/routing.ts`

**Ruling — implement only what an ordinary app can actually do.**
A normal installed app cannot run `adb shell`, cannot read logcat (`READ_LOGS` is
signature-level), and cannot capture the screen without `MediaProjection` consent. Shipping
those as commands that always fail would be a dead control; shipping them as pretend
successes would be worse. So this task implements the one real capability and reports the
others as explicit, documented refusals.

**Interfaces:**
- `screen.snapshot {}` → `{png_base64,width,height,captured_at_ms}` from `MediaProjection`.
  Consent is requested only from the setup screen (a user action), stored for the service
  lifetime; without consent the command returns `error: consent_required` and never prompts.
  PNG is downscaled as needed so the encoded result stays under 2 MiB.
- `system.props {}` → `{selected map}` read through `android.os.SystemProperties`
  reflection for a documented allowlist (sdk, release, model, manufacturer, build id,
  security patch); anything else is `not_permitted`. This replaces `shell.exec` for the
  read-only properties that are actually reachable.
- `shell.exec` and `logcat.tail` → always `error: not_permitted` with a constant message
  naming the platform restriction, documented in `android/README.md` and rendered in the UI
  as unavailable-with-reason. They exist so callers get a machine code instead of
  `unknown_command`.
- The server forwards these as normal commands; no streaming endpoint in this task.

Steps: tests first (consent-required path, property allowlist, the two documented refusals,
size cap), then Android (including the setup-screen consent action), server, web, verify, commit.

### Task 5: Toggles and device control

**Files:**
- Create: `android/.../control/ControlHandler.kt` + test, `server/src/controls.rs`, `web/src/components/ControlPanel.tsx` + test
- Modify: `CommandDispatcher.kt`, `server/src/lib.rs`, `web/src/api.ts`, `web/src/routes/DeviceStatusRoute.tsx`

**Ruling — same honesty rule as Task 4.** An ordinary app can read most of these and change
only some. Each key reports what the platform actually allows, with the reason, and never a
silent no-op.

**Interfaces:**
- `control.get {}` → `{brightness, brightness_mode, volume_music, volume_max, rotation,
  dnd_filter, night_mode, wifi_enabled, bluetooth_enabled, mobile_data_enabled,
  battery_saver, battery_percent}` — each `null` when the platform refuses the read, and a
  companion `unavailable: {key: reason}` map so the UI can say *why* rather than implying zero.
- `control.set {key,value}`:
  - `brightness` — real on API 23+ only with the user-granted `WRITE_SETTINGS`; without it
    `not_permitted: write_settings_required`, with a setup-screen action to request it.
  - `volume_music` — real via `AudioManager.setStreamVolume` (no permission).
  - `dnd_filter` — real only with user-granted notification-policy access
    (`ACCESS_NOTIFICATION_POLICY`); otherwise `not_permitted: policy_access_required`.
  - `wifi`, `bluetooth`, `mobile_data`, `night_mode`, `rotation` — `not_permitted` with a
    constant reason (platform removed or signature-gated the setter), documented in
    `android/README.md` and rendered unavailable-with-reason.
- `control.reboot` → constant `not_permitted: reboot_requires_privilege` (REBOOT is
  signature-level; a device-owner build could add it later). It exists so callers get a
  machine code, and the UI shows it as unavailable.

Steps: tests first (per-key mapping, each refusal code, grant-gated paths, no silent success), then Android (including the two setup-screen grant actions), server, web, verify, commit.

### Task 6: Command audit surface and web polish

**Files:**
- Create: `server/src/audit.rs`, `server/tests/audit.rs`, `web/src/routes/AuditRoute.tsx` + test
- Modify: `server/src/store.rs` (audit queries), `server/src/lib.rs`, `web/src/api.ts`, `web/src/routing.ts`

**Interfaces:**
- `GET /api/audit?device_id=&limit=` → newest-first bounded list (`limit<=200`) of `{at_ms, actor, action, device_id, outcome, error}`.
- Audit rows are written for every command dispatch and every revocation; 30-day retention applies.
- The audit screen renders filters, empty state, and errors honestly; no "all clear" when the query failed.

Steps: tests first, implement, verify, commit.

### Task 7: Documentation parity and capability matrix

**Files:**
- Modify: `README.md`, `android/README.md`, `server/README.md`, `web/README.md` (create if missing), `native/README.md`
- Create: `docs/capabilities.md`

**Interfaces:**
- `docs/capabilities.md` is one table: every command name, what it does, whether an ordinary
  installed app can perform it, and the exact refusal code when it cannot. It is generated by
  hand from the handlers, and a test asserts every command name registered by the Android
  dispatcher appears in it (and nothing appears that is not implemented).
- The root README gains a "What works today" section listing only what the tests and the
  emulator smoke actually exercised, and a "Not implemented" section naming mirroring/input,
  mic/recordings, calls/SMS/notifications, OTA, accounts, CI publishing, the Android TCP proxy
  bridge, and direct hole-punched paths on Android.

Steps: write the matrix, add the documentation test on the Android side, update each README,
run all suites, commit.

## Later plans (not in this plan)

1. Mirroring and input (MediaProjection + H.264 encode, web decode, input injection) — largest and highest risk.
2. Mic streaming and recordings.
3. Calls/SMS/notifications records and device history + CSV.
4. Accounts: local login, MFA, device assignments, per-user visibility; replaces the admin token.
5. Agent OTA with signed manifests and a release channel.
6. Signed release publishing (GHCR image push, signed APK, native installers). CI itself exists
   (`.github/workflows/ci.yml`: Rust clippy and tests, web typecheck/lint/tests/build, Android
   unit tests/lint/APK artifact, Docker build); only the publishing half is future work.
7. Direct hole-punched paths on Android and the Android TCP proxy bridge.

## Verification gate

- Every task: Rust workspace tests, Android unit tests, web tests/typecheck/lint all green.
- No command may report success without a device-produced `ok` result.
- No management path stores files or media server-side.
- A device that is offline, revoked, or not leased fails fast and explicitly.
