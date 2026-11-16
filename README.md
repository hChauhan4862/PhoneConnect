# PhoneConnect

PhoneConnect is a self-hosted client and relay stack designed to reach an owner's own Android
phone from a desktop client. It pairs an ordinary user-installed Android agent with a server
that authorizes sessions and relays end-to-end encrypted frames, plus a desktop shell and a
web UI served by that same server. The relay only forwards ciphertext: peers seal every frame
with keys the server never holds. Nothing here exposes raw ADB to a network.

## Milestone status

This is an early milestone, not a finished product.

- The server, protocol, and transport are implemented and covered by automated tests.
- The Android agent's code path enrolls and holds one relay session against a real server in
  its JVM test harness. No run on a physical device is recorded in this repository; the
  end-to-end runs recorded here used an Android 15 emulator, and `docs/capabilities.md` says for
  each command whether it was exercised there or only in a unit test.
- The native shell builds on macOS and runs its headless `--print-context` path. It is a
  webview over the server-served UI plus loopback proxy endpoints; the GUI path was not
  exercised here, and those endpoints have no Android peer, so nothing on the phone is
  reachable through them.
- The web UI is a static admin surface. It renders the snapshot it last read and polls a
  command until the device answers; there is no server-to-client push channel.
- Each enrolled device keeps a second, authenticated management connection to the server
  carrying JSON telemetry and commands. `docs/capabilities.md` is the single table of those
  commands: what each one does, whether an ordinary installed app can perform it, the exact
  refusal code and reason when it cannot, and whether it was verified on the emulator, by a
  unit test only, or not at all. The sealed peer relay is unchanged and the server still cannot
  read it.
- Direct hole-punched paths are implemented and tested in the transport, but both shipped
  clients use the relay. Production connectivity is relay-only.
- Telemetry aggregates are bounded and kept in memory.

## Repository layout

- `server/` — control plane: enrollment, sessions, signed rendezvous tickets, the bounded
  relay, control leases, telemetry, retention, and the admin API.
- `crates/protocol/` — generated protobuf types, the frame codec, and the sealed-frame header.
- `proto/` — the `.proto` schema shared by the Rust crates and the Android module.
- `crates/transport/` — end-to-end frame sealing, authenticated hole punching, candidate
  selection, path upgrade/fallback, and the relay keepalive.
- `android/` — the ordinary user-installed agent APK: one foreground service, one notification.
- `native/` — the Tauri/Rust desktop shell over the server-served UI, plus loopback proxy
  endpoints.
- `web/` — the only UI implementation, served by the server.
- `docker/` — the server image, the compose file, and the container transport end-to-end test.
- `docs/` — the design spec, the implementation plan, and `docs/capabilities.md`, the device
  command matrix.

## Prerequisites

- Rust 1.85 or newer (the workspace uses edition 2024).
- `protoc`, because `crates/protocol/build.rs` shells out to it and every Cargo command builds
  that crate:

  ```sh
  brew install protobuf                          # macOS
  sudo apt-get install -y protobuf-compiler      # Debian/Ubuntu
  ```

- Node 24 for the web app.
- JDK 21 and the Android SDK for the APK; `android/README.md` lists the environment variables
  the Gradle build expects.
- Docker 29 with the compose plugin for the server image and the transport end-to-end test.

## Build and test

```sh
cargo test --workspace                            # Rust server, protocol, transport, native logic
(cd web && npm ci && npm test)                    # web UI
(cd android && ./gradlew :app:testDebugUnitTest)  # Android unit + Robolectric tests
```

Each component's README documents its own commands, including `cargo clippy`, the web build,
the APK build, and the Docker end-to-end test.

## What works today

Only what the suites and the emulator smoke actually exercised is listed. `docs/capabilities.md`
is the single table of every device command: what it does, whether an ordinary installed app can
perform it, the exact refusal code and reason when it cannot, and whether it was verified on the
emulator, by a unit test only, or not at all.

- **Enrollment and recovery.** A device enrolls with a one-time token, holds one relay session
  and one authenticated management connection, and reconnects with bounded backoff. The agent's
  session flow runs against a real HTTP/WebSocket server in its JVM harness; enrollment and the
  management channel were exercised on an Android 15 emulator, where one service and one
  notification held. The setup screen offers the documented persistence mitigation — a button
  that opens Android's battery-optimisation exemption screen — and then reports what Android
  says. It is a request the user can decline; the app never claims it cannot be stopped.
- **Identity and telemetry.** `device.info` and `telemetry.now` work end to end (emulator).
  `device.ping` is covered by unit tests only. `telemetry.now` reports battery, memory, and the
  active network transport; CPU percentage is always absent because Android does not expose it
  to an ordinary app.
- **Files.** All six `files.*` commands work inside the app's own external files directory
  (emulator): a 256 KiB read chunk with an honest `truncated`, a non-recursive delete, and
  `path_outside_root` for a traversal. The 1 MiB write cap is enforced by the server before
  dispatch (a live `413 too_large`) and by the device (unit test).
- **Apps.** `apps.list`, `apps.launch` (only while Android permits a background start; the live
  run saw both a real launch and `launch_blocked`), and `apps.stop` (a kill *request*, never a
  confirmed stop) work (emulator). `apps.clear` and `apps.set_enabled` are constant refusals:
  they need signature-level permissions.
- **Screen.** `screen.snapshot` returns one real frame after the user grants screen capture on
  the device (emulator, including a resize on rotation); without that grant it is
  `consent_required` and no code path can prompt.
- **System properties and the console.** `system.props` reports a six-name allowlist (emulator).
  `shell.exec` and `logcat.tail` are constant `not_permitted` refusals with a reason, because an
  installed app has neither a shell UID nor `READ_LOGS`.
- **Device control.** `control.get` reports its twelve readings (emulator). `control.set` really
  changes screen brightness (with the user-granted `WRITE_SETTINGS`), music volume, and the Do
  Not Disturb filter (with notification-policy access), confirming each by reading it back, and
  it refuses Wi-Fi, Bluetooth, mobile data, night mode, and rotation with a machine reason.
  `control.reboot` always refuses: `REBOOT` is signature-level.
- **Server, protocol, and transport.** Covered by the Rust tests, including the relay limits,
  leases, retention, the audit surface and its 30-day deletion, and the sealed-frame
  compatibility vectors. Direct hole-punched paths are
  implemented and tested in the Rust transport.
- **Web UI.** Routes, panels, and API errors are covered by Vitest. The control panel was
  driven against the emulator in a real desktop browser. The file, app, screen, and console
  screens have component tests and the served SPA answers their routes, but no run has driven
  them against a live device in a real desktop browser. Onboarding — minting a single-use
  enrollment token and revoking a device behind a confirmation — is covered by Vitest and was
  exercised against the real server with `curl` (mint → enroll → single-use refusal → revoke),
  but not clicked through in a browser. The audit screen (newest-first rows, a server-side
  device filter, and explicit empty and error states) is covered by Vitest only. There is no
  server-to-client push, so every screen renders the snapshot it last read. The audit page
  says in visible text what its rows can and cannot mean: the actor is asserted by the token
  holder and is not verified by the server. An `accepted` outcome means the command was
  delivered to the device's channel, not that the device executed it.
- **Native shell.** Builds on macOS and runs its headless `--print-context` path. The GUI path
  was not exercised here.

A command is `ok` only when the device produced that answer; nothing above is inferred from a
dispatch.

## Not implemented

None of the capabilities below exists in code. The last bullet is the exception: it names a
verification gap, not a missing feature. This is not a roadmap promise; it is what a reader must
not assume.

- **Mirroring and input.** No continuous screen stream, no video encode, and no touch or key
  injection. `screen.snapshot` is one frame per command.
- **Microphone and recordings.** No audio capture, streaming, or recording.
- **Calls, SMS, and notification records.** No call log, SMS, or notification history, and no
  device history export (CSV or otherwise).
- **Agent OTA.** No self-update, no signed manifest, and no release channel.
- **Accounts, login, and MFA.** Access uses the admin bearer token, so control leases constrain
  an already accepted user but are not an authorization boundary. There are no device
  assignments or per-user visibility. The audit log inherits that gap and cannot close it: the
  actor is asserted by the token holder and is not verified by the server. An `accepted`
  outcome means the command was delivered to the device's channel, not that the device
  executed it.
- **The Android TCP proxy bridge.** The native shell's loopback proxy has no Android peer, so it
  reaches no phone. No screen creates a session until local login and MFA land.
- **Direct hole-punched paths on Android.** The Rust transport implements and tests them; the
  Android agent always uses the relay, and it does not verify ticket signatures (TLS to the hub
  is its trust anchor).
- **Signed release publishing.** CI is configured in `.github/workflows/ci.yml` to run Rust
  clippy and tests, the web typecheck, lint, tests, and build, the Android unit tests, lint,
  and debug APK, and a Docker image build on every push to `main` and every pull request. It
  has not yet been observed running on GitHub — this checkout has no remote. Nothing is
  *published*: there is no signed release artifact, no APK or native installer release, and
  no GHCR image push.
- **Windows and Linux native builds.** Only macOS has been built here.
- **Device control of Wi-Fi, Bluetooth, mobile data, rotation, night mode, or reboot.** These are
  refusals, not features: an ordinary installed app cannot hold the signature-level permissions
  or the system-UI role they need. ADB is not implemented, exposed, or tunnelled either; the
  agent is not a shell.
- **The file, app, screen, and console screens in a real desktop browser.** They are covered by
  component tests and the served SPA answers their routes, but no run has driven them against a
  live device in a real desktop browser; only the control panel has been.

## License

MIT. See [LICENSE](LICENSE).
