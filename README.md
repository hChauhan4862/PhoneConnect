# PhoneConnect

PhoneConnect is a self-hosted client and relay stack designed to reach an owner's own Android
phone from a desktop client. It pairs an ordinary user-installed Android agent with a server
that authorizes sessions and relays end-to-end encrypted frames, plus a desktop shell and a
web UI served by that same server. The relay only forwards ciphertext: peers seal every frame
with keys the server never holds. Nothing here exposes raw ADB to a network.

## Milestone status

This is the foundation milestone, not a finished product.

- The server, protocol, and transport are implemented and covered by automated tests.
- The Android agent's code path enrolls and holds one relay session against a real server in
  its JVM test harness. No run on a physical device is recorded in this repository.
- The native shell builds on macOS and runs its headless `--print-context` path. It is a
  webview over the server-served UI plus loopback proxy endpoints; the GUI path was not
  exercised here, and those endpoints have no Android peer, so nothing on the phone is
  reachable through them.
- The web UI is a static admin surface. It renders the snapshot it last read; there is no
  server-to-client push channel.
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
- `docs/` — the design spec and the implementation plan.

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

## Not implemented yet

The component READMEs are the source of truth for what does and does not work:

- `android/README.md` — no direct-path port, no ticket-signature verification, and no command,
  telemetry, or feature adapters. ADB, files, media, apps, input, screen mirroring, and audio
  are not implemented, and the phone is not remotely controllable.
- `native/README.md` — there is no Android-side TCP bridge, so the loopback proxy does not
  reach a phone yet; no screen creates a session until the server's user login and MFA land.
  Only macOS has been built here; Windows and Linux are untested.
- `web/README.md` and `server/README.md` — the UI is not live, and local password login/MFA do
  not exist. Access uses the admin bearer token, so control leases constrain an already
  accepted user but are not an authorization boundary.

## License

MIT. See [LICENSE](LICENSE).
