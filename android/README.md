# PhoneConnect Android agent

An ordinary user-installed APK (no device-owner provisioning). It enrolls against a
self-hosted hub, holds one authenticated session over the server relay, and keeps exactly one
foreground connection service with exactly one visible status notification.

ADB is used only to sideload the app; it is never the runtime identity or the transport.

## How it connects

1. **Setup.** `SetupActivity` takes the hub URL and a one-time enrollment token, requests
   `POST_NOTIFICATIONS`, generates an X25519 identity, calls `POST /api/devices/enroll`, and
   stores the credential and private key sealed by the Android Keystore. It then starts the
   service. The screen also shows the enrollment state and what to do after a stop.
2. **Session discovery.** A user or client authorizes a session for this device
   (`POST /api/sessions`); the device credential reads it from
   `GET /api/devices/{id}/sessions/next` with a device-role ticket. The device never creates
   sessions and never holds client or admin credentials.
3. **Rendezvous.** `GET /ticket` mints a fresh device ticket. The device then redeems that
   ticket **once** at `POST /candidates` with no `endpoint`: this publishes its half of the
   connection epoch without advertising a probe target (a relay-only device has no direct
   address, and a wildcard would be handed to the peer as a candidate that can never answer).
   It then polls the read-only `GET /candidates` until the client's nonce appears. The two
   ticket nonces are the per-connection key epoch. A ticket is single-use, so an attempt that
   re-posted it would answer `409 ticket_replayed`; polling never redeems one.
4. **Transport.** `SessionCipher` agrees X25519 → HKDF-SHA256 keys and seals every frame;
   `RelayFrameChannel` attaches to the relay WebSocket (binary frame per message, WebSocket
   ping every 10 s) and reports the server's close code.
5. **Reconnect.** `ConnectionSupervisor` retries with bounded jittered backoff, resets after a
   healthy session, and stops for the terminal class (revoked device, relay 409, unenrolled,
   ended session) with the invalidation that failure implies.

## Layout

| File | Responsibility |
| --- | --- |
| `SetupActivity.kt` | The only screen: hub URL, token, enrollment, notification permission, status and recovery. |
| `ConnectionService.kt` | The only foreground service and the only `startForeground` call site; lifecycle, recovery wiring, outcome handling, `onTimeout`. |
| `NotificationController.kt` | The only notification: one fixed id, one channel, updated in place. |
| `ConnectionStatus.kt` / `ConnectionStatusBus.kt` | What the notification and setup screen show. |
| `ConnectionSupervisor.kt` | One session at a time, bounded backoff, reset after health, terminal classification. |
| `ReconnectPolicy.kt` / `ConnectionFailure.kt` | Backoff maths; retryable vs terminal failures and their invalidation. |
| `EnrollmentStore.kt` | Enrollment contract, `@IdentityBoundary`, `DeviceIdentity`. |
| `EnrollmentFlow.kt` | Identity generation + `POST /api/devices/enroll` + sealed persistence. |
| `KeystoreEnrollmentStore.kt` / `KeystoreSecretCipher.kt` | One JSON record with both secrets sealed by AES-256-GCM under a non-exportable Keystore key. |
| `EnvelopeCodec.kt` | The shared envelope contract: 4-byte length prefix, control-only 1 MiB profile. |
| `AgentTransport.kt` | Control/event streams over one `FrameChannel`: seals/opens, sequences, binds frames to this session/device, maps close codes. |
| `crypto/X25519.kt`, `crypto/HkdfSha256.kt` | RFC 7748 scalar multiplication and RFC 5869 key derivation. |
| `crypto/SealedFrame.kt`, `crypto/SessionCipher.kt`, `crypto/ReplayWindow.kt` | Byte-compatible port of `crates/transport/src/aead.rs`. |
| `net/HubClient.kt` | Enroll, session discovery, ticket, candidates, relay URL (HTTPS or loopback HTTP only). |
| `net/RelayFrameChannel.kt` | Relay WebSocket transport with the 10 s keepalive ping. |
| `net/TransportSessionRunner.kt` | One session: identity → discovery → ticket → epoch → relay → frames. |
| `RecoveryReceiver.kt` | Boot and post-update recovery with `goAsync`, refusing gracefully when the OS refuses. |
| `AgentSettings.kt` / `AgentDiagnostics.kt` | Hub URL and the last background-start refusal. |

## Toolchain

- JDK 21 through a Gradle toolchain (`kotlin { jvmToolchain(21) }`); no absolute JDK path is
  committed. A machine-local `org.gradle.java.home` belongs in `~/.gradle/gradle.properties`.
- Gradle 8.13 through the committed wrapper with a pinned `distributionSha256Sum`.
- AGP 8.9.1, Kotlin 2.2.0, `compileSdk`/`targetSdk` 35, `minSdk` 28 (ChaCha20-Poly1305 is a
  platform cipher from API 28; nothing is hand-rolled for AEAD).
- Envelope types are generated from `../proto` by `protobuf-gradle-plugin` (protoc 4.29.3,
  javalite runtime). There is no copy of the schema in this module.

Keep local build state inside this directory so an unwritable `$HOME` cannot block a build
(`.gradle-home/`, `.android/`, `local.properties` are git-ignored):

```sh
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_USER_HOME="$PWD/.android"
export GRADLE_USER_HOME="$PWD/.gradle-home"

./gradlew :app:testDebugUnitTest   # JVM + Robolectric tests
./gradlew :app:assembleDebug       # app/build/outputs/apk/debug/app-debug.apk
./gradlew :app:lintDebug           # app/build/reports/lint-results-debug.xml
```

## Cleartext policy for a loopback hub

`HubClient` accepts `https` anywhere and plain `http` only for `127.0.0.1`, `localhost`, and
`::1`, and the compose default is that loopback origin. Because `targetSdk` 35 denies
cleartext by default, `app/src/main/res/xml/network_security_config.xml` permits cleartext for
exactly those three literals and leaves every other host on TLS; the manifest applies it with
`android:networkSecurityConfig`. `NetworkSecurityConfigTest` parses the manifest and the XML
and fails if a non-loopback domain is covered or the base config starts allowing cleartext.

## Foreground service type

The service is `connectedDevice` with `FOREGROUND_SERVICE_CONNECTED_DEVICE` and
`CHANGE_NETWORK_STATE`. `dataSync` is wrong for this product on Android 15: it cannot be
started from `BOOT_COMPLETED` and it is capped at six hours per day. `onTimeout` stops the
loop and removes the notification if the system still ends the service, and a refused
background start is recorded and shown on the setup screen instead of crashing the receiver.

## Invariants the tests hold

- **One notification.** `NotificationControllerTest` scans the module's own sources: one
  `startForeground` call site, one `notify` call site, only the single `NOTIFICATION_ID`, one
  declaration, and no notification APIs outside the controller.
- **One service loop.** Two start deliveries open one session; a terminal outcome stops the
  service but leaves the reason visible; a later enrollment starts a fresh instance.
- **Secrets stay behind the boundary.** No plaintext getter; only the storage, enrollment
  flow, and session runner opt in to `@IdentityBoundary`; the on-disk record holds ciphertext;
  `DeviceIdentity.close()` zeroes both buffers.
- **Bounded reconnect.** Doubling to a hard cap, jitter inside the band, reset after health,
  terminal class with explicit invalidation.
- **Wire and crypto compatibility.** 18 tests compare against Rust: the length-prefixed
  envelope fixtures, RFC 7748/5869 vectors, and sealed frames produced by
  `crates/transport` for fixed identity keys, epoch, session id, and envelope — byte for byte,
  in both roles — plus tamper, replay, regression, wrong-direction, unknown-key-id, and
  degenerate-key rejection.
- **Real hub flow.** `HubSessionTest` runs the agent against a real HTTP/WebSocket server:
  discovery, ticket, candidates with the peer nonce, relay attach, sealed frame exchange, a
  terminal close, a relay 409 that is never retried, and a 204 poll loop.
- **Setup.** `SetupActivityTest` enrolls through the screen into a Keystore-sealed store and
  starts the one service.

## Best-effort persistence

This is an ordinary app. `START_STICKY`, boot recovery, and a `connectedDevice` foreground
service improve survival but cannot promise it: users, the OS, and OEM battery managers can
still stop the agent. The notification and setup screen say so and show recovery steps.

## Known gaps in this milestone

- **Direct (hole-punched) paths are not ported.** `crates/transport` probes candidates with
  HMAC-authenticated datagrams and a dual-commit switch; this build always uses the relay and
  reports `ConnectionPath.RELAY`. The relay is the documented fallback for symmetric NAT,
  CGNAT, and restrictive firewalls, so the agent connects, but a direct path is not attempted.
- **Ticket signatures are not verified.** The Ed25519 signature is carried from the hub but
  not checked; TLS authenticity to the hub is the trust anchor, exactly as the Rust transport
  documents for trust-on-first-use. Porting Ed25519 verification is follow-up work.
- **Command, telemetry, and feature adapters are a follow-up task.** The session stays
  authenticated and framed; inbound control payloads are not yet dispatched.
- **Instrumentation tests cannot run in this environment** (no AVD, no emulator system
  images), so the emulator smoke test and real-Keystore/OEM behaviour are unverified here.
