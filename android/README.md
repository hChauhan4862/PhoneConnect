# PhoneConnect Android agent

An ordinary user-installed APK (no device-owner provisioning). It keeps exactly one
foreground connection service with exactly one visible status notification, reports bounded
telemetry/events, and holds the authenticated control connection with bounded reconnect.

ADB is used only to sideload and enroll the app; it is never the runtime identity or the
transport.

## Layout

| File | Responsibility |
| --- | --- |
| `ConnectionService.kt` | The only foreground service and the only `startForeground` call site. Owns lifecycle, boot/network recovery wiring, and cancellation. |
| `NotificationController.kt` | The only notification: one fixed id, one channel, updated in place. |
| `ConnectionStatus.kt` | What the notification and the status UI show. |
| `ConnectionSupervisor.kt` | One session at a time, bounded backoff, reset after a healthy connection, terminal classification. |
| `ReconnectPolicy.kt` | Bounded exponential backoff with jitter. |
| `ConnectionFailure.kt` | Retryable vs terminal failures and what a terminal failure invalidates. |
| `EnrollmentStore.kt` | Enrollment contract, `@IdentityBoundary`, and the short-lived `DeviceIdentity`. |
| `KeystoreEnrollmentStore.kt` | Persists one JSON record with both secrets sealed. |
| `KeystoreSecretCipher.kt` | AES-256-GCM under a non-exportable Android Keystore key. |
| `EnvelopeCodec.kt` | The shared envelope contract: 4-byte length prefix, control-only 1 MiB profile. |
| `AgentTransport.kt` | Control/event streams over one `FrameChannel`; server revocation closes the stream immediately. |
| `RecoveryReceiver.kt` | Boot and post-update recovery, only when an enrollment exists. |

## Toolchain

- JDK 21 (`org.gradle.java.home` in `gradle.properties`).
- Gradle 8.13 through the committed wrapper, with a pinned `distributionSha256Sum`.
- AGP 8.9.1, Kotlin 2.2.0, `compileSdk`/`targetSdk` 35, `minSdk` 26.
- Envelope types are generated from `../proto` by `protobuf-gradle-plugin` (protoc 4.29.3,
  javalite runtime). There is no copy of the schema in this module.

Keep all local build state inside this directory so an unwritable `$HOME` cannot block a
build (`.gradle-home/`, `.android/`, `local.properties` are git-ignored):

```sh
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-21.jdk/Contents/Home
export ANDROID_HOME="$HOME/Library/Android/sdk"
export ANDROID_USER_HOME="$PWD/.android"
export GRADLE_USER_HOME="$PWD/.gradle-home"

./gradlew :app:testDebugUnitTest   # JVM + Robolectric tests
./gradlew :app:assembleDebug       # app/build/outputs/apk/debug/app-debug.apk
./gradlew :app:lintDebug           # app/build/reports/lint-results-debug.html
```

## Invariants the tests hold

- **One notification.** `NotificationControllerTest` scans the module's own sources: exactly
  one `startForeground` call site, exactly one `notify` call site, every id argument is the
  single `NOTIFICATION_ID` constant, that constant is declared once, and only
  `NotificationController` touches the notification APIs. A second id fails the build.
- **One service loop.** Two `startService`/`startForegroundService` deliveries open one
  session (`ConnectionServiceTest`).
- **Secrets stay behind the boundary.** `EnrollmentStore` has no plaintext getter; only the
  store implementation opts in to `@IdentityBoundary`; the on-disk record never contains
  the credential or the private key; `DeviceIdentity.close()` zeroes both.
- **Bounded reconnect.** Delays double to a hard cap, jitter never escapes the cap, a
  healthy connection resets to the base delay, and the terminal class (revoked device,
  relay `409 relay_unavailable`, missing enrollment, ended session) stops retrying and
  applies exactly its invalidation.
- **Wire compatibility.** `AgentTransportTest` decodes frames produced by the Rust codec
  (`crates/protocol`) and re-encodes them byte for byte, including the 1 MiB prefix cap.

## Best-effort persistence

This is an ordinary app. `START_STICKY`, boot recovery, and a foreground service improve
survival but cannot promise it: users, the OS, and OEM battery managers can still stop the
agent. The notification says so, and the status UI is expected to show recovery steps rather
than claim otherwise.

## Known gaps in this milestone

- The sealed transport behind `FrameChannel` (session negotiation, ticket verification,
  X25519/HKDF key agreement, ChaCha20-Poly1305) is not implemented in Kotlin. The Rust
  `crates/transport` implementation is the reference; until a channel implementation is
  installed, `ConnectionService` reports `ActionRequired` instead of pretending to connect.
- Instrumentation tests cannot run in this environment (no AVD, no emulator system images),
  so the emulator smoke test is unverified here.
