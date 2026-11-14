# PhoneConnect Android agent

An ordinary user-installed APK (no device-owner provisioning). It enrolls against a
self-hosted hub, holds one authenticated session over the server relay plus one authenticated
management connection, and keeps exactly one foreground connection service with exactly one
visible status notification.

ADB is used only to sideload the app; it is never the runtime identity or the transport.

`docs/capabilities.md` at the repository root is the single table of the commands this agent
implements: what each one does, whether an ordinary installed app can perform it, the exact
refusal code and reason when it cannot, and whether it was verified on the emulator or only in a
unit test. This file describes how they are built; the matrix is the authority on what works.

## How it connects

1. **Setup.** `SetupActivity` takes the hub URL and a one-time enrollment token, requests
   `POST_NOTIFICATIONS`, generates an X25519 identity, calls `POST /api/devices/enroll`, and
   stores the credential and private key sealed by the Android Keystore. It then starts the
   service. The screen also shows the enrollment state and what to do after a stop, plus the
   two optional grants device control uses ("Allow brightness changes" opens
   `ACTION_MANAGE_WRITE_SETTINGS` for this package, "Allow Do Not Disturb changes" opens
   `ACTION_NOTIFICATION_POLICY_ACCESS_SETTINGS`) and what Android currently reports for each.
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
6. **Management.** `DeviceControlChannel` keeps a second WebSocket
   (`/api/devices/{id}/control`) inside the same service: it announces the device with
   `hello`, reports a `TelemetrySampler` sample on connect and every 30 s, and answers each
   `command` frame with exactly one `result`. It refuses to *start* a command whose absolute
   `expires_at_ms` has already passed (answered `timeout`, never executed), clamps a running
   handler to the remaining server budget rather than its full `deadline_ms`, and refuses
   non-object `args` as `invalid_args`. Its server-clock estimate is re-learned on every new
   socket and revised downward when several samples agree, so a device clock correction cannot
   wedge every command into `timeout`. Its reconnect backoff is bounded (1 s doubling to
   60 s); a repeatedly refused credential stops it as `offline` instead of looping. The
   channel never starts a service, posts a notification, or publishes a status: the service
   reports its state in the existing notification.
7. **Files.** `files.list`, `files.read`, `files.write`, `files.mkdir`, `files.delete`, and
   `files.rename` operate inside one root: the app's own external files directory (no storage
   permission, removed with the app), never `/`. `PathGuard` resolves every request — rejecting
   `..`, absolute paths, NUL, and symlinks whose real target leaves the root — before a handler
   touches the filesystem, and the handlers run on `Dispatchers.IO`, never on the command
   receive loop. A read returns at most 256 KiB of decoded bytes per chunk with an honest
   `truncated`; a write accepts at most 1 MiB decoded (`too_large` beyond that); delete removes
   a file or an *empty* directory and is never recursive (`dir_not_empty`). A listing is capped
   at 4 096 entries (or ~1 MB encoded) and refused as `listing_too_large` instead of being
   materialized, and an I/O fault is `io_error` with a root-relative path — never the platform
   message that names the device's absolute path.
8. **Apps.** `apps.list` reports the packages visible to the app's UID — `package`, `label`
   from `PackageManager` (an unresolvable label falls back to the package name, never an
   invented one), `version_name`, `version_code`, `system`, `enabled`, and `updated_ms` from
   `PackageInfo` — sorted by label, case-insensitive, and refused as `listing_too_large` at
   2 000 apps or ~1 MB encoded instead of being truncated. `apps.launch` starts the app's own
   launch intent; Android 10+ restricts background activity starts, so when the platform will
   not allow one the answer is `error: launch_blocked` (`background_activity_start_restricted`,
   or `platform_refused` when the start itself is refused) and never a success; a package with
   no launchable activity is `error: no_launch_activity`. `apps.stop` calls
   `ActivityManager.killBackgroundProcesses` and reports `kill_requested: true` — a request,
   never a confirmed stop — and `error: not_permitted` when the platform refuses.
   `apps.clear` and `apps.set_enabled` need signature-level permissions an ordinary installed
   app cannot hold, so they are constant `error: not_permitted` refusals whose message names
   the ADB path (`adb shell pm clear`, `adb shell pm disable-user`). Every acting command
   resolves `package` against the device's own list first: an unknown name is
   `error: unknown_package`, not a platform exception.

   `QUERY_ALL_PACKAGES` is declared because Android 11+ hides other installed apps otherwise,
   and a partial inventory would be a fabricated one. Google Play restricts that permission to
   apps whose core purpose needs it and requires a declaration: **a Play-distributed build of
   this agent would have to justify it (device management) or ship without a complete app
   list.** `KILL_BACKGROUND_PROCESSES` is declared for `apps.stop`. Both are ordinary
   permissions; neither grants the signature-level authority `apps.clear`/`apps.set_enabled`
   would need.
9. **Screen capture.** `screen.snapshot` returns one real frame from a `MediaProjection` the
   user granted: `{png_base64, width, height, captured_at_ms}`. Consent is requested only from
   `SetupActivity` ("Enable screen capture", an explicit user action that opens the system
   dialog); the result is handed to the one service through `ACTION_GRANT_CAPTURE` and held for
   the service's lifetime. **Without consent the command is `error: consent_required` and no
   code path can prompt**: `ScreenHandler` refuses before touching the platform. Android cannot
   persist a projection token across process death, so after a restart the answer is
   `consent_required` again rather than a crash. One `VirtualDisplay` + `ImageReader` pair
   serves the whole grant, and its listener keeps the newest frame (so a capture of an unchanged
   screen returns that frame, with the `captured_at_ms` when it was produced, instead of waiting
   for a change that will never come). The pair **cannot** be re-created per frame: on Android
   14/15 a token may create one virtual display, and a second `createVirtualDisplay` logs
   `Reusing token: Throw exception due to invalid projection` and stops the projection (observed
   on the `pc35` emulator). A screen-size change (rotation, fold, resolution change) does **not**
   cost the user another grant: the display the token already owns is resized
   (`VirtualDisplay.resize`) and pointed at a fresh `ImageReader` of the new size
   (`VirtualDisplay.setSurface`), triggered by the platform's `onCapturedContentResize` callback
   and also checked against the current display metrics by every capture. The grant is retired
   with `consent_required` and a size-changed message only if the resize genuinely fails.
   Everything — the display, the readers, the cached frame, and the projection — is released on
   **every** stop path (user stop, service stop, system stop), on one process-wide teardown
   worker that `onDestroy` shuts down, never on the caller's thread, so nothing outlives the
   service and a stop during a capture cannot block the main thread. A capture waits for the
   first frame bounded by the command's remaining budget (and at most 5 s) and never runs on the
   command receive loop. The encoded frame is downscaled by whole factors
   until its base64 is under 2 MiB minus an envelope allowance, and `width`/`height` report the
   size actually captured; a frame that cannot get under the budget is `result_too_large`,
   never truncated.
10. **System properties and the two honest refusals.** `system.props` reports a documented
    allowlist read through `android.os.SystemProperties` reflection: `sdk`
    (`ro.build.version.sdk`), `release` (`ro.build.version.release`), `model`
    (`ro.product.model`), `manufacturer` (`ro.product.manufacturer`), `build_id`
    (`ro.build.id`), and `security_patch` (`ro.build.version.security_patch`). `{}` returns the
    whole map; `{keys:[...]}` selects a subset; a name outside the allowlist is
    `not_permitted` (and is never read); a reflection failure is `props_unavailable`. A
    property the platform does not report is `null`, never an invented value. `shell.exec` and
    `logcat.tail` always answer `not_permitted` with a constant message naming the platform
    restriction: a shell needs the ADB/root UID, and `READ_LOGS` is signature-level. They exist
    so a caller receives a machine code instead of `unknown_command`; the web console renders
    both as unavailable-with-reason, never as controls that fail silently.
11. **Device control.** `control.get` reports one reading per key: screen `brightness`, the
    `brightness_mode`, `volume_music` and its stream `volume_max`, `rotation` (the auto-rotate
    setting, 0 off / 1 on), the Do Not Disturb `dnd_filter`, `night_mode`, `wifi_enabled`,
    `bluetooth_enabled`, `mobile_data_enabled`, `battery_saver`, and `battery_percent`. A value
    the platform will not read is `null` — never a fabricated 0 — and `unavailable` maps the
    key to a constant machine reason (`platform_read_failed` for a throwing read or a setting
    the device does not keep, `no_bluetooth_adapter`, `no_telephony_data`,
    `battery_not_reported`). A read can never throw out of the handler and never becomes an
    `internal_error` carrying platform text.

    `control.set` changes three keys and refuses the rest. Every refusal is `not_permitted`
    with the reason as its message, and every reason is a stable token:

    | Key | Result |
    | --- | --- |
    | `brightness` (0–255) | real, through `Settings.System.SCREEN_BRIGHTNESS`, only with the user-granted `WRITE_SETTINGS`; otherwise `not_permitted` / `write_settings_required`. Automatic brightness is turned off first (the mode is written to `MANUAL`), because a stored value would not reach a display an ambient-light strategy governs; the answer reports the resulting `brightness_mode` and whether this call changed it (`mode_changed`) |
    | `volume_music` (0 to the reported `volume_max`) | real, `AudioManager.setStreamVolume` on `STREAM_MUSIC`; no permission. A change that would toggle Do Not Disturb is `not_permitted` / `policy_access_required` |
    | `dnd_filter` (1 All, 2 Priority, 3 None, 4 Alarms) | real, `NotificationManager.setInterruptionFilter`, only with notification-policy access; otherwise `not_permitted` / `policy_access_required` |
    | `wifi` | `not_permitted` / `wifi_setter_removed` — `WifiManager.setWifiEnabled` returns false for an app targeting Android 10+ |
    | `bluetooth` | `not_permitted` / `bluetooth_setter_removed` — `BluetoothAdapter.enable` is a no-op for an app targeting Android 13+ |
    | `mobile_data` | `not_permitted` / `mobile_data_setter_signature_gated` — `TelephonyManager.setDataEnabled` needs `MODIFY_PHONE_STATE` |
    | `night_mode` | `not_permitted` / `night_mode_setter_signature_gated` — `UiModeManager.setNightMode` needs `MODIFY_DAY_NIGHT_MODE` |
    | `rotation` | `not_permitted` / `rotation_requires_system_ui` — the rotation lock belongs to the system UI; an installed app has no setter for it |

    `control.reboot` is always `not_permitted` / `reboot_requires_privilege`: `REBOOT` is
    signature-level, and a device-owner build could add it later. It exists so a caller gets a
    machine code instead of `unknown_command`; there is no reboot path that cannot work.

    Values are validated before the platform is touched: a brightness outside 0–255, a volume
    outside 0 to the reported max, a filter outside 1–4, or a value of the wrong type is
    `invalid_args`; a key this build does not implement is `invalid_args` too. A key Android has
    no setter for is `not_permitted` whatever value it is given — the refusal is about the
    platform, not the value.

    **Automatic brightness is an explicit, reported side effect, not a silent no-op.** A
    `SCREEN_BRIGHTNESS` write only governs the display in manual mode, so when the mode is
    `AUTOMATIC` — or cannot be read, which is treated as automatic — the agent writes
    `SCREEN_BRIGHTNESS_MODE_MANUAL` first, then the brightness, and the answer carries
    `brightness_mode` and `mode_changed`. If the mode write does not stick, the answer is
    `not_applied` / `brightness_mode_automatic` and the brightness is not written at all: a
    value the display would ignore is never reported as applied.

    **A brightness change that fails puts the mode back.** Turning automatic off is a committed
    setting, so every failure after it — the write refused, the value did not stick, nothing
    could be read back, or the mode could not be confirmed manual — first restores the mode the
    call found and then answers. A failed change therefore leaves the device as the user left
    it. If the restore itself fails the reason says so, because the device is now manual and the
    caller must know: `brightness_not_applied_mode_left_manual`,
    `read_back_unavailable_mode_left_manual`, `write_settings_required_mode_left_manual`. Only a
    mode the call actually read is reported: an unreadable previous mode omits `mode_changed`
    rather than claiming a change that may not have happened, and a mode that cannot be read
    back after the write is `unconfirmed` / `read_back_unavailable`, never a fabricated
    `MANUAL`.

    A write is confirmed by reading the value back: if the settings provider accepted the
    brightness but the setting did not stick, the audio service accepted the volume but the
    stream reports another index, or the interruption filter did not change, the answer is
    `not_applied` (`brightness_not_applied`, `volume_not_applied`, `dnd_not_applied`), never
    `ok`. A write the platform accepted but would not let the app confirm — the read-back
    throws or is unavailable — is `unconfirmed` / `read_back_unavailable`, never `ok` either.
    A grant the user revokes mid-change is neither of those: `Settings.System.putInt` throws
    `SecurityException`, and the adapter rethrows it so the answer is `not_permitted` /
    `write_settings_required` (with the mode restored, or `_mode_left_manual` when it cannot
    be), because "you may not write this" is not the same answer as "the value did not stick".
    A volume whose stream max cannot be read is `platform_read_failed` with
    `volume_max_unreadable`. `control.get` names every refused key in `unavailable` — including
    `reboot` — so the web panel renders a disabled control with the reason as visible text.

    Both grants are given in Android's own settings, never by this app: the setup screen opens
    them and reports what Android says. `WRITE_SETTINGS` and `ACCESS_NOTIFICATION_POLICY` are
    declared for that; neither grants the signature-level authority Wi-Fi, Bluetooth, mobile
    data, night mode, rotation, or a reboot would need. Nothing here is a silent no-op, and
    there is still one foreground service and one notification: control reads and writes run
    inside the same service.

## Layout

| File | Responsibility |
| --- | --- |
| `SetupActivity.kt` | The only screen: hub URL, token, enrollment, notification permission, the screen-capture consent control, status and recovery. |
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
| `net/DeviceControlChannel.kt` | The management WebSocket: hello, telemetry, command results, bounded reconnect. |
| `control/CommandDispatcher.kt` | Routes command names to handlers; an unimplemented name is `unknown_command`. |
| `control/DeviceInfoHandler.kt` | `device.info` and the `hello` description, from `Build` only. |
| `control/PathGuard.kt` | The one root, and the only place a requested path becomes a concrete path. |
| `control/FileHandler.kt` | The six `files.*` commands: chunked reads, capped writes, empty-directory delete. |
| `control/AppsHandler.kt` | The five `apps.*` commands, the `AppPlatform` contract, and the honest refusals a non-privileged app must give. |
| `control/AndroidAppPlatform.kt` | The only `AppPlatform`: `PackageManager` inventory and launch intent, `ActivityManager` kill and background-start check. |
| `control/ScreenHandler.kt` | `screen.snapshot`: the `consent_required` refusal, the result budget, and the `ScreenCapture` contract. |
| `control/MediaProjectionScreenCapture.kt` | The only `ScreenCapture`: the consent token, one mirror per grant (resized on rotation), grant-scoped callbacks, and teardown on a worker for every stop path. |
| `control/ScreenMirror.kt` | The mirrored surface: `MediaProjection` + `VirtualDisplay` + `ImageReader`, the newest frame, PNG-safe copying at the frame's own size, and `resize`/`setSurface` for a new screen size. |
| `control/ScreenTeardown.kt` | The one process-wide worker every capture's teardown runs on, shut down by the service's `onDestroy`. |
| `control/SystemPropsHandler.kt` | `system.props`: the allowlist and the reflective `android.os.SystemProperties` reader. |
| `control/ShellHandler.kt` / `control/LogcatHandler.kt` | The two constant `not_permitted` refusals that name the platform restriction. |
| `control/ControlHandler.kt` | The three `control.*` commands, the `ControlPlatform` contract, the reading/reason vocabulary, and the validate-then-read-back rules. |
| `control/AndroidControlPlatform.kt` | The only `ControlPlatform`: the settings, audio, notification, UI-mode, Wi-Fi, Bluetooth, telephony, power, and battery services, with a constant reason for everything they refuse. |
| `telemetry/TelemetrySampler.kt` | Battery, memory, and connectivity mapped from the framework; unsupported metrics stay null. |
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

The service is `connectedDevice|mediaProjection` with `FOREGROUND_SERVICE_CONNECTED_DEVICE`,
`FOREGROUND_SERVICE_MEDIA_PROJECTION`, and `CHANGE_NETWORK_STATE`. `dataSync` is wrong for this
product on Android 15: it cannot be started from `BOOT_COMPLETED` and it is capped at six hours
per day. `onTimeout` stops the loop and removes the notification if the system still ends the
service, and a refused background start is recorded and shown on the setup screen instead of
crashing the receiver.

The `mediaProjection` type is added only when a projection is held: the service enters the
foreground with both types *before* it acquires the token, because Android 14+ requires the
mediaProjection type to be running when `getMediaProjection` is called. When the user stops
capture the type drops back to `connectedDevice`. It remains one service, one notification id,
and one channel; the extra type changes nothing the user sees.

## Invariants the tests hold

- **One notification.** `NotificationControllerTest` scans the module's own sources: every
  `startForeground` call site is in `ConnectionService`, one `notify` call site, only the
  single `NOTIFICATION_ID`, one declaration, and no notification APIs outside the controller.
  (The typed and untyped `startForeground` forms are API-gated branches of the one place.)
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
- **The capability matrix matches the code.** `CapabilityMatrixTest` compares
  `CommandDispatcher.COMMANDS`, the command constants in `CommandDispatcher.kt`, and the table
  in `../docs/capabilities.md`, and fails when they disagree in either direction — a command
  the code registers but the document omits, or a row the code does not implement. It also
  fails when a token in `CommandReasons.tokens` is not named in the table, so a new refusal
  reason cannot reach a caller without a place to look it up.

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
- **The management vocabulary is small.** `device.info`, `device.ping`, `telemetry.now`, the
  `files.*` commands, the `apps.*` commands, `screen.snapshot`, `system.props`, the
  `control.*` commands, and the five constant refusals (`apps.clear`, `apps.set_enabled`,
  `shell.exec`, `logcat.tail`, `control.reboot`) are implemented; another feature adds a handler
  file and a branch to the same dispatcher. `docs/capabilities.md` lists every one with its
  verification status. Device control changes three keys (brightness with `WRITE_SETTINGS`,
  music volume, and the Do Not Disturb filter with policy access) and refuses the rest; Wi-Fi,
  Bluetooth, mobile data, night mode, and the rotation lock stay with the system UI. File
  transfers stay inside the app's own external files directory: shared storage at large needs
  a scoped-storage design of its own and is not offered. CPU percentage is reported as `null`:
  Android does not expose per-app CPU counters to an ordinary app.
- **Screen capture is one frame, not a stream.** There is no mirroring, no continuous encoder,
  and no input injection. A capture needs the grant the user made from the setup screen; the
  grant does not survive a process restart, and the setup screen says so.
- **Instrumentation tests cannot run in this environment** (no AVD, no emulator system
  images), so the emulator smoke test and real-Keystore/OEM behaviour are unverified here.
