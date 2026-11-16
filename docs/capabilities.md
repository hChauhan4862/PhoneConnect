# Device command capabilities

This is the single table of commands the Android agent implements. It is written by hand from
`android/app/src/main/java/com/phoneconnect/agent/control/CommandDispatcher.kt` and the handler
each name routes to, and `CapabilityMatrixTest` (in the Android unit suite) fails when this
document and the code disagree in either direction: a command name or one of the stable tokens
in `CommandReasons.tokens` that the document omits, or a row the code does not implement. A
component README describes its own component; when it names a command, this table is the
authority on what that command can do.

Every command travels the management channel: the server forwards a name and arguments, the
device answers with exactly one result, and a result is `ok` only when the device produced it.
The server stores the answer in a bounded in-memory record and never invents one.

## How to read this table

- **Ordinary app can perform it** — whether a user-installed APK (`targetSdk` 35, `minSdk` 28,
  no device-owner provisioning, no root) can do the thing at all. "With …" means the operation
  is real but needs a grant the user gives in Android's own settings, which this app can only
  display and open.
- **Constant refusal** — the code and reason the device always answers with, for a command or
  key that cannot work in this app. A reason is a stable machine token or a fixed sentence; it
  never carries platform text or a device path.
- **Other device answers** — the codes the command can answer with for a bad argument, a bad
  request, or a platform fault. They are documented per command because they are part of its
  contract, not because they are refusals of the capability.
- **Verified** — `Emulator` means the command was exercised end to end on `emulator-5554`
  (Android 15 / API 35) through the server API, not only in tests. `Unit test` means JVM and
  Robolectric tests only. `None` means neither.

## Device (`device.*`)

Identity and liveness. `device.info` reads only platform-provided values; `telemetry.now` maps
the framework services and leaves a metric the platform will not report absent.

| Command | What it does | Ordinary app can perform it | Constant refusal | Other device answers | Verified |
| --- | --- | --- | --- | --- | --- |
| `device.info` | Reports `model`, `manufacturer`, `android_version`, and `sdk` from `Build`. | Yes | — | — | Emulator |
| `device.ping` | Answers `{pong: true, at_ms}` from the device clock. | Yes | — | — | Unit test |
| `telemetry.now` | One sample: battery percent and charging, memory used and total, the active network transport. `cpu_percent` is never present. | Yes | — | — | Emulator |

`telemetry.now` has no CPU reading because Android does not expose per-app CPU counters to an
ordinary app; the field is omitted rather than reported as zero.

## Files (`files.*`)

All six commands operate inside one root — the app's own external files directory, removed with
the app — and every requested path is resolved and checked (`..`, absolute paths, NUL, and
symlinks leaving the root are refused) before the filesystem is touched. A path in an answer is
relative to that root, never an absolute device path.

| Command | What it does | Ordinary app can perform it | Constant refusal | Other device answers | Verified |
| --- | --- | --- | --- | --- | --- |
| `files.list` | Lists one directory, sorted by name, with `name`, root-relative `path`, `is_dir`, `size_bytes` (0 for a directory), and `modified_ms`. Refused as `listing_too_large` past 4 096 entries or ~1 MB encoded instead of being truncated. | Yes | — | `not_found`, `not_a_directory`, `path_outside_root`, `invalid_path`, `invalid_args`, `listing_too_large`, `io_error` | Emulator (`listing_too_large` and `io_error` unit only) |
| `files.read` | Returns one chunk of at most 256 KiB decoded bytes with `truncated` when more remains; `offset` and `length` are optional. | Yes | — | `not_found`, `not_a_file`, `path_outside_root`, `invalid_path`, `invalid_args`, `io_error` | Emulator |
| `files.write` | Writes or appends up to 1 MiB decoded bytes and answers `bytes_written`. | Yes | — | `too_large`, `is_directory`, `not_found` (parent), `path_outside_root`, `invalid_path`, `invalid_args`, `io_error` | Emulator (the 1 MiB cap was refused by the server as `413` before dispatch, so the device's own `too_large` and `append` are unit only) |
| `files.mkdir` | Creates one directory; never recursive. | Yes | — | `already_exists`, `not_found` (parent), `path_outside_root`, `invalid_path`, `invalid_args`, `io_error` | Emulator |
| `files.delete` | Deletes a file or an *empty* directory; never recursive. | Yes | — | `dir_not_empty`, `not_found`, `path_outside_root`, `invalid_path`, `invalid_args`, `io_error` | Emulator |
| `files.rename` | Moves `from` to `to` and never replaces an existing destination. | Yes | — | `already_exists`, `not_found`, `path_outside_root`, `invalid_path`, `invalid_args`, `io_error` | Emulator |

An escaping symlink cannot be created through ADB under scoped storage, so that refusal is
proven by `PathGuardTest` on a real filesystem rather than by the emulator.

## Apps (`apps.*`)

The inventory is what `PackageManager` reports for this app's UID; `QUERY_ALL_PACKAGES` is
declared so that list is complete rather than silently filtered. Every acting command resolves
`package` against that inventory first, so an unknown name is `unknown_package` and never a
platform exception string.

| Command | What it does | Ordinary app can perform it | Constant refusal | Other device answers | Verified |
| --- | --- | --- | --- | --- | --- |
| `apps.list` | Lists visible packages with `package`, `label` (the package name when the platform cannot resolve a label), `version_name`, `version_code`, `system`, `enabled`, and `updated_ms`, sorted by label. Refused as `listing_too_large` past 2 000 apps or ~1 MB encoded. | Yes | — | `listing_too_large` | Emulator (`listing_too_large` unit only) |
| `apps.launch` | Starts the package's own launch intent and answers `{launched: true}` when the platform accepted the start. Android offers no callback proving the activity became visible, and the answer does not claim it did. | Yes, when the platform permits a background activity start | `launch_blocked` when Android restricts the start (`background_activity_start_restricted`) or refuses it (`platform_refused`); `no_launch_activity` when the package has no launchable activity | `unknown_package`, `invalid_args` | Emulator (allowed with a visible activity, blocked with the agent backgrounded) |
| `apps.stop` | Calls `ActivityManager.killBackgroundProcesses` and answers `kill_requested: true`. This is a request; Android never confirms the process died. | Yes, as a request only | `not_permitted` — "Android refused to kill background processes; the KILL_BACKGROUND_PROCESSES permission is not granted" | `unknown_package`, `invalid_args` | Emulator (`kill_requested`); the refusal is unit only |
| `apps.clear` | Validates the package, then always refuses. Clearing app data needs a signature-level permission an installed app cannot hold. | No | `not_permitted` — "clearing app data needs a signature-level permission an installed app cannot hold; use the ADB path: adb shell pm clear <package>" | `unknown_package`, `invalid_args` | Emulator (constant refusal) |
| `apps.set_enabled` | Validates the package and the boolean, then always refuses. Enabling or disabling a package needs `CHANGE_COMPONENT_ENABLED_STATE`, a signature-level permission. | No | `not_permitted` — "enabling or disabling a package needs a signature-level permission an installed app cannot hold; use the ADB path: adb shell pm disable-user --user 0 <package>" | `unknown_package`, `invalid_args` | Emulator (constant refusal) |

## Screen (`screen.snapshot`)

| Command | What it does | Ordinary app can perform it | Constant refusal | Other device answers | Verified |
| --- | --- | --- | --- | --- | --- |
| `screen.snapshot` | Returns one PNG frame — `{png_base64, width, height, captured_at_ms}` — from a `MediaProjection` the user granted on the device's setup screen. A static screen answers with the newest buffered frame and its original timestamp. The frame is downscaled until its base64 fits the result budget. | Yes, only with the user's `MediaProjection` consent | `consent_required` — "screen capture needs the user's consent, granted from the PhoneConnect setup screen on the device; no projection is held" | `capture_timeout`, `capture_failed`, `result_too_large` | Emulator (consent refused and real 1080×2400 frames after consent) |

There is no mirroring and no input injection: this is one frame per command, and the command can
never raise the consent dialog. The grant does not survive process death, so after a restart the
answer is `consent_required` again.

## System and console

| Command | What it does | Ordinary app can perform it | Constant refusal | Other device answers | Verified |
| --- | --- | --- | --- | --- | --- |
| `system.props` | Reports the six allowlisted properties (`sdk`, `release`, `model`, `manufacturer`, `build_id`, `security_patch`) read through `android.os.SystemProperties`; `{}` returns all of them, `{keys:[…]}` a subset. A property the platform does not report is `null`. | Yes | `not_permitted` (a requested name outside the allowlist is refused before anything is read) — "only the documented system properties may be read: sdk, release, model, manufacturer, build_id, security_patch"; `props_unavailable` when this build does not expose the property reader through reflection | `invalid_args` | Emulator |
| `shell.exec` | Always refuses. A shell needs the ADB shell UID or root; an ordinary installed app is neither. | No | `not_permitted` — "an ordinary installed app cannot run a shell: executing commands on the device needs the privileged shell (ADB) or root user, which this app is not" | — | Emulator (constant refusal) |
| `logcat.tail` | Always refuses. The system log is protected by `READ_LOGS`, a signature-level permission. | No | `not_permitted` — "an ordinary installed app cannot read the system log: READ_LOGS is a signature-level permission, so only a system or privileged app can read logcat" | — | Emulator (constant refusal) |

`shell.exec` and `logcat.tail` exist so a caller receives a machine code and a reason instead of
`unknown_command`. They have no code path that could produce output.

## Device control (`control.*`)

| Command | What it does | Ordinary app can perform it | Constant refusal | Other device answers | Verified |
| --- | --- | --- | --- | --- | --- |
| `control.get` | Reports one reading per key: `brightness`, `brightness_mode`, `volume_music`, `volume_max`, `rotation` (the auto-rotate setting), `dnd_filter`, `night_mode`, `wifi_enabled`, `bluetooth_enabled`, `mobile_data_enabled`, `battery_saver`, `battery_percent`. A reading the platform will not produce is `null` with a reason in `unavailable`; the read never throws. | Yes | — | `unavailable` carries a reason per key: `platform_read_failed`, `no_bluetooth_adapter`, `no_telephony_data`, `battery_not_reported`, the change refusals listed under `control.set`, and `reboot` → `reboot_requires_privilege` | Emulator |
| `control.set` | Changes `brightness` (0–255), `volume_music` (0 to the reported `volume_max`), and `dnd_filter` (1 All, 2 Priority, 3 None, 4 Alarms), and confirms each by reading the value back. `brightness` needs the user-granted `WRITE_SETTINGS` and turns automatic brightness off first, reporting `brightness_mode` and `mode_changed`; a change that then fails puts the mode it read back, and when it cannot — the restore fails, or the previous mode was never readable — the device is left in manual brightness and the reason says so. `volume_music` needs nothing beyond the platform's own Do Not Disturb rule; `dnd_filter` needs notification-policy access. | Yes for those three keys, with the grants named above. No for `wifi`, `bluetooth`, `mobile_data`, `night_mode`, `rotation` | `not_permitted` with the reason token `write_settings_required` (brightness without the grant), `write_settings_required_mode_left_manual` (a grant revoked mid-change whose automatic mode could not be restored), `policy_access_required` (Do Not Disturb without access, or a volume change that would toggle it), `wifi_setter_removed`, `bluetooth_setter_removed`, `mobile_data_setter_signature_gated`, `night_mode_setter_signature_gated`, `rotation_requires_system_ui` | `invalid_args`, `not_applied` (`brightness_not_applied`, `brightness_not_applied_mode_left_manual`, `brightness_mode_automatic`, `volume_not_applied`, `dnd_not_applied`), `unconfirmed` (`read_back_unavailable`, `read_back_unavailable_mode_left_manual`), `platform_read_failed` (`volume_max_unreadable`) | Emulator (the three changes, every refusal, and the automatic-to-manual brightness switch; `not_applied`, `unconfirmed`, and their `*_mode_left_manual` variants are unit only, and the emulator has no light sensor to reproduce the silent automatic-brightness no-op) |
| `control.reboot` | Always refuses. `REBOOT` is signature-level; only a system or device-owner build could reboot. | No | `not_permitted` — `reboot_requires_privilege` | — | Emulator (constant refusal) |

The five controls with no app-facing setter (`wifi`, `bluetooth`, `mobile_data`, `night_mode`,
`rotation`) and `reboot` are listed in `control.get`'s `unavailable` map as well, so a control
surface can render them disabled with the device's own reason instead of a button that would
fail.

## Answers that are not commands

These come from the channel or the dispatcher rather than from a handler, and they apply to every
command:

| Code | Meaning |
| --- | --- |
| `unknown_command` | The name is not in this table. The message is "this agent does not implement '<name>'". |
| `invalid_args` | `args` was present but not a JSON object, or a handler rejected an argument. |
| `timeout` | The command was queued past the server's absolute deadline and was not executed, or it did not finish inside the remaining budget. |
| `internal_error` | A handler failed in a way it does not model; the channel reports it rather than dropping the command. |

The server's own refusals — `device_offline`, `device_revoked`, `lease_read_only`,
`command_capacity`, and `invalid_request` — never reach the device; `server/README.md` documents
them.

Everything a command does not do here is not implemented: there is no mirroring, no input
injection, no audio capture or recording, no calls/SMS/notification history, no agent OTA, no
accounts, no Android TCP proxy bridge, and no direct hole-punched path on Android. The root
`README.md` lists those gaps.

## Setup-screen actions (not commands)

These are things the *user* does on the device's own setup screen. They are not device
commands, so they are not in the table above; they exist because the corresponding command is
otherwise unreachable.

| Action | What it does | Why it is a user action | Verified |
| --- | --- | --- | --- |
| Allow notifications | Requests `POST_NOTIFICATIONS` so the one connection notification is visible on Android 13+ | Android only lets the app ask with a system dialog, and a hidden notification would make the foreground service invisible | Emulator (dialog shown and accepted) |
| Enable screen capture | Opens `MediaProjectionManager.createScreenCaptureIntent` and hands the grant to the service | Screen capture requires explicit per-grant consent; no command may prompt, so `screen.snapshot` answers `consent_required` until this is done | Emulator (consent → four real captures → stop → `consent_required`) |
| Stop screen capture | Ends the projection and drops the `mediaProjection` service type | Same consent rule, in reverse | Emulator |
| Allow brightness changes | Opens `ACTION_MANAGE_WRITE_SETTINGS` for this package | `WRITE_SETTINGS` is user-granted; without it `control.set brightness` is `not_permitted: write_settings_required` | Emulator (grant → brightness 102→200) |
| Allow Do Not Disturb changes | Opens `ACTION_NOTIFICATION_POLICY_ACCESS_SETTINGS` | Notification-policy access is user-granted; without it `control.set dnd_filter` is `not_permitted: policy_access_required` | Emulator (`zen_mode` 0→2) |
| Allow running in the background | Opens the battery-optimisation exemption screen scoped to this package, after asking the package manager whether that dialog resolves on this build; falls back to the settings list when it does not | The exemption is a request the user can refuse. Android and OEM battery managers may still stop the service, so the screen reports "exempt", "may still stop this app", or "did not say" and never promises it cannot be stopped | Robolectric (both screens, all three status texts); no physical device |
