/// One package's row, and the three actions an ordinary app can attempt.
///
/// Purely presentational: the route owns every command, and this list never invents an app it
/// was not given. `apps.clear` and `apps.set_enabled` need signature-level permissions an
/// installed app cannot hold, so those controls render disabled with the reason and the ADB
/// path — never as buttons that would fail silently.

import type { AppEntryView } from "../api";
import { formatTime } from "../format";

/// The reasons the device itself answers with. The disabled controls state the same thing, so
/// the UI and the command cannot drift.
export const CLEAR_UNAVAILABLE =
  "clearing app data needs a signature-level permission an installed app cannot hold; " +
  "use the ADB path: adb shell pm clear <package>";

export const SET_ENABLED_UNAVAILABLE =
  "enabling or disabling a package needs a signature-level permission an installed app " +
  "cannot hold; use the ADB path: adb shell pm disable-user --user 0 <package>";

export interface AppListProps {
  apps: AppEntryView[];
  /// True while one action is in flight: every action is disabled, so one click cannot become
  /// two commands.
  busy: boolean;
  onLaunch(app: AppEntryView): void;
  onStop(app: AppEntryView): void;
}

export function AppList({ apps, busy, onLaunch, onStop }: AppListProps) {
  return (
    <>
      <p className="muted">
        Clear data and enable/disable need a signature-level permission an installed app cannot
        hold; use ADB (<code>adb shell pm clear</code>,{" "}
        <code>adb shell pm disable-user</code>). Those actions are shown disabled.
      </p>
      <ul className="app-list" aria-label="Installed apps">
        {apps.map((app) => (
          <li key={app.package} className="app-entry">
            <span>{app.label}</span>
            <code>{app.package}</code>
            <span className="muted">{versionOf(app)}</span>
            <span className="muted">{app.system ? "system" : "user"}</span>
            <span className="muted">{app.enabled ? "enabled" : "disabled"}</span>
            <span className="muted">{formatTime(app.updated_ms)}</span>
            <button type="button" disabled={busy} onClick={() => onLaunch(app)}>
              Launch {app.label}
            </button>
            <button type="button" disabled={busy} onClick={() => onStop(app)}>
              Stop {app.label}
            </button>
            <button type="button" disabled title={CLEAR_UNAVAILABLE}>
              Clear data {app.label}
            </button>
            <button type="button" disabled title={SET_ENABLED_UNAVAILABLE}>
              {app.enabled ? "Disable" : "Enable"} {app.label}
            </button>
          </li>
        ))}
      </ul>
    </>
  );
}

function versionOf(app: AppEntryView): string {
  const name = app.version_name === null ? "version not reported" : app.version_name;
  return `${name} (code ${app.version_code})`;
}
