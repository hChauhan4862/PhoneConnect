/// The device control panel: every reading the device can produce, the three changes an
/// ordinary installed app can make, and the constant reason for everything Android removed or
/// made signature-level.
///
/// The panel is a view of the device's own answer, never a second opinion. A key the device
/// names in `unavailable` is rendered as a disabled control with the reason as visible text —
/// not a tooltip only, and not a button that would always fail. A change is reported as
/// confirmed only after the device answers `ok`, and a confirmed change re-reads `control.get`
/// instead of assuming the value took.

import { useCallback, useEffect, useRef, useState } from "react";

import type {
  ApiClient,
  CommandView,
  ControlReadingsOutput,
  ControlSetOutput,
  ControlValue,
} from "../api";
import { pollCommand } from "../data/commands";
import { REASON_TEXT, reasonText } from "../data/controlReasons";
import { failureOfCommand, failureOfError, type Failure } from "../data/failures";
import { FailureNotice } from "./FailureNotice";

type ReadingKey = Exclude<keyof ControlReadingsOutput, "unavailable">;

/// Every reading, in the order the command reports it.
const READING_FIELDS: { key: ReadingKey; label: string }[] = [
  { key: "brightness", label: "Screen brightness" },
  { key: "brightness_mode", label: "Brightness mode (0 manual, 1 automatic)" },
  { key: "volume_music", label: "Music volume" },
  { key: "volume_max", label: "Music volume max" },
  { key: "rotation", label: "Auto-rotate (0 off, 1 on)" },
  { key: "dnd_filter", label: "Do Not Disturb filter" },
  { key: "night_mode", label: "Night mode" },
  { key: "wifi_enabled", label: "Wi-Fi" },
  { key: "bluetooth_enabled", label: "Bluetooth" },
  { key: "mobile_data_enabled", label: "Mobile data" },
  { key: "battery_saver", label: "Battery saver" },
  { key: "battery_percent", label: "Battery percent" },
];

/// The changes Android has no app-facing setter for. Each is a disabled control whose reason
/// comes from the device; the fallback keeps the reason visible for an older device build.
const REFUSED_CHANGES: { key: string; label: string; fallback: string }[] = [
  { key: "wifi", label: "Wi-Fi", fallback: "wifi_setter_removed" },
  { key: "bluetooth", label: "Bluetooth", fallback: "bluetooth_setter_removed" },
  { key: "mobile_data", label: "Mobile data", fallback: "mobile_data_setter_signature_gated" },
  { key: "night_mode", label: "Night mode", fallback: "night_mode_setter_signature_gated" },
  { key: "rotation", label: "Rotation", fallback: "rotation_requires_system_ui" },
];

const DND_OPTIONS = [
  { value: "1", label: "All interruptions" },
  { value: "2", label: "Priority only" },
  { value: "3", label: "No interruptions" },
  { value: "4", label: "Alarms only" },
];

export interface ControlPanelProps {
  api: ApiClient;
  deviceId: string;
  userId: string;
  /// Poll interval; tests shorten it.
  pollIntervalMs?: number;
}

export function ControlPanel({ api, deviceId, userId, pollIntervalMs }: ControlPanelProps) {
  const [readings, setReadings] = useState<ControlReadingsOutput | null>(null);
  const [readFailure, setReadFailure] = useState<Failure | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloadNonce, setReloadNonce] = useState(0);

  const [busy, setBusy] = useState(false);
  const [actionFailure, setActionFailure] = useState<Failure | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [brightness, setBrightness] = useState("");
  const [volume, setVolume] = useState("");
  const [dnd, setDnd] = useState("");

  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  /// Reads `control.get`. A non-`ok` answer or a malformed map is a failure with no readings:
  /// the panel never keeps an older map looking current or invents one.
  const read = useCallback(
    async (isActive: () => boolean): Promise<ControlReadingsOutput | null> => {
      try {
        const accepted = await api.controlReadings(deviceId, userId);
        const command = await pollCommand(api, userId, accepted.command_id, {
          pollIntervalMs,
          isActive,
        });
        if (!isActive()) return null;
        if (command.status !== "ok") {
          // A failed read leaves no map at all: the previous one is not the device's current
          // answer, so it must not keep looking current.
          setReadings(null);
          setReadFailure(failureOfCommand(command));
          return null;
        }
        const parsed = readReadings(command.output);
        if (!parsed) {
          setReadings(null);
          setReadFailure({
            code: "invalid_result",
            message: "the device's answer is not a control reading map",
          });
          return null;
        }
        setReadings(parsed);
        setReadFailure(null);
        return parsed;
      } catch (error) {
        if (isActive()) {
          setReadings(null);
          setReadFailure(failureOfError(error));
        }
        return null;
      }
    },
    [api, deviceId, userId, pollIntervalMs],
  );

  useEffect(() => {
    let cancelled = false;
    setReadings(null);
    setReadFailure(null);
    setLoading(true);
    void read(() => !cancelled).finally(() => {
      if (!cancelled) setLoading(false);
    });
    return () => {
      cancelled = true;
    };
  }, [read, reloadNonce]);

  /// Sends one change and waits for the device's own answer. Only `ok` may put a confirmation
  /// on the screen; then the whole map is re-read rather than patched with the value sent.
  async function apply(key: string, value: ControlValue, label: string): Promise<void> {
    setBusy(true);
    setActionFailure(null);
    setNotice(null);
    try {
      const accepted = await api.setControl(deviceId, userId, key, value);
      const command = await pollCommand(api, userId, accepted.command_id, {
        pollIntervalMs,
        isActive: () => mounted.current,
      });
      if (!mounted.current) return;
      if (command.status !== "ok") {
        const failure = actionFailureOf(command);
        setActionFailure(failure);
        // Anything that may have reached the device must not leave the previous map looking
        // current: `unconfirmed` means the value may have moved either way, and a brightness
        // change turns automatic mode off before it can fail.
        if (failure.code === "unconfirmed" || key === "brightness") {
          await read(() => mounted.current);
        }
        return;
      }
      const result = readApplied(command.output);
      if (!result) {
        setActionFailure({
          code: "invalid_result",
          message: "the device's answer does not confirm the change",
        });
        return;
      }
      setNotice(noticeFor(label, key, result));
      await read(() => mounted.current);
    } catch (error) {
      if (mounted.current) setActionFailure(failureOfError(error));
    } finally {
      if (mounted.current) setBusy(false);
    }
  }

  const refused = (key: string): string | null => readings?.unavailable[key] ?? null;
  const volumeMax = readings?.volume_max ?? null;

  return (
    <section className="panel" aria-labelledby="control-heading">
      <h2 id="control-heading">Device control</h2>
      <p className="muted">
        These are the readings this device can produce and the changes an ordinary installed app
        can make. Android removed or signature-gated the rest, so those controls are shown
        disabled with the device&apos;s reason.
      </p>

      <div className="actions">
        <button type="button" disabled={loading || busy} onClick={() => setReloadNonce((n) => n + 1)}>
          Refresh controls
        </button>
      </div>

      {readFailure ? <FailureNotice failure={readFailure} /> : null}
      {loading && !readFailure ? <p>Loading device control…</p> : null}
      {!readFailure && readings ? (
        <ul className="control-readings" aria-label="Control readings">
          {READING_FIELDS.map(({ key, label }) => {
            const value = readings[key];
            return (
              <li key={key} className="control-reading">
                <span>{label}</span>
                <span>
                  {value === null
                    ? reasonText(readings.unavailable[key] ?? "not_reported")
                    : formatReading(value)}
                </span>
              </li>
            );
          })}
        </ul>
      ) : null}

      {actionFailure ? (
        <FailureNotice failure={actionFailure} note={failureNote(actionFailure)} />
      ) : null}
      {notice ? (
        <p role="status" className="notice">
          {notice}
        </p>
      ) : null}

      {readings ? (
        <>
          <h3>Changes</h3>
          <div className="actions">
            <label htmlFor="control-brightness">Brightness value (0–255)</label>
            <input
              id="control-brightness"
              type="number"
              min={0}
              max={255}
              value={brightness}
              disabled={busy || refused("brightness") !== null}
              onChange={(event) => setBrightness(event.target.value)}
            />
            <button
              type="button"
              disabled={busy || brightness === "" || refused("brightness") !== null}
              onClick={() => void apply("brightness", Number(brightness), "screen brightness")}
            >
              Set brightness
            </button>
          </div>
          {refused("brightness") ? (
            <p className="muted">{reasonText(refused("brightness") ?? "")}</p>
          ) : (
            <p className="muted">
              Setting brightness turns automatic brightness off first, because a value written
              under an ambient-light strategy would not reach the display; the device&apos;s
              answer reports the mode it now runs under.
            </p>
          )}

          <div className="actions">
            <label htmlFor="control-volume">Music volume</label>
            <input
              id="control-volume"
              type="number"
              min={0}
              max={volumeMax ?? undefined}
              value={volume}
              disabled={busy || refused("volume_music") !== null}
              onChange={(event) => setVolume(event.target.value)}
            />
            <button
              type="button"
              disabled={busy || volume === "" || refused("volume_music") !== null}
              onClick={() => void apply("volume_music", Number(volume), "music volume")}
            >
              Set music volume
            </button>
            <span className="muted">
              {volumeMax === null ? "range not reported" : `0 to ${volumeMax}`}
            </span>
          </div>

          <div className="actions">
            <label htmlFor="control-dnd">Do Not Disturb filter</label>
            <select
              id="control-dnd"
              value={dnd}
              disabled={busy || refused("dnd_filter") !== null}
              onChange={(event) => setDnd(event.target.value)}
            >
              <option value="">Choose a filter</option>
              {DND_OPTIONS.map((option) => (
                <option key={option.value} value={option.value}>
                  {option.label}
                </option>
              ))}
            </select>
            <button
              type="button"
              disabled={busy || dnd === "" || refused("dnd_filter") !== null}
              onClick={() => void apply("dnd_filter", Number(dnd), "Do Not Disturb")}
            >
              Set Do Not Disturb
            </button>
          </div>
          {refused("dnd_filter") ? (
            <p className="muted">{reasonText(refused("dnd_filter") ?? "")}</p>
          ) : null}

          <h3>Unavailable changes</h3>
          <ul className="control-refusals" aria-label="Unavailable changes">
            {REFUSED_CHANGES.map(({ key, label, fallback }) => {
              const reason = refused(key) ?? fallback;
              return (
                <li key={key}>
                  <button type="button" disabled>
                    {label}
                  </button>{" "}
                  <span className="muted">{reasonText(reason)}</span>
                </li>
              );
            })}
            <li>
              <button type="button" disabled>
                Reboot device
              </button>{" "}
              <span className="muted">
                {reasonText(refused("reboot") ?? "reboot_requires_privilege")}
              </span>
            </li>
          </ul>
        </>
      ) : null}
    </section>
  );
}

function formatReading(value: number | boolean): string {
  if (typeof value === "boolean") return value ? "on" : "off";
  return String(value);
}

/// `null` when the output is not the reading map the device promises.
function readReadings(output: unknown): ControlReadingsOutput | null {
  if (typeof output !== "object" || output === null) return null;
  const value = output as Record<string, unknown>;
  const unavailable = value.unavailable;
  if (typeof unavailable !== "object" || unavailable === null || Array.isArray(unavailable)) {
    return null;
  }
  const reasons: Record<string, string> = {};
  for (const [key, reason] of Object.entries(unavailable as Record<string, unknown>)) {
    if (typeof reason !== "string") return null;
    reasons[key] = reason;
  }
  for (const { key } of READING_FIELDS) {
    const reading = value[key];
    if (reading === null) continue;
    const expected = key === "wifi_enabled" ||
      key === "bluetooth_enabled" ||
      key === "mobile_data_enabled" ||
      key === "battery_saver"
      ? "boolean"
      : "number";
    if (typeof reading !== expected) return null;
  }
  return { ...(value as unknown as ControlReadingsOutput), unavailable: reasons };
}

function readApplied(output: unknown): ControlSetOutput | null {
  if (typeof output !== "object" || output === null) return null;
  const value = output as Record<string, unknown>;
  if (typeof value.key !== "string") return null;
  if (value.applied !== true) return null;
  const applied = value.value;
  if (typeof applied !== "number" && typeof applied !== "boolean") return null;
  const mode = value.brightness_mode;
  if (mode !== undefined && typeof mode !== "number") return null;
  const changed = value.mode_changed;
  if (changed !== undefined && typeof changed !== "boolean") return null;
  return {
    key: value.key,
    value: applied,
    applied: true,
    brightness_mode: mode,
    mode_changed: changed,
  };
}

/// A machine reason in the device's message is rendered as the sentence the operator needs; the
/// code stays the machine identity the caller acts on.
function actionFailureOf(command: CommandView): Failure {
  const failure = failureOfCommand(command);
  const message = failure.message;
  return {
    code: failure.code,
    message: message !== null && REASON_TEXT[message] !== undefined ? reasonText(message) : message,
  };
}

/// The one code whose meaning needs a sentence of its own: the change was accepted but nothing
/// confirmed it.
const UNCONFIRMED_NOTE =
  "the device accepted the change but could not confirm it, so the panel does not treat it as applied";

function failureNote(failure: Failure): string | undefined {
  return failure.code === "unconfirmed" ? UNCONFIRMED_NOTE : undefined;
}

/// The confirmation never claims more than the answer did: a brightness change that turned
/// automatic mode off says so.
function noticeFor(label: string, key: string, result: ControlSetOutput): string {
  if (key === "brightness" && result.mode_changed === true) {
    return `The device confirmed the ${label} change and turned automatic brightness off so it holds.`;
  }
  return `The device confirmed the ${label} change.`;
}
