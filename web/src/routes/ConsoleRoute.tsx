/// The console page: the properties an ordinary app can read, and the two capabilities it
/// cannot have.
///
/// `system.props` reports a documented allowlist through the platform's own property reader.
/// Shell access needs the ADB/root UID and the system log needs the signature-level
/// `READ_LOGS` permission, so those commands always answer `not_permitted`; they are rendered
/// here as disabled controls with the device's own reason, never as buttons that would fail
/// silently.
///
/// The property list is cleared the moment a reload starts and an abandoned answer is dropped:
/// a failure never leaves an older list looking current.

import { useCallback, useEffect, useRef, useState } from "react";

import type { ApiClient, CommandAccepted } from "../api";
import { FailureNotice } from "../components/FailureNotice";
import { RouteLink } from "../components/RouteLink";
import { pollCommand } from "../data/commands";
import {
  failureOfCommand,
  failureOfError,
  outcomeOf,
  unknownOutcome,
  type FailureOutcome,
} from "../data/failures";
import { devicePath } from "../routing";

/// The device's own constant refusals, so the disabled controls and the command cannot drift.
export const SHELL_UNAVAILABLE =
  "an ordinary installed app cannot run a shell: executing commands on the device needs " +
  "the privileged shell (ADB) or root user, which this app is not";

export const LOGCAT_UNAVAILABLE =
  "an ordinary installed app cannot read the system log: READ_LOGS is a signature-level " +
  "permission, so only a system or privileged app can read logcat";

export interface ConsoleRouteProps {
  api: ApiClient;
  deviceId: string;
  userId: string;
  /// Poll interval; tests shorten it.
  pollIntervalMs?: number;
}

export function ConsoleRoute({ api, deviceId, userId, pollIntervalMs }: ConsoleRouteProps) {
  const [selected, setSelected] = useState<Record<string, string | null> | null>(null);
  const [failure, setFailure] = useState<FailureOutcome | null>(null);
  const [loading, setLoading] = useState(true);
  const [reloadNonce, setReloadNonce] = useState(0);

  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  useEffect(() => {
    let cancelled = false;
    setSelected(null);
    setFailure(null);
    setLoading(true);
    (async () => {
      let accepted: CommandAccepted;
      try {
        accepted = await api.systemProperties(deviceId, userId);
      } catch (error) {
        // Nothing was dispatched: this read really was refused.
        if (!cancelled) {
          setFailure(outcomeOf(failureOfError(error), false));
          setLoading(false);
        }
        return;
      }
      try {
        const command = await pollCommand(api, userId, accepted.command_id, {
          pollIntervalMs,
          isActive: () => !cancelled,
        });
        if (cancelled) return;
        if (command.status !== "ok") {
          // Accepted, so a code that is not the device's answer leaves the read unknown.
          setFailure(outcomeOf(failureOfCommand(command), true));
          return;
        }
        const properties = readSelected(command.output);
        if (!properties) {
          // The device answered `ok`, so it read something; its answer just cannot be read.
          setFailure(
            unknownOutcome({
              code: "invalid_result",
              message: "the device's answer is not a property map",
            }),
          );
          return;
        }
        setSelected(properties);
      } catch (error) {
        // Accepted, then the poll failed: the answer was lost, never refused.
        if (!cancelled) setFailure(unknownOutcome(failureOfError(error)));
      } finally {
        if (!cancelled) setLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api, deviceId, userId, pollIntervalMs, reloadNonce]);

  const reload = useCallback(() => setReloadNonce((value) => value + 1), []);

  return (
    <>
      <nav>
        <RouteLink to={devicePath(deviceId)}>Back to status</RouteLink>
      </nav>
      <h1>Console</h1>
      <p className="muted">
        An ordinary installed app has no shell and cannot read the system log. The properties
        below are the documented allowlist it can read through the platform&apos;s own reader.
      </p>

      <section className="panel" aria-labelledby="props-heading">
        <h2 id="props-heading">System properties</h2>
        <div className="actions">
          <button type="button" disabled={loading} onClick={reload}>
            Refresh
          </button>
        </div>

        {failure ? (
          <FailureNotice failure={failure.failure} lead={failure.lead} />
        ) : null}
        {loading && !failure ? <p>Loading system properties…</p> : null}
        {!loading && !failure && selected && Object.keys(selected).length === 0 ? (
          <p>The device reported no system properties.</p>
        ) : null}
        {!failure && selected && Object.keys(selected).length > 0 ? (
          <dl className="property-list" aria-label="System properties">
            {Object.entries(selected).map(([key, value]) => (
              <div key={key}>
                <dt>{key}</dt>
                <dd>{value === null ? "not reported" : value}</dd>
              </div>
            ))}
          </dl>
        ) : null}
      </section>

      <section className="panel" aria-labelledby="unavailable-heading">
        <h2 id="unavailable-heading">Not available to an installed app</h2>
        <p>
          Both commands exist so a caller receives <code>not_permitted</code> with the platform
          reason. They are shown disabled, never as controls that fail silently.
        </p>
        <div className="actions">
          <button type="button" disabled title={SHELL_UNAVAILABLE}>
            Run shell command
          </button>
          <button type="button" disabled title={LOGCAT_UNAVAILABLE}>
            Read logcat
          </button>
        </div>
        <ul>
          <li>{SHELL_UNAVAILABLE}</li>
          <li>{LOGCAT_UNAVAILABLE}</li>
        </ul>
      </section>
    </>
  );
}

/// `null` when the output is not a map of property names to strings or explicit nulls.
function readSelected(output: unknown): Record<string, string | null> | null {
  if (typeof output !== "object" || output === null) return null;
  const selected = (output as { selected?: unknown }).selected;
  if (typeof selected !== "object" || selected === null || Array.isArray(selected)) {
    return null;
  }
  const properties: Record<string, string | null> = {};
  for (const [key, value] of Object.entries(selected as Record<string, unknown>)) {
    if (value !== null && typeof value !== "string") return null;
    properties[key] = value;
  }
  return properties;
}
