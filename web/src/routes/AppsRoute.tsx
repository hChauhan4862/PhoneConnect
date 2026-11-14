/// The app screen: the device's own inventory, and the actions an ordinary app can attempt.
///
/// The list never fabricates or recycles an answer. It is cleared the moment a reload starts,
/// an abandoned query's late answer is dropped, a refusal is an alert carrying its machine
/// code, and a success whose output is not a well-typed listing is `invalid_result`. Launch
/// reports the platform's decision (a blocked start is `launch_blocked`), and stop reports the
/// kill Android was asked for — never that a process stopped.

import { useCallback, useEffect, useRef, useState } from "react";

import {
  type ApiClient,
  type AppEntryView,
  type CommandAccepted,
  type CommandView,
} from "../api";
import { AppList } from "../components/AppList";
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

export interface AppsRouteProps {
  api: ApiClient;
  deviceId: string;
  userId: string;
  /// Poll interval; tests shorten it.
  pollIntervalMs?: number;
}

export function AppsRoute({ api, deviceId, userId, pollIntervalMs }: AppsRouteProps) {
  const [apps, setApps] = useState<AppEntryView[] | null>(null);
  const [listingFailure, setListingFailure] = useState<FailureOutcome | null>(null);
  const [listingLoading, setListingLoading] = useState(true);
  const [reloadNonce, setReloadNonce] = useState(0);

  const [busy, setBusy] = useState(false);
  const [actionFailure, setActionFailure] = useState<FailureOutcome | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // A reload clears the listing *before* the new query starts, and an answer for an abandoned
  // query is dropped: the screen never shows one answer against another question.
  useEffect(() => {
    let cancelled = false;
    setApps(null);
    setListingFailure(null);
    setListingLoading(true);
    (async () => {
      let accepted: CommandAccepted;
      try {
        accepted = await api.listApps(deviceId, userId);
      } catch (failure) {
        // Nothing was dispatched: this listing really was refused.
        if (!cancelled) {
          setListingFailure(outcomeOf(failureOfError(failure), false));
          setListingLoading(false);
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
          // Accepted, so a code that is not the device's answer leaves the listing unknown.
          setListingFailure(outcomeOf(failureOfCommand(command), true));
          return;
        }
        const listing = readApps(command.output);
        if (!listing) {
          setListingFailure(
            unknownOutcome({
              code: "invalid_result",
              message: "the device's answer is not an app listing",
            }),
          );
          return;
        }
        setApps(listing);
      } catch (failure) {
        // Accepted, then the poll itself failed: the answer was lost, not refused.
        if (!cancelled) setListingFailure(unknownOutcome(failureOfError(failure)));
      } finally {
        if (!cancelled) setListingLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api, deviceId, userId, pollIntervalMs, reloadNonce]);

  const reload = useCallback(() => setReloadNonce((value) => value + 1), []);

  /// Dispatches one command and waits for the device's answer. A non-`ok` answer becomes the
  /// action's failure and `null` is returned, so no caller can mistake a refusal for success.
  ///
  /// Acceptance and the answer are separate facts. A refusal before the command is accepted is
  /// the ordinary "the device did not do that"; an outcome after acceptance that may have reached
  /// the device re-reads the inventory, so a change that landed cannot sit under a stale list.
  const run = useCallback(
    async (operation: () => Promise<CommandAccepted>): Promise<CommandView | null> => {
      setBusy(true);
      setActionFailure(null);
      setNotice(null);
      try {
        let accepted: CommandAccepted;
        try {
          accepted = await operation();
        } catch (failure) {
          // Nothing was dispatched, so this is the ordinary refusal it looks like.
          if (mounted.current) setActionFailure(outcomeOf(failureOfError(failure), false));
          return null;
        }
        try {
          const command = await pollCommand(api, userId, accepted.command_id, {
            pollIntervalMs,
            isActive: () => mounted.current,
          });
          if (!mounted.current) return null;
          if (command.status !== "ok") {
            const outcome = outcomeOf(failureOfCommand(command), true);
            setActionFailure(outcome);
            if (outcome.unknown) reload();
            return null;
          }
          return command;
        } catch (failure) {
          // Accepted, then the poll failed: the answer was lost, never refused.
          if (mounted.current) {
            setActionFailure(unknownOutcome(failureOfError(failure)));
            reload();
          }
          return null;
        }
      } finally {
        if (mounted.current) setBusy(false);
      }
    },
    [api, userId, pollIntervalMs, reload],
  );

  async function launch(app: AppEntryView): Promise<void> {
    const command = await run(() => api.launchApp(deviceId, userId, app.package));
    if (!command) return;
    if (!readLaunched(command.output)) {
      // The device answered `ok`, so it acted; its answer just cannot be read here.
      setActionFailure(
        unknownOutcome({
          code: "invalid_result",
          message: "the device's answer does not confirm the app launch",
        }),
      );
      reload();
      return;
    }
    setNotice(`Asked Android to launch ${app.label}.`);
  }

  async function stop(app: AppEntryView): Promise<void> {
    const command = await run(() => api.stopApp(deviceId, userId, app.package));
    if (!command) return;
    if (!readKillRequested(command.output)) {
      setActionFailure(
        unknownOutcome({
          code: "invalid_result",
          message: "the device's answer does not confirm the kill request",
        }),
      );
      reload();
      return;
    }
    // Not "stopped": Android never confirms that a background process died.
    setNotice(`Asked Android to kill background processes for ${app.label}.`);
  }

  return (
    <>
      <nav>
        <RouteLink to={devicePath(deviceId)}>Back to status</RouteLink>
      </nav>
      <h1>Apps</h1>
      <p className="muted">
        These are the apps the device reports as installed. Only apps visible to the agent
        appear, and an ordinary app cannot clear data or change a package&apos;s enabled state.
      </p>

      <section className="panel" aria-labelledby="apps-heading">
        <h2 id="apps-heading">Installed apps</h2>
        <div className="actions">
          <button type="button" disabled={busy || listingLoading} onClick={reload}>
            Refresh
          </button>
        </div>

        {listingFailure ? (
          <FailureNotice failure={listingFailure.failure} lead={listingFailure.lead} />
        ) : null}
        {listingLoading && !listingFailure ? <p>Loading apps…</p> : null}
        {!listingLoading && !listingFailure && apps?.length === 0 ? (
          <p>The device reported no installed apps.</p>
        ) : null}
        {!listingFailure && apps && apps.length > 0 ? (
          <AppList
            apps={apps}
            busy={busy}
            onLaunch={(app) => void launch(app)}
            onStop={(app) => void stop(app)}
          />
        ) : null}
      </section>

      {actionFailure ? (
        <FailureNotice failure={actionFailure.failure} lead={actionFailure.lead} />
      ) : null}
      {notice ? (
        <p role="status" className="notice">
          {notice}
        </p>
      ) : null}
    </>
  );
}

function readApps(output: unknown): AppEntryView[] | null {
  if (typeof output !== "object" || output === null) return null;
  const apps = (output as { apps?: unknown }).apps;
  if (!Array.isArray(apps)) return null;
  const parsed: AppEntryView[] = [];
  for (const raw of apps) {
    if (!isApp(raw)) return null;
    parsed.push(raw);
  }
  return parsed;
}

function isApp(raw: unknown): raw is AppEntryView {
  if (typeof raw !== "object" || raw === null) return false;
  const value = raw as Record<string, unknown>;
  return (
    typeof value.package === "string" &&
    typeof value.label === "string" &&
    (value.version_name === null || typeof value.version_name === "string") &&
    typeof value.version_code === "number" &&
    typeof value.system === "boolean" &&
    typeof value.enabled === "boolean" &&
    typeof value.updated_ms === "number"
  );
}

function readLaunched(output: unknown): boolean {
  if (typeof output !== "object" || output === null) return false;
  return (output as { launched?: unknown }).launched === true;
}

function readKillRequested(output: unknown): boolean {
  if (typeof output !== "object" || output === null) return false;
  return (output as { kill_requested?: unknown }).kill_requested === true;
}
