/// The command surface: one command at a time, dispatched through the server and polled until
/// the device answers.
///
/// The four states are rendered distinctly and nothing else counts as success: only `ok`
/// carries output, `error` and `timeout` say so in an alert, and a `pending` command says the
/// device has not answered yet. A refusal from the server (`device_offline`,
/// `device_revoked`, ...) is an alert too, never a pending row that appears to be working.
///
/// Polling is bounded: the server converts a command past its deadline into `timeout`, so a
/// long-running poll gives up at the longest deadline and asks the user to check again.

import { useCallback, useEffect, useRef, useState } from "react";

import {
  asApiError,
  type ApiClient,
  type CommandView,
} from "../api";
import { ErrorNotice } from "./ErrorNotice";

/// Names this build's agent answers. The field stays free-text: the device owns the
/// vocabulary, and a later feature adds names without changing this screen.
const SUGGESTED_COMMANDS = ["device.info", "device.ping", "telemetry.now"] as const;

const DEFAULT_POLL_INTERVAL_MS = 250;

/// 240 polls at 250 ms is the longest deadline (60 s) the server accepts.
const MAX_POLLS = 240;

const REFUSAL_MESSAGES: Record<string, string> = {
  device_offline: "The device is not connected to the server, so the command was not sent.",
  device_revoked: "This device was revoked, so it cannot be commanded.",
  lease_read_only: "You do not control this device, so the command was refused.",
  command_capacity: "This device already has too many commands in flight. Try again shortly.",
  rate_limited: "Commands for this device are being sent too quickly. Wait a moment and retry.",
  invalid_timeout: "The requested deadline is outside the allowed range.",
};

export interface CommandPanelProps {
  api: ApiClient;
  deviceId: string;
  userId: string;
  /// Poll interval; tests shorten it. Production keeps a quarter-second cadence.
  pollIntervalMs?: number;
}

export function CommandPanel({
  api,
  deviceId,
  userId,
  pollIntervalMs = DEFAULT_POLL_INTERVAL_MS,
}: CommandPanelProps) {
  const [name, setName] = useState<string>(SUGGESTED_COMMANDS[0]);
  const [argsText, setArgsText] = useState("");
  const [command, setCommand] = useState<CommandView | null>(null);
  const [submitError, setSubmitError] = useState<unknown>(null);
  const [inputError, setInputError] = useState<string | null>(null);
  const [polling, setPolling] = useState(false);
  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const submit = useCallback(async () => {
    setSubmitError(null);
    setInputError(null);

    const commandName = name.trim();
    if (commandName.length === 0) {
      setInputError("A command name is required.");
      return;
    }
    let args: unknown = null;
    const trimmedArgs = argsText.trim();
    if (trimmedArgs.length > 0) {
      try {
        args = JSON.parse(trimmedArgs);
      } catch {
        setInputError("Arguments must be valid JSON.");
        return;
      }
    }

    try {
      const accepted = await api.dispatchCommand(
        deviceId,
        userId,
        commandName,
        args,
        null,
      );
      if (!mounted.current) return;
      // The POST only proves the command was queued. The device has not answered, so the
      // first state on screen is explicitly pending.
      setCommand({
        command_id: accepted.command_id,
        device_id: deviceId,
        name: commandName,
        status: "pending",
        output: null,
        error: null,
        message: null,
        created_at_ms: Date.now(),
        completed_at_ms: null,
      });
      setPolling(true);
      for (let attempt = 0; attempt < MAX_POLLS; attempt += 1) {
        await sleep(pollIntervalMs);
        if (!mounted.current) return;
        const latest = await api.command(accepted.command_id, userId);
        if (!mounted.current) return;
        setCommand(latest);
        if (latest.status !== "pending") {
          setPolling(false);
          return;
        }
      }
      if (!mounted.current) return;
      setPolling(false);
    } catch (failure) {
      if (!mounted.current) return;
      setCommand(null);
      setSubmitError(failure);
      setPolling(false);
    }
  }, [api, argsText, deviceId, name, pollIntervalMs, userId]);

  return (
    <section className="panel" aria-labelledby="commands-heading">
      <h2 id="commands-heading">Run a command</h2>
      <p className="muted">
        The command travels to the device over its management channel. The page polls until
        the device answers; only the device&apos;s own result counts as success.
      </p>
      <div className="actions">
        <label htmlFor="command-name">Command</label>
        <input
          id="command-name"
          list="command-names"
          value={name}
          onChange={(event) => setName(event.target.value)}
        />
        <datalist id="command-names">
          {SUGGESTED_COMMANDS.map((suggestion) => (
            <option key={suggestion} value={suggestion} />
          ))}
        </datalist>
        <label htmlFor="command-args">Arguments (JSON, optional)</label>
        <textarea
          id="command-args"
          rows={3}
          value={argsText}
          onChange={(event) => setArgsText(event.target.value)}
        />
        <button type="button" disabled={polling} onClick={() => void submit()}>
          Run command
        </button>
      </div>

      {inputError ? (
        <p role="alert" className="notice notice-error">
          {inputError}
        </p>
      ) : null}
      {submitError ? <DispatchFailure error={submitError} /> : null}
      {command ? <CommandResult command={command} polling={polling} /> : null}
    </section>
  );
}

function CommandResult({
  command,
  polling,
}: {
  command: CommandView;
  polling: boolean;
}) {
  return (
    <div className="command-result" data-status={command.status}>
      <h3>Command result</h3>
      <p className="muted">
        <code>{command.name}</code> · <code>{command.command_id}</code>
      </p>
      {command.status === "pending" ? (
        <p role="status" className="notice">
          <strong>Pending</strong>: the device has not answered yet.
          {polling ? " Waiting for its result…" : " Check again in a moment."}
        </p>
      ) : null}
      {command.status === "ok" ? (
        <pre data-testid="command-output">{formatOutput(command.output)}</pre>
      ) : null}
      {command.status === "error" ? (
        <div role="alert" className="notice notice-error">
          <p>
            <strong>Command failed</strong> <code>{command.error ?? "device_error"}</code>
          </p>
          {command.message ? <p>{command.message}</p> : null}
        </div>
      ) : null}
      {command.status === "timeout" ? (
        <div role="alert" className="notice notice-error">
          <p>
            <strong>Timed out</strong>: the device did not answer before the deadline.
          </p>
        </div>
      ) : null}
    </div>
  );
}

function DispatchFailure({ error }: { error: unknown }) {
  const api = asApiError(error);
  const explanation = REFUSAL_MESSAGES[api.code];
  if (!explanation) {
    return <ErrorNotice error={error} />;
  }
  return (
    <div role="alert" className="notice notice-error">
      <p>
        <strong>{explanation}</strong> <code>{api.code}</code>
      </p>
    </div>
  );
}

function formatOutput(output: unknown): string {
  if (output === null || output === undefined) return "null";
  try {
    return JSON.stringify(output, null, 2);
  } catch {
    return String(output);
  }
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
