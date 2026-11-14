/// Polling one accepted command to its terminal state.
///
/// A POST only proves the command was queued. The server converts a command past its deadline
/// into `timeout`, so the budget is the longest deadline it accepts (60 s at a quarter-second
/// cadence) and a caller that runs out sees `pending`, never a success it invented.

import type { ApiClient, CommandView } from "../api";

export const DEFAULT_POLL_INTERVAL_MS = 250;

/// 240 polls at 250 ms is the longest deadline (60 s) the server accepts.
export const MAX_POLLS = 240;

export interface PollOptions {
  pollIntervalMs?: number;
  maxPolls?: number;
  /// Checked between polls so an unmounted screen stops asking.
  isActive?: () => boolean;
}

export async function pollCommand(
  api: ApiClient,
  userId: string,
  commandId: string,
  options: PollOptions = {},
): Promise<CommandView> {
  const pollIntervalMs = options.pollIntervalMs ?? DEFAULT_POLL_INTERVAL_MS;
  const maxPolls = options.maxPolls ?? MAX_POLLS;
  let latest = await api.command(commandId, userId);
  for (let attempt = 0; attempt < maxPolls && latest.status === "pending"; attempt += 1) {
    if (options.isActive && !options.isActive()) return latest;
    await sleep(pollIntervalMs);
    if (options.isActive && !options.isActive()) return latest;
    latest = await api.command(commandId, userId);
  }
  return latest;
}

function sleep(ms: number): Promise<void> {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
