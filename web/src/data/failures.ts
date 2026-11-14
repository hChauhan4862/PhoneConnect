/// The one way a screen says "that did not happen": a machine code and, when the device gave
/// one, its explanation. There is no success-shaped failure.
///
/// Acceptance and the answer are separate facts. A refusal that arrives before the command is
/// accepted is an ordinary "the device did not do that". A terminal outcome that arrives after
/// acceptance and is not the device's own answer — the server's deadline expired, the channel
/// dropped, the record was trimmed, the poll budget ended — is not evidence of anything, and
/// neither an alert nor a listing may claim the device refused something it may well have done.

import type { CommandView } from "../api";
import { asApiError } from "../api";

export interface Failure {
  code: string;
  message: string | null;
}

/// What a screen may say about one failure, and whether anything may still look current.
export interface FailureOutcome {
  failure: Failure;
  /// The lead sentence that is true for this outcome; `undefined` leaves the refusal default.
  lead: string | undefined;
  /// True when the command may have reached the device: no listing or reading may stay current.
  unknown: boolean;
}

/// The lead an alert wears when the command was accepted but its answer never arrived, or
/// arrived `ok` in a shape the screen cannot read. The device may well have acted.
export const UNKNOWN_OUTCOME_LEAD = "The device may not have completed that";

/// Terminal codes that are not the device's answer: the server stopped waiting (`timeout`), the
/// channel dropped (`device_offline`), the record was trimmed past the retention cap
/// (`command_unknown`), or the poll budget ended with the device still silent (`pending`). All
/// of them happen after dispatch, so the device may have acted before the answer was lost.
export const UNKNOWN_OUTCOME_CODES: ReadonlySet<string> = new Set([
  "timeout",
  "device_offline",
  "command_unknown",
  "pending",
]);

/// The device's own answer that it changed something but could not read it back. Not a refusal,
/// and not unknown either: the device told us exactly what it could not confirm.
const UNCONFIRMED_CODE = "unconfirmed";
const UNCONFIRMED_LEAD = "The device could not confirm that";

export function failureOfCommand(command: CommandView): Failure {
  // `timeout` and a poll budget that ended in `pending` are their own codes, never
  // `device_error`: the screen says exactly which state it saw.
  return {
    code: command.error ?? command.status,
    message:
      command.message ??
      (command.status === "pending" ? "the device has not answered yet" : null),
  };
}

export function failureOfError(error: unknown): Failure {
  const api = asApiError(error);
  return { code: api.code, message: null };
}

/// The one rule every screen applies. `accepted` says whether this command came back accepted
/// (a 202): only then was anything dispatched, so only then can an outcome be unknown.
export function outcomeOf(failure: Failure, accepted: boolean): FailureOutcome {
  if (failure.code === UNCONFIRMED_CODE) {
    return { failure, lead: UNCONFIRMED_LEAD, unknown: false };
  }
  const unknown = accepted && UNKNOWN_OUTCOME_CODES.has(failure.code);
  return { failure, lead: unknown ? UNKNOWN_OUTCOME_LEAD : undefined, unknown };
}

/// An answer that never arrived, or arrived in a shape the screen cannot read: the command may
/// have reached the device, so neither the alert nor any listing may claim otherwise.
export function unknownOutcome(failure: Failure): FailureOutcome {
  return { failure, lead: UNKNOWN_OUTCOME_LEAD, unknown: true };
}
