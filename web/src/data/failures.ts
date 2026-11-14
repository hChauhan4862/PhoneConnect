/// The one way a screen says "that did not happen": a machine code and, when the device gave
/// one, its explanation. There is no success-shaped failure.

import type { CommandView } from "../api";
import { asApiError } from "../api";

export interface Failure {
  code: string;
  message: string | null;
}

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
