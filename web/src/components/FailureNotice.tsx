/// A refusal, rendered the same way on every screen: the code first, because that is what the
/// caller acts on, then the device's own explanation when it gave one. A screen that knows more
/// about a particular code can replace the lead sentence or add one, without hiding the code or
/// the device's message — the default lead is wrong for an outcome the device could not confirm.

import type { Failure } from "../data/failures";

export function FailureNotice({
  failure,
  lead,
  note,
}: {
  failure: Failure;
  lead?: string;
  note?: string;
}) {
  return (
    <div role="alert" className="notice notice-error">
      <p>
        <strong>{lead ?? "The device did not do that"}</strong> <code>{failure.code}</code>
      </p>
      {failure.message ? <p>{failure.message}</p> : null}
      {note ? <p>{note}</p> : null}
    </div>
  );
}
