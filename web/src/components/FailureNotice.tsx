/// A refusal, rendered the same way on every screen: the code first, because that is what the
/// caller acts on, then the device's own explanation when it gave one. A screen that knows more
/// about a particular code can add a sentence without hiding the code or the device's message.

import type { Failure } from "../data/failures";

export function FailureNotice({ failure, note }: { failure: Failure; note?: string }) {
  return (
    <div role="alert" className="notice notice-error">
      <p>
        <strong>The device did not do that</strong> <code>{failure.code}</code>
      </p>
      {failure.message ? <p>{failure.message}</p> : null}
      {note ? <p>{note}</p> : null}
    </div>
  );
}
