/// A refusal, rendered the same way on every screen: the code first, because that is what the
/// caller acts on, then the device's own explanation when it gave one.

import type { Failure } from "../data/failures";

export function FailureNotice({ failure }: { failure: Failure }) {
  return (
    <div role="alert" className="notice notice-error">
      <p>
        <strong>The device did not do that</strong> <code>{failure.code}</code>
      </p>
      {failure.message ? <p>{failure.message}</p> : null}
    </div>
  );
}
