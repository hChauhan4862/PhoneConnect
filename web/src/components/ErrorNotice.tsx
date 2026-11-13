/// An explicit failure. There is no success-shaped fallback: the screen says what failed
/// and offers a retry when a retry can help.

import { asApiError } from "../api";

function describeError(error: unknown): string {
  const api = asApiError(error);
  if (api.status === 0) return "Could not reach the server";
  if (api.status === 401 || api.status === 403) return "Permission denied";
  if (api.status === 404) return "Not found";
  return "The server refused the request";
}

export function ErrorNotice({
  error,
  onRetry,
}: {
  error: unknown;
  onRetry?: () => void;
}) {
  const api = asApiError(error);
  return (
    <div role="alert" className="notice notice-error">
      <p>
        <strong>{describeError(api)}</strong> <code>{api.code}</code>
      </p>
      {onRetry ? (
        <button type="button" onClick={onRetry}>
          Retry
        </button>
      ) : null}
    </div>
  );
}
