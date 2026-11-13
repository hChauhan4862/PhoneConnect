import type { ApiClient } from "../api";
import { useResource } from "../data/useResource";
import { ErrorNotice } from "../components/ErrorNotice";
import { RouteLink } from "../components/RouteLink";
import { TelemetryPanel } from "../components/TelemetryPanel";
import { devicePath } from "../routing";

export function LiveTelemetryRoute({
  api,
  deviceId,
  userId,
}: {
  api: ApiClient;
  deviceId: string;
  userId: string;
}) {
  const resource = useResource(`telemetry:${deviceId}:${userId}`, () =>
    api.deviceStatus(deviceId, userId),
  );

  return (
    <>
      <nav>
        <RouteLink to={devicePath(deviceId)}>Back to status</RouteLink>
      </nav>
      <h1>Live telemetry</h1>
      {resource.error ? (
        <ErrorNotice error={resource.error} onRetry={resource.reload} />
      ) : null}
      {resource.loading && !resource.data ? <p>Loading telemetry…</p> : null}
      {resource.data ? (
        <>
          <TelemetryPanel telemetry={resource.data.telemetry} />
          <div className="actions">
            <button type="button" onClick={resource.reload}>
              Refresh telemetry
            </button>
          </div>
        </>
      ) : null}
    </>
  );
}
