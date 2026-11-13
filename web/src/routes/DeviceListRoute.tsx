import type { ApiClient } from "../api";
import { useResource } from "../data/useResource";
import { ErrorNotice } from "../components/ErrorNotice";
import { RouteLink } from "../components/RouteLink";
import { devicePath } from "../routing";

export function DeviceListRoute({
  api,
  userId,
}: {
  api: ApiClient;
  userId: string;
}) {
  const resource = useResource(`devices:${userId}`, () => api.listDevices());

  if (resource.error) {
    return <ErrorNotice error={resource.error} onRetry={resource.reload} />;
  }
  if (resource.loading && !resource.data) {
    return <p>Loading devices…</p>;
  }
  const devices = resource.data?.devices ?? [];

  return (
    <section className="panel" aria-labelledby="devices-heading">
      <h1 id="devices-heading">Devices</h1>
      {devices.length === 0 ? (
        <p>No devices enrolled</p>
      ) : (
        <ul className="device-list">
          {devices.map((device) => (
            <li key={device.device_id}>
              <RouteLink to={devicePath(device.device_id)}>
                {device.device_id}
              </RouteLink>
              <span className="muted">
                {device.owner_id} ·{" "}
                {device.state === "enrolled" ? "Enrolled" : "Revoked"}
              </span>
            </li>
          ))}
        </ul>
      )}
    </section>
  );
}
