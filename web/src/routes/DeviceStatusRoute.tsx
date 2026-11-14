import type { ApiClient } from "../api";
import { useResource } from "../data/useResource";
import { ControlPanel } from "../components/ControlPanel";
import { DeviceIdentity } from "../components/DeviceIdentity";
import { ErrorNotice } from "../components/ErrorNotice";
import { HostActions } from "../components/HostActions";
import { LeasePanel } from "../components/LeasePanel";
import { RouteLink } from "../components/RouteLink";
import { SessionPanel } from "../components/SessionPanel";
import { TelemetryPanel } from "../components/TelemetryPanel";
import { appsPath, commandsPath, consolePath, filesPath, screenPath } from "../routing";

export function DeviceStatusRoute({
  api,
  deviceId,
  userId,
}: {
  api: ApiClient;
  deviceId: string;
  userId: string;
}) {
  const resource = useResource(`status:${deviceId}:${userId}`, () =>
    api.deviceStatus(deviceId, userId),
  );

  if (resource.error) {
    return (
      <>
        <nav>
          <RouteLink to="/">Devices</RouteLink>
        </nav>
        <ErrorNotice error={resource.error} onRetry={resource.reload} />
      </>
    );
  }
  if (resource.loading && !resource.data) {
    return <p>Loading device status…</p>;
  }
  const status = resource.data;
  if (!status) return null;

  return (
    <>
      <nav>
        <RouteLink to="/">Devices</RouteLink>
      </nav>
      <DeviceIdentity device={status.device} />
      <div className="actions">
        <button type="button" onClick={resource.reload}>
          Refresh status
        </button>
        <span className="muted">
          Not live: the server has no push channel, so refresh to see changes.
        </span>
      </div>
      <SessionPanel session={status.session} />
      <LeasePanel
        api={api}
        device={status.device}
        userId={userId}
        status={status.lease}
        onChanged={resource.reload}
      />
      <TelemetryPanel telemetry={status.telemetry} />
      <ControlPanel api={api} deviceId={status.device.device_id} userId={userId} />
      <p>
        <RouteLink to={commandsPath(status.device.device_id)}>
          Open the command console
        </RouteLink>
      </p>
      <p>
        <RouteLink to={filesPath(status.device.device_id)}>Browse files</RouteLink>
      </p>
      <p>
        <RouteLink to={appsPath(status.device.device_id)}>Browse apps</RouteLink>
      </p>
      <p>
        <RouteLink to={screenPath(status.device.device_id)}>Screen snapshot</RouteLink>
      </p>
      <p>
        <RouteLink to={consolePath(status.device.device_id)}>System properties and console</RouteLink>
      </p>
      <HostActions deviceId={status.device.device_id} />
    </>
  );
}
