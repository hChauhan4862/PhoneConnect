import type { ApiClient } from "../api";
import { CommandPanel } from "../components/CommandPanel";
import { RouteLink } from "../components/RouteLink";
import { devicePath } from "../routing";

/// One device's command console. Commands are dispatched through the server and answered by
/// the device; this screen never infers a result it did not receive.
export function CommandsRoute({
  api,
  deviceId,
  userId,
}: {
  api: ApiClient;
  deviceId: string;
  userId: string;
}) {
  return (
    <>
      <nav>
        <RouteLink to={devicePath(deviceId)}>Back to status</RouteLink>
      </nav>
      <h1>Commands</h1>
      <CommandPanel api={api} deviceId={deviceId} userId={userId} />
    </>
  );
}
