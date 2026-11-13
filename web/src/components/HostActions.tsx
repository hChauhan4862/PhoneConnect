/// Host-dependent affordances. The in-page action always exists; the detached-window action
/// is additive and only rendered when the host can actually open one.

import { liveTelemetryPath } from "../routing";
import { useHostAdapter } from "../host/HostAdapter";

export function HostActions({ deviceId }: { deviceId: string }) {
  const host = useHostAdapter();
  const route = liveTelemetryPath(deviceId);

  return (
    <section className="panel actions" aria-labelledby="views-heading">
      <h2 id="views-heading">Views</h2>
      <p className="muted">
        The live telemetry view is a long-lived screen. The native shell can host it in a
        separate window; a browser keeps it in this tab.
      </p>
      <button type="button" onClick={() => void host.openView(route, { detached: false })}>
        Open live telemetry
      </button>
      {host.kind === "native" ? (
        <button
          type="button"
          onClick={() => void host.openView(route, { detached: true })}
        >
          Open live telemetry in a detached window
        </button>
      ) : null}
    </section>
  );
}
