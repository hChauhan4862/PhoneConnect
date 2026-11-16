/// The device list: every enrolled device, plus the two operator actions that exist here.
///
/// The list is the server's own answer, never inferred. The empty state teaches the two steps
/// instead of saying "no devices" and leaving an operator stuck. A revoked device stays listed
/// — that is a fact the server reports — and offers re-enrolling rather than a dead control.

import { useCallback, useState } from "react";

import { type ApiClient, asApiError } from "../api";
import { EnrollmentTokenPanel } from "../components/EnrollmentTokenPanel";
import { ErrorNotice } from "../components/ErrorNotice";
import { RouteLink } from "../components/RouteLink";
import { useResource } from "../data/useResource";
import { devicePath } from "../routing";

export function DeviceListRoute({
  api,
  userId,
}: {
  api: ApiClient;
  userId: string;
}) {
  const resource = useResource(`devices:${userId}`, () => api.listDevices());
  const [pendingRevoke, setPendingRevoke] = useState<string | null>(null);
  const [revoking, setRevoking] = useState<string | null>(null);
  // The device the failure belongs to travels with it, so a stale error can never read as
  // another device's result.
  const [revokeFailure, setRevokeFailure] = useState<{
    deviceId: string;
    error: unknown;
  } | null>(null);

  const reload = resource.reload;

  const confirmRevoke = useCallback(
    async (deviceId: string) => {
      setRevoking(deviceId);
      setRevokeFailure(null);
      try {
        await api.revokeDevice(deviceId);
        setPendingRevoke(null);
        reload();
      } catch (error) {
        setRevokeFailure({ deviceId, error });
      } finally {
        setRevoking(null);
      }
    },
    [api, reload],
  );

  if (resource.loading && !resource.data) {
    // Onboarding does not need the list, so the panel stays available while it loads.
    return (
      <>
        <section className="panel" aria-labelledby="devices-heading">
          <h1 id="devices-heading">Devices</h1>
          <p>Loading devices…</p>
        </section>
        <EnrollmentTokenPanel api={api} defaultOwner={userId} />
      </>
    );
  }
  const devices = resource.data?.devices ?? [];

  return (
    <>
      <section className="panel" aria-labelledby="devices-heading">
        <h1 id="devices-heading">Devices</h1>

        {/* A failed read is reported here, not in place of the whole route: minting a token
            is the only way back to a working list, so it must stay reachable. */}
        {resource.error ? (
          <ErrorNotice error={resource.error} onRetry={reload} />
        ) : devices.length === 0 ? (
          <>
            <p>No devices yet. Two steps:</p>
            <ol>
              <li>Create a one-time enrollment token below.</li>
              <li>Enter it in the PhoneConnect app on the phone.</li>
            </ol>
          </>
        ) : (
          <ul className="device-list">
            {devices.map((device) => {
              const revoked = device.state === "revoked";
              return (
                <li key={device.device_id}>
                  <RouteLink to={devicePath(device.device_id)}>
                    {device.device_id}
                  </RouteLink>
                  <span className="muted">
                    {device.owner_id} · {revoked ? "Revoked" : "Enrolled"}
                  </span>

                  {revoked ? (
                    <span className="muted">
                      {" "}
                      — create a new token below to enroll it again
                    </span>
                  ) : pendingRevoke === device.device_id ? (
                    <span className="actions">
                      <span>
                        Revoke this device? Its channel closes and it must be enrolled again.
                      </span>
                      <button
                        type="button"
                        disabled={revoking === device.device_id}
                        onClick={() => void confirmRevoke(device.device_id)}
                      >
                        Confirm revoke
                      </button>
                      <button
                        type="button"
                        onClick={() => {
                          setPendingRevoke(null);
                          setRevokeFailure(null);
                        }}
                      >
                        Cancel revoke
                      </button>
                    </span>
                  ) : (
                    <button
                      type="button"
                      onClick={() => {
                        setRevokeFailure(null);
                        setPendingRevoke(device.device_id);
                      }}
                    >
                      Revoke…
                    </button>
                  )}
                </li>
              );
            })}
          </ul>
        )}

        {revokeFailure ? (
          <p role="alert" className="notice notice-error">
            <code>{revokeFailure.deviceId}</code> was not revoked:{" "}
            <code>{asApiError(revokeFailure.error).code}</code>
          </p>
        ) : null}
      </section>

      <EnrollmentTokenPanel api={api} defaultOwner={userId} />
    </>
  );
}
