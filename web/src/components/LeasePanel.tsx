/// The lease surface: who controls the device, what this user may do, and the two explicit
/// ways control changes hands (handoff and revocation).

import { useState } from "react";

import type { ApiClient, LeaseStatusView } from "../api";
import { ErrorNotice } from "./ErrorNotice";
import { StatusField } from "./StatusField";

export function LeasePanel({
  api,
  deviceId,
  userId,
  status,
  onChanged,
}: {
  api: ApiClient;
  deviceId: string;
  userId: string;
  status: LeaseStatusView;
  onChanged: () => void;
}) {
  const [handoffTo, setHandoffTo] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function run(action: () => Promise<unknown>): Promise<void> {
    setPending(true);
    setError(null);
    try {
      await action();
      onChanged();
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }

  return (
    <section className="panel" aria-labelledby="lease-heading">
      <h2 id="lease-heading">Control lease</h2>
      <dl>
        <StatusField label="Controller">
          <strong>
            {status.lease
              ? `Controlled by ${status.lease.holder_id}`
              : "No active controller"}
          </strong>
        </StatusField>
        <StatusField label="Your access">
          <strong>
            {status.access.can_control ? "You control this device" : "Read-only access"}
          </strong>
        </StatusField>
      </dl>

      {status.access.can_control && status.lease ? (
        <div className="actions">
          <button
            type="button"
            disabled={pending}
            onClick={() =>
              void run(() =>
                api.revokeLease(status.lease?.lease_id ?? "", userId),
              )
            }
          >
            Release control
          </button>
          <label htmlFor="handoff-user">Hand off to user id</label>
          <input
            id="handoff-user"
            value={handoffTo}
            onChange={(event) => setHandoffTo(event.target.value)}
          />
          <button
            type="button"
            disabled={pending || handoffTo.trim().length === 0}
            onClick={() =>
              void run(() =>
                api.handoffLease(deviceId, userId, handoffTo.trim()),
              )
            }
          >
            Hand off control
          </button>
        </div>
      ) : null}

      {!status.access.can_control && status.access.is_owner && !status.lease ? (
        <div className="actions">
          <button
            type="button"
            disabled={pending}
            onClick={() => void run(() => api.acquireLease(deviceId, userId))}
          >
            Take control
          </button>
        </div>
      ) : null}

      {error ? <ErrorNotice error={error} /> : null}
    </section>
  );
}
