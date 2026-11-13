/// The lease surface: who controls the device, what this user may do, and the explicit ways
/// control changes hands (handoff and revocation).
///
/// The owner may revoke a lease they do not hold, so revoke is offered to the owner *and* the
/// holder. "Read-only access" is reserved for a user who is neither.

import { useState } from "react";

import type { ApiClient, DeviceView, LeaseStatusView } from "../api";
import { ErrorNotice } from "./ErrorNotice";
import { StatusField } from "./StatusField";

export function LeasePanel({
  api,
  device,
  userId,
  status,
  onChanged,
}: {
  api: ApiClient;
  device: DeviceView;
  userId: string;
  status: LeaseStatusView;
  onChanged: () => void;
}) {
  const [handoffTo, setHandoffTo] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  const revoked = device.state === "revoked";
  const lease = status.lease;
  const isOwner = status.access.is_owner;
  const canControl = status.access.can_control;
  // The server authorizes the owner or the current holder to revoke and hand off.
  const mayManageLease = !revoked && lease !== null && (isOwner || canControl);
  const mayTakeControl = !revoked && lease === null && isOwner && !canControl;

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
            {lease ? `Controlled by ${lease.holder_id}` : "No active controller"}
          </strong>
        </StatusField>
        <StatusField label="Your access">
          <strong>{describeAccess(revoked, isOwner, canControl, lease !== null)}</strong>
        </StatusField>
      </dl>

      {revoked ? (
        <p className="muted">
          Control cannot be granted for a revoked device. Enroll it again to control it.
        </p>
      ) : null}

      {mayManageLease ? (
        <div className="actions">
          <button
            type="button"
            disabled={pending}
            onClick={() =>
              void run(() => api.revokeLease(lease?.lease_id ?? "", userId))
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
              void run(() => api.handoffLease(device.device_id, userId, handoffTo.trim()))
            }
          >
            Hand off control
          </button>
        </div>
      ) : null}

      {mayTakeControl ? (
        <div className="actions">
          <button
            type="button"
            disabled={pending}
            onClick={() => void run(() => api.acquireLease(device.device_id, userId))}
          >
            Take control
          </button>
        </div>
      ) : null}

      {error ? <ErrorNotice error={error} /> : null}
    </section>
  );
}

function describeAccess(
  revoked: boolean,
  isOwner: boolean,
  canControl: boolean,
  hasLease: boolean,
): string {
  if (revoked) return "Device revoked — no control is possible";
  if (canControl) return "You control this device";
  if (isOwner && hasLease) return "Owner — you can revoke this lease";
  if (isOwner) return "Owner — you can take control";
  return "Read-only access";
}
