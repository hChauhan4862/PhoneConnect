import type { DeviceView } from "../api";
import { formatTime } from "../format";
import { StatusField } from "./StatusField";

export function DeviceIdentity({ device }: { device: DeviceView }) {
  return (
    <header className="panel">
      <h1>{device.device_id}</h1>
      <dl>
        <StatusField label="Owner">{device.owner_id}</StatusField>
        <StatusField label="Enrollment">
          <strong>{device.state === "enrolled" ? "Enrolled" : "Revoked"}</strong>
        </StatusField>
        <StatusField label="Enrolled at">
          {formatTime(device.enrolled_at_ms)}
        </StatusField>
        {device.revoked_at_ms !== null ? (
          <StatusField label="Revoked at">
            {formatTime(device.revoked_at_ms)}
          </StatusField>
        ) : null}
      </dl>
    </header>
  );
}
