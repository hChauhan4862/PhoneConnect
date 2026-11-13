import type { TelemetryView } from "../api";
import { formatAge, formatPercent } from "../format";
import { StatusField } from "./StatusField";

const FRESHNESS_LABEL = {
  fresh: "Telemetry fresh",
  stale: "Telemetry stale",
  missing: "No telemetry reported",
} as const;

/// Bounded aggregates only: the newest reading, a small window summary, and how old it is.
export function TelemetryPanel({ telemetry }: { telemetry: TelemetryView }) {
  const aggregate = telemetry.aggregate;
  return (
    <section className="panel" aria-labelledby="telemetry-heading">
      <h2 id="telemetry-heading">Telemetry</h2>
      <p>
        <strong>{FRESHNESS_LABEL[telemetry.freshness]}</strong>
      </p>
      {telemetry.age_ms !== null ? (
        <p className="muted">Last report {formatAge(telemetry.age_ms)}</p>
      ) : null}
      {aggregate ? (
        <dl>
          <StatusField label="CPU">
            {formatPercent(aggregate.window_cpu_percent?.latest)}
            {aggregate.window_cpu_percent
              ? ` (avg ${formatPercent(aggregate.window_cpu_percent.mean)})`
              : ""}
          </StatusField>
          <StatusField label="Memory">
            {formatPercent(aggregate.window_memory_percent?.latest)}
          </StatusField>
          <StatusField label="Battery">
            {formatPercent(aggregate.latest.battery_percent)}
            {aggregate.latest.battery_charging === null
              ? ""
              : aggregate.latest.battery_charging
                ? " charging"
                : " discharging"}
          </StatusField>
          {aggregate.latest.connectivity !== null ? (
            <StatusField label="Connectivity">
              {aggregate.latest.connectivity}
            </StatusField>
          ) : null}
          <StatusField label="Window">
            {aggregate.window_samples} samples over {formatWindow(aggregate.window_ms)}
          </StatusField>
        </dl>
      ) : null}
    </section>
  );
}

function formatWindow(windowMs: number): string {
  if (windowMs < 1_000) return `${windowMs}ms`;
  if (windowMs < 60_000) return `${Math.round(windowMs / 1_000)}s`;
  return `${Math.round(windowMs / 60_000)}m`;
}
