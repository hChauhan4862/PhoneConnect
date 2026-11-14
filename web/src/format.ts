/// Display helpers. Absent values stay absent: nothing is formatted as a fabricated zero.

export function formatAge(ageMs: number): string {
  const seconds = Math.max(0, Math.round(ageMs / 1_000));
  if (seconds < 60) return `${seconds}s ago`;
  const minutes = Math.round(seconds / 60);
  if (minutes < 60) return `${minutes}m ago`;
  const hours = Math.round(minutes / 60);
  if (hours < 48) return `${hours}h ago`;
  return `${Math.round(hours / 24)}d ago`;
}

export function formatPercent(value: number | null | undefined): string {
  if (value === null || value === undefined) return "not reported";
  return `${value.toFixed(1)}%`;
}

export function formatTime(timestampMs: number | null): string {
  if (timestampMs === null) return "not reported";
  return new Date(timestampMs).toLocaleTimeString();
}

/// A full date and time. An audit row is read days later, so the time alone is not enough.
export function formatDateTime(timestampMs: number): string {
  return new Date(timestampMs).toLocaleString();
}
