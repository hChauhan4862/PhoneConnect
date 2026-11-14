/// The server REST surface this UI renders. Types mirror the server's JSON exactly; they are
/// transport views, not a second domain model. Every failure is an explicit [`ApiError`].

export interface DeviceView {
  device_id: string;
  owner_id: string;
  enrolled_at_ms: number;
  revoked_at_ms: number | null;
  state: "enrolled" | "revoked";
}

export interface DeviceList {
  devices: DeviceView[];
}

export type SessionState = "active" | "expired" | "revoked" | "none";
export type PathState = "none" | "unknown" | "direct_ready" | "relay";

export interface PathView {
  state: PathState;
  relay_attached: boolean;
  direct_candidates: boolean;
}

export interface SessionView {
  session_id: string | null;
  created_at_ms: number | null;
  expires_at_ms: number | null;
  revoked_at_ms: number | null;
  state: SessionState;
  path: PathView;
  /// Control frames this session's client tried to send while read-only.
  control_refusals: number;
}

export interface LeaseView {
  lease_id: string;
  device_id: string;
  owner_id: string;
  holder_id: string;
  granted_by: string;
  acquired_at_ms: number;
  expires_at_ms: number;
  revoked_at_ms: number | null;
  revoked_reason: "revoked" | "handoff" | null;
}

export interface LeaseAccessView {
  user_id: string;
  is_owner: boolean;
  role: "controller" | "viewer";
  can_control: boolean;
}

export interface LeaseStatusView {
  lease: LeaseView | null;
  access: LeaseAccessView;
}

export interface TelemetrySampleView {
  sampled_at_ms: number;
  cpu_percent: number | null;
  memory_used_bytes: number | null;
  memory_total_bytes: number | null;
  battery_percent: number | null;
  battery_charging: boolean | null;
  connectivity: string | null;
}

export interface MetricAggregateView {
  min: number;
  max: number;
  mean: number;
  latest: number;
}

export interface TelemetryAggregateView {
  device_id: string;
  samples_received: number;
  window_samples: number;
  window_ms: number;
  first_received_ms: number;
  last_received_ms: number;
  latest: TelemetrySampleView;
  window_cpu_percent: MetricAggregateView | null;
  window_memory_percent: MetricAggregateView | null;
  window_battery_percent: MetricAggregateView | null;
}

export type TelemetryFreshness = "fresh" | "stale" | "missing";

export interface TelemetryView {
  freshness: TelemetryFreshness;
  age_ms: number | null;
  sampled_at_ms: number | null;
  latest: TelemetrySampleView | null;
  aggregate: TelemetryAggregateView | null;
}

export interface DeviceStatus {
  device: DeviceView;
  session: SessionView;
  lease: LeaseStatusView;
  telemetry: TelemetryView;
}

/// One dispatched command. `pending` is the only non-terminal state, and only `ok` carries
/// output: a failed or timed-out command never looks like a success.
export type CommandStatus = "pending" | "ok" | "error" | "timeout";

export interface CommandView {
  command_id: string;
  device_id: string;
  name: string;
  status: CommandStatus;
  output: unknown;
  error: string | null;
  message: string | null;
  created_at_ms: number;
  completed_at_ms: number | null;
}

export interface CommandAccepted {
  command_id: string;
}

export interface RevocationEvent {
  lease_id: string;
  device_id: string;
  actor_id: string;
  revoked_at_ms: number;
  reason: "revoked" | "handoff";
  invalidated_sessions: string[];
}

export interface LeaseHandoff {
  lease: LeaseView;
  replaced: RevocationEvent | null;
}

export interface ApiClient {
  listDevices(): Promise<DeviceList>;
  deviceStatus(deviceId: string, userId: string): Promise<DeviceStatus>;
  acquireLease(deviceId: string, actorId: string): Promise<LeaseView>;
  handoffLease(
    deviceId: string,
    actorId: string,
    toUserId: string,
  ): Promise<LeaseHandoff>;
  revokeLease(leaseId: string, actorId: string): Promise<RevocationEvent>;
  /// Dispatches one management command. The actor is the server's `user_id`: the admin
  /// token carries no identity of its own.
  dispatchCommand(
    deviceId: string,
    userId: string,
    name: string,
    args?: unknown,
    timeoutMs?: number | null,
  ): Promise<CommandAccepted>;
  command(commandId: string, userId: string): Promise<CommandView>;
}

/// A refusal that names the status and stable machine code the server returned. A transport
/// failure is `status: 0, code: "network_unavailable"`, never an empty success.
export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
  ) {
    super(code);
    this.name = "ApiError";
  }
}

export interface HttpApiOptions {
  token: string;
  /// Same-origin by default: the native shell loads the server URL, so relative calls are
  /// the same calls a browser makes.
  baseUrl?: string;
  fetchImpl?: typeof fetch;
}

export function createHttpApi(options: HttpApiOptions): ApiClient {
  const baseUrl = options.baseUrl ?? "";
  const fetchImpl = options.fetchImpl ?? globalThis.fetch;

  async function request<T>(
    method: string,
    path: string,
    body?: unknown,
  ): Promise<T> {
    let response: Response;
    try {
      response = await fetchImpl(`${baseUrl}${path}`, {
        method,
        headers: {
          Accept: "application/json",
          "Content-Type": "application/json",
          Authorization: `Bearer ${options.token}`,
        },
        body: body === undefined ? undefined : JSON.stringify(body),
      });
    } catch {
      throw new ApiError(0, "network_unavailable");
    }
    if (!response.ok) {
      throw new ApiError(response.status, await errorCode(response));
    }
    if (response.status === 204) return undefined as T;
    return (await response.json()) as T;
  }

  return {
    listDevices: () => request<DeviceList>("GET", "/api/devices"),
    deviceStatus: (deviceId, userId) =>
      request<DeviceStatus>(
        "GET",
        `/api/devices/${encodeURIComponent(deviceId)}/status?user_id=${encodeURIComponent(userId)}`,
      ),
    acquireLease: (deviceId, actorId) =>
      request<LeaseView>("POST", `/api/devices/${encodeURIComponent(deviceId)}/lease`, {
        actor_id: actorId,
      }),
    handoffLease: (deviceId, actorId, toUserId) =>
      request<LeaseHandoff>(
        "POST",
        `/api/devices/${encodeURIComponent(deviceId)}/lease/handoff`,
        { actor_id: actorId, to_user_id: toUserId },
      ),
    revokeLease: (leaseId, actorId) =>
      request<RevocationEvent>(
        "POST",
        `/api/leases/${encodeURIComponent(leaseId)}/revoke`,
        { actor_id: actorId },
      ),
    dispatchCommand: (deviceId, userId, name, args, timeoutMs) =>
      request<CommandAccepted>(
        "POST",
        `/api/devices/${encodeURIComponent(deviceId)}/commands?user_id=${encodeURIComponent(userId)}`,
        { name, args: args ?? null, timeout_ms: timeoutMs ?? null },
      ),
    command: (commandId, userId) =>
      request<CommandView>(
        "GET",
        `/api/commands/${encodeURIComponent(commandId)}?user_id=${encodeURIComponent(userId)}`,
      ),
  };
}

async function errorCode(response: Response): Promise<string> {
  try {
    const body = (await response.json()) as { error?: unknown };
    if (typeof body.error === "string" && body.error.length > 0) {
      return body.error;
    }
  } catch {
    // A non-JSON refusal still has a status; the caller sees `http_<status>`.
  }
  return `http_${response.status}`;
}

export function asApiError(error: unknown): ApiError {
  if (error instanceof ApiError) return error;
  if (error instanceof Error) return new ApiError(0, error.message);
  return new ApiError(0, "unknown_failure");
}
