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

/// One entry of a directory listing, exactly as the device reported it. [path] is relative to
/// the device's shared root and is what the next file command takes.
export interface FileEntryView {
  name: string;
  path: string;
  is_dir: boolean;
  size_bytes: number;
  modified_ms: number;
}

/// `files.list` output: one directory's entries.
export interface FileListOutput {
  entries: FileEntryView[];
}

/// `files.read` output: one chunk of decoded bytes, and whether more remain.
export interface FileReadOutput {
  data_base64: string;
  truncated: boolean;
  name: string;
}

/// `files.write` output: how many bytes the device wrote.
export interface FileWriteOutput {
  bytes_written: number;
}

/// One installed app, exactly as the device reported it. A label the platform could not
/// resolve is the package name, never an invented one; [version_name] is absent on packages
/// that do not set it.
export interface AppEntryView {
  package: string;
  label: string;
  version_name: string | null;
  version_code: number;
  system: boolean;
  enabled: boolean;
  updated_ms: number;
}

/// `apps.list` output: the apps visible to the device's own UID.
export interface AppListOutput {
  apps: AppEntryView[];
}

/// `apps.launch` output: the platform accepted the start unless the command failed.
export interface AppLaunchOutput {
  package: string;
  launched: boolean;
}

/// `apps.stop` output: a kill Android was asked for, not a stop it confirmed.
export interface AppKillOutput {
  package: string;
  kill_requested: boolean;
}

/// `screen.snapshot` output: one PNG frame, the size it was actually captured at (the device
/// downscales to stay under the result cap), and when the frame was taken.
export interface ScreenSnapshotOutput {
  png_base64: string;
  width: number;
  height: number;
  captured_at_ms: number;
}

/// `system.props` output: the allowlisted properties the device reported. A property the
/// platform would not report is `null`, never an invented value.
export interface SystemPropsOutput {
  selected: Record<string, string | null>;
}

/// `control.get` output: one reading per key, `null` when the platform refused it, and the
/// constant reason for every key the device will not read or change. A key in [unavailable]
/// may still carry a reading: that means the value is known and it is the *change* that the
/// platform refuses.
export interface ControlReadingsOutput {
  brightness: number | null;
  brightness_mode: number | null;
  volume_music: number | null;
  volume_max: number | null;
  rotation: number | null;
  dnd_filter: number | null;
  night_mode: number | null;
  wifi_enabled: boolean | null;
  bluetooth_enabled: boolean | null;
  mobile_data_enabled: boolean | null;
  battery_saver: boolean | null;
  battery_percent: number | null;
  unavailable: Record<string, string>;
}

/// A value `control.set` accepts. The device validates the range and answers `invalid_args`
/// outside it; the panel never guesses a range the device did not report.
export type ControlValue = number | boolean;

/// `control.set` output: the change the device applied and confirmed by reading it back.
export interface ControlSetOutput {
  key: string;
  value: ControlValue;
  applied: boolean;
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
  /// The file commands. Each returns the accepted command id, which is polled like any other
  /// command: the device's own answer is the only result, and no content is stored here.
  listFiles(deviceId: string, userId: string, path: string): Promise<CommandAccepted>;
  readFile(
    deviceId: string,
    userId: string,
    path: string,
    offset?: number,
  ): Promise<CommandAccepted>;
  writeFile(
    deviceId: string,
    userId: string,
    path: string,
    dataBase64: string,
    append?: boolean,
  ): Promise<CommandAccepted>;
  createDirectory(
    deviceId: string,
    userId: string,
    path: string,
  ): Promise<CommandAccepted>;
  deleteEntry(deviceId: string, userId: string, path: string): Promise<CommandAccepted>;
  renameEntry(
    deviceId: string,
    userId: string,
    from: string,
    to: string,
  ): Promise<CommandAccepted>;
  /// The app commands. Each returns the accepted command id, which is polled like any other
  /// command: the device's own answer — including `launch_blocked` or `not_permitted` — is the
  /// only result.
  listApps(deviceId: string, userId: string): Promise<CommandAccepted>;
  launchApp(
    deviceId: string,
    userId: string,
    packageName: string,
  ): Promise<CommandAccepted>;
  stopApp(
    deviceId: string,
    userId: string,
    packageName: string,
  ): Promise<CommandAccepted>;
  clearApp(
    deviceId: string,
    userId: string,
    packageName: string,
  ): Promise<CommandAccepted>;
  setAppEnabled(
    deviceId: string,
    userId: string,
    packageName: string,
    enabled: boolean,
  ): Promise<CommandAccepted>;
  /// One screen frame. Without the consent the user granted on the device's setup screen the
  /// device answers `consent_required`; the screen renders that as an alert, never as a blank
  /// image. The frame is not stored anywhere: it exists in this response only.
  captureScreen(deviceId: string, userId: string): Promise<CommandAccepted>;
  /// The documented system properties, optionally narrowed to `keys`. A name outside the
  /// device's allowlist is its `not_permitted`.
  systemProperties(
    deviceId: string,
    userId: string,
    keys?: string[],
  ): Promise<CommandAccepted>;
  /// Device control. Each returns the accepted command id, polled like any other command: the
  /// device's readings, its refusals (`not_permitted` with a machine reason), and a change it
  /// did not keep (`not_applied`) are the only results.
  controlReadings(deviceId: string, userId: string): Promise<CommandAccepted>;
  setControl(
    deviceId: string,
    userId: string,
    key: string,
    value: ControlValue,
  ): Promise<CommandAccepted>;
  rebootDevice(deviceId: string, userId: string): Promise<CommandAccepted>;
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
    listFiles: (deviceId, userId, path) =>
      filesRequest(deviceId, userId, "list", { path }),
    readFile: (deviceId, userId, path, offset) =>
      filesRequest(deviceId, userId, "read", offset === undefined ? { path } : { path, offset }),
    writeFile: (deviceId, userId, path, dataBase64, append) =>
      filesRequest(deviceId, userId, "write", {
        path,
        data_base64: dataBase64,
        append: append ?? false,
      }),
    createDirectory: (deviceId, userId, path) =>
      filesRequest(deviceId, userId, "mkdir", { path }),
    deleteEntry: (deviceId, userId, path) =>
      filesRequest(deviceId, userId, "delete", { path }),
    renameEntry: (deviceId, userId, from, to) =>
      filesRequest(deviceId, userId, "rename", { from, to }),
    listApps: (deviceId, userId) => appsRequest(deviceId, userId, "list", {}),
    launchApp: (deviceId, userId, packageName) =>
      appsRequest(deviceId, userId, "launch", { package: packageName }),
    stopApp: (deviceId, userId, packageName) =>
      appsRequest(deviceId, userId, "stop", { package: packageName }),
    clearApp: (deviceId, userId, packageName) =>
      appsRequest(deviceId, userId, "clear", { package: packageName }),
    setAppEnabled: (deviceId, userId, packageName, enabled) =>
      appsRequest(deviceId, userId, "set_enabled", { package: packageName, enabled }),
    captureScreen: (deviceId, userId) =>
      request<CommandAccepted>(
        "POST",
        `/api/devices/${encodeURIComponent(deviceId)}/screen/snapshot?user_id=${encodeURIComponent(userId)}`,
        {},
      ),
    systemProperties: (deviceId, userId, keys) =>
      request<CommandAccepted>(
        "POST",
        `/api/devices/${encodeURIComponent(deviceId)}/console/props?user_id=${encodeURIComponent(userId)}`,
        keys === undefined ? {} : { keys },
      ),
    controlReadings: (deviceId, userId) =>
      controlRequest(deviceId, userId, "get", {}),
    setControl: (deviceId, userId, key, value) =>
      controlRequest(deviceId, userId, "set", { key, value }),
    rebootDevice: (deviceId, userId) => controlRequest(deviceId, userId, "reboot", {}),
  };

  function controlRequest(
    deviceId: string,
    userId: string,
    operation: string,
    body: unknown,
  ): Promise<CommandAccepted> {
    return request<CommandAccepted>(
      "POST",
      `/api/devices/${encodeURIComponent(deviceId)}/control/${operation}?user_id=${encodeURIComponent(userId)}`,
      body,
    );
  }

  function filesRequest(
    deviceId: string,
    userId: string,
    operation: string,
    body: unknown,
  ): Promise<CommandAccepted> {
    return request<CommandAccepted>(
      "POST",
      `/api/devices/${encodeURIComponent(deviceId)}/files/${operation}?user_id=${encodeURIComponent(userId)}`,
      body,
    );
  }

  function appsRequest(
    deviceId: string,
    userId: string,
    operation: string,
    body: unknown,
  ): Promise<CommandAccepted> {
    return request<CommandAccepted>(
      "POST",
      `/api/devices/${encodeURIComponent(deviceId)}/apps/${operation}?user_id=${encodeURIComponent(userId)}`,
      body,
    );
  }
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
