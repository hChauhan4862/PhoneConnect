/// The single documentation point for how a native shell tells the page it is not a browser.
///
/// The shell injects `window.__PHONECONNECT_HOST__` before the app loads. Absence of a valid
/// context is not an error: the page behaves as a browser. The shell also installs
/// `window.__PHONECONNECT_BRIDGE__` with the optional capabilities it can actually provide;
/// a missing capability degrades to the in-page equivalent instead of a dead control.

export const HOST_CONTEXT_GLOBAL = "__PHONECONNECT_HOST__";
export const HOST_BRIDGE_GLOBAL = "__PHONECONNECT_BRIDGE__";

/// Dispatched in a browser so a notification still reaches the user in the page.
export const IN_PAGE_NOTIFICATION_EVENT = "phoneconnect:notification";

export type HostKind = "browser" | "native";

/// A loopback endpoint the native shell exposes back to the page.
export interface LocalEndpoint {
  deviceId: string;
  stream: string;
  url: string;
}

export type TrayHealth =
  | "connected"
  | "degraded"
  | "disconnected"
  | "unknown";

export interface TrayStatus {
  label: string;
  health: TrayHealth;
  detail?: string;
}

export interface NotificationInput {
  title: string;
  body: string;
}

/// Injected by the native shell (Task 6's `web_shell::host_context`).
export interface NativeHostContext {
  kind: "native";
  serverUrl: string;
  proxyCapabilities: LocalEndpoint[];
}

/// Optional capabilities the native shell registers. Any absent method falls back to the
/// browser behavior for that one operation.
export interface NativeHostBridge {
  openWindow?(route: string): Promise<void> | void;
  setTrayStatus?(status: TrayStatus): Promise<void> | void;
  localEndpoints?(): Promise<LocalEndpoint[]> | LocalEndpoint[];
  notify?(input: NotificationInput): Promise<void> | void;
}

function globals(source: Window): Record<string, unknown> {
  return source as unknown as Record<string, unknown>;
}

function isLocalEndpoint(value: unknown): value is LocalEndpoint {
  if (!value || typeof value !== "object") return false;
  const endpoint = value as Partial<LocalEndpoint>;
  return (
    typeof endpoint.deviceId === "string" &&
    typeof endpoint.stream === "string" &&
    typeof endpoint.url === "string"
  );
}

/// Reads the injected context. Anything incomplete is treated as "no context" so a page can
/// never half-enable native behavior.
export function readHostContext(
  source: Window = window,
): NativeHostContext | undefined {
  const candidate = globals(source)[HOST_CONTEXT_GLOBAL];
  if (!candidate || typeof candidate !== "object") return undefined;
  const context = candidate as Partial<NativeHostContext>;
  if (context.kind !== "native") return undefined;
  if (typeof context.serverUrl !== "string" || context.serverUrl.length === 0) {
    return undefined;
  }
  return {
    kind: "native",
    serverUrl: context.serverUrl,
    proxyCapabilities: Array.isArray(context.proxyCapabilities)
      ? context.proxyCapabilities.filter(isLocalEndpoint)
      : [],
  };
}

/// Reads the shell's bridge at call time, so a shell that installs it after page load is
/// still honored.
export function readHostBridge(
  source: Window = window,
): NativeHostBridge | undefined {
  const candidate = globals(source)[HOST_BRIDGE_GLOBAL];
  if (!candidate || typeof candidate !== "object") return undefined;
  return candidate as NativeHostBridge;
}
