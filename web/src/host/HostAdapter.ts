/// The only place browser/native differences live.
///
/// Screens call this interface, never `window` or a bridge directly. `createHostAdapter`
/// is the explicit selection point: a shell-injected context means native, and its absence
/// means browser.

import { createContext, useContext } from "react";

import { createBrowserHost } from "./browserHost";
import { createNativeHost } from "./nativeHost";
import type {
  LocalEndpoint,
  NativeHostContext,
  NotificationInput,
  ProxyEndpointRequest,
  TicketKeyRotation,
  TrayStatus,
} from "./hostContext";

export type {
  LocalEndpoint,
  NotificationInput,
  ProxyEndpointRequest,
  TicketKeyRotation,
  TrayStatus,
};

/// Whether this host can expose loopback endpoints at all. A browser says no with a reason,
/// so a screen can explain the absence instead of rendering a control that cannot work.
export type EndpointCapability =
  | { available: true }
  | { available: false; reason: string };

/// The result of asking for an endpoint. "unavailable" is explicit; a browser never reports
/// a silent success.
export type OpenEndpointResult =
  | { status: "opened"; endpoint: LocalEndpoint }
  | { status: "unavailable"; reason: string };

export type CloseEndpointResult =
  | { status: "closed"; closed: boolean }
  | { status: "unavailable"; reason: string };

export type TicketKeyRotationResult =
  | { status: "pending"; rotation: TicketKeyRotation }
  | { status: "unavailable"; reason: string };

export type TrustTicketKeyResult =
  | { status: "trusted" }
  | { status: "refused"; reason: string }
  | { status: "unavailable"; reason: string };

export interface OpenViewOptions {
  /// A detached view becomes a separate OS window under a native host.
  detached: boolean;
}

export interface HostAdapter {
  readonly kind: "browser" | "native";
  openView(route: string, options: OpenViewOptions): Promise<void>;
  setTrayStatus(status: TrayStatus): Promise<void>;
  localEndpoints(): Promise<LocalEndpoint[]>;
  notify(input: NotificationInput): Promise<void>;
  /// Whether this host can open a loopback endpoint. A browser reports `available: false`.
  readonly endpoints: EndpointCapability;
  /// The shell's public identity key. A browser has none and rejects, never fabricates one.
  identityKey(): Promise<string>;
  openEndpoint(request: ProxyEndpointRequest): Promise<OpenEndpointResult>;
  closeEndpoint(deviceId: string, stream: string): Promise<CloseEndpointResult>;
  /// The server key rotation awaiting confirmation, or unavailable when the host has no pin.
  pendingTicketKey(
    sessionId: string,
    capability: string,
  ): Promise<TicketKeyRotationResult>;
  /// Asks for a native confirmation and pins the key only if the user approves.
  trustTicketKey(
    sessionId: string,
    capability: string,
  ): Promise<TrustTicketKeyResult>;
}

export function createHostAdapter(context?: NativeHostContext): HostAdapter {
  return context?.kind === "native"
    ? createNativeHost(context)
    : createBrowserHost();
}

export const HostAdapterContext = createContext<HostAdapter | null>(null);

export function useHostAdapter(): HostAdapter {
  const adapter = useContext(HostAdapterContext);
  if (!adapter) {
    throw new Error("useHostAdapter must be used inside HostAdapterContext");
  }
  return adapter;
}
