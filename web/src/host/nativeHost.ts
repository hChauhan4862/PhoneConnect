/// Native host: the shell may open a detached OS window, update its tray, show OS
/// notifications, and expose loopback endpoints. Every capability is optional; a shell that
/// provides none still gets a working page.

import { navigate } from "../routing";
import type {
  CloseEndpointResult,
  EndpointCapability,
  HostAdapter,
  OpenEndpointResult,
  TicketKeyRotationResult,
  TrustTicketKeyResult,
} from "./HostAdapter";
import {
  readHostBridge,
  type LocalEndpoint,
  type NativeHostBridge,
  type NativeHostContext,
  type ProxyEndpointRequest,
} from "./hostContext";

const ENDPOINTS_UNAVAILABLE =
  "This native shell does not expose loopback endpoints.";

/// A native host can expose endpoints only when the shell installed all three commands.
function endpointCapability(
  bridge: NativeHostBridge | undefined,
): EndpointCapability {
  return bridge?.identityKey && bridge.openEndpoint && bridge.closeEndpoint
    ? { available: true }
    : { available: false, reason: ENDPOINTS_UNAVAILABLE };
}

export function createNativeHost(context: NativeHostContext): HostAdapter {
  return {
    kind: "native",

    // Read at call time like every other bridge capability, so a shell that installs the
    // bridge late is still honored.
    get endpoints(): EndpointCapability {
      return endpointCapability(readHostBridge());
    },

    // A detached view is a separate OS window; an attached one is the embedded webview.
    // Without a bridge this degrades to in-page navigation, never to a dead control.
    async openView(route: string, options: { detached: boolean }): Promise<void> {
      const bridge = readHostBridge();
      if (options.detached && bridge?.openWindow) {
        await bridge.openWindow(route);
        return;
      }
      navigate(route);
    },

    async setTrayStatus(status): Promise<void> {
      await readHostBridge()?.setTrayStatus?.(status);
    },

    async localEndpoints(): Promise<LocalEndpoint[]> {
      const bridge = readHostBridge();
      if (bridge?.localEndpoints) {
        return bridge.localEndpoints();
      }
      return context.proxyCapabilities;
    },

    async notify(input): Promise<void> {
      await readHostBridge()?.notify?.(input);
    },

    async identityKey(): Promise<string> {
      const bridge = readHostBridge();
      if (!bridge?.identityKey) {
        throw new Error(ENDPOINTS_UNAVAILABLE);
      }
      return bridge.identityKey();
    },

    async openEndpoint(request: ProxyEndpointRequest): Promise<OpenEndpointResult> {
      const bridge = readHostBridge();
      if (!bridge?.openEndpoint) {
        return { status: "unavailable", reason: ENDPOINTS_UNAVAILABLE };
      }
      return { status: "opened", endpoint: await bridge.openEndpoint(request) };
    },

    async closeEndpoint(
      deviceId: string,
      stream: string,
    ): Promise<CloseEndpointResult> {
      const bridge = readHostBridge();
      if (!bridge?.closeEndpoint) {
        return { status: "unavailable", reason: ENDPOINTS_UNAVAILABLE };
      }
      return { status: "closed", closed: await bridge.closeEndpoint(deviceId, stream) };
    },

    async pendingTicketKey(
      sessionId: string,
      capability: string,
    ): Promise<TicketKeyRotationResult> {
      const bridge = readHostBridge();
      if (!bridge?.pendingTicketKey) {
        return { status: "unavailable", reason: ENDPOINTS_UNAVAILABLE };
      }
      return {
        status: "pending",
        rotation: await bridge.pendingTicketKey(sessionId, capability),
      };
    },

    async trustTicketKey(
      expectedCurrent: string,
      sessionId: string,
      capability: string,
    ): Promise<TrustTicketKeyResult> {
      const bridge = readHostBridge();
      if (!bridge?.trustTicketKey) {
        return { status: "unavailable", reason: ENDPOINTS_UNAVAILABLE };
      }
      try {
        await bridge.trustTicketKey(expectedCurrent, sessionId, capability);
        return { status: "trusted" };
      } catch (error) {
        // The shell refuses a key that changed after the user looked; say so instead of
        // reporting success.
        return {
          status: "refused",
          reason: error instanceof Error ? error.message : String(error),
        };
      }
    },
  };
}
