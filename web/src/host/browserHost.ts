/// Browser host: in-page navigation and tabs only. There is no tray, no OS window, and no
/// local endpoint. Absent capabilities are reported as unavailable with a reason, never as a
/// silent success.

import { navigate } from "../routing";
import type {
  CloseEndpointResult,
  HostAdapter,
  OpenEndpointResult,
  TicketKeyRotationResult,
  TrustTicketKeyResult,
} from "./HostAdapter";
import { IN_PAGE_NOTIFICATION_EVENT } from "./hostContext";

const ENDPOINTS_UNAVAILABLE =
  "This is the web app; only the native shell can expose a loopback endpoint.";

export function createBrowserHost(): HostAdapter {
  return {
    kind: "browser",
    endpoints: { available: false, reason: ENDPOINTS_UNAVAILABLE },

    // A browser has no second window: the long-lived view opens in this tab.
    async openView(route: string): Promise<void> {
      navigate(route);
    },

    async setTrayStatus(): Promise<void> {
      // No tray exists in a browser.
    },

    async localEndpoints(): Promise<[]> {
      return [];
    },

    async identityKey(): Promise<string> {
      throw new Error(ENDPOINTS_UNAVAILABLE);
    },

    async openEndpoint(): Promise<OpenEndpointResult> {
      return { status: "unavailable", reason: ENDPOINTS_UNAVAILABLE };
    },

    async closeEndpoint(): Promise<CloseEndpointResult> {
      return { status: "unavailable", reason: ENDPOINTS_UNAVAILABLE };
    },

    async pendingTicketKey(): Promise<TicketKeyRotationResult> {
      return { status: "unavailable", reason: ENDPOINTS_UNAVAILABLE };
    },

    async trustTicketKey(): Promise<TrustTicketKeyResult> {
      return { status: "unavailable", reason: ENDPOINTS_UNAVAILABLE };
    },

    async notify(input): Promise<void> {
      // A browser shows notifications in the page, not through the OS.
      window.dispatchEvent(
        new CustomEvent(IN_PAGE_NOTIFICATION_EVENT, { detail: input }),
      );
    },
  };
}
