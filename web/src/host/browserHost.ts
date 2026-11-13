/// Browser host: in-page navigation and tabs only. There is no tray, no OS window, and no
/// local endpoint, so those operations resolve as explicit no-ops rather than failures.

import { navigate } from "../routing";
import type { HostAdapter } from "./HostAdapter";
import { IN_PAGE_NOTIFICATION_EVENT } from "./hostContext";

export function createBrowserHost(): HostAdapter {
  return {
    kind: "browser",

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

    async notify(input): Promise<void> {
      // A browser shows notifications in the page, not through the OS.
      window.dispatchEvent(
        new CustomEvent(IN_PAGE_NOTIFICATION_EVENT, { detail: input }),
      );
    },
  };
}
