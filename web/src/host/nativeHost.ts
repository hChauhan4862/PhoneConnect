/// Native host: the shell may open a detached OS window, update its tray, show OS
/// notifications, and expose loopback endpoints. Every capability is optional; a shell that
/// provides none still gets a working page.

import { navigate } from "../routing";
import type { HostAdapter } from "./HostAdapter";
import {
  readHostBridge,
  type LocalEndpoint,
  type NativeHostContext,
} from "./hostContext";

export function createNativeHost(context: NativeHostContext): HostAdapter {
  return {
    kind: "native",

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
  };
}
