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
  TrayStatus,
} from "./hostContext";

export type { LocalEndpoint, NotificationInput, TrayStatus };

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
