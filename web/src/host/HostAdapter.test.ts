import { afterEach, describe, expect, it, vi } from "vitest";

import { createHostAdapter } from "./HostAdapter";
import {
  HOST_BRIDGE_GLOBAL,
  HOST_CONTEXT_GLOBAL,
  IN_PAGE_NOTIFICATION_EVENT,
  readHostContext,
  type NativeHostContext,
} from "./hostContext";

type HostGlobals = Record<string, unknown>;
const globalsWindow = window as unknown as HostGlobals;

const nativeContext: NativeHostContext = {
  kind: "native",
  serverUrl: "https://phoneconnect.example",
  proxyCapabilities: [
    { deviceId: "dev_1", stream: "proxy", url: "http://127.0.0.1:49152" },
  ],
};

function installBridge(bridge: HostGlobals): void {
  globalsWindow[HOST_BRIDGE_GLOBAL] = bridge;
}

afterEach(() => {
  delete globalsWindow[HOST_CONTEXT_GLOBAL];
  delete globalsWindow[HOST_BRIDGE_GLOBAL];
  window.history.replaceState({}, "", "/");
});

describe("createHostAdapter", () => {
  it("is a browser host when the shell injected nothing", () => {
    expect(createHostAdapter().kind).toBe("browser");
    expect(createHostAdapter(undefined).kind).toBe("browser");
  });

  it("is a native host when the shell injected a host context", () => {
    expect(createHostAdapter(nativeContext).kind).toBe("native");
  });

  it("reads the injected context from the window and ignores a malformed one", () => {
    globalsWindow[HOST_CONTEXT_GLOBAL] = {
      kind: "native",
      serverUrl: "https://phoneconnect.example",
      proxyCapabilities: [],
    };
    expect(readHostContext()).toEqual({
      kind: "native",
      serverUrl: "https://phoneconnect.example",
      proxyCapabilities: [],
    });
    expect(createHostAdapter(readHostContext()).kind).toBe("native");

    globalsWindow[HOST_CONTEXT_GLOBAL] = { kind: "native" };
    expect(readHostContext()).toBeUndefined();
    expect(createHostAdapter(readHostContext()).kind).toBe("browser");
  });
});

describe("browserHost", () => {
  it("navigates in the SPA and ignores detached", async () => {
    const openWindow = vi.fn();
    installBridge({ openWindow });
    const host = createHostAdapter();

    await host.openView("/devices/dev_1", { detached: true });
    await host.openView("/devices/dev_1/telemetry", { detached: false });

    expect(window.location.pathname).toBe("/devices/dev_1/telemetry");
    expect(openWindow).not.toHaveBeenCalled();
  });

  it("shows a notification in the page because a browser has no OS tray", async () => {
    const host = createHostAdapter();
    const received = vi.fn();
    window.addEventListener(IN_PAGE_NOTIFICATION_EVENT, received);

    await host.notify({ title: "Lease revoked", body: "Control returned to the owner" });

    expect(received).toHaveBeenCalledTimes(1);
    const event = received.mock.calls[0][0] as CustomEvent;
    expect(event.detail).toEqual({
      title: "Lease revoked",
      body: "Control returned to the owner",
    });
    window.removeEventListener(IN_PAGE_NOTIFICATION_EVENT, received);
  });

  it("degrades tray state and local endpoints to explicit no-ops", async () => {
    const host = createHostAdapter();
    await expect(
      host.setTrayStatus({ label: "PhoneConnect", health: "connected" }),
    ).resolves.toBeUndefined();
    await expect(host.localEndpoints()).resolves.toEqual([]);
  });

  it("reports loopback endpoints as unavailable instead of a dead control", async () => {
    const host = createHostAdapter();
    expect(host.endpoints.available).toBe(false);
    if (host.endpoints.available) throw new Error("a browser must not expose endpoints");
    expect(host.endpoints.reason).toMatch(/native shell/);

    await expect(host.identityKey()).rejects.toThrow(/native shell/);
    await expect(
      host.openEndpoint({
        deviceId: "dev_1",
        stream: "adb",
        ttlSeconds: 30,
        session: { kind: "established", sessionId: "sess_1" },
      }),
    ).resolves.toEqual({
      status: "unavailable",
      reason: expect.stringMatching(/native shell/),
    });
    await expect(host.closeEndpoint("dev_1", "adb")).resolves.toEqual({
      status: "unavailable",
      reason: expect.stringMatching(/native shell/),
    });
    await expect(host.pendingTicketKey("sess_1", "cap")).resolves.toEqual({
      status: "unavailable",
      reason: expect.stringMatching(/native shell/),
    });
    await expect(host.trustTicketKey("sess_1", "cap")).resolves.toEqual({
      status: "unavailable",
      reason: expect.stringMatching(/native shell/),
    });
  });
});

describe("nativeHost", () => {
  it("opens exactly one detached OS window for a long-lived view", async () => {
    const openWindow = vi.fn(async () => {});
    installBridge({ openWindow });
    const host = createHostAdapter(nativeContext);

    await host.openView("/devices/dev_1/telemetry", { detached: true });

    expect(openWindow).toHaveBeenCalledTimes(1);
    expect(openWindow).toHaveBeenCalledWith("/devices/dev_1/telemetry");
    expect(window.location.pathname).toBe("/");
  });

  it("navigates the embedded webview for an in-page view", async () => {
    const openWindow = vi.fn();
    installBridge({ openWindow });
    const host = createHostAdapter(nativeContext);

    await host.openView("/devices/dev_1", { detached: false });

    expect(window.location.pathname).toBe("/devices/dev_1");
    expect(openWindow).not.toHaveBeenCalled();
  });

  it("degrades a detached view to in-page navigation when the bridge lacks it", async () => {
    const host = createHostAdapter(nativeContext);

    await host.openView("/devices/dev_1", { detached: true });

    expect(window.location.pathname).toBe("/devices/dev_1");
  });

  it("forwards tray state, notifications, and local endpoints", async () => {
    const setTrayStatus = vi.fn(async () => {});
    const notify = vi.fn(async () => {});
    installBridge({ setTrayStatus, notify });
    const host = createHostAdapter(nativeContext);

    await host.setTrayStatus({ label: "dev_1", health: "degraded", detail: "relay" });
    await host.notify({ title: "Stale", body: "No telemetry for 5 minutes" });

    expect(setTrayStatus).toHaveBeenCalledTimes(1);
    expect(setTrayStatus).toHaveBeenCalledWith({
      label: "dev_1",
      health: "degraded",
      detail: "relay",
    });
    expect(notify).toHaveBeenCalledTimes(1);
    expect(notify).toHaveBeenCalledWith({
      title: "Stale",
      body: "No telemetry for 5 minutes",
    });
    await expect(host.localEndpoints()).resolves.toEqual(
      nativeContext.proxyCapabilities,
    );
  });

  it("opens and closes an endpoint through the shell commands", async () => {
    const identityKey = vi.fn(async () => "shell-public-key");
    const openEndpoint = vi.fn(async () => ({
      deviceId: "dev_1",
      stream: "adb",
      url: "http://127.0.0.1:49152",
    }));
    const closeEndpoint = vi.fn(async () => true);
    installBridge({ identityKey, openEndpoint, closeEndpoint });
    const host = createHostAdapter(nativeContext);

    expect(host.endpoints.available).toBe(true);
    await expect(host.identityKey()).resolves.toBe("shell-public-key");

    const request = {
      deviceId: "dev_1",
      stream: "adb",
      ttlSeconds: 30,
      session: { kind: "established", sessionId: "sess_1" },
    } as const;
    await expect(host.openEndpoint(request)).resolves.toEqual({
      status: "opened",
      endpoint: {
        deviceId: "dev_1",
        stream: "adb",
        url: "http://127.0.0.1:49152",
      },
    });
    expect(openEndpoint).toHaveBeenCalledWith(request);
    await expect(host.closeEndpoint("dev_1", "adb")).resolves.toEqual({
      status: "closed",
      closed: true,
    });
    expect(closeEndpoint).toHaveBeenCalledWith("dev_1", "adb");
  });

  it("shows a server key rotation and pins it only after confirmation", async () => {
    const pendingTicketKey = vi.fn(async () => ({
      pinned: "old-key",
      current: "new-key",
    }));
    const trustTicketKey = vi.fn(async () => {});
    installBridge({ pendingTicketKey, trustTicketKey });
    const host = createHostAdapter(nativeContext);

    await expect(host.pendingTicketKey("sess_1", "cap")).resolves.toEqual({
      status: "pending",
      rotation: { pinned: "old-key", current: "new-key" },
    });
    expect(pendingTicketKey).toHaveBeenCalledWith("sess_1", "cap");
    await expect(host.trustTicketKey("sess_1", "cap")).resolves.toEqual({
      status: "trusted",
    });
    expect(trustTicketKey).toHaveBeenCalledWith("sess_1", "cap");
  });

  it("reports a refused rotation instead of claiming success", async () => {
    const trustTicketKey = vi.fn(async () => {
      throw new Error("the server key changed again");
    });
    installBridge({ trustTicketKey });
    const host = createHostAdapter(nativeContext);

    await expect(host.trustTicketKey("sess_1", "cap")).resolves.toEqual({
      status: "refused",
      reason: "the server key changed again",
    });
  });

  it("reports endpoint capability as unavailable when the shell lacks it", async () => {
    const host = createHostAdapter(nativeContext);
    expect(host.endpoints.available).toBe(false);
    await expect(
      host.openEndpoint({
        deviceId: "dev_1",
        stream: "adb",
        ttlSeconds: 30,
        session: { kind: "established", sessionId: "sess_1" },
      }),
    ).resolves.toEqual({
      status: "unavailable",
      reason: expect.stringMatching(/native shell/),
    });
    await expect(host.identityKey()).rejects.toThrow(/native shell/);
  });
});
