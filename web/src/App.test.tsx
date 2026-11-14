import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { App } from "./App";
import {
  ApiError,
  type ApiClient,
  type DeviceStatus,
  type LeaseView,
} from "./api";
import { HOST_BRIDGE_GLOBAL, HOST_CONTEXT_GLOBAL } from "./host/hostContext";
import { saveSession } from "./session";

type HostGlobals = Record<string, unknown>;
const globalsWindow = window as unknown as HostGlobals;

const NOW = 1_760_000_000_000;

const activeLease: LeaseView = {
  lease_id: "lease_1",
  device_id: "dev_1",
  owner_id: "owner-1",
  holder_id: "user-b",
  granted_by: "owner-1",
  acquired_at_ms: NOW,
  expires_at_ms: NOW + 600_000,
  revoked_at_ms: null,
  revoked_reason: null,
};

function statusFixture(overrides: Partial<DeviceStatus> = {}): DeviceStatus {
  return {
    device: {
      device_id: "dev_1",
      owner_id: "owner-1",
      enrolled_at_ms: NOW,
      revoked_at_ms: null,
      state: "enrolled",
    },
    session: {
      session_id: "sess_1",
      created_at_ms: NOW,
      expires_at_ms: NOW + 300_000,
      revoked_at_ms: null,
      state: "active",
      path: { state: "relay", relay_attached: true, direct_candidates: false },
      control_refusals: 0,
    },
    lease: {
      lease: activeLease,
      access: {
        user_id: "owner-1",
        is_owner: true,
        role: "viewer",
        can_control: false,
      },
    },
    telemetry: {
      freshness: "stale",
      age_ms: 300_000,
      sampled_at_ms: NOW - 300_000,
      latest: {
        sampled_at_ms: NOW - 300_000,
        cpu_percent: 12.5,
        memory_used_bytes: 1_048_576,
        memory_total_bytes: 8_388_608,
        battery_percent: 64,
        battery_charging: true,
        connectivity: "wifi",
      },
      aggregate: {
        device_id: "dev_1",
        samples_received: 12,
        window_samples: 12,
        window_ms: 60_000,
        first_received_ms: NOW - 360_000,
        last_received_ms: NOW - 300_000,
        latest: {
          sampled_at_ms: NOW - 300_000,
          cpu_percent: 12.5,
          memory_used_bytes: 1_048_576,
          memory_total_bytes: 8_388_608,
          battery_percent: 64,
          battery_charging: true,
          connectivity: "wifi",
        },
        window_cpu_percent: { min: 5, max: 20, mean: 10.5, latest: 12.5 },
        window_memory_percent: { min: 10, max: 20, mean: 12.5, latest: 12.5 },
        window_battery_percent: { min: 60, max: 70, mean: 64, latest: 64 },
      },
    },
    ...overrides,
  };
}

function createFakeApi(status: DeviceStatus | (() => Promise<DeviceStatus>)): ApiClient {
  return {
    listDevices: vi.fn(async () => ({ devices: [statusFixture().device] })),
    deviceStatus: vi.fn(
      typeof status === "function" ? status : async () => status,
    ),
    acquireLease: vi.fn(async () => activeLease),
    handoffLease: vi.fn(async () => ({ lease: activeLease, replaced: null })),
    revokeLease: vi.fn(async () => ({
      lease_id: activeLease.lease_id,
      device_id: activeLease.device_id,
      actor_id: "owner-1",
      revoked_at_ms: NOW,
      reason: "revoked" as const,
      invalidated_sessions: [],
    })),
    dispatchCommand: vi.fn(async () => ({ command_id: "cmd_1" })),
    listFiles: vi.fn(async () => ({ command_id: "cmd_1" })),
    readFile: vi.fn(async () => ({ command_id: "cmd_1" })),
    writeFile: vi.fn(async () => ({ command_id: "cmd_1" })),
    createDirectory: vi.fn(async () => ({ command_id: "cmd_1" })),
    deleteEntry: vi.fn(async () => ({ command_id: "cmd_1" })),
    renameEntry: vi.fn(async () => ({ command_id: "cmd_1" })),
    listApps: vi.fn(async () => ({ command_id: "cmd_1" })),
    launchApp: vi.fn(async () => ({ command_id: "cmd_1" })),
    stopApp: vi.fn(async () => ({ command_id: "cmd_1" })),
    clearApp: vi.fn(async () => ({ command_id: "cmd_1" })),
    setAppEnabled: vi.fn(async () => ({ command_id: "cmd_1" })),
    captureScreen: vi.fn(async () => ({ command_id: "cmd_1" })),
    systemProperties: vi.fn(async () => ({ command_id: "cmd_1" })),
    command: vi.fn(async () => ({
      command_id: "cmd_1",
      device_id: "dev_1",
      name: "device.info",
      status: "pending" as const,
      output: null,
      error: null,
      message: null,
      created_at_ms: NOW,
      completed_at_ms: null,
    })),
  };
}

function installHost(kind: "browser" | "native"): void {
  if (kind === "native") {
    globalsWindow[HOST_CONTEXT_GLOBAL] = {
      kind: "native",
      serverUrl: "https://phoneconnect.example",
      proxyCapabilities: [],
    };
  }
}

function installBridge(bridge: HostGlobals): void {
  globalsWindow[HOST_BRIDGE_GLOBAL] = bridge;
}

function renderApp(api: ApiClient, path = "/devices/dev_1"): void {
  window.history.replaceState({}, "", path);
  render(<App api={api} />);
}

beforeEach(() => {
  saveSession({ token: "admin-token", userId: "owner-1" });
});

afterEach(() => {
  window.sessionStorage.clear();
  delete globalsWindow[HOST_CONTEXT_GLOBAL];
  delete globalsWindow[HOST_BRIDGE_GLOBAL];
  window.history.replaceState({}, "", "/");
  vi.restoreAllMocks();
});

describe("the status screen", () => {
  it.each(["browser", "native"] as const)(
    "renders enrollment, relay path, controller, and stale telemetry under %s",
    async (kind) => {
      installHost(kind);
      renderApp(createFakeApi(statusFixture()));

      expect(
        await screen.findByRole("heading", { name: /dev_1/ }),
      ).toBeInTheDocument();
      expect(screen.getByText("Enrolled", { selector: "strong" })).toBeInTheDocument();
      expect(screen.getByText("Relay attached")).toBeInTheDocument();
      expect(screen.getByText(/Controlled by user-b/)).toBeInTheDocument();
      expect(screen.getByText(/Telemetry stale/)).toBeInTheDocument();
      expect(screen.getByText(/5m ago/)).toBeInTheDocument();
      // The screen does not stream: it reads a snapshot and must say so.
      expect(screen.getByText(/not live/i)).toBeInTheDocument();
      // A stale reading is shown, but never labelled fresh.
      expect(screen.queryByText(/Telemetry fresh/)).not.toBeInTheDocument();
    },
  );

  it("shows a direct-ready path when both peers published endpoints", async () => {
    installHost("browser");
    const fixture = statusFixture();
    fixture.session.path = {
      state: "direct_ready",
      relay_attached: false,
      direct_candidates: true,
    };
    renderApp(createFakeApi(fixture));

    expect(await screen.findByText("Direct path ready")).toBeInTheDocument();
    expect(screen.queryByText("Relay attached")).not.toBeInTheDocument();
  });

  it("reports refused control attempts on a read-only session", async () => {
    installHost("browser");
    const fixture = statusFixture();
    fixture.session = { ...fixture.session, control_refusals: 2 };
    renderApp(createFakeApi(fixture));

    expect(
      await screen.findByText(/2 control attempts were refused/i),
    ).toBeInTheDocument();
  });

  it("reports a revoked session and missing telemetry explicitly", async () => {
    installHost("browser");
    const fixture = statusFixture();
    fixture.session = {
      session_id: "sess_1",
      created_at_ms: NOW,
      expires_at_ms: NOW,
      revoked_at_ms: NOW,
      state: "revoked",
      path: {
        state: "none",
        relay_attached: false,
        direct_candidates: false,
      },
      control_refusals: 0,
    };
    fixture.telemetry = {
      freshness: "missing",
      age_ms: null,
      sampled_at_ms: null,
      latest: null,
      aggregate: null,
    };
    fixture.lease = {
      lease: null,
      access: {
        user_id: "owner-1",
        is_owner: true,
        role: "viewer",
        can_control: false,
      },
    };
    renderApp(createFakeApi(fixture));

    expect(await screen.findByText("Session revoked")).toBeInTheDocument();
    expect(screen.getByText("No telemetry reported")).toBeInTheDocument();
    expect(screen.getByText("No active controller")).toBeInTheDocument();
    expect(screen.queryByText(/Connected/)).not.toBeInTheDocument();
  });

  it("renders a permission error instead of a success-shaped device", async () => {
    installHost("browser");
    const api = createFakeApi(statusFixture());
    api.deviceStatus = vi.fn(async () => {
      throw new ApiError(401, "invalid_admin_token");
    });
    renderApp(api);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/Permission denied/);
    expect(alert).toHaveTextContent(/invalid_admin_token/);
    expect(screen.queryByText("Relay attached")).not.toBeInTheDocument();
    expect(screen.queryByText(/Controlled by/)).not.toBeInTheDocument();
  });

  it("offers a retry when the server cannot be reached", async () => {
    installHost("browser");
    let attempts = 0;
    const api = createFakeApi(async () => {
      attempts += 1;
      if (attempts === 1) {
        throw new ApiError(0, "network_unavailable");
      }
      return statusFixture();
    });
    renderApp(api);

    expect(
      await screen.findByText(/Could not reach the server/),
    ).toBeInTheDocument();
    await userEvent.click(screen.getByRole("button", { name: /retry/i }));
    expect(
      await screen.findByRole("heading", { name: /dev_1/ }),
    ).toBeInTheDocument();
  });
});

describe("the host adapter in the screen", () => {
  it("keeps native-only controls out of a browser and navigates in-page instead", async () => {
    installHost("browser");
    const openWindow = vi.fn();
    installBridge({ openWindow });
    renderApp(createFakeApi(statusFixture()));

    const inPage = await screen.findByRole("button", {
      name: "Open telemetry view",
    });
    expect(
      screen.queryByRole("button", {
        name: "Open telemetry view in a detached window",
      }),
    ).not.toBeInTheDocument();

    await userEvent.click(inPage);
    expect(window.location.pathname).toBe("/devices/dev_1/telemetry");
    expect(openWindow).not.toHaveBeenCalled();
  });

  it("opens the detached window exactly once under nativeHost", async () => {
    installHost("native");
    const openWindow = vi.fn(async () => {});
    installBridge({ openWindow });
    renderApp(createFakeApi(statusFixture()));

    await userEvent.click(
      await screen.findByRole("button", {
        name: "Open telemetry view in a detached window",
      }),
    );

    expect(openWindow).toHaveBeenCalledTimes(1);
    expect(openWindow).toHaveBeenCalledWith("/devices/dev_1/telemetry");
    expect(window.location.pathname).toBe("/devices/dev_1");
    // The additive control does not replace the in-page one.
    expect(
      screen.getByRole("button", { name: "Open telemetry view" }),
    ).toBeInTheDocument();
  });
});

describe("the lease surface", () => {
  it("lets the owner take control when no lease is held", async () => {
    installHost("browser");
    const withoutLease = statusFixture();
    withoutLease.lease = {
      lease: null,
      access: {
        user_id: "owner-1",
        is_owner: true,
        role: "viewer",
        can_control: false,
      },
    };
    let served = withoutLease;
    const api = createFakeApi(async () => served);
    api.acquireLease = vi.fn(async () => {
      served = statusFixture();
      return activeLease;
    });
    renderApp(api);

    await userEvent.click(
      await screen.findByRole("button", { name: "Take control" }),
    );

    await waitFor(() => expect(api.acquireLease).toHaveBeenCalledTimes(1));
    expect(api.acquireLease).toHaveBeenCalledWith("dev_1", "owner-1");
    expect(await screen.findByText(/Controlled by user-b/)).toBeInTheDocument();
  });

  it("lets the owner revoke a handoff and take control back", async () => {
    installHost("browser");
    let served = statusFixture();
    served.lease = {
      lease: activeLease,
      access: {
        user_id: "owner-1",
        is_owner: true,
        role: "viewer",
        can_control: false,
      },
    };
    const api = createFakeApi(async () => served);
    api.revokeLease = vi.fn(async () => {
      served = statusFixture();
      served.lease = {
        lease: null,
        access: {
          user_id: "owner-1",
          is_owner: true,
          role: "viewer",
          can_control: false,
        },
      };
      return {
        lease_id: activeLease.lease_id,
        device_id: activeLease.device_id,
        actor_id: "owner-1",
        revoked_at_ms: NOW,
        reason: "revoked" as const,
        invalidated_sessions: [],
      };
    });
    api.acquireLease = vi.fn(async () => {
      served = statusFixture();
      served.lease = {
        lease: { ...activeLease, holder_id: "owner-1" },
        access: {
          user_id: "owner-1",
          is_owner: true,
          role: "controller",
          can_control: true,
        },
      };
      return served.lease.lease as LeaseView;
    });
    renderApp(api);

    // The owner does not hold the lease, but is not read-only: the server lets the owner
    // revoke, so the panel must offer it.
    expect(
      await screen.findByText("Owner — you can revoke this lease"),
    ).toBeInTheDocument();
    await userEvent.click(
      screen.getByRole("button", { name: "Release control" }),
    );
    await waitFor(() => expect(api.revokeLease).toHaveBeenCalledTimes(1));
    expect(api.revokeLease).toHaveBeenCalledWith("lease_1", "owner-1");

    // Once the lease is gone, the owner can take control again.
    await userEvent.click(
      await screen.findByRole("button", { name: "Take control" }),
    );
    await waitFor(() => expect(api.acquireLease).toHaveBeenCalledTimes(1));
    expect(api.acquireLease).toHaveBeenCalledWith("dev_1", "owner-1");
    expect(
      await screen.findByText("You control this device"),
    ).toBeInTheDocument();
  });

  it("offers no control action for a revoked device", async () => {
    installHost("browser");
    const fixture = statusFixture();
    fixture.device = {
      ...fixture.device,
      state: "revoked",
      revoked_at_ms: NOW,
    };
    fixture.session = {
      session_id: null,
      created_at_ms: null,
      expires_at_ms: null,
      revoked_at_ms: null,
      state: "none",
      path: { state: "none", relay_attached: false, direct_candidates: false },
      control_refusals: 0,
    };
    fixture.lease = {
      lease: null,
      access: {
        user_id: "owner-1",
        is_owner: true,
        role: "viewer",
        can_control: false,
      },
    };
    renderApp(createFakeApi(fixture));

    expect(
      await screen.findByText("Revoked", { selector: "strong" }),
    ).toBeInTheDocument();
    expect(
      screen.getByText(/Control cannot be granted for a revoked device/),
    ).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Take control" }),
    ).not.toBeInTheDocument();
  });

  it("shows read-only access and no control action for a secondary viewer", async () => {
    installHost("browser");
    const fixture = statusFixture();
    fixture.lease.access = {
      user_id: "owner-1",
      is_owner: false,
      role: "viewer",
      can_control: false,
    };
    renderApp(createFakeApi(fixture));

    expect(await screen.findByText("Read-only access")).toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Take control" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Release control" }),
    ).not.toBeInTheDocument();
    expect(
      screen.queryByRole("button", { name: "Hand off control" }),
    ).not.toBeInTheDocument();
  });

  it("releases control through the lease API and shows the explicit result", async () => {
    installHost("browser");
    const controlled = statusFixture();
    controlled.lease = {
      lease: activeLease,
      access: {
        user_id: "owner-1",
        is_owner: true,
        role: "controller",
        can_control: true,
      },
    };
    let served = controlled;
    const api = createFakeApi(async () => served);
    api.revokeLease = vi.fn(async () => {
      served = statusFixture();
      served.lease = {
        lease: null,
        access: {
          user_id: "owner-1",
          is_owner: true,
          role: "viewer",
          can_control: false,
        },
      };
      return {
        lease_id: activeLease.lease_id,
        device_id: activeLease.device_id,
        actor_id: "owner-1",
        revoked_at_ms: NOW,
        reason: "revoked" as const,
        invalidated_sessions: [],
      };
    });
    renderApp(api);

    await userEvent.click(
      await screen.findByRole("button", { name: "Release control" }),
    );

    await waitFor(() => expect(api.revokeLease).toHaveBeenCalledTimes(1));
    expect(api.revokeLease).toHaveBeenCalledWith("lease_1", "owner-1");
    expect(await screen.findByText("No active controller")).toBeInTheDocument();
  });
});

describe("the command console route", () => {
  it("renders the command panel at the device's commands path", async () => {
    installHost("browser");
    const api = createFakeApi(statusFixture());
    renderApp(api, "/devices/dev_1/commands");

    expect(
      await screen.findByRole("heading", { name: /^commands$/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /run command/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /back to status/i }),
    ).toHaveAttribute("href", "/devices/dev_1");
  });
});

describe("the file browser route", () => {
  it("renders the file browser at the device's files path", async () => {
    installHost("browser");
    renderApp(createFakeApi(statusFixture()), "/devices/dev_1/files");

    expect(
      await screen.findByRole("heading", { name: /^files$/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /back to status/i }),
    ).toHaveAttribute("href", "/devices/dev_1");
  });
});

describe("the apps screen route", () => {
  it("renders the apps screen at the device's apps path", async () => {
    installHost("browser");
    const api = createFakeApi(statusFixture());
    renderApp(api, "/devices/dev_1/apps");

    expect(
      await screen.findByRole("heading", { name: /^apps$/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("link", { name: /back to status/i }),
    ).toHaveAttribute("href", "/devices/dev_1");
  });
});

describe("the screen and console routes", () => {
  it("renders the screen page at the device's screen path without capturing on its own", async () => {
    installHost("browser");
    const api = createFakeApi(statusFixture());
    renderApp(api, "/devices/dev_1/screen");

    expect(
      await screen.findByRole("heading", { name: /^screen$/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /capture screen/i }),
    ).toBeInTheDocument();
    expect(api.captureScreen).not.toHaveBeenCalled();
    expect(
      screen.getByRole("link", { name: /back to status/i }),
    ).toHaveAttribute("href", "/devices/dev_1");
  });

  it("renders the console page at the device's console path", async () => {
    installHost("browser");
    const api = createFakeApi(statusFixture());
    renderApp(api, "/devices/dev_1/console");

    expect(
      await screen.findByRole("heading", { name: /^console$/i }),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /read logcat/i }),
    ).toBeDisabled();
    expect(
      screen.getByRole("link", { name: /back to status/i }),
    ).toHaveAttribute("href", "/devices/dev_1");
  });

  it("links to both screens from the status page", async () => {
    installHost("browser");
    renderApp(createFakeApi(statusFixture()));

    expect(
      await screen.findByRole("link", { name: /screen snapshot/i }),
    ).toHaveAttribute("href", "/devices/dev_1/screen");
    expect(
      screen.getByRole("link", { name: /system properties and console/i }),
    ).toHaveAttribute("href", "/devices/dev_1/console");
  });
});

describe("the access gate", () => {
  it("asks for an admin token when no session is stored", () => {
    window.sessionStorage.clear();
    installHost("browser");
    const api = createFakeApi(statusFixture());
    renderApp(api, "/");

    expect(
      screen.getByRole("heading", { name: /sign in/i }),
    ).toBeInTheDocument();
    expect(api.deviceStatus).not.toHaveBeenCalled();
  });
});
