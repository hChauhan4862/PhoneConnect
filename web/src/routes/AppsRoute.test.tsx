import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import {
  ApiError,
  type ApiClient,
  type AppEntryView,
  type CommandAccepted,
  type CommandView,
} from "../api";
import { AppsRoute } from "./AppsRoute";

const NOW = 1_760_000_000_000;

function app(packageName: string, label: string, overrides: Partial<AppEntryView> = {}): AppEntryView {
  return {
    package: packageName,
    label,
    version_name: "1.0",
    version_code: 1,
    system: false,
    enabled: true,
    updated_ms: NOW,
    ...overrides,
  };
}

/// A fake transport whose `command` answers the terminal record of every accepted command, so
/// the screen sees exactly what a device would have answered.
function fakeApi() {
  const records = new Map<string, CommandView>();
  let nextId = 0;

  function accept(name: string, view: Partial<CommandView> = {}): CommandAccepted {
    nextId += 1;
    const command_id = `cmd_${nextId}`;
    records.set(command_id, {
      command_id,
      device_id: "dev_1",
      name,
      status: "ok",
      output: null,
      error: null,
      message: null,
      created_at_ms: NOW,
      completed_at_ms: NOW,
      ...view,
    });
    return { command_id };
  }

  const api = {
    listDevices: vi.fn(),
    deviceStatus: vi.fn(),
    acquireLease: vi.fn(),
    handoffLease: vi.fn(),
    revokeLease: vi.fn(),
    dispatchCommand: vi.fn(),
    command: vi.fn(async (commandId: string) => {
      const record = records.get(commandId);
      if (!record) throw new Error(`unknown command ${commandId}`);
      return record;
    }),
    listFiles: vi.fn(),
    readFile: vi.fn(),
    writeFile: vi.fn(),
    createDirectory: vi.fn(),
    deleteEntry: vi.fn(),
    renameEntry: vi.fn(),
    listApps: vi.fn(async () => accept("apps.list", { output: { apps: [] } })),
    launchApp: vi.fn(async () => accept("apps.launch", { output: { package: "com.example.zeta", launched: true } })),
    stopApp: vi.fn(async () => accept("apps.stop", { output: { package: "com.example.zeta", kill_requested: true } })),
    clearApp: vi.fn(async () => accept("apps.clear")),
    setAppEnabled: vi.fn(async () => accept("apps.set_enabled")),
  } as unknown as ApiClient & Record<string, ReturnType<typeof vi.fn>>;

  return { api, accept, records };
}

function renderRoute(api: ApiClient) {
  return render(<AppsRoute api={api} deviceId="dev_1" userId="user-a" pollIntervalMs={1} />);
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  const promise = new Promise<T>((res) => {
    resolve = res;
  });
  return { promise, resolve };
}

describe("the apps screen", () => {
  it("renders the device's listing and names its actions", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listApps = vi.fn(async () =>
      accept("apps.list", { output: { apps: [app("com.example.zeta", "Zeta")] } }),
    ) as never;

    renderRoute(api);

    const list = await screen.findByRole("list", { name: /installed apps/i });
    expect(within(list).getByText("Zeta")).toBeInTheDocument();
    expect(api.listApps).toHaveBeenCalledWith("dev_1", "user-a");

    await user.click(within(list).getByRole("button", { name: /launch zeta/i }));
    expect(api.launchApp).toHaveBeenCalledWith("dev_1", "user-a", "com.example.zeta");
    expect(await screen.findByText(/asked android to launch zeta/i)).toBeInTheDocument();
  });

  it("renders a server refusal as an alert with the machine code and no list", async () => {
    const { api } = fakeApi();
    api.listApps = vi.fn(async () => {
      throw new ApiError(409, "device_offline");
    }) as never;

    renderRoute(api);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("device_offline");
    expect(screen.queryByRole("list", { name: /installed apps/i })).toBeNull();
    expect(screen.queryByText(/no apps/i)).toBeNull();
  });

  it("renders the device's launch failure with its machine code", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listApps = vi.fn(async () =>
      accept("apps.list", { output: { apps: [app("com.example.zeta", "Zeta")] } }),
    ) as never;
    api.launchApp = vi.fn(async () =>
      accept("apps.launch", {
        status: "error",
        error: "launch_blocked",
        message: "background_activity_start_restricted",
      }),
    ) as never;

    renderRoute(api);

    const list = await screen.findByRole("list", { name: /installed apps/i });
    await user.click(within(list).getByRole("button", { name: /launch zeta/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("launch_blocked");
    expect(alert).toHaveTextContent(/background_activity_start_restricted/);
    expect(screen.queryByText(/asked android to launch/i)).toBeNull();
  });

  it("says what a stop requested, never that the app stopped", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listApps = vi.fn(async () =>
      accept("apps.list", { output: { apps: [app("com.example.zeta", "Zeta")] } }),
    ) as never;

    renderRoute(api);

    const list = await screen.findByRole("list", { name: /installed apps/i });
    await user.click(within(list).getByRole("button", { name: /stop zeta/i }));

    expect(api.stopApp).toHaveBeenCalledWith("dev_1", "user-a", "com.example.zeta");
    expect(
      await screen.findByText(/asked android to kill background processes for zeta/i),
    ).toBeInTheDocument();
    expect(screen.queryByText(/\bstopped\b/i)).toBeNull();
  });

  it("refuses a success whose output is not an app listing", async () => {
    const { api, accept } = fakeApi();
    api.listApps = vi.fn(async () =>
      accept("apps.list", { output: { apps: [{ package: "com.example.zeta" }] } }),
    ) as never;

    renderRoute(api);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("invalid_result");
    expect(screen.queryByRole("list", { name: /installed apps/i })).toBeNull();
  });

  it("reports a launch whose answer does not confirm the start as no success", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listApps = vi.fn(async () =>
      accept("apps.list", { output: { apps: [app("com.example.zeta", "Zeta")] } }),
    ) as never;
    api.launchApp = vi.fn(async () =>
      accept("apps.launch", { output: { package: "com.example.zeta" } }),
    ) as never;

    renderRoute(api);

    const list = await screen.findByRole("list", { name: /installed apps/i });
    await user.click(within(list).getByRole("button", { name: /launch zeta/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("invalid_result");
    expect(screen.queryByText(/asked android to launch/i)).toBeNull();
  });

  it("clears the old apps the moment a reload starts", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    const first = accept("apps.list", {
      output: { apps: [app("com.example.zeta", "Zeta")] },
    });
    const next = deferred<CommandAccepted>();
    let call = 0;
    api.listApps = vi.fn(async () => {
      call += 1;
      return call === 1 ? first : next.promise;
    }) as never;

    renderRoute(api);
    expect(await screen.findByText("Zeta")).toBeInTheDocument();

    await user.click(screen.getByRole("button", { name: /refresh/i }));
    // The previous answer must not survive the reload while the new one is pending.
    await waitFor(() => expect(screen.queryByText("Zeta")).toBeNull());
    expect(screen.getByText(/loading apps/i)).toBeInTheDocument();

    next.resolve(accept("apps.list", { output: { apps: [app("com.example.alpha", "Alpha")] } }));
    expect(await screen.findByText("Alpha")).toBeInTheDocument();
    expect(screen.queryByText("Zeta")).toBeNull();
  });

  it("drops a late answer for a query that was abandoned", async () => {
    const { api, accept } = fakeApi();
    const abandoned = deferred<CommandAccepted>();
    const current = deferred<CommandAccepted>();
    api.listApps = vi.fn(async (deviceId: string) =>
      deviceId === "dev_1" ? abandoned.promise : current.promise,
    ) as never;

    const { rerender } = render(
      <AppsRoute api={api} deviceId="dev_1" userId="user-a" pollIntervalMs={1} />,
    );
    await waitFor(() => expect(api.listApps).toHaveBeenCalledWith("dev_1", "user-a"));

    rerender(<AppsRoute api={api} deviceId="dev_2" userId="user-a" pollIntervalMs={1} />);
    current.resolve(
      accept("apps.list", { output: { apps: [app("com.example.alpha", "Alpha")] } }),
    );
    expect(await screen.findByText("Alpha")).toBeInTheDocument();

    // The abandoned query answers last; it must not replace the current listing.
    abandoned.resolve(
      accept("apps.list", { output: { apps: [app("com.example.beta", "Beta")] } }),
    );
    await waitFor(() => expect(screen.getByText("Alpha")).toBeInTheDocument());
    expect(screen.queryByText("Beta")).toBeNull();
  });

  it("treats a terminal device_offline after acceptance as unknown, and re-reads", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listApps = vi.fn(async () =>
      accept("apps.list", { output: { apps: [app("com.example.zeta", "Zeta")] } }),
    ) as never;
    api.launchApp = vi.fn(async () =>
      accept("apps.launch", {
        status: "error",
        output: null,
        error: "device_offline",
        message: "the management channel closed before the device answered",
      }),
    ) as never;

    renderRoute(api);
    const list = await screen.findByRole("list", { name: /installed apps/i });
    await user.click(within(list).getByRole("button", { name: /launch zeta/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("device_offline");
    // The launch was accepted, so it may have happened: never "did not do that".
    expect(alert).toHaveTextContent(/may not have completed that/i);
    expect(alert).not.toHaveTextContent(/did not do that/i);
    // The inventory is read again rather than left as it was before the attempt.
    await waitFor(() => expect(api.listApps).toHaveBeenCalledTimes(2));
  });

  it("keeps the refusal lead when the launch is refused before acceptance", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listApps = vi.fn(async () =>
      accept("apps.list", { output: { apps: [app("com.example.zeta", "Zeta")] } }),
    ) as never;
    api.launchApp = vi.fn(async () => {
      throw new ApiError(403, "lease_read_only");
    }) as never;

    renderRoute(api);
    const list = await screen.findByRole("list", { name: /installed apps/i });
    await user.click(within(list).getByRole("button", { name: /launch zeta/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("lease_read_only");
    // Nothing was dispatched, so this really is "did not do that".
    expect(alert).toHaveTextContent(/did not do that/i);
    expect(alert).not.toHaveTextContent(/may not have completed that/i);
    expect(api.listApps, "nothing landed, so the inventory is not re-read").toHaveBeenCalledTimes(
      1,
    );
  });

  it("says an empty listing is empty, not that the device has no apps it cannot see", async () => {
    const { api, accept } = fakeApi();
    api.listApps = vi.fn(async () => accept("apps.list", { output: { apps: [] } })) as never;

    renderRoute(api);

    expect(await screen.findByText(/the device reported no installed apps/i)).toBeInTheDocument();
    expect(screen.queryByRole("list", { name: /installed apps/i })).toBeNull();
  });
});
