import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import {
  ApiError,
  type ApiClient,
  type CommandAccepted,
  type CommandView,
} from "../api";
import { ConsoleRoute, LOGCAT_UNAVAILABLE, SHELL_UNAVAILABLE } from "./ConsoleRoute";

const NOW = 1_760_000_000_000;

const SELECTED = {
  sdk: "35",
  release: "15",
  model: "Pixel 8",
  manufacturer: "Google",
  build_id: "AP4A.250105.002",
  security_patch: null,
};

/// A fake transport whose `command` answers the terminal record of every accepted command.
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
    systemProperties: vi.fn(async () =>
      accept("system.props", { output: { selected: SELECTED } }),
    ),
    command: vi.fn(async (commandId: string) => {
      const record = records.get(commandId);
      if (!record) throw new Error(`unknown command ${commandId}`);
      return record;
    }),
  } as unknown as ApiClient & { systemProperties: ReturnType<typeof vi.fn> };

  return { api, accept };
}

function renderRoute(api: ApiClient) {
  render(
    <ConsoleRoute api={api} deviceId="dev_1" userId="owner-1" pollIntervalMs={1} />,
  );
}

describe("the console route", () => {
  it("renders the documented system properties the device reported", async () => {
    const { api } = fakeApi();
    renderRoute(api);

    expect(await screen.findByText("sdk")).toBeInTheDocument();
    expect(screen.getByText("35")).toBeInTheDocument();
    expect(screen.getByText("Pixel 8")).toBeInTheDocument();
    expect(screen.getByText("AP4A.250105.002")).toBeInTheDocument();
    // A property the platform would not report is absent, never invented.
    expect(screen.getByText("security_patch")).toBeInTheDocument();
    expect(screen.getByText(/not reported/i)).toBeInTheDocument();
    expect(api.systemProperties).toHaveBeenCalledWith("dev_1", "owner-1");
  });

  it("renders shell and logcat as unavailable with the device's reason, never as live controls", async () => {
    const { api } = fakeApi();
    renderRoute(api);

    const shell = await screen.findByRole("button", { name: /run shell command/i });
    expect(shell).toBeDisabled();
    expect(shell).toHaveAttribute("title", SHELL_UNAVAILABLE);
    expect(screen.getByText(SHELL_UNAVAILABLE)).toBeInTheDocument();

    const logcat = screen.getByRole("button", { name: /read logcat/i });
    expect(logcat).toBeDisabled();
    expect(logcat).toHaveAttribute("title", LOGCAT_UNAVAILABLE);
    expect(screen.getByText(LOGCAT_UNAVAILABLE)).toBeInTheDocument();

    // Neither refusal is dispatchable from the UI: nothing silently fails.
    expect(api.systemProperties).toHaveBeenCalledTimes(1);
  });

  it("renders a property refusal as an alert with its machine code", async () => {
    const { api, accept } = fakeApi();
    api.systemProperties = vi.fn(async () =>
      accept("system.props", {
        status: "error",
        output: null,
        error: "props_unavailable",
        message: "this build's platform does not expose its system-property reader through reflection, so no property can be reported",
      }),
    );
    renderRoute(api);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("props_unavailable");
    expect(screen.queryByText("sdk")).not.toBeInTheDocument();
  });

  it("never renders a stale property list when a reload fails", async () => {
    const { api, accept } = fakeApi();
    renderRoute(api);
    expect(await screen.findByText("sdk")).toBeInTheDocument();

    api.systemProperties = vi.fn(async () =>
      accept("system.props", {
        status: "error",
        output: null,
        error: "not_permitted",
        message: "only the documented system properties may be read",
      }),
    );
    await userEvent.click(screen.getByRole("button", { name: /refresh/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("not_permitted");
    expect(screen.queryByText("sdk")).not.toBeInTheDocument();
  });

  it("reports a refused dispatch as an alert with the server's code", async () => {
    const { api } = fakeApi();
    api.systemProperties = vi.fn(async () => {
      throw new ApiError(409, "device_offline");
    });
    renderRoute(api);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("device_offline");
  });

  it("refuses an answer that is not a property map as invalid_result", async () => {
    const { api, accept } = fakeApi();
    api.systemProperties = vi.fn(async () =>
      accept("system.props", { output: { selected: ["not", "a", "map"] } }),
    );
    renderRoute(api);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("invalid_result");
  });
});
