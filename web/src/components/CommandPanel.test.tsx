import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ApiError, type ApiClient, type CommandView } from "../api";
import { CommandPanel } from "./CommandPanel";

const NOW = 1_760_000_000_000;

function commandView(overrides: Partial<CommandView> = {}): CommandView {
  return {
    command_id: "cmd_1",
    device_id: "dev_1",
    name: "device.info",
    status: "ok",
    output: null,
    error: null,
    message: null,
    created_at_ms: NOW,
    completed_at_ms: NOW + 20,
    ...overrides,
  };
}

/// Only the two command calls matter here; the rest of the surface is never reached.
function fakeApi(overrides: Partial<ApiClient>): ApiClient {
  return {
    listDevices: vi.fn(),
    deviceStatus: vi.fn(),
    acquireLease: vi.fn(),
    handoffLease: vi.fn(),
    revokeLease: vi.fn(),
    dispatchCommand: vi.fn(),
    command: vi.fn(),
    ...overrides,
  } as unknown as ApiClient;
}

function renderPanel(api: ApiClient) {
  return render(
    <CommandPanel
      api={api}
      deviceId="dev_1"
      userId="user-a"
      pollIntervalMs={1}
    />,
  );
}

describe("the command panel", () => {
  it("posts the command and renders the device's ok output", async () => {
    const user = userEvent.setup();
    const api = fakeApi({
      dispatchCommand: vi.fn(async () => ({ command_id: "cmd_1" })),
      command: vi.fn(async () =>
        commandView({ output: { model: "Pixel 8", sdk: 35 } }),
      ),
    });

    renderPanel(api);
    await user.click(screen.getByRole("button", { name: /run command/i }));

    const output = await screen.findByTestId("command-output");
    expect(output).toHaveTextContent("Pixel 8");
    expect(document.querySelector('[data-status="ok"]')).not.toBeNull();
    expect(api.dispatchCommand).toHaveBeenCalledWith(
      "dev_1",
      "user-a",
      "device.info",
      null,
      null,
    );
  });

  it("renders device_offline as an explicit error and never as success", async () => {
    const user = userEvent.setup();
    const api = fakeApi({
      dispatchCommand: vi.fn(async () => {
        throw new ApiError(409, "device_offline");
      }),
    });

    renderPanel(api);
    await user.click(screen.getByRole("button", { name: /run command/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("device_offline");
    expect(alert).toHaveTextContent(/not connected/i);
    expect(screen.queryByTestId("command-output")).toBeNull();
    expect(document.querySelector('[data-status="ok"]')).toBeNull();
    expect(api.command, "the command was refused, so nothing is polled").not.toHaveBeenCalled();
    // Nothing was dispatched, so the refusal lead is true and no unknown outcome is claimed.
    expect(alert).toHaveTextContent(/did not do that/i);
    expect(alert).not.toHaveTextContent(/may not have completed that/i);
  });

  it("treats a terminal device_offline after acceptance as an unknown outcome", async () => {
    const user = userEvent.setup();
    const api = fakeApi({
      dispatchCommand: vi.fn(async () => ({ command_id: "cmd_1" })),
      command: vi.fn(async () =>
        commandView({
          status: "error",
          output: null,
          error: "device_offline",
          message: "the management channel closed before the device answered",
        }),
      ),
    });

    renderPanel(api);
    await user.click(screen.getByRole("button", { name: /run command/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("device_offline");
    // The command was accepted: the channel dropped, so the device may have run it.
    expect(alert).toHaveTextContent(/may not have completed that/i);
    expect(alert).not.toHaveTextContent(/did not do that/i);
    expect(alert).toHaveTextContent(/management channel closed/i);
    expect(screen.queryByTestId("command-output")).toBeNull();
  });

  it("treats a poll failure after acceptance as an unknown outcome", async () => {
    const user = userEvent.setup();
    const api = fakeApi({
      dispatchCommand: vi.fn(async () => ({ command_id: "cmd_1" })),
      command: vi.fn(async () => {
        throw new ApiError(404, "command_unknown");
      }),
    });

    renderPanel(api);
    await user.click(screen.getByRole("button", { name: /run command/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("command_unknown");
    expect(alert).toHaveTextContent(/may not have completed that/i);
    expect(alert).not.toHaveTextContent(/did not do that/i);
    expect(document.querySelector('[data-status="ok"]')).toBeNull();
  });

  it("never renders a pending command as success", async () => {
    const user = userEvent.setup();
    const command = vi.fn(async () => commandView({ status: "pending" }));
    const api = fakeApi({
      dispatchCommand: vi.fn(async () => ({ command_id: "cmd_1" })),
      command,
    });

    renderPanel(api);
    await user.click(screen.getByRole("button", { name: /run command/i }));

    const pending = await screen.findByRole("status");
    expect(pending).toHaveTextContent(/pending/i);
    expect(document.querySelector('[data-status="pending"]')).not.toBeNull();

    // Several polls later it is still pending: no output, no success-shaped state.
    await waitFor(() => expect(command.mock.calls.length).toBeGreaterThan(1));
    expect(screen.queryByTestId("command-output")).toBeNull();
    expect(document.querySelector('[data-status="ok"]')).toBeNull();
    expect(document.body.textContent ?? "").not.toMatch(/completed|succeeded/i);
  });

  it("renders error and timeout distinctly from ok", async () => {
    const user = userEvent.setup();
    const cases: Array<{ view: CommandView; pattern: RegExp }> = [
      {
        view: commandView({
          status: "error",
          error: "not_permitted",
          message: "the app cannot read this",
        }),
        pattern: /not_permitted/,
      },
      {
        view: commandView({ status: "timeout" }),
        pattern: /did not answer before the deadline/i,
      },
    ];

    for (const entry of cases) {
      const api = fakeApi({
        dispatchCommand: vi.fn(async () => ({ command_id: "cmd_1" })),
        command: vi.fn(async () => entry.view),
      });
      const { unmount } = renderPanel(api);
      await user.click(screen.getByRole("button", { name: /run command/i }));

      const alert = await screen.findByRole("alert");
      expect(alert).toHaveTextContent(entry.pattern);
      expect(document.querySelector(`[data-status="${entry.view.status}"]`)).not.toBeNull();
      expect(screen.queryByTestId("command-output")).toBeNull();
      unmount();
    }
  });
});
