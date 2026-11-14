import { render, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import {
  ApiError,
  type ApiClient,
  type CommandAccepted,
  type CommandView,
} from "../api";
import { ScreenRoute } from "./ScreenRoute";

const NOW = 1_760_000_000_000;
const PNG = "iVBORw0KGgoAAAANSUhEUg==";

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
    captureScreen: vi.fn(async () =>
      accept("screen.snapshot", {
        output: { png_base64: PNG, width: 1080, height: 1920, captured_at_ms: NOW },
      }),
    ),
    command: vi.fn(async (commandId: string) => {
      const record = records.get(commandId);
      if (!record) throw new Error(`unknown command ${commandId}`);
      return record;
    }),
  } as unknown as ApiClient & { captureScreen: ReturnType<typeof vi.fn> };

  return { api, accept, records };
}

function renderRoute(api: ApiClient) {
  render(
    <ScreenRoute api={api} deviceId="dev_1" userId="owner-1" pollIntervalMs={1} />,
  );
}

describe("the screen route", () => {
  it("renders the captured frame with alt text, its time, and the size actually captured", async () => {
    const { api } = fakeApi();
    renderRoute(api);

    await userEvent.click(screen.getByRole("button", { name: /capture screen/i }));

    const image = await screen.findByRole("img", { name: /screen snapshot/i });
    expect(image).toHaveAttribute("src", `data:image/png;base64,${PNG}`);
    expect(image).toHaveAttribute("alt", expect.stringMatching(/screen snapshot/i));
    expect(screen.getByText(new RegExp(String(NOW)))).toBeInTheDocument();
    expect(screen.getByText(/1080 × 1920/)).toBeInTheDocument();
    expect(api.captureScreen).toHaveBeenCalledWith("dev_1", "owner-1");
  });

  it("renders consent_required as an alert with its code, never as an image", async () => {
    const { api, accept } = fakeApi();
    api.captureScreen = vi.fn(async () =>
      accept("screen.snapshot", {
        status: "error",
        output: null,
        error: "consent_required",
        message: "screen capture needs the user's consent, granted from the PhoneConnect setup screen on the device; no projection is held",
      }),
    );
    renderRoute(api);

    await userEvent.click(screen.getByRole("button", { name: /capture screen/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("consent_required");
    expect(alert).toHaveTextContent(/setup screen/i);
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("never leaves a stale image visible after a failed capture", async () => {
    const { api, accept } = fakeApi();
    renderRoute(api);
    await userEvent.click(screen.getByRole("button", { name: /capture screen/i }));
    expect(await screen.findByRole("img", { name: /screen snapshot/i })).toBeInTheDocument();

    api.captureScreen = vi.fn(async () =>
      accept("screen.snapshot", {
        status: "error",
        output: null,
        error: "capture_timeout",
        message: "no frame arrived within 5000 ms",
      }),
    );
    await userEvent.click(screen.getByRole("button", { name: /capture screen/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("capture_timeout");
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("refuses an answer that is not a well-typed frame as invalid_result", async () => {
    const { api, accept } = fakeApi();
    api.captureScreen = vi.fn(async () =>
      accept("screen.snapshot", {
        output: { png_base64: "", width: 0, height: 0, captured_at_ms: 1 },
      }),
    );
    renderRoute(api);

    await userEvent.click(screen.getByRole("button", { name: /capture screen/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("invalid_result");
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("reports a refused dispatch as an alert with the server's code", async () => {
    const { api } = fakeApi();
    api.captureScreen = vi.fn(async () => {
      throw new ApiError(409, "device_offline");
    });
    renderRoute(api);

    await userEvent.click(screen.getByRole("button", { name: /capture screen/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("device_offline");
    expect(screen.queryByRole("img")).not.toBeInTheDocument();
  });

  it("disables the control while a capture is in flight", async () => {
    const { api, accept } = fakeApi();
    api.captureScreen = vi.fn(async () =>
      accept("screen.snapshot", { status: "pending", output: null }),
    );
    renderRoute(api);

    await userEvent.click(screen.getByRole("button", { name: /capture screen/i }));
    expect(screen.getByRole("button", { name: /capturing/i })).toBeDisabled();

    await waitFor(() =>
      expect(screen.getByRole("button", { name: /capture screen/i })).toBeEnabled(),
    );
    // A command that never completed is `pending`, never a success.
    expect(await screen.findByRole("alert")).toHaveTextContent("pending");
  });
});
