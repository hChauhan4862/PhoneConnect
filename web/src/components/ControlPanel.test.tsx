import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import {
  type ApiClient,
  type CommandAccepted,
  type CommandView,
  type ControlReadingsOutput,
} from "../api";
import { ControlPanel } from "./ControlPanel";

const NOW = 1_760_000_000_000;

const READINGS: ControlReadingsOutput = {
  brightness: 102,
  brightness_mode: 1,
  volume_music: 7,
  volume_max: 15,
  rotation: null,
  dnd_filter: 2,
  night_mode: 1,
  wifi_enabled: true,
  bluetooth_enabled: null,
  mobile_data_enabled: true,
  battery_saver: false,
  battery_percent: 88,
  unavailable: {
    rotation: "rotation_requires_system_ui",
    bluetooth_enabled: "no_bluetooth_adapter",
    brightness: "write_settings_required",
    dnd_filter: "policy_access_required",
    wifi: "wifi_setter_removed",
    bluetooth: "bluetooth_setter_removed",
    mobile_data: "mobile_data_setter_signature_gated",
    night_mode: "night_mode_setter_signature_gated",
  },
};

function command(overrides: Partial<CommandView> = {}): CommandView {
  return {
    command_id: "cmd_1",
    device_id: "dev_1",
    name: "control.get",
    status: "ok",
    output: READINGS,
    error: null,
    message: null,
    created_at_ms: NOW,
    completed_at_ms: NOW,
    ...overrides,
  };
}

/// A fake transport whose `command` answers one queued record per accepted command, so the
/// panel sees exactly what a device would have answered.
function fakeApi(records: CommandView[]) {
  const queue = [...records];
  let nextId = 0;
  const accepted = (): CommandAccepted => {
    nextId += 1;
    return { command_id: `cmd_${nextId}` };
  };
  const api = {
    controlReadings: vi.fn(async () => accepted()),
    setControl: vi.fn(async () => accepted()),
    rebootDevice: vi.fn(async () => accepted()),
    command: vi.fn(async () => {
      const next = queue.shift();
      if (!next) throw new Error("no queued answer");
      return next;
    }),
  } as unknown as ApiClient & Record<string, ReturnType<typeof vi.fn>>;
  return api;
}

function renderPanel(api: ApiClient) {
  render(<ControlPanel api={api} deviceId="dev_1" userId="owner-1" pollIntervalMs={0} />);
}

describe("the control panel", () => {
  it("renders each reading with the value the device reported", async () => {
    renderPanel(fakeApi([command()]));

    const list = await screen.findByRole("list", { name: /control readings/i });
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(12);
    expect(within(list).getByText("Screen brightness")).toBeInTheDocument();
    expect(within(list).getByText("102")).toBeInTheDocument();
    expect(within(list).getByText("88")).toBeInTheDocument();
  });

  it("explains a reading the device could not produce instead of showing zero", async () => {
    renderPanel(fakeApi([command()]));

    const list = await screen.findByRole("list", { name: /control readings/i });
    const bluetooth = within(list)
      .getAllByRole("listitem")
      .find((row) => row.textContent?.includes("Bluetooth"));
    expect(bluetooth).toBeDefined();
    expect(bluetooth).toHaveTextContent(/no bluetooth adapter/i);
    // A null reading must not be rendered as a number.
    expect(bluetooth).not.toHaveTextContent(/\b0\b/);

    const rotation = within(list)
      .getAllByRole("listitem")
      .find((row) => row.textContent?.includes("Auto-rotate"));
    expect(rotation).toHaveTextContent(/rotation lock belongs to the system UI/i);
  });

  it("renders every refused change as a disabled control with the reason visible", async () => {
    renderPanel(fakeApi([command()]));
    await screen.findByRole("list", { name: /control readings/i });

    const wifi = screen.getByRole("button", { name: /wi-fi/i });
    expect(wifi).toBeDisabled();
    // The reason is on the page, not only in a tooltip.
    expect(
      screen.getAllByText(/Android returns false from Wi-Fi toggles/i).length,
    ).toBeGreaterThan(0);

    const bluetooth = screen.getByRole("button", { name: /^bluetooth/i });
    expect(bluetooth).toBeDisabled();
    expect(screen.getAllByText(/Android ignores Bluetooth toggles/i).length).toBeGreaterThan(0);

    const mobile = screen.getByRole("button", { name: /mobile data/i });
    expect(mobile).toBeDisabled();
    expect(screen.getAllByText(/MODIFY_PHONE_STATE/i).length).toBeGreaterThan(0);

    // A grant-gated change is disabled too, with the grant named.
    const brightness = screen.getByRole("button", { name: /set brightness/i });
    expect(brightness).toBeDisabled();
    expect(screen.getAllByText(/modify system settings/i).length).toBeGreaterThan(0);

    const reboot = screen.getByRole("button", { name: /reboot/i });
    expect(reboot).toBeDisabled();
    expect(screen.getAllByText(/REBOOT permission/i).length).toBeGreaterThan(0);
  });

  it("does not claim a change succeeded until the device answers ok", async () => {
    const user = userEvent.setup();
    const api = fakeApi([
      command(),
      command({
        name: "control.set",
        status: "error",
        output: null,
        error: "not_permitted",
        message: "policy_access_required",
      }),
    ]);
    renderPanel(api);
    await screen.findByRole("list", { name: /control readings/i });

    const field = screen.getByLabelText(/music volume/i);
    await user.clear(field);
    await user.type(field, "4");
    await user.click(screen.getByRole("button", { name: /set music volume/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("not_permitted");
    // The device's reason token is rendered as the sentence an operator can act on.
    expect(alert).toHaveTextContent(/Do Not Disturb access/i);
    expect(screen.queryByText(/device confirmed/i)).not.toBeInTheDocument();
    // No re-read after a refusal: the panel has nothing new to show.
    expect(api.controlReadings).toHaveBeenCalledTimes(1);
  });

  it("after a confirmed change it re-reads control.get instead of assuming the value", async () => {
    const user = userEvent.setup();
    const api = fakeApi([
      command(),
      command({
        name: "control.set",
        output: { key: "volume_music", value: 9, applied: true },
      }),
      command({
        output: { ...READINGS, volume_music: 9 },
      }),
    ]);
    renderPanel(api);
    await screen.findByRole("list", { name: /control readings/i });

    const field = screen.getByLabelText(/music volume/i);
    await user.clear(field);
    await user.type(field, "9");
    await user.click(screen.getByRole("button", { name: /set music volume/i }));

    await waitFor(() => expect(api.controlReadings).toHaveBeenCalledTimes(2));
    expect(api.setControl).toHaveBeenCalledWith("dev_1", "owner-1", "volume_music", 9);
    const list = screen.getByRole("list", { name: /control readings/i });
    expect(within(list).getByText("9")).toBeInTheDocument();
    expect(screen.getByText(/device confirmed/i)).toBeInTheDocument();
  });

  it("reports the automatic-brightness side effect only when the device said it happened", async () => {
    const user = userEvent.setup();
    const granted: ControlReadingsOutput = {
      ...READINGS,
      unavailable: { ...READINGS.unavailable },
    };
    delete granted.unavailable.brightness;
    delete granted.unavailable.dnd_filter;

    const api = fakeApi([
      command({ output: granted }),
      command({
        name: "control.set",
        output: {
          key: "brightness",
          value: 120,
          applied: true,
          brightness_mode: 0,
          mode_changed: true,
        },
      }),
      command({ output: { ...granted, brightness: 120 } }),
    ]);
    renderPanel(api);
    await screen.findByRole("list", { name: /control readings/i });
    expect(screen.getByText(/turns automatic brightness off first/i)).toBeInTheDocument();

    const field = screen.getByLabelText(/brightness value/i);
    await user.clear(field);
    await user.type(field, "120");
    await user.click(screen.getByRole("button", { name: /set brightness/i }));

    await waitFor(() => expect(api.controlReadings).toHaveBeenCalledTimes(2));
    expect(
      screen.getByText(/turned automatic brightness off so it holds/i),
    ).toBeInTheDocument();
  });

  it("explains an unconfirmed change and re-reads instead of keeping the old map", async () => {
    const user = userEvent.setup();
    const api = fakeApi([
      command(),
      command({
        name: "control.set",
        status: "error",
        output: null,
        error: "unconfirmed",
        message: "read_back_unavailable",
      }),
      command({ output: { ...READINGS, volume_music: 4 } }),
    ]);
    renderPanel(api);
    await screen.findByRole("list", { name: /control readings/i });

    const field = screen.getByLabelText(/music volume/i);
    await user.clear(field);
    await user.type(field, "4");
    await user.click(screen.getByRole("button", { name: /set music volume/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("unconfirmed");
    expect(alert).toHaveTextContent(/accepted the change but could not confirm/i);
    // The value may or may not have moved, so the map is read again rather than assumed.
    await waitFor(() => expect(api.controlReadings).toHaveBeenCalledTimes(2));
    const list = screen.getByRole("list", { name: /control readings/i });
    expect(within(list).getByText("4")).toBeInTheDocument();
  });

  it("renders the mode-left-manual brightness reason as a sentence, not a token", async () => {
    const user = userEvent.setup();
    const granted: ControlReadingsOutput = {
      ...READINGS,
      brightness_mode: 1,
      unavailable: { ...READINGS.unavailable },
    };
    delete granted.unavailable.brightness;
    delete granted.unavailable.dnd_filter;

    const api = fakeApi([
      command({ output: granted }),
      command({
        name: "control.set",
        status: "error",
        output: null,
        error: "not_applied",
        message: "brightness_not_applied_mode_left_manual",
      }),
      // The failed change left the display manual: the panel must show that, not the old mode.
      command({ output: { ...granted, brightness_mode: 0 } }),
    ]);
    renderPanel(api);
    await screen.findByRole("list", { name: /control readings/i });

    const field = screen.getByLabelText(/brightness value/i);
    await user.clear(field);
    await user.type(field, "120");
    await user.click(screen.getByRole("button", { name: /set brightness/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("not_applied");
    expect(alert).toHaveTextContent(/automatic brightness could not be turned back on/i);
    expect(alert).not.toHaveTextContent("brightness_not_applied_mode_left_manual");
    await waitFor(() => expect(api.controlReadings).toHaveBeenCalledTimes(2));
  });

  it("drops the readings when the re-read after a confirmed change fails", async () => {
    const user = userEvent.setup();
    const api = fakeApi([
      command(),
      command({
        name: "control.set",
        output: { key: "volume_music", value: 9, applied: true },
      }),
      command({ status: "error", output: null, error: "device_offline", message: null }),
    ]);
    renderPanel(api);
    await screen.findByRole("list", { name: /control readings/i });

    const field = screen.getByLabelText(/music volume/i);
    await user.clear(field);
    await user.type(field, "9");
    await user.click(screen.getByRole("button", { name: /set music volume/i }));

    await waitFor(() => expect(api.controlReadings).toHaveBeenCalledTimes(2));
    // The change was confirmed, but the map could not be re-read: the old values must not keep
    // looking like the device's current answer, and the notice must not imply they are on screen.
    expect(screen.getByText(/device confirmed/i)).toBeInTheDocument();
    expect(screen.getByText(/device confirmed/i)).not.toHaveTextContent(/re-read/i);
    expect(screen.queryByRole("list", { name: /control readings/i })).not.toBeInTheDocument();
    expect(screen.getByRole("alert")).toHaveTextContent("device_offline");
  });

  it("reports an answer that is not a reading map as invalid_result", async () => {
    renderPanel(fakeApi([command({ output: { brightness: "bright" } })]));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("invalid_result");
  });

  it("reports a failed read with the machine code and never a fabricated map", async () => {
    const api = fakeApi([
      command({ status: "error", output: null, error: "not_permitted", message: "nope" }),
    ]);
    renderPanel(api);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("not_permitted");
    expect(screen.queryByRole("list", { name: /control readings/i })).not.toBeInTheDocument();
  });
});
