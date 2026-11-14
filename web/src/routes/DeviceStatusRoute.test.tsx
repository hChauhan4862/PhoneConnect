import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import {
  type ApiClient,
  type CommandView,
  type DeviceStatus,
  type LeaseAccessView,
} from "../api";
import { App } from "../App";
import { saveSession } from "../session";

const NOW = 1_760_000_000_000;

const READINGS = {
  brightness: 102,
  brightness_mode: 0,
  volume_music: 7,
  volume_max: 15,
  rotation: 0,
  dnd_filter: 1,
  night_mode: 1,
  wifi_enabled: true,
  bluetooth_enabled: false,
  mobile_data_enabled: true,
  battery_saver: false,
  battery_percent: 88,
  unavailable: { wifi: "wifi_setter_removed", reboot: "reboot_requires_privilege" },
};

function access(overrides: Partial<LeaseAccessView>): LeaseAccessView {
  return {
    user_id: "user-a",
    is_owner: false,
    role: "viewer",
    can_control: false,
    ...overrides,
  };
}

function statusFixture(accessView: LeaseAccessView): DeviceStatus {
  return {
    device: {
      device_id: "dev_1",
      owner_id: "user-a",
      enrolled_at_ms: NOW,
      revoked_at_ms: null,
      state: "enrolled",
    },
    session: {
      session_id: null,
      created_at_ms: null,
      expires_at_ms: null,
      revoked_at_ms: null,
      state: "none",
      path: { state: "none", relay_attached: false, direct_candidates: false },
      control_refusals: 0,
    },
    lease: { lease: null, access: accessView },
    telemetry: {
      freshness: "missing",
      age_ms: null,
      sampled_at_ms: null,
      latest: null,
      aggregate: null,
    },
  };
}

function fakeApi(status: DeviceStatus) {
  const record: CommandView = {
    command_id: "cmd_1",
    device_id: "dev_1",
    name: "control.get",
    status: "ok",
    output: READINGS,
    error: null,
    message: null,
    created_at_ms: NOW,
    completed_at_ms: NOW,
  };
  const api = {
    deviceStatus: vi.fn(async () => status),
    controlReadings: vi.fn(async () => ({ command_id: "cmd_1" })),
    command: vi.fn(async () => record),
  } as unknown as ApiClient & Record<string, ReturnType<typeof vi.fn>>;
  return api;
}

beforeEach(() => {
  saveSession({ token: "admin-token", userId: "user-a" });
  window.history.replaceState({}, "", "/devices/dev_1");
});

afterEach(() => {
  window.sessionStorage.clear();
  window.history.replaceState({}, "", "/");
});

function renderRoute(status: DeviceStatus) {
  const api = fakeApi(status);
  render(<App api={api} />);
  return api;
}

describe("the status screen's control panel", () => {
  it("renders the readings for the owner, who may control the device", async () => {
    const api = renderRoute(statusFixture(access({ is_owner: true })));

    expect(
      await screen.findByRole("list", { name: /control readings/i }),
    ).toBeInTheDocument();
    expect(api.controlReadings).toHaveBeenCalledTimes(1);
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
  });

  it("renders the readings for the holder of the control lease", async () => {
    const api = renderRoute(
      statusFixture(access({ is_owner: false, role: "controller", can_control: true })),
    );

    expect(
      await screen.findByRole("list", { name: /control readings/i }),
    ).toBeInTheDocument();
    expect(api.controlReadings).toHaveBeenCalledTimes(1);
  });

  it("tells a read-only viewer why there are no controls instead of alerting", async () => {
    const api = renderRoute(statusFixture(access({ is_owner: false, can_control: false })));

    expect(
      await screen.findByText(/require control access/i),
    ).toBeInTheDocument();
    // A viewer's landing page must not be an error the viewer can do nothing about.
    expect(screen.queryByRole("alert")).not.toBeInTheDocument();
    expect(
      screen.queryByRole("list", { name: /control readings/i }),
    ).not.toBeInTheDocument();
    await waitFor(() => expect(api.deviceStatus).toHaveBeenCalled());
    expect(api.controlReadings).not.toHaveBeenCalled();
  });
});
