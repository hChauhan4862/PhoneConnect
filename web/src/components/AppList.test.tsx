import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import type { AppEntryView } from "../api";
import { AppList } from "./AppList";

const NOW = 1_760_000_000_000;

const ZETA: AppEntryView = {
  package: "com.example.zeta",
  label: "Zeta",
  version_name: "2.1",
  version_code: 21,
  system: false,
  enabled: true,
  updated_ms: NOW,
};

const SYSTEM: AppEntryView = {
  package: "com.android.settings",
  label: "Settings",
  version_name: null,
  version_code: 35,
  system: true,
  enabled: false,
  updated_ms: NOW,
};

function renderList(overrides: Partial<Parameters<typeof AppList>[0]> = {}) {
  const props = {
    apps: [ZETA, SYSTEM],
    busy: false,
    onLaunch: vi.fn(),
    onStop: vi.fn(),
    ...overrides,
  };
  render(<AppList {...props} />);
  return props;
}

describe("the app list", () => {
  it("renders each app with the fields the device reported", () => {
    renderList();

    const list = screen.getByRole("list", { name: /installed apps/i });
    const rows = within(list).getAllByRole("listitem");
    expect(rows).toHaveLength(2);

    expect(rows[0]).toHaveTextContent("Zeta");
    expect(rows[0]).toHaveTextContent("com.example.zeta");
    expect(rows[0]).toHaveTextContent("2.1 (code 21)");
    expect(rows[0]).toHaveTextContent("enabled");
    expect(rows[0]).not.toHaveTextContent("system");

    expect(rows[1]).toHaveTextContent("Settings");
    expect(rows[1]).toHaveTextContent("com.android.settings");
    expect(rows[1]).toHaveTextContent("version not reported");
    expect(rows[1]).toHaveTextContent("35");
    expect(rows[1]).toHaveTextContent("system");
    expect(rows[1]).toHaveTextContent("disabled");
  });

  it("routes launch and stop to the app they name", async () => {
    const user = userEvent.setup();
    const props = renderList();

    await user.click(screen.getByRole("button", { name: /launch zeta/i }));
    expect(props.onLaunch).toHaveBeenCalledWith(ZETA);

    await user.click(screen.getByRole("button", { name: /stop zeta/i }));
    expect(props.onStop).toHaveBeenCalledWith(ZETA);
    expect(props.onLaunch).toHaveBeenCalledTimes(1);
  });

  it("disables every action while one is in flight", () => {
    renderList({ busy: true });

    for (const button of screen.getAllByRole("button")) {
      expect(button).toBeDisabled();
    }
  });

  it("renders clear and enable/disable as unavailable with the reason, never as working buttons", () => {
    renderList();

    const clear = screen.getByRole("button", { name: /clear data zeta/i });
    expect(clear).toBeDisabled();
    expect(clear).toHaveAttribute("title", expect.stringContaining("adb shell pm clear"));

    const disable = screen.getByRole("button", { name: /disable zeta/i });
    expect(disable).toBeDisabled();
    expect(disable).toHaveAttribute("title", expect.stringContaining("adb shell pm disable-user"));

    // The reason is visible, not only in a tooltip: an ordinary app cannot do this.
    expect(screen.getByText(/signature-level permission/i)).toBeInTheDocument();

    const enable = screen.getByRole("button", { name: /enable settings/i });
    expect(enable).toBeDisabled();
  });
});
