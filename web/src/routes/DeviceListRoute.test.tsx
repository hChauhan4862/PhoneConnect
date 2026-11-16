import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ApiError, type ApiClient, type DeviceList } from "../api";
import { DeviceListRoute } from "./DeviceListRoute";

const NOW = 1_760_000_000_000;

function device(overrides: Partial<DeviceList["devices"][number]> = {}) {
  return {
    device_id: "dev_1",
    owner_id: "owner-1",
    enrolled_at_ms: NOW,
    revoked_at_ms: null,
    state: "enrolled" as const,
    ...overrides,
  };
}

function fakeApi(options: {
  devices?: DeviceList["devices"];
  listFailure?: unknown;
  issueFailure?: unknown;
  revokeFailure?: unknown;
  token?: { token: string; expires_at: number };
} = {}) {
  const api = {
    listDevices: vi.fn(async () => {
      if (options.listFailure) throw options.listFailure;
      return { devices: options.devices ?? [] };
    }),
    issueEnrollmentToken: vi.fn(async () => {
      if (options.issueFailure) throw options.issueFailure;
      return options.token ?? { token: "pcenr_abc123", expires_at: NOW + 900_000 };
    }),
    revokeDevice: vi.fn(async () => {
      if (options.revokeFailure) throw options.revokeFailure;
      return { revoked: true, revoked_at: NOW };
    }),
  } as unknown as ApiClient & {
    listDevices: ReturnType<typeof vi.fn>;
    issueEnrollmentToken: ReturnType<typeof vi.fn>;
    revokeDevice: ReturnType<typeof vi.fn>;
  };
  return api;
}

function renderList(api: ApiClient) {
  return render(<DeviceListRoute api={api} userId="owner-1" />);
}

describe("DeviceListRoute", () => {
  it("teaches both onboarding steps when no device is enrolled", async () => {
    const api = fakeApi();
    renderList(api);

    await screen.findByText(/No devices yet/i);
    expect(screen.getByText(/Create a one-time enrollment token below/i)).toBeInTheDocument();
    expect(
      screen.getByText(/Enter it in the PhoneConnect app on the phone/i),
    ).toBeInTheDocument();
    expect(
      screen.getByRole("button", { name: /Create enrollment token/i }),
    ).toBeInTheDocument();
  });

  it("mints a token and shows it once with its expiry and the phone steps", async () => {
    const api = fakeApi();
    renderList(api);
    await screen.findByText(/No devices yet/i);

    await userEvent.click(
      screen.getByRole("button", { name: /Create enrollment token/i }),
    );

    const token = await screen.findByTestId("enrollment-token");
    expect(token).toHaveTextContent("pcenr_abc123");
    // The default lifetime is 15 minutes.
    expect(api.issueEnrollmentToken).toHaveBeenCalledWith("owner-1", 900);
    const panel = screen.getByRole("status");
    expect(panel).toHaveTextContent(/Enrollment token/i);
    expect(panel).toHaveTextContent(/expires/i);
    expect(screen.getByText(/Install the PhoneConnect app/i)).toBeInTheDocument();
    expect(screen.getByText(/single-use/i)).toBeInTheDocument();
  });

  it("shows the server's refusal and no token when minting fails", async () => {
    const api = fakeApi({
      issueFailure: new ApiError(400, "invalid_request"),
    });
    renderList(api);
    await screen.findByText(/No devices yet/i);

    await userEvent.click(
      screen.getByRole("button", { name: /Create enrollment token/i }),
    );

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/invalid_request/);
    expect(screen.queryByTestId("enrollment-token")).not.toBeInTheDocument();
  });

  it("copies the token exactly once and never logs it", async () => {
    const writeText = vi.fn(async () => {});
    Object.assign(navigator, { clipboard: { writeText } });
    const logged = vi.spyOn(console, "log").mockImplementation(() => {});
    const errors = vi.spyOn(console, "error").mockImplementation(() => {});

    const api = fakeApi();
    renderList(api);
    await screen.findByText(/No devices yet/i);
    await userEvent.click(
      screen.getByRole("button", { name: /Create enrollment token/i }),
    );
    await screen.findByTestId("enrollment-token");

    await userEvent.click(screen.getByRole("button", { name: /Copy token/i }));

    expect(writeText).toHaveBeenCalledTimes(1);
    expect(writeText).toHaveBeenCalledWith("pcenr_abc123");
    await screen.findByText(/Copied to the clipboard/i);

    const printed = [...logged.mock.calls, ...errors.mock.calls]
      .flat()
      .join(" ");
    expect(printed).not.toContain("pcenr_abc123");
    logged.mockRestore();
    errors.mockRestore();
  });

  it("drops the token when dismissed", async () => {
    const api = fakeApi();
    renderList(api);
    await screen.findByText(/No devices yet/i);
    await userEvent.click(
      screen.getByRole("button", { name: /Create enrollment token/i }),
    );
    await screen.findByTestId("enrollment-token");

    await userEvent.click(screen.getByRole("button", { name: /Dismiss/i }));
    expect(screen.queryByTestId("enrollment-token")).not.toBeInTheDocument();
  });

  it("requires a second confirmation before revoking a device", async () => {
    const api = fakeApi({ devices: [device()] });
    renderList(api);

    const row = (await screen.findByText("dev_1")).closest("li") as HTMLElement;
    await userEvent.click(within(row).getByRole("button", { name: /Revoke…/i }));
    expect(api.revokeDevice).not.toHaveBeenCalled();
    expect(
      within(row).getByText(/its channel closes and it must be enrolled again/i),
    ).toBeInTheDocument();

    await userEvent.click(
      within(row).getByRole("button", { name: /Confirm revoke/i }),
    );
    await waitFor(() => expect(api.revokeDevice).toHaveBeenCalledWith("dev_1"));
    // The list is re-read, so a revoked device is the server's own report.
    await waitFor(() => expect(api.listDevices).toHaveBeenCalledTimes(2));
  });

  it("cancels a staged revoke without calling the server", async () => {
    const api = fakeApi({ devices: [device()] });
    renderList(api);

    const row = (await screen.findByText("dev_1")).closest("li") as HTMLElement;
    await userEvent.click(within(row).getByRole("button", { name: /Revoke…/i }));
    await userEvent.click(
      within(row).getByRole("button", { name: /Cancel revoke/i }),
    );
    expect(api.revokeDevice).not.toHaveBeenCalled();
    expect(within(row).getByRole("button", { name: /Revoke…/i })).toBeInTheDocument();
  });

  it("reports a failed revoke and keeps the device", async () => {
    const api = fakeApi({
      devices: [device()],
      revokeFailure: new ApiError(404, "device_unknown"),
    });
    renderList(api);

    const row = (await screen.findByText("dev_1")).closest("li") as HTMLElement;
    await userEvent.click(within(row).getByRole("button", { name: /Revoke…/i }));
    await userEvent.click(
      within(row).getByRole("button", { name: /Confirm revoke/i }),
    );

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/device_unknown/);
    expect(screen.getByText("dev_1")).toBeInTheDocument();
  });

  it("offers re-enrolling, not a dead control, for a revoked device", async () => {
    const api = fakeApi({
      devices: [device({ state: "revoked", revoked_at_ms: NOW })],
    });
    renderList(api);

    await screen.findByText("dev_1");
    expect(screen.getByText(/create a new token below to enroll it again/i)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Revoke…/i })).not.toBeInTheDocument();
  });

  it("renders the list failure with its code instead of an empty list", async () => {
    const api = fakeApi({
      listFailure: new ApiError(500, "store_failure"),
    });
    renderList(api);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/store_failure/);
    expect(screen.queryByText(/No devices yet/i)).not.toBeInTheDocument();
  });
});
