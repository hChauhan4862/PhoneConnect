import { render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import { ApiError, type ApiClient, type AuditEntryView } from "../api";
import { AuditRoute } from "./AuditRoute";

const NOW = 1_760_000_000_000;

function entry(overrides: Partial<AuditEntryView> = {}): AuditEntryView {
  return {
    at_ms: NOW,
    actor: "owner-1",
    action: "command.dispatch",
    device_id: "dev_1",
    outcome: "accepted",
    error: null,
    ...overrides,
  };
}

function fakeApi(answer: AuditEntryView[] | (() => Promise<AuditEntryView[]>)) {
  const api = {
    listAudit: vi.fn(
      typeof answer === "function" ? answer : async () => answer,
    ),
  } as unknown as ApiClient & { listAudit: ReturnType<typeof vi.fn> };
  return api;
}

function renderRoute(api: ApiClient) {
  return render(<AuditRoute api={api} />);
}

function deferred<T>() {
  let resolve!: (value: T) => void;
  let reject!: (reason: unknown) => void;
  const promise = new Promise<T>((res, rej) => {
    resolve = res;
    reject = rej;
  });
  return { promise, resolve, reject };
}

describe("the audit screen", () => {
  it("renders the newest row first and names accepted and refused outcomes", async () => {
    const api = fakeApi([
      entry({ at_ms: NOW + 2, actor: "owner-1" }),
      entry({
        at_ms: NOW + 1,
        actor: "user-b",
        outcome: "refused",
        error: "device_offline",
      }),
      entry({ at_ms: NOW, actor: "user-c", outcome: "refused", error: "lease_read_only" }),
    ]);

    renderRoute(api);

    const table = await screen.findByRole("table", { name: /audit entries/i });
    const rows = within(table).getAllByRole("row").slice(1);
    expect(rows).toHaveLength(3);
    expect(within(rows[0]).getByText("Accepted")).toBeInTheDocument();
    expect(within(rows[1]).getByText("Refused")).toBeInTheDocument();
    // A refusal is never just "refused": the machine code the server stored is visible.
    expect(within(rows[1]).getByText("device_offline")).toBeInTheDocument();
    expect(within(rows[2]).getByText("lease_read_only")).toBeInTheDocument();
    expect(within(rows[1]).getByText("user-b")).toBeInTheDocument();
    expect(api.listAudit).toHaveBeenCalledWith({ deviceId: undefined, limit: 50 });
  });

  it("filters by device on the server, never by hiding rows locally", async () => {
    const user = userEvent.setup();
    const api = fakeApi([
      entry({ device_id: "dev_1" }),
      entry({ device_id: "dev_2", outcome: "refused", error: "device_offline" }),
    ]);

    renderRoute(api);
    await screen.findByRole("table", { name: /audit entries/i });

    await user.type(screen.getByLabelText(/^device$/i), "dev_2");
    await user.click(screen.getByRole("button", { name: /apply filter/i }));

    await waitFor(() =>
      expect(api.listAudit).toHaveBeenLastCalledWith({
        deviceId: "dev_2",
        limit: 50,
      }),
    );
  });

  it("clears the previous entries the moment a new filter is applied", async () => {
    const user = userEvent.setup();
    const next = deferred<AuditEntryView[]>();
    let call = 0;
    const api = fakeApi(async () => {
      call += 1;
      return call === 1 ? [entry()] : next.promise;
    });

    renderRoute(api);
    expect(await screen.findByText("owner-1")).toBeInTheDocument();

    await user.type(screen.getByLabelText(/^device$/i), "dev_2");
    await user.click(screen.getByRole("button", { name: /apply filter/i }));

    // The old device's rows must not survive the filter change while the new read is pending.
    await waitFor(() => expect(screen.queryByText("owner-1")).toBeNull());
    expect(screen.getByText(/loading audit entries/i)).toBeInTheDocument();

    next.resolve([entry({ device_id: "dev_2", actor: "user-b" })]);
    expect(await screen.findByText("user-b")).toBeInTheDocument();
  });

  it("says an empty answer is empty, without claiming anything happened or did not", async () => {
    const api = fakeApi([]);

    renderRoute(api);

    expect(await screen.findByText(/no audit entries/i)).toBeInTheDocument();
    expect(screen.queryByRole("table", { name: /audit entries/i })).toBeNull();
    expect(screen.queryByText(/all clear/i)).toBeNull();
  });

  it("names the device in the empty state when a filter is active", async () => {
    const user = userEvent.setup();
    const api = fakeApi([]);

    renderRoute(api);
    await screen.findByText(/no audit entries/i);

    await user.type(screen.getByLabelText(/^device$/i), "dev-unknown");
    await user.click(screen.getByRole("button", { name: /apply filter/i }));

    expect(
      await screen.findByText(/no audit entries for dev-unknown/i),
    ).toBeInTheDocument();
  });

  it("renders a failed read as an alert with its machine code, not an empty log", async () => {
    const api = fakeApi(async () => {
      throw new ApiError(503, "store_failure");
    });

    renderRoute(api);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("store_failure");
    expect(screen.queryByText(/no audit entries/i)).toBeNull();
    expect(screen.queryByRole("table", { name: /audit entries/i })).toBeNull();
  });

  it("asks the server for the page size the operator chooses", async () => {
    const user = userEvent.setup();
    const api = fakeApi([entry()]);

    renderRoute(api);
    await screen.findByRole("table", { name: /audit entries/i });

    await user.selectOptions(screen.getByLabelText(/^limit$/i), "200");

    await waitFor(() =>
      expect(api.listAudit).toHaveBeenLastCalledWith({
        deviceId: undefined,
        limit: 200,
      }),
    );
  });

  it("drops a late answer for a filter that was abandoned", async () => {
    const user = userEvent.setup();
    const abandoned = deferred<AuditEntryView[]>();
    const current = deferred<AuditEntryView[]>();
    let call = 0;
    const api = fakeApi(async () => {
      call += 1;
      return call === 1 ? abandoned.promise : current.promise;
    });

    renderRoute(api);
    await user.type(screen.getByLabelText(/^device$/i), "dev_2");
    await user.click(screen.getByRole("button", { name: /apply filter/i }));

    current.resolve([entry({ device_id: "dev_2", actor: "user-b" })]);
    expect(await screen.findByText("user-b")).toBeInTheDocument();

    abandoned.resolve([entry({ device_id: "dev_1", actor: "user-a" })]);
    await waitFor(() => expect(screen.queryByText("user-a")).toBeNull());
    expect(screen.getByText("user-b")).toBeInTheDocument();
  });
});
