import { act, render, screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";

import {
  ApiError,
  type ApiClient,
  type CommandAccepted,
  type CommandView,
  type FileEntryView,
} from "../api";
import { FilesRoute } from "./FilesRoute";

const NOW = 1_760_000_000_000;

function file(path: string, size = 5): FileEntryView {
  const name = path.split("/").at(-1) ?? path;
  return { name, path, is_dir: false, size_bytes: size, modified_ms: NOW };
}

function dir(path: string): FileEntryView {
  const name = path.split("/").at(-1) ?? path;
  return { name, path, is_dir: true, size_bytes: 0, modified_ms: NOW };
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
    listFiles: vi.fn(async () => accept("files.list", { output: { entries: [] } })),
    readFile: vi.fn(async () => accept("files.read")),
    writeFile: vi.fn(async () => accept("files.write", { output: { bytes_written: 0 } })),
    createDirectory: vi.fn(async () => accept("files.mkdir")),
    deleteEntry: vi.fn(async () => accept("files.delete")),
    renameEntry: vi.fn(async () => accept("files.rename")),
  } as unknown as ApiClient & Record<string, ReturnType<typeof vi.fn>>;

  return { api, accept };
}

function renderRoute(api: ApiClient) {
  return render(
    <FilesRoute api={api} deviceId="dev_1" userId="user-a" pollIntervalMs={1} />,
  );
}

describe("the file browser", () => {
  it("lists the shared root and opens a directory", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listFiles = vi.fn(async (_device, _user, path: string) =>
      accept("files.list", {
        output: {
          entries: path === "docs" ? [file("docs/inside.txt")] : [dir("docs"), file("notes.txt")],
        },
      }),
    ) as never;

    renderRoute(api);

    const root = await screen.findByRole("list", { name: /files/i });
    expect(within(root).getByText("docs")).toBeInTheDocument();
    expect(within(root).getByText("notes.txt")).toBeInTheDocument();
    expect(within(root).getByText("5 bytes")).toBeInTheDocument();
    expect(api.listFiles).toHaveBeenCalledWith("dev_1", "user-a", "");

    await user.click(within(root).getByRole("button", { name: /open docs/i }));

    expect(
      await screen.findByRole("button", { name: /open inside\.txt/i }),
    ).toBeInTheDocument();
    expect(api.listFiles).toHaveBeenLastCalledWith("dev_1", "user-a", "docs");
    expect(screen.queryByText("notes.txt")).toBeNull();
  });

  it("renders a server refusal as an alert with the machine code and no listing", async () => {
    const { api } = fakeApi();
    api.listFiles = vi.fn(async () => {
      throw new ApiError(409, "device_offline");
    }) as never;

    renderRoute(api);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("device_offline");
    expect(screen.queryByRole("list", { name: /files/i })).toBeNull();
    expect(screen.queryByText(/this folder is empty/i)).toBeNull();
  });

  it("renders the device's error code and never an empty listing", async () => {
    const { api, accept } = fakeApi();
    api.listFiles = vi.fn(async () =>
      accept("files.list", {
        status: "error",
        error: "path_outside_root",
        message: "\"../\" leaves the shared root",
      }),
    ) as never;

    renderRoute(api);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("path_outside_root");
    expect(alert).toHaveTextContent(/leaves the shared root/);
    expect(screen.queryByText(/this folder is empty/i)).toBeNull();
  });

  it("refuses to render a success whose output is not a listing", async () => {
    const { api, accept } = fakeApi();
    api.listFiles = vi.fn(async () => accept("files.list", { output: { oops: true } })) as never;

    renderRoute(api);

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("invalid_result");
    expect(screen.queryByRole("list", { name: /files/i })).toBeNull();
  });

  it("never shows the previous directory while the next one is pending", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    let releaseDocs: (() => void) | null = null;
    api.listFiles = vi.fn(async (_device, _user, path: string) => {
      if (path !== "docs") {
        return accept("files.list", { output: { entries: [dir("docs"), file("notes.txt")] } });
      }
      return new Promise<CommandAccepted>((resolve) => {
        releaseDocs = () =>
          resolve(accept("files.list", { output: { entries: [file("docs/inside.txt")] } }));
      });
    }) as never;

    renderRoute(api);
    await screen.findByText("notes.txt");
    await user.click(screen.getByRole("button", { name: /open docs/i }));

    // The old entries are gone the moment the path changes: nothing stale is shown.
    expect(screen.queryByText("notes.txt")).toBeNull();
    expect(screen.getByText(/loading/i)).toBeInTheDocument();

    await act(async () => {
      releaseDocs?.();
    });
    expect(await screen.findByText("inside.txt")).toBeInTheDocument();
  });

  it("reads a file in chunks and says honestly when more remains", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listFiles = vi.fn(async () =>
      accept("files.list", { output: { entries: [file("big.bin", 300 * 1024)] } }),
    ) as never;
    api.readFile = vi.fn(async (_device, _user, _path, offset = 0) =>
      accept("files.read", {
        output: {
          name: "big.bin",
          data_base64: offset === 0 ? btoa("x".repeat(262_144)) : btoa("tail"),
          truncated: offset === 0,
        },
      }),
    ) as never;

    renderRoute(api);
    await user.click(await screen.findByRole("button", { name: /open big\.bin/i }));

    expect(await screen.findByText(/262144 bytes/)).toBeInTheDocument();
    expect(screen.getByText(/more remains/i)).toBeInTheDocument();
    expect(api.readFile).toHaveBeenLastCalledWith("dev_1", "user-a", "big.bin", 0);

    await user.click(screen.getByRole("button", { name: /load more/i }));

    await waitFor(() =>
      expect(api.readFile).toHaveBeenLastCalledWith(
        "dev_1",
        "user-a",
        "big.bin",
        262_144,
      ),
    );
    expect(await screen.findByText(/the whole file is shown/i)).toBeInTheDocument();
  });

  it("requires an explicit confirmation before writing", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listFiles = vi.fn(async () => accept("files.list", { output: { entries: [] } })) as never;
    api.writeFile = vi.fn(async () =>
      accept("files.write", { output: { bytes_written: 5 } }),
    ) as never;

    renderRoute(api);
    await screen.findByText(/this folder is empty/i);

    await user.upload(
      screen.getByLabelText(/file to upload/i),
      new File(["hello"], "hello.txt", { type: "text/plain" }),
    );

    expect(await screen.findByText(/write "hello\.txt"/i)).toBeInTheDocument();
    expect(api.writeFile, "nothing is written before the confirmation").not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: /confirm write/i }));

    await waitFor(() =>
      expect(api.writeFile).toHaveBeenCalledWith(
        "dev_1",
        "user-a",
        "hello.txt",
        btoa("hello"),
        false,
      ),
    );
    expect(await screen.findByText(/wrote 5 bytes/i)).toBeInTheDocument();
  });

  it("requires an explicit confirmation before deleting", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listFiles = vi.fn(async () =>
      accept("files.list", { output: { entries: [file("notes.txt")] } }),
    ) as never;
    api.deleteEntry = vi.fn(async () => accept("files.delete")) as never;

    renderRoute(api);
    await screen.findByText("notes.txt");
    await user.click(screen.getByRole("button", { name: /delete notes\.txt/i }));

    expect(await screen.findByText(/delete "notes\.txt"/i)).toBeInTheDocument();
    expect(api.deleteEntry, "nothing is deleted before the confirmation").not.toHaveBeenCalled();

    await user.click(screen.getByRole("button", { name: /confirm delete/i }));

    await waitFor(() =>
      expect(api.deleteEntry).toHaveBeenCalledWith("dev_1", "user-a", "notes.txt"),
    );
    expect(api.listFiles).toHaveBeenCalledTimes(2);
  });

  it("renders a refused delete as an alert with the device's code", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listFiles = vi.fn(async () =>
      accept("files.list", { output: { entries: [dir("full")] } }),
    ) as never;
    api.deleteEntry = vi.fn(async () =>
      accept("files.delete", { status: "error", error: "dir_not_empty", message: "not empty" }),
    ) as never;

    renderRoute(api);
    await user.click(await screen.findByRole("button", { name: /delete full/i }));
    await user.click(screen.getByRole("button", { name: /confirm delete/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("dir_not_empty");
  });

  it("treats a terminal device_offline after acceptance as unknown, and re-reads", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listFiles = vi.fn(async () =>
      accept("files.list", { output: { entries: [file("notes.txt")] } }),
    ) as never;
    api.deleteEntry = vi.fn(async () =>
      accept("files.delete", {
        status: "error",
        output: null,
        error: "device_offline",
        message: "the management channel closed before the device answered",
      }),
    ) as never;

    renderRoute(api);
    await screen.findByText("notes.txt");
    await user.click(screen.getByRole("button", { name: /delete notes\.txt/i }));
    await user.click(screen.getByRole("button", { name: /confirm delete/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("device_offline");
    // The delete was accepted, so the delete may have landed: never "did not do that".
    expect(alert).toHaveTextContent(/may not have completed that/i);
    expect(alert).not.toHaveTextContent(/did not do that/i);
    // The listing is read again, so a delete that landed cannot sit under the old entries.
    await waitFor(() => expect(api.listFiles).toHaveBeenCalledTimes(2));
  });

  it("keeps the refusal lead when the delete is refused before acceptance", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listFiles = vi.fn(async () =>
      accept("files.list", { output: { entries: [file("notes.txt")] } }),
    ) as never;
    api.deleteEntry = vi.fn(async () => {
      throw new ApiError(403, "lease_read_only");
    }) as never;

    renderRoute(api);
    await screen.findByText("notes.txt");
    await user.click(screen.getByRole("button", { name: /delete notes\.txt/i }));
    await user.click(screen.getByRole("button", { name: /confirm delete/i }));

    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent("lease_read_only");
    // Nothing was dispatched, so this really is "did not do that".
    expect(alert).toHaveTextContent(/did not do that/i);
    expect(alert).not.toHaveTextContent(/may not have completed that/i);
    expect(api.listFiles, "nothing landed, so the listing is not re-read").toHaveBeenCalledTimes(
      1,
    );
  });

  it("creates a folder and renames an entry through the same command surface", async () => {
    const user = userEvent.setup();
    const { api, accept } = fakeApi();
    api.listFiles = vi.fn(async () =>
      accept("files.list", { output: { entries: [file("old.txt")] } }),
    ) as never;
    api.createDirectory = vi.fn(async () => accept("files.mkdir")) as never;
    api.renameEntry = vi.fn(async () => accept("files.rename")) as never;

    renderRoute(api);
    await screen.findByText("old.txt");

    await user.type(screen.getByLabelText(/new folder name/i), "photos");
    await user.click(screen.getByRole("button", { name: /create folder/i }));
    await waitFor(() =>
      expect(api.createDirectory).toHaveBeenCalledWith("dev_1", "user-a", "photos"),
    );

    await user.click(screen.getByRole("button", { name: /rename old\.txt/i }));
    const input = screen.getByLabelText(/new path for old\.txt/i);
    await user.clear(input);
    await user.type(input, "new.txt");
    await user.click(screen.getByRole("button", { name: /^rename$/i }));
    await waitFor(() =>
      expect(api.renameEntry).toHaveBeenCalledWith("dev_1", "user-a", "old.txt", "new.txt"),
    );
  });
});
