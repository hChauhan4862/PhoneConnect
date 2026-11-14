import { render, screen, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi, type Mock } from "vitest";

import type { FileEntryView } from "../api";
import { FileList } from "./FileList";

const NOW = 1_760_000_000_000;
const DIRECTORY: FileEntryView = {
  name: "photos",
  path: "photos",
  is_dir: true,
  size_bytes: 0,
  modified_ms: NOW,
};
const FILE: FileEntryView = {
  name: "notes.txt",
  path: "notes.txt",
  is_dir: false,
  size_bytes: 2048,
  modified_ms: NOW,
};

function renderList(overrides: Partial<Parameters<typeof FileList>[0]> = {}) {
  const props = {
    entries: [DIRECTORY, FILE],
    busy: false,
    onOpen: vi.fn(),
    onRename: vi.fn(),
    onDelete: vi.fn(),
    ...overrides,
  };
  render(<FileList {...props} />);
  return props;
}

describe("the file list", () => {
  it("renders a directory as openable and a file with its exact size", async () => {
    const user = userEvent.setup();
    const props = renderList();

    const list = screen.getByRole("list", { name: /files/i });
    expect(within(list).getAllByRole("listitem")).toHaveLength(2);
    expect(within(list).getByText("2048 bytes")).toBeInTheDocument();
    expect(within(list).getByText("folder")).toBeInTheDocument();

    await user.click(within(list).getByRole("button", { name: /open photos/i }));
    expect(props.onOpen).toHaveBeenCalledWith(DIRECTORY);

    const openFile = within(list).getByRole("button", { name: /open notes\.txt/i });
    await user.click(openFile);
    expect(props.onOpen).toHaveBeenLastCalledWith(FILE);
  });

  it("routes rename and delete to the entry they name", async () => {
    const user = userEvent.setup();
    const props = renderList();

    await user.click(screen.getByRole("button", { name: /rename notes\.txt/i }));
    await user.click(screen.getByRole("button", { name: /delete notes\.txt/i }));

    expect(props.onRename).toHaveBeenCalledWith(FILE);
    expect(props.onDelete).toHaveBeenCalledWith(FILE);
    expect((props.onDelete as Mock).mock.calls[0][0].path).toBe("notes.txt");
  });

  it("disables every action while an operation is in flight", () => {
    renderList({ busy: true });

    for (const button of screen.getAllByRole("button")) {
      expect(button).toBeDisabled();
    }
  });
});
