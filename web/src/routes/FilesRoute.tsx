/// The file browser: one directory at a time, every answer the device's own.
///
/// The screen never fabricates a listing. A refusal is an alert carrying its machine code, a
/// success whose output is not a listing is refused as `invalid_result`, and the entries are
/// cleared the moment the path changes — a pending read never shows the previous directory.
/// Write and delete are two-step: the first click stages the operation, the second confirms.

import { useCallback, useEffect, useRef, useState } from "react";

import {
  asApiError,
  type ApiClient,
  type CommandAccepted,
  type CommandView,
  type FileEntryView,
} from "../api";
import { FileList } from "../components/FileList";
import { RouteLink } from "../components/RouteLink";
import { pollCommand } from "../data/commands";
import { devicePath } from "../routing";

/// A machine code and, when the device gave one, its explanation. Nothing here is a success.
interface Failure {
  code: string;
  message: string | null;
}

interface StagedWrite {
  name: string;
  path: string;
  dataBase64: string;
  byteCount: number;
}

interface RenameDraft {
  entry: FileEntryView;
  path: string;
}

interface OpenFile {
  path: string;
  name: string;
  /// Where the next chunk starts.
  offset: number;
  /// Decoded bytes received so far.
  bytes: number;
  truncated: boolean;
  /// Text when the chunk decodes as UTF-8, `null` when it is binary.
  preview: string | null;
}

const MAX_PREVIEW_CHARS = 4_000;

/// The same cap the device and the server enforce, so the UI can refuse a hopeless upload
/// before it is sent.
const MAX_WRITE_BYTES = 1024 * 1024;

export interface FilesRouteProps {
  api: ApiClient;
  deviceId: string;
  userId: string;
  /// Poll interval; tests shorten it.
  pollIntervalMs?: number;
}

export function FilesRoute({
  api,
  deviceId,
  userId,
  pollIntervalMs,
}: FilesRouteProps) {
  const [path, setPath] = useState("");
  const [entries, setEntries] = useState<FileEntryView[] | null>(null);
  const [listingFailure, setListingFailure] = useState<Failure | null>(null);
  const [listingLoading, setListingLoading] = useState(true);
  const [reloadNonce, setReloadNonce] = useState(0);

  const [busy, setBusy] = useState(false);
  const [actionFailure, setActionFailure] = useState<Failure | null>(null);
  const [notice, setNotice] = useState<string | null>(null);

  const [openFile, setOpenFile] = useState<OpenFile | null>(null);
  const [stagedWrite, setStagedWrite] = useState<StagedWrite | null>(null);
  const [pendingDelete, setPendingDelete] = useState<FileEntryView | null>(null);
  const [rename, setRename] = useState<RenameDraft | null>(null);
  const [folderName, setFolderName] = useState("");

  const mounted = useRef(true);

  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  // A path change clears the listing *before* the new read starts, so nothing from the
  // previous directory can be shown against the new one.
  useEffect(() => {
    let cancelled = false;
    setEntries(null);
    setListingFailure(null);
    setListingLoading(true);
    (async () => {
      try {
        const accepted = await api.listFiles(deviceId, userId, path);
        const command = await pollCommand(api, userId, accepted.command_id, {
          pollIntervalMs,
          isActive: () => !cancelled,
        });
        if (cancelled) return;
        if (command.status !== "ok") {
          setListingFailure(failureOfCommand(command));
          return;
        }
        const listing = readListing(command.output);
        if (!listing) {
          setListingFailure({
            code: "invalid_result",
            message: "the device's answer is not a directory listing",
          });
          return;
        }
        setEntries(listing);
      } catch (failure) {
        if (!cancelled) setListingFailure(failureOfError(failure));
      } finally {
        if (!cancelled) setListingLoading(false);
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [api, deviceId, userId, path, pollIntervalMs, reloadNonce]);

  const reload = useCallback(() => setReloadNonce((value) => value + 1), []);

  /// Dispatches one command and waits for the device's answer. A non-`ok` answer becomes the
  /// action's failure and `null` is returned: no caller can mistake a refusal for success.
  const run = useCallback(
    async (operation: () => Promise<CommandAccepted>): Promise<CommandView | null> => {
      setBusy(true);
      setActionFailure(null);
      setNotice(null);
      try {
        const accepted = await operation();
        const command = await pollCommand(api, userId, accepted.command_id, {
          pollIntervalMs,
          isActive: () => mounted.current,
        });
        if (!mounted.current) return null;
        if (command.status !== "ok") {
          setActionFailure(failureOfCommand(command));
          return null;
        }
        return command;
      } catch (failure) {
        if (mounted.current) setActionFailure(failureOfError(failure));
        return null;
      } finally {
        if (mounted.current) setBusy(false);
      }
    },
    [api, userId, pollIntervalMs],
  );

  async function loadChunk(
    filePath: string,
    offset: number,
    alreadyLoaded: number,
  ): Promise<void> {
    const command = await run(() => api.readFile(deviceId, userId, filePath, offset));
    if (!command) return;
    const chunk = readChunk(command.output);
    if (!chunk) {
      setActionFailure({
        code: "invalid_result",
        message: "the device's read answer is not a chunk",
      });
      return;
    }
    let bytes: Uint8Array;
    try {
      bytes = decodeBase64(chunk.data_base64);
    } catch {
      setActionFailure({
        code: "invalid_result",
        message: "the device's chunk is not valid base64",
      });
      return;
    }
    setOpenFile({
      path: filePath,
      name: chunk.name,
      offset: offset + bytes.length,
      bytes: alreadyLoaded + bytes.length,
      truncated: chunk.truncated,
      preview: previewOf(bytes),
    });
  }

  async function openEntry(entry: FileEntryView): Promise<void> {
    setOpenFile(null);
    setStagedWrite(null);
    setPendingDelete(null);
    setRename(null);
    setActionFailure(null);
    setNotice(null);
    if (entry.is_dir) {
      setPath(entry.path);
      return;
    }
    await loadChunk(entry.path, 0, 0);
  }

  async function stageUpload(files: FileList | null): Promise<void> {
    const file = files?.[0];
    if (!file) return;
    setActionFailure(null);
    setNotice(null);
    setOpenFile(null);
    if (file.size > MAX_WRITE_BYTES) {
      setActionFailure({
        code: "too_large",
        message: `a write may carry at most ${MAX_WRITE_BYTES} bytes`,
      });
      return;
    }
    const dataBase64 = bytesToBase64(new Uint8Array(await file.arrayBuffer()));
    setStagedWrite({
      name: file.name,
      path: joinPath(path, file.name),
      dataBase64,
      byteCount: file.size,
    });
  }

  async function confirmWrite(): Promise<void> {
    if (!stagedWrite) return;
    const command = await run(() =>
      api.writeFile(deviceId, userId, stagedWrite.path, stagedWrite.dataBase64, false),
    );
    if (!command) return;
    const written = readWritten(command.output);
    setStagedWrite(null);
    setNotice(
      written === null
        ? `Wrote "${stagedWrite.path}".`
        : `Wrote ${written} bytes to "${stagedWrite.path}".`,
    );
    reload();
  }

  async function confirmDelete(): Promise<void> {
    if (!pendingDelete) return;
    const entry = pendingDelete;
    const command = await run(() => api.deleteEntry(deviceId, userId, entry.path));
    setPendingDelete(null);
    if (!command) return;
    setNotice(`Deleted "${entry.path}".`);
    reload();
  }

  async function createFolder(): Promise<void> {
    const name = folderName.trim();
    if (name.length === 0) {
      setActionFailure({ code: "invalid_args", message: "a folder name is required" });
      return;
    }
    const target = joinPath(path, name);
    const command = await run(() => api.createDirectory(deviceId, userId, target));
    if (!command) return;
    setFolderName("");
    setNotice(`Created "${target}".`);
    reload();
  }

  async function submitRename(): Promise<void> {
    if (!rename) return;
    const target = rename.path.trim();
    if (target.length === 0) {
      setActionFailure({ code: "invalid_args", message: "a new path is required" });
      return;
    }
    const command = await run(() =>
      api.renameEntry(deviceId, userId, rename.entry.path, target),
    );
    if (!command) return;
    setRename(null);
    setNotice(`Renamed "${rename.entry.path}" to "${target}".`);
    reload();
  }

  const parentPath = path.split("/").slice(0, -1).join("/");

  return (
    <>
      <nav>
        <RouteLink to={devicePath(deviceId)}>Back to status</RouteLink>
      </nav>
      <h1>Files</h1>
      <p className="muted">
        The shared root is the app&apos;s own files directory on the device. Paths are relative
        to it, and every operation is answered by the device.
      </p>

      <section className="panel" aria-labelledby="files-heading">
        <h2 id="files-heading">
          {path === "" ? "Shared root" : path}
        </h2>
        <div className="actions">
          {path !== "" ? (
            <button type="button" disabled={busy} onClick={() => setPath(parentPath)}>
              Up one level
            </button>
          ) : null}
          <button type="button" disabled={busy || listingLoading} onClick={reload}>
            Refresh
          </button>
        </div>

        {listingFailure ? <FailureNotice failure={listingFailure} /> : null}
        {listingLoading && !listingFailure ? <p>Loading files…</p> : null}
        {!listingLoading && !listingFailure && entries?.length === 0 ? (
          <p>This folder is empty.</p>
        ) : null}
        {!listingFailure && entries && entries.length > 0 ? (
          <FileList
            entries={entries}
            busy={busy}
            onOpen={(entry) => void openEntry(entry)}
            onRename={(entry) =>
              setRename({ entry, path: entry.path })
            }
            onDelete={(entry) => setPendingDelete(entry)}
          />
        ) : null}
      </section>

      {actionFailure ? <FailureNotice failure={actionFailure} /> : null}
      {notice ? (
        <p role="status" className="notice">
          {notice}
        </p>
      ) : null}

      <section className="panel" aria-labelledby="files-actions-heading">
        <h2 id="files-actions-heading">Change this folder</h2>
        <div className="actions">
          <label htmlFor="new-folder">New folder name</label>
          <input
            id="new-folder"
            value={folderName}
            onChange={(event) => setFolderName(event.target.value)}
          />
          <button type="button" disabled={busy} onClick={() => void createFolder()}>
            Create folder
          </button>
        </div>
        <div className="actions">
          <label htmlFor="upload">File to upload</label>
          <input
            id="upload"
            type="file"
            disabled={busy}
            onChange={(event) => {
              const files = event.target.files;
              event.target.value = "";
              void stageUpload(files);
            }}
          />
        </div>

        {stagedWrite ? (
          <div className="actions">
            <p>
              Write &quot;{stagedWrite.name}&quot; ({stagedWrite.byteCount} bytes) to{" "}
              <code>{stagedWrite.path}</code>?
            </p>
            <button type="button" disabled={busy} onClick={() => void confirmWrite()}>
              Confirm write
            </button>
            <button type="button" disabled={busy} onClick={() => setStagedWrite(null)}>
              Cancel write
            </button>
          </div>
        ) : null}

        {pendingDelete ? (
          <div className="actions">
            <p>
              Delete &quot;{pendingDelete.path}&quot;? A directory is only removed when it is
              empty.
            </p>
            <button type="button" disabled={busy} onClick={() => void confirmDelete()}>
              Confirm delete
            </button>
            <button type="button" disabled={busy} onClick={() => setPendingDelete(null)}>
              Cancel delete
            </button>
          </div>
        ) : null}

        {rename ? (
          <div className="actions">
            <label htmlFor="rename-path">New path for {rename.entry.name}</label>
            <input
              id="rename-path"
              value={rename.path}
              onChange={(event) => setRename({ ...rename, path: event.target.value })}
            />
            <button type="button" disabled={busy} onClick={() => void submitRename()}>
              Rename
            </button>
            <button type="button" disabled={busy} onClick={() => setRename(null)}>
              Cancel rename
            </button>
          </div>
        ) : null}
      </section>

      {openFile ? (
        <section className="panel" aria-labelledby="file-heading">
          <h2 id="file-heading">{openFile.name}</h2>
          <p className="muted">
            {openFile.bytes} bytes read ·{" "}
            {openFile.truncated ? "more remains." : "the whole file is shown."}
          </p>
          {openFile.preview === null ? (
            <p>This chunk is binary; the browser does not pretend to show text.</p>
          ) : (
            <pre data-testid="file-preview">{openFile.preview}</pre>
          )}
          {openFile.truncated ? (
            <button
              type="button"
              disabled={busy}
              onClick={() => void loadChunk(openFile.path, openFile.offset, openFile.bytes)}
            >
              Load more
            </button>
          ) : null}
        </section>
      ) : null}
    </>
  );
}

function FailureNotice({ failure }: { failure: Failure }) {
  return (
    <div role="alert" className="notice notice-error">
      <p>
        <strong>The device did not do that</strong> <code>{failure.code}</code>
      </p>
      {failure.message ? <p>{failure.message}</p> : null}
    </div>
  );
}

function failureOfCommand(command: CommandView): Failure {
  // `timeout` and a poll budget that ended in `pending` are their own codes, never
  // `device_error`: the screen says exactly which state it saw.
  return {
    code: command.error ?? command.status,
    message:
      command.message ??
      (command.status === "pending" ? "the device has not answered yet" : null),
  };
}

function failureOfError(error: unknown): Failure {
  const api = asApiError(error);
  return { code: api.code, message: null };
}

function readListing(output: unknown): FileEntryView[] | null {
  if (typeof output !== "object" || output === null) return null;
  const entries = (output as { entries?: unknown }).entries;
  if (!Array.isArray(entries)) return null;
  const parsed: FileEntryView[] = [];
  for (const raw of entries) {
    if (!isEntry(raw)) return null;
    parsed.push(raw);
  }
  return parsed;
}

function isEntry(raw: unknown): raw is FileEntryView {
  if (typeof raw !== "object" || raw === null) return false;
  const value = raw as Record<string, unknown>;
  return (
    typeof value.name === "string" &&
    typeof value.path === "string" &&
    typeof value.is_dir === "boolean" &&
    typeof value.size_bytes === "number" &&
    typeof value.modified_ms === "number"
  );
}

function readChunk(output: unknown): { data_base64: string; truncated: boolean; name: string } | null {
  if (typeof output !== "object" || output === null) return null;
  const value = output as Record<string, unknown>;
  if (typeof value.data_base64 !== "string") return null;
  if (typeof value.truncated !== "boolean") return null;
  if (typeof value.name !== "string") return null;
  return {
    data_base64: value.data_base64,
    truncated: value.truncated,
    name: value.name,
  };
}

function readWritten(output: unknown): number | null {
  if (typeof output !== "object" || output === null) return null;
  const value = (output as { bytes_written?: unknown }).bytes_written;
  return typeof value === "number" ? value : null;
}

function joinPath(directory: string, name: string): string {
  return directory === "" ? name : `${directory}/${name}`;
}

function decodeBase64(encoded: string): Uint8Array {
  const binary = atob(encoded);
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index += 1) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function bytesToBase64(bytes: Uint8Array): string {
  let binary = "";
  const chunk = 0x8000;
  for (let index = 0; index < bytes.length; index += chunk) {
    binary += String.fromCharCode(...bytes.subarray(index, index + chunk));
  }
  return btoa(binary);
}

/// Text when the chunk is text, `null` when it is not: a binary chunk is never rendered as if
/// it were readable.
function previewOf(bytes: Uint8Array): string | null {
  if (bytes.some((byte) => byte === 0)) return null;
  try {
    const text = new TextDecoder("utf-8", { fatal: true }).decode(bytes);
    return text.length > MAX_PREVIEW_CHARS ? `${text.slice(0, MAX_PREVIEW_CHARS)}…` : text;
  } catch {
    return null;
  }
}
