/// One directory's entries. Purely presentational: the route owns every operation, and this
/// list never invents an entry it was not given.

import type { FileEntryView } from "../api";
import { formatTime } from "../format";

export interface FileListProps {
  entries: FileEntryView[];
  /// True while an operation is in flight: every action is disabled, so one click cannot
  /// become two commands.
  busy: boolean;
  onOpen(entry: FileEntryView): void;
  onRename(entry: FileEntryView): void;
  onDelete(entry: FileEntryView): void;
}

export function FileList({ entries, busy, onOpen, onRename, onDelete }: FileListProps) {
  return (
    <ul className="file-list" aria-label="Files">
      {entries.map((entry) => (
        <li key={entry.path} className="file-entry">
          <button
            type="button"
            disabled={busy}
            onClick={() => onOpen(entry)}
          >
            Open {entry.name}
          </button>
          <span>{entry.name}</span>
          <span className="muted">
            {entry.is_dir ? "folder" : `${entry.size_bytes} bytes`}
          </span>
          <span className="muted">{formatTime(entry.modified_ms)}</span>
          <button
            type="button"
            disabled={busy}
            onClick={() => onRename(entry)}
          >
            Rename {entry.name}
          </button>
          <button
            type="button"
            disabled={busy}
            onClick={() => onDelete(entry)}
          >
            Delete {entry.name}
          </button>
        </li>
      ))}
    </ul>
  );
}
