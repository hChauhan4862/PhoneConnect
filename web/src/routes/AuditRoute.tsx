/// The audit screen: the durable trace of every command attempt and revocation, newest first.
///
/// The filter is the server's: an exact device id, and an unknown id is an empty answer, not
/// another device's history. A failed read is an alert carrying its machine code — never an
/// empty list that reads as "nothing happened". A refusal always shows the stored code.

import { useEffect, useState, type FormEvent } from "react";

import { ApiError, asApiError, type ApiClient, type AuditEntryView } from "../api";
import { ErrorNotice } from "../components/ErrorNotice";
import { RouteLink } from "../components/RouteLink";
import { formatDateTime } from "../format";

/// The page sizes the surface offers. The server caps any request at 200.
const LIMITS = [25, 50, 100, 200] as const;
const DEFAULT_LIMIT = 50;

/// One answered query. The key names the query it answers, so an answer for a filter that is
/// no longer on screen is never rendered — not even for the frame before a reload starts.
interface Answer {
  key: string;
  entries: AuditEntryView[] | null;
  error: ApiError | null;
}

export function AuditRoute({ api }: { api: ApiClient }) {
  const [deviceDraft, setDeviceDraft] = useState("");
  const [deviceFilter, setDeviceFilter] = useState("");
  const [limit, setLimit] = useState<number>(DEFAULT_LIMIT);
  const [reloadNonce, setReloadNonce] = useState(0);
  const [answer, setAnswer] = useState<Answer | null>(null);

  const queryKey = `${deviceFilter}\u0000${limit}\u0000${reloadNonce}`;

  useEffect(() => {
    let cancelled = false;
    api
      .listAudit({ deviceId: deviceFilter || undefined, limit })
      .then(
        (rows) => {
          if (cancelled) return;
          setAnswer({ key: queryKey, entries: rows, error: null });
        },
        (failure: unknown) => {
          if (cancelled) return;
          setAnswer({ key: queryKey, entries: null, error: asApiError(failure) });
        },
      );
    return () => {
      cancelled = true;
    };
  }, [api, deviceFilter, limit, queryKey]);

  // The previous answer never stands in for the query on screen: a new filter starts empty.
  const current = answer?.key === queryKey ? answer : null;
  const entries = current?.entries ?? null;
  const error = current?.error ?? null;
  const loading = current === null;

  const applyFilter = (event: FormEvent<HTMLFormElement>) => {
    event.preventDefault();
    setDeviceFilter(deviceDraft.trim());
  };

  return (
    <section className="panel" aria-labelledby="audit-heading">
      <nav>
        <RouteLink to="/">Devices</RouteLink>
      </nav>
      <h1 id="audit-heading">Audit log</h1>
      <p className="muted">
        Every command attempt and revocation the server recorded. Newest first. Not live:
        refresh to read the newest rows.
      </p>

      <form onSubmit={applyFilter}>
        <label htmlFor="audit-device">Device</label>
        <input
          id="audit-device"
          name="device_id"
          value={deviceDraft}
          placeholder="All devices"
          autoComplete="off"
          onChange={(event) => setDeviceDraft(event.target.value)}
        />
        <label htmlFor="audit-limit">Limit</label>
        <select
          id="audit-limit"
          name="limit"
          value={limit}
          onChange={(event) => setLimit(Number(event.target.value))}
        >
          {LIMITS.map((value) => (
            <option key={value} value={value}>
              {value}
            </option>
          ))}
        </select>
        <div className="actions">
          <button type="submit">Apply filter</button>
          {deviceFilter ? (
            <button
              type="button"
              onClick={() => {
                setDeviceDraft("");
                setDeviceFilter("");
              }}
            >
              Show all devices
            </button>
          ) : null}
          <button
            type="button"
            onClick={() => setReloadNonce((value) => value + 1)}
          >
            Refresh
          </button>
        </div>
      </form>

      {error ? (
        <ErrorNotice
          error={error}
          onRetry={() => setReloadNonce((value) => value + 1)}
        />
      ) : loading || entries === null ? (
        <p>Loading audit entries…</p>
      ) : entries.length === 0 ? (
        <p>
          {deviceFilter
            ? `No audit entries for ${deviceFilter}.`
            : "No audit entries were recorded."}
        </p>
      ) : (
        <>
          <p className="muted">
            {deviceFilter
              ? `Newest ${entries.length} entries for ${deviceFilter}.`
              : `Newest ${entries.length} entries across all devices.`}
            {entries.length >= limit
              ? " The page is full; older entries are not shown."
              : ""}
          </p>
          <table className="audit-table" aria-label="Audit entries">
            <thead>
              <tr>
                <th scope="col">When</th>
                <th scope="col">Device</th>
                <th scope="col">Actor</th>
                <th scope="col">Action</th>
                <th scope="col">Outcome</th>
              </tr>
            </thead>
            <tbody>
              {entries.map((entry, index) => (
                <tr key={`${entry.at_ms}-${entry.device_id}-${entry.actor}-${index}`}>
                  <td>
                    <time dateTime={new Date(entry.at_ms).toISOString()}>
                      {formatDateTime(entry.at_ms)}
                    </time>
                  </td>
                  <td>{entry.device_id}</td>
                  <td>{entry.actor}</td>
                  <td>
                    <code>{entry.action}</code>
                  </td>
                  <td>
                    <span
                      className={
                        entry.outcome === "accepted"
                          ? "outcome outcome-accepted"
                          : "outcome outcome-refused"
                      }
                    >
                      {entry.outcome === "accepted" ? "Accepted" : "Refused"}
                    </span>
                    {entry.error ? (
                      <>
                        {" "}
                        <code>{entry.error}</code>
                      </>
                    ) : null}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </>
      )}
    </section>
  );
}
