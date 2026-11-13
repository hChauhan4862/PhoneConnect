import type { SessionView } from "../api";
import { formatTime } from "../format";
import { StatusField } from "./StatusField";

const SESSION_LABEL = {
  active: "Session active",
  expired: "Session expired",
  revoked: "Session revoked",
  none: "No session",
} as const;

const PATH_LABEL = {
  none: "No path",
  unknown: "No path evidence yet",
  direct_ready: "Direct path ready",
  relay: "Relay attached",
} as const;

export function SessionPanel({ session }: { session: SessionView }) {
  return (
    <section className="panel" aria-labelledby="session-heading">
      <h2 id="session-heading">Session</h2>
      <dl>
        <StatusField label="State">
          <strong>{SESSION_LABEL[session.state]}</strong>
        </StatusField>
        <StatusField label="Path">
          <strong>{PATH_LABEL[session.path.state]}</strong>
        </StatusField>
        {session.session_id !== null ? (
          <StatusField label="Session id">{session.session_id}</StatusField>
        ) : null}
        {session.expires_at_ms !== null ? (
          <StatusField label="Expires">
            {formatTime(session.expires_at_ms)}
          </StatusField>
        ) : null}
      </dl>
      {session.state === "active" ? (
        <p className="muted">
          A direct path is chosen by the peers when both publish an endpoint; the relay
          stays attached as the fallback.
        </p>
      ) : null}
    </section>
  );
}
