/// Onboarding: mint a one-time enrollment token and see the exact steps an operator follows.
///
/// The token is the only moment the secret is readable — the server stores a hash and no
/// endpoint can return it again — so it is shown once, with a copy control, never in the URL,
/// never in a log, and it is cleared when the operator dismisses or revokes it. A failure is
/// the server's own refusal with its machine code; nothing is fabricated.

import { useCallback, useState } from "react";

import { type ApiClient } from "../api";
import { ErrorNotice } from "../components/ErrorNotice";

/// The server accepts 1–3600 seconds and defaults to 900.
const LIFETIMES: { label: string; seconds: number }[] = [
  { label: "15 minutes", seconds: 900 },
  { label: "1 hour", seconds: 3600 },
];

/// A minted token plus the owner it was minted for. The owner is captured at mint time, so the
/// panel can never show a token under a different owner than the one it will enroll as.
interface IssuedToken {
  token: string;
  expiresAt: number;
  ownerId: string;
}

export function EnrollmentTokenPanel({
  api,
  defaultOwner,
}: {
  api: ApiClient;
  defaultOwner: string;
}) {
  const [owner, setOwner] = useState(defaultOwner);
  const [lifetime, setLifetime] = useState(900);
  const [issued, setIssued] = useState<IssuedToken | null>(null);
  const [failure, setFailure] = useState<unknown>(null);
  const [revokeFailure, setRevokeFailure] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");
  const [withdrawn, setWithdrawn] = useState(false);

  const mint = useCallback(async () => {
    const ownerId = owner.trim();
    setBusy(true);
    setFailure(null);
    setRevokeFailure(null);
    setCopied("idle");
    setWithdrawn(false);
    try {
      const token = await api.issueEnrollmentToken(ownerId, lifetime);
      setIssued({ token: token.token, expiresAt: token.expires_at, ownerId });
    } catch (error) {
      // A refusal means nothing was created; never leave a previous token looking current.
      setIssued(null);
      setFailure(error);
    } finally {
      setBusy(false);
    }
  }, [api, owner, lifetime]);

  const copy = useCallback(async () => {
    if (!issued) return;
    try {
      await navigator.clipboard.writeText(issued.token);
      setCopied("copied");
    } catch {
      setCopied("failed");
    }
  }, [issued]);

  /// Withdraws the token on the server, so one shown by mistake can never enroll a device.
  /// Dismissing only forgets the token here; this is the control that makes it useless.
  const revoke = useCallback(async () => {
    if (!issued) return;
    setRevoking(true);
    setRevokeFailure(null);
    try {
      await api.revokeEnrollmentToken(issued.token);
      setIssued(null);
      setCopied("idle");
      setWithdrawn(true);
    } catch (error) {
      setRevokeFailure(error);
    } finally {
      setRevoking(false);
    }
  }, [api, issued]);

  const dismiss = useCallback(() => {
    setIssued(null);
    setCopied("idle");
    setRevokeFailure(null);
  }, []);

  const hub = hubUrlHint();

  return (
    <section className="panel" aria-labelledby="enroll-heading">
      <h2 id="enroll-heading">Add a device</h2>
      <p className="muted">
        A token is single-use and expires. Create one, then enter it in the app on the phone.
      </p>

      <div className="actions">
        <label htmlFor="enroll-owner">Owner</label>
        <input
          id="enroll-owner"
          type="text"
          value={owner}
          onChange={(event) => setOwner(event.target.value)}
          autoComplete="off"
        />

        <label htmlFor="enroll-lifetime">Valid for</label>
        <select
          id="enroll-lifetime"
          value={lifetime}
          onChange={(event) => setLifetime(Number(event.target.value))}
        >
          {LIFETIMES.map((option) => (
            <option key={option.seconds} value={option.seconds}>
              {option.label}
            </option>
          ))}
        </select>

        <button
          type="button"
          disabled={busy || owner.trim() === ""}
          onClick={() => void mint()}
        >
          Create enrollment token
        </button>
      </div>

      {withdrawn ? (
        <p role="status" className="muted">
          The token was revoked. It can no longer enroll a device.
        </p>
      ) : null}

      {failure ? <ErrorNotice error={failure} onRetry={() => void mint()} /> : null}

      {issued ? (
        <div role="status" className="notice">
          <p>
            <strong>Enrollment token for {issued.ownerId}</strong> — expires{" "}
            <time dateTime={new Date(issued.expiresAt).toISOString()}>
              {new Date(issued.expiresAt).toLocaleString()}
            </time>
          </p>
          <p>
            <code data-testid="enrollment-token">{issued.token}</code>
          </p>
          <div className="actions">
            <button type="button" onClick={() => void copy()}>
              Copy token
            </button>
            <button type="button" disabled={revoking} onClick={() => void revoke()}>
              {revoking ? "Revoking…" : "Revoke token"}
            </button>
            <button type="button" onClick={dismiss}>
              Dismiss
            </button>
          </div>
          {revokeFailure ? (
            <ErrorNotice error={revokeFailure} onRetry={() => void revoke()} />
          ) : null}
          {copied === "copied" ? <p className="muted">Copied to the clipboard.</p> : null}
          {copied === "failed" ? (
            <p className="notice-error">
              The clipboard refused the copy. Select the token above and copy it by hand.
            </p>
          ) : null}
          <ol>
            <li>Install the PhoneConnect app on the phone.</li>
            <li>
              Open it and enter this hub URL: <code>{hub.url}</code>.
            </li>
            <li>Paste the token above and press “Enroll and connect”.</li>
          </ol>
          {hub.warning ? <p className="notice-error">{hub.warning}</p> : null}
          <p className="muted">
            The token is not stored in a readable form on the server, so this is the only time
            it can be shown. Revoke it if it was minted for the wrong owner or seen by anyone
            else.
          </p>
        </div>
      ) : null}
    </section>
  );
}

/// The hub URL to put in the phone, plus a warning when it cannot be the right one.
///
/// The browser reached the server through this origin, so for a deployment opened at its
/// public address this is exactly right. It is wrong when the operator is on the server's own
/// machine: `localhost` and `127.0.0.1` on the phone mean the phone, not the server. The
/// server knows the origin clients dial (`PHONECONNECT_PUBLIC_URL`) but does not expose it, so
/// this can only flag the case it can detect rather than substitute the right value.
function hubUrlHint(): { url: string; warning: string | null } {
  if (typeof window === "undefined") {
    return { url: "the server origin", warning: null };
  }
  const { origin, hostname } = window.location;
  const loopback =
    hostname === "localhost" ||
    hostname === "127.0.0.1" ||
    hostname === "::1" ||
    hostname === "[::1]";
  return {
    url: origin,
    warning: loopback
      ? "This address is on this computer, not the network. On the phone, “localhost” and “127.0.0.1” mean the phone itself, so enter the hub's own address instead — the HTTPS origin this deployment is reachable at."
      : null,
  };
}
