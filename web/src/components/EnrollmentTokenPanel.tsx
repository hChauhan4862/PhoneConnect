/// Onboarding: mint a one-time enrollment token and see the exact steps an operator follows.
///
/// The token is the only moment the secret is readable — the server stores a hash and no
/// endpoint can return it again — so it is shown once, with a copy control, never in the URL,
/// never in a log, and it is cleared when the operator dismisses it. A failure is the server's
/// own refusal with its machine code; nothing is fabricated.

import { useCallback, useState } from "react";

import { type ApiClient, type IssuedEnrollmentToken } from "../api";
import { ErrorNotice } from "../components/ErrorNotice";

/// The server accepts 1–3600 seconds and defaults to 900.
const LIFETIMES: { label: string; seconds: number }[] = [
  { label: "15 minutes", seconds: 900 },
  { label: "1 hour", seconds: 3600 },
];

export function EnrollmentTokenPanel({
  api,
  defaultOwner,
}: {
  api: ApiClient;
  defaultOwner: string;
}) {
  const [owner, setOwner] = useState(defaultOwner);
  const [lifetime, setLifetime] = useState(900);
  const [issued, setIssued] = useState<IssuedEnrollmentToken | null>(null);
  const [failure, setFailure] = useState<unknown>(null);
  const [busy, setBusy] = useState(false);
  const [copied, setCopied] = useState<"idle" | "copied" | "failed">("idle");

  const mint = useCallback(async () => {
    setBusy(true);
    setFailure(null);
    setCopied("idle");
    try {
      const token = await api.issueEnrollmentToken(owner.trim(), lifetime);
      setIssued(token);
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

  const dismiss = useCallback(() => {
    setIssued(null);
    setCopied("idle");
  }, []);

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

      {failure ? <ErrorNotice error={failure} onRetry={() => void mint()} /> : null}

      {issued ? (
        <div role="status" className="notice">
          <p>
            <strong>Enrollment token</strong> — expires{" "}
            <time dateTime={new Date(issued.expires_at).toISOString()}>
              {new Date(issued.expires_at).toLocaleString()}
            </time>
          </p>
          <p>
            <code data-testid="enrollment-token">{issued.token}</code>
          </p>
          <div className="actions">
            <button type="button" onClick={() => void copy()}>
              Copy token
            </button>
            <button type="button" onClick={dismiss}>
              Dismiss
            </button>
          </div>
          {copied === "copied" ? <p className="muted">Copied to the clipboard.</p> : null}
          {copied === "failed" ? (
            <p className="notice-error">
              The clipboard refused the copy. Select the token above and copy it by hand.
            </p>
          ) : null}
          <ol>
            <li>Install the PhoneConnect app on the phone.</li>
            <li>Open it and enter this hub URL: <code>{hubUrl()}</code>.</li>
            <li>Paste the token above and press “Enroll and connect”.</li>
          </ol>
          <p className="muted">
            The token is not stored in a readable form on the server, so this is the only time
            it can be shown.
          </p>
        </div>
      ) : null}
    </section>
  );
}

/// The origin the operator is using now is the origin the phone must dial, because the
/// browser reached the server through it.
function hubUrl(): string {
  if (typeof window === "undefined") return "the server origin";
  return window.location.origin;
}
