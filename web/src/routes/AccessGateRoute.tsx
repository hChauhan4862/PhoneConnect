/// Until local password login and MFA exist, the operator supplies the bootstrap admin token
/// and the user id they act as. This is the only screen that knows about credentials; no
/// screen ever renders a hard-coded one.

import { useState, type FormEvent } from "react";

import type { Session } from "../session";
import { ErrorNotice } from "../components/ErrorNotice";

export function AccessGateRoute({
  onSignIn,
}: {
  onSignIn: (session: Session) => Promise<void>;
}) {
  const [token, setToken] = useState("");
  const [userId, setUserId] = useState("");
  const [pending, setPending] = useState(false);
  const [error, setError] = useState<unknown>(null);

  async function onSubmit(event: FormEvent<HTMLFormElement>): Promise<void> {
    event.preventDefault();
    setPending(true);
    setError(null);
    try {
      await onSignIn({ token: token.trim(), userId: userId.trim() });
    } catch (failure) {
      setError(failure);
    } finally {
      setPending(false);
    }
  }

  return (
    <main className="panel">
      <h1>Sign in</h1>
      <p className="muted">
        PhoneConnect is a single-organization deployment. Access is authorized with the
        server's admin token until local password login and MFA replace it.
      </p>
      <form onSubmit={(event) => void onSubmit(event)}>
        <label htmlFor="admin-token">Admin token</label>
        <input
          id="admin-token"
          type="password"
          autoComplete="off"
          value={token}
          onChange={(event) => setToken(event.target.value)}
          required
        />
        <label htmlFor="user-id">User id</label>
        <input
          id="user-id"
          autoComplete="username"
          value={userId}
          onChange={(event) => setUserId(event.target.value)}
          required
        />
        <button type="submit" disabled={pending}>
          Sign in
        </button>
      </form>
      {error ? <ErrorNotice error={error} /> : null}
    </main>
  );
}
