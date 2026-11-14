/// The application shell: one adapter, one session, route-based screens.
///
/// It is deliberately thin. Host behavior comes from [`HostAdapter`], navigation from
/// [`useRoute`], and every screen under `routes/` works in a plain browser.

import { useCallback, useMemo, useState } from "react";

import { createHttpApi, type ApiClient } from "./api";
import { AccessGateRoute } from "./routes/AccessGateRoute";
import { AppsRoute } from "./routes/AppsRoute";
import { AuditRoute } from "./routes/AuditRoute";
import { CommandsRoute } from "./routes/CommandsRoute";
import { ConsoleRoute } from "./routes/ConsoleRoute";
import { DeviceListRoute } from "./routes/DeviceListRoute";
import { DeviceStatusRoute } from "./routes/DeviceStatusRoute";
import { FilesRoute } from "./routes/FilesRoute";
import { ScreenRoute } from "./routes/ScreenRoute";
import { TelemetryRoute } from "./routes/TelemetryRoute";
import { NotFoundRoute } from "./routes/NotFoundRoute";
import { RouteLink } from "./components/RouteLink";
import { createHostAdapter, HostAdapterContext } from "./host/HostAdapter";
import { readHostContext } from "./host/hostContext";
import { auditPath, useRoute } from "./routing";
import {
  clearSession,
  readSession,
  saveSession,
  type Session,
} from "./session";

export interface AppProps {
  /// Injected by tests; deployments build the same-origin client from the stored token.
  api?: ApiClient;
}

export function App({ api: apiOverride }: AppProps) {
  // Adapter selection is explicit: the shell's injected context means native, otherwise a
  // browser. It is read once, so a shell cannot change host behavior mid-session.
  const adapter = useMemo(() => createHostAdapter(readHostContext()), []);
  const [session, setSession] = useState<Session | null>(() => readSession());

  const api = useMemo(() => {
    if (apiOverride) return apiOverride;
    return createHttpApi({ token: session?.token ?? "" });
  }, [apiOverride, session?.token]);

  const signIn = useCallback(
    async (next: Session) => {
      const verifier = apiOverride ?? createHttpApi({ token: next.token });
      // An invalid token must fail here, never on the first screen behind the gate.
      await verifier.listDevices();
      saveSession(next);
      setSession(next);
    },
    [apiOverride],
  );

  const signOut = useCallback(() => {
    clearSession();
    setSession(null);
  }, []);

  return (
    <HostAdapterContext.Provider value={adapter}>
      <div className="app" data-host={adapter.kind}>
        {session ? (
          <AuthenticatedShell
            api={api}
            session={session}
            onSignOut={signOut}
          />
        ) : (
          <AccessGateRoute onSignIn={signIn} />
        )}
      </div>
    </HostAdapterContext.Provider>
  );
}

function AuthenticatedShell({
  api,
  session,
  onSignOut,
}: {
  api: ApiClient;
  session: Session;
  onSignOut: () => void;
}) {
  const route = useRoute();
  return (
    <>
      <header className="shell-header">
        <strong>PhoneConnect</strong>
        <span className="muted">{session.userId}</span>
        <RouteLink to={auditPath()}>Audit log</RouteLink>
        <button type="button" onClick={onSignOut}>
          Sign out
        </button>
      </header>
      {route.name === "device" ? (
        <DeviceStatusRoute
          api={api}
          deviceId={route.deviceId}
          userId={session.userId}
        />
      ) : null}
      {route.name === "telemetry" ? (
        <TelemetryRoute
          api={api}
          deviceId={route.deviceId}
          userId={session.userId}
        />
      ) : null}
      {route.name === "commands" ? (
        <CommandsRoute
          api={api}
          deviceId={route.deviceId}
          userId={session.userId}
        />
      ) : null}
      {route.name === "files" ? (
        <FilesRoute api={api} deviceId={route.deviceId} userId={session.userId} />
      ) : null}
      {route.name === "apps" ? (
        <AppsRoute api={api} deviceId={route.deviceId} userId={session.userId} />
      ) : null}
      {route.name === "screen" ? (
        <ScreenRoute api={api} deviceId={route.deviceId} userId={session.userId} />
      ) : null}
      {route.name === "console" ? (
        <ConsoleRoute api={api} deviceId={route.deviceId} userId={session.userId} />
      ) : null}
      {route.name === "audit" ? <AuditRoute api={api} /> : null}
      {route.name === "devices" ? (
        <DeviceListRoute api={api} userId={session.userId} />
      ) : null}
      {route.name === "unknown" ? <NotFoundRoute path={route.path} /> : null}
    </>
  );
}
