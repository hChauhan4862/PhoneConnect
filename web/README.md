# PhoneConnect web UI

This is the **only** UI implementation. The server serves it at `/` and the native shell
loads that same URL in a webview; screens are never forked per host.

**The UI is not live.** There is no server-to-client push channel yet: a screen renders the
snapshot it last read, so another user's handoff, a lease revocation, a new session, or a
fresh telemetry report appears only after a refresh. The status and telemetry screens say
this next to their refresh controls, and no screen claims otherwise. The command console
polls the dispatched command until the device answers; it never infers a result.

**Leases are not yet an authentication boundary.** Access uses the admin bearer token and an
asserted user id; the lease rules constrain what an accepted user may do, but they do not
authenticate that user. Local password login and MFA replace the access gate without changing
the screens.

```sh
npm ci
npm test          # Vitest + Testing Library
npm run typecheck
npm run lint
npm run build     # emits dist/, which the server serves from PHONECONNECT_WEB_ROOT
```

## Layout

- `src/App.tsx` — the shell: selects one host adapter, holds the session, and renders the
  current route. It contains no screen logic.
- `src/routing.ts` — `matchRoute`, `navigate`, and `useRoute`. Routes are plain paths:
  `/` (devices), `/devices/:id` (status), `/devices/:id/telemetry` (live telemetry),
  `/devices/:id/commands` (the command console), `/devices/:id/files` (the file browser),
  `/devices/:id/apps` (the app inventory), `/devices/:id/screen` (one screen snapshot), and
  `/devices/:id/console` (system properties and the two documented refusals).
  The server's SPA fallback serves the same document for each, so a reload or deep link works.
- `src/api.ts` — the REST surface as typed views (`DeviceStatus`, `LeaseStatusView`,
  `TelemetryView`, …). Failures are `ApiError { status, code }`; there is no success-shaped
  fallback and no second domain model. The client is same-origin, so the native shell's
  embedded page makes exactly the calls a browser makes.
- `src/host/` — the single place host differences live (see below).
- `src/routes/` — one component per route. `AccessGateRoute`, `DeviceListRoute`,
  `DeviceStatusRoute`, `TelemetryRoute`, `CommandsRoute`, `FilesRoute`, `AppsRoute`,
  `ScreenRoute`, `ConsoleRoute`, `NotFoundRoute`.
- `src/components/` — small presentational pieces plus `LeasePanel` (the lease surface),
  `TelemetryPanel` (bounded aggregates and explicit freshness), `CommandPanel` (dispatch
  and poll), and `FileList` (one directory's entries). `FileList` is presentational: `FilesRoute`
  owns navigation and every operation, clears the listing the moment the path changes, refuses
  a success whose output is not a listing, and requires a second confirmation before a write or
  a delete. `AppList` is presentational in the same way: `AppsRoute` owns the commands, clears
  the listing on every reload, drops a late answer for an abandoned query, shows a launch
  refusal (`launch_blocked`) as an alert with its machine code, says only that Android was
  *asked* to kill a package, and renders `apps.clear`/`apps.set_enabled` as disabled controls
  with the signature-permission reason and the ADB path — never as buttons that fail
  silently. `ScreenRoute` captures only when the user presses its button (opening the page
  never prompts the device), drops the previous frame the moment a new capture starts, renders
  the PNG with alt text plus `captured_at_ms` and the width/height actually captured, and shows
  every refusal — `consent_required` first among them — as an alert with its machine code, never
  as a blank or stale image. `ConsoleRoute` renders the device's documented system properties
  (an unreadable property is "not reported", never invented) and shows `shell.exec` and
  `logcat.tail` as disabled controls with the device's own constant reason, because an ordinary
  app can never run either. `CommandPanel` renders `pending`, `ok`, `error`, and `timeout` distinctly: only
  `ok` shows output, and a refused dispatch (`device_offline`, `device_revoked`,
  `lease_read_only`) is an alert, never a pending row that looks like it is working. `LeasePanel` offers revoke and
  handoff to the owner *or* the holder, because the server lets the owner revoke a lease they
  do not hold; "Read-only access" is reserved for a user who is neither. `SessionPanel` also
  shows the server's `control_refusals` count, so a refused control attempt on a read-only
  session is visible rather than silently dropped. `ControlPanel` (mounted on the status
  screen for the owner or the holder of the control lease, which is the server's own rule)
  renders every reading the device reported and every key it refused as a disabled control
  with the reason as visible text, only confirms a change once the device answers `ok`, and
  re-reads `control.get` after a confirmed change instead of assuming the value took. A
  secondary viewer gets a short "requires control access" line instead of the panel, because
  `control.get` would answer `lease_read_only` — a refusal the viewer can do nothing about.
- `src/data/useResource.ts` — one load/retry primitive; `src/data/controlReasons.ts` — the
  device's constant control reasons as the sentences the panel shows; `src/session.ts` — the
  browser session (admin token + acting user id) used until local password login and MFA land.

## The host adapter contract

`HostAdapter` is the only abstraction that knows whether the page is in a browser or a
native shell:

```ts
interface HostAdapter {
  readonly kind: "browser" | "native";
  openView(route: string, options: { detached: boolean }): Promise<void>;
  setTrayStatus(status: TrayStatus): Promise<void>;
  localEndpoints(): Promise<LocalEndpoint[]>;
  notify(input: { title: string; body: string }): Promise<void>;
}
```

- `createHostAdapter(context?)` returns the native adapter only when `context.kind ===
  "native"`; otherwise it returns the browser adapter. `App` calls
  `createHostAdapter(readHostContext())`, so selection is explicit and failure to inject a
  context simply means "browser".
- `browserHost` navigates in the SPA (ignoring `detached`), has no tray or OS window, returns
  no local endpoints, and turns a notification into an in-page event.
- `nativeHost` opens a detached OS window when the shell bridge provides `openWindow`, and
  otherwise navigates the embedded webview to the same route. Every bridge capability is
  optional; a missing one degrades to the browser behavior for that operation.
- Native-only affordances are additive: `HostActions` always renders the in-page action and
  only adds the detached-window action when `kind === "native"`, so a web user never sees a
  control that cannot work.

### What the native shell injects

Before the app loads, the shell sets two globals (see `src/host/hostContext.ts`):

```js
window.__PHONECONNECT_HOST__ = {
  kind: "native",
  serverUrl: "https://phoneconnect.example", // the URL the shell loaded
  proxyCapabilities: [{ deviceId, stream, url }],
};
window.__PHONECONNECT_BRIDGE__ = {
  openWindow(route) {},        // optional: separate OS window
  setTrayStatus(status) {},    // optional: tray label/health/detail
  localEndpoints() {},         // optional: loopback endpoints currently exposed
  notify({ title, body }) {},  // optional: OS notification
};
```

The bridge is read at call time, so a shell may install it after page load. The page never
reads a privileged credential from this object: server authentication is the same cookie or
token a browser uses.
