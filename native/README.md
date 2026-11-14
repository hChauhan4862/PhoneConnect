# PhoneConnect native shell

The desktop client is a **thin Tauri/Rust shell over the one web UI**. It loads the
server-served app at the configured URL in a webview and adds only what a browser cannot: a
tray, detached OS windows, OS notifications, and loopback proxy endpoints. It does not bundle,
fork, or reimplement the React app, and it does not rewrite its paths.

```sh
# the headless logic: URL policy, host context, proxy pump, session client
cargo test -p phoneconnect-native

# the real desktop binary (macOS was the built target; Windows/Linux are untested)
cargo build -p phoneconnect-native --features shell

# check what the shell would load and inject, without starting a webview
PHONECONNECT_SERVER_URL=https://phoneconnect.example \
  cargo run -q -p phoneconnect-native -- --print-context
```

## What it loads

`PHONECONNECT_SERVER_URL` names the server **origin**; the default is
`http://127.0.0.1:8080`. `web_shell::resolve_url` accepts only:

- `https://` on any host, or
- `http://127.0.0.1[:port]` / `http://localhost[:port]` for development,

and rejects userinfo, fragments, queries, a path other than `/`, and every other scheme. The
rule is deliberate: the server serves the app at `/`, the shell must not rewrite a path, and
plain HTTP to a remote host would carry the page's session cookie in the clear. A rejected URL
names what is wrong; nothing is silently corrected.

The webview is created with `WebviewUrl::External(<that exact URL>)`. There is no
`frontendDist` directory: no assets are compiled into the binary, so a build cannot drift from
the server-served UI.

Server authentication is unchanged. The page uses the same session cookie or token it uses in
a browser; the shell embeds no credential and has no privileged path into the API.

## What the shell injects

Before the page loads, both the embedded window and every detached window run two
initialization scripts from `native/src/web_shell.rs`:

```js
// __PHONECONNECT_HOST__ — selects the native HostAdapter
{ kind: "native", serverUrl: "https://phoneconnect.example/", proxyCapabilities: [...] }

// __PHONECONNECT_BRIDGE__ — the capabilities this shell actually provides
openWindow(route)              // detached OS window on the same origin
setTrayStatus(status)          // { label, health, detail? }
localEndpoints()               // [{ deviceId, stream, url }]
notify({ title, body })        // OS notification
identityKey()                  // the shell's X25519 public key, for POST /api/sessions
openEndpoint(request)          // establish/reuse a session, bind a port
closeEndpoint(deviceId, stream)
```

`proxyCapabilities` is derived from what the endpoint manager is serving when the window is
created; it is never a placeholder. A window opened later sees the endpoints open at that
moment, and the page refreshes through `localEndpoints()`.

Field names and JSON shape match `web/src/host/hostContext.ts` exactly; a page that cannot
read the context stays a browser, and each missing bridge method falls back to the page's
in-page behavior. Strings are escaped as JavaScript literals, so a page-supplied value cannot
break out of the injected script.

`openWindow` accepts only a single-slash absolute path and re-resolves it against the
configured origin; a protocol-relative path, a full URL, or a path that lands on another
origin is refused. Detached windows are reused by a stable per-route label rather than
duplicated.

### Endpoints and sessions

`open_endpoint` is the command that makes a mapped port real:

1. The page asks `identityKey()` for the shell's X25519 public key and creates the session on
   the server (`POST /api/sessions` with that key), exactly as any client does.
2. The page registers its candidates and passes the issued ticket, its candidates view, and
   the session capability to `openEndpoint({ deviceId, stream, ttlSeconds, session })` with
   `session.kind = "rendezvous"`.
3. `EndpointManager` verifies everything through the shared transport
   (`SessionClient::connect`: signed ticket, authenticated direct probe against the relay,
   shortest validated path), reusing the session for the next endpoint on that device.
4. It binds `127.0.0.1:0`, registers the endpoint with its capability deadline, and starts a
   serving task that accepts one local connection at a time until closed, expired, or the
   session path fails.

The shell's identity private half never leaves the process and no server credential is
embedded in the page: the ticket is single-use and short-lived, and the capability is the one
the signed-in user already holds. `EndpointManager` is plain Rust, so this whole command path
is covered by `native/tests/endpoints.rs`; the Tauri command is three lines of glue.

An endpoint disappears from `localEndpoints()` when it is closed, when its capability
expires (bounded by the ticket and `MAX_ENDPOINT_TTL_SECONDS`), or when its serving task ends
because the session path failed.

### Tauri IPC scope

Tauri grants IPC to remote origins only through an explicit capability. `native/build.rs`
declares the seven application commands, so tauri-build generates `allow-open-window`,
`allow-set-tray-status`, `allow-local-endpoints`, `allow-notify`, `allow-native-identity-key`,
`allow-open-endpoint`, and `allow-close-endpoint`.

`native/capabilities/default.json` carries **no** `remote` entry. At startup `main.rs` mints a
runtime capability for exactly the configured origin (`capability_origins`: `https://host` and
`https://host/*`, never a wildcard) and grants those seven permissions there. Another origin — or a subframe on Windows, where WebView2
installs initialization scripts into frames too — cannot reach the commands. The server sends
`frame-src 'self'` as the second half of that mitigation, and the webview also refuses to
navigate off the configured origin (`on_navigation`).

The server's CSP must let the page reach that IPC. `server/src/web.rs` therefore adds `ipc:`
and `http://ipc.localhost` to `connect-src`; a reverse proxy that replaces the CSP with its own
must keep those two sources, or every bridge call is blocked and native behavior silently
degrades to browser behavior.

Inputs are bounded before they reach the OS: tray label 128 bytes, detail 256, notification
title 200, body 2,000.

## Tray and windows

- The tray has two items: *Show PhoneConnect* (focus the embedded window) and *Quit
  PhoneConnect*. A left click on the icon also focuses the window.
- Closing the window hides the shell; the tray keeps the process alive. Quit exits.
- Tray status comes from the page: the tooltip is `label — health[: detail]`, and on macOS the
  menu-bar title shows the label.
- A notification failure is returned to the page as an error; it is never reported as
  delivered.

## Loopback proxy

`native/src/proxy.rs` implements the native half of the localhost proxy:

- `ProxyAllocator::bind(device_id, capability)` binds `127.0.0.1:0` — loopback only, OS-chosen
  ephemeral port, never `0.0.0.0` and never a fixed port. Concurrent binds cannot collide; a
  second endpoint for the same `device/stream` is refused.
- `ProxyHub` is the **single reader** of the session's `ConnectedPath`, as the transport
  requires. It routes each `StreamKind::Proxy` frame to the stream that owns its
  `request_id`; frames of other kinds (control, events, file) and frames for a stream that is
  not open belong to another consumer and are ignored. One tunnel therefore cannot tear down
  another, and several streams share the session concurrently (`adb`, `screen`, …).
- `ProxyAllocator::serve(endpoint, session)` accepts one local TCP connection and pumps it as
  `StreamKind::Proxy` envelopes. The request id is derived from the stream
  (`proxy-<stream>`), and each stream keeps its own pump and its own inbound queue.
- Every frame carries `deadline_unix_ms` and a per-stream `sequence`. The receiver requires
  contiguous sequences: a jump, or a `FramesLost` report (the path already discarded frames),
  closes that tunnel with `SequenceGap` / `FramesLost` instead of writing a hole into a TCP
  stream. Bytes are never reported as delivered across a gap.
- A slow local reader fails only its own stream (`Backpressure`); it cannot stall the shared
  path or make the reader drop frames.
- A send over `send_timeout`, a transport error, an idle connection, and capability expiry all
  close the local socket immediately and return an explicit error. A capability that has
  expired is removed from `endpoints()`, so the page never lists a dead port.
- The uplink reads one chunk, sends it, and only then reads the next. A stalled transport
  therefore stops the local socket with TCP backpressure instead of buffering.
- Idle means silence in **either** direction, and the default is 300 s: `adb shell sleep 60`
  moves nothing for a minute and is still healthy. Five minutes bounds an abandoned port
  without killing a quiet session.
- **`send_frame` returning `Ok` is not proof of delivery.** It means the sealed frame was
  handed to the direct socket or the relay; neither acknowledges the peer. `ProxySummary`
  counts bytes *accepted by the transport*, never bytes delivered, and `bytes_down` counts
  bytes actually written in sequence.

Only loopback clients can reach an endpoint. There is no authentication on the endpoint itself
— an ADB-shaped port accepts the local tool that connects to it — so it is a capability for
this machine's local processes, not a network service. Opening one to `0.0.0.0` would turn a
local capability into an unauthenticated remote one; the allocator cannot do that.

### What is not implemented yet

There is **no Android-side TCP bridge**, so nothing here claims ADB proxying works end to end.
The Task 5 page also does not call `openEndpoint` yet; it reads `localEndpoints()`, so the
endpoint API is complete, tested, and reachable from the bridge, but no shipped screen opens
one.
What is proven is the native half:

- `native/tests/proxy.rs` binds real loopback ports and drives a real `ConnectedPath` over an
  in-process relay, with a device-side stub that answers `StreamKind::Proxy` envelopes. It
  covers loopback-only binding, concurrent allocation, byte preservation across many frames,
  per-stream sequences and deadlines, two streams on one path, an interleaved Events frame, a
  foreign request id, a sequence gap, backpressure, failed sends, idle deadlines in both
  directions, capability expiry, and relay fallback (`PathKind::Relay`).
- `native/tests/endpoints.rs` exercises the command path through `EndpointManager`: an
  endpoint opened through it is reachable on `127.0.0.1`, carries bytes to the stub, two
  endpoints share one session, and it disappears from `endpoints()` after close or expiry. A
  closed session and a ticket for another device are refused before any port opens.
- Unit tests in `native/src/proxy.rs` prove a `FramesLost` report ends every live stream with
  that error and that a full queue fails only its own stream.
- The same tests would run unchanged against the Android agent once it answers proxy frames;
  the stub is the contract.
- The Docker transport end-to-end test still proves a control frame crosses processes over
  the relay: the driver now grants a lease and creates a control session, so the stub's
  CONTROL frames are authorized rather than silently dropped on a read-only session.

## Session client

`native/src/session_client.rs` wraps the shared transport:

- `SessionClient::connect(ticket, candidates, setup)` runs `PathController::connect`, so the
  ticket is verified, direct candidates are probed authenticated, and the lower-latency of
  direct and relay wins.
- `SessionClient::connect_relay_only(setup)` is the fallback when UDP is unavailable or direct
  negotiation already failed. It still seals every frame.
- `SessionPath::path_kind()` reports the path that was actually selected, and
  `proxy_session(stream, limits)` builds the pump that rides it.
- The data-path profile uses `FrameLimits::new()` instead of the control-only profile; a
  configuration whose proxy frame limit cannot hold one full chunk is refused at construction.

Direct-path and relay transport live in `crates/transport`, not here, so the native client and
the Android agent run the same negotiation. A successful send on either path is best-effort
until the peer answers; the transport's own README documents the handshake, keepalive, and
fallback rules.

## Packaging status

The binary builds for macOS (`cargo build -p phoneconnect-native --features shell`, verified:
a Mach-O arm64 executable) and its headless `--print-context` path runs. The GUI path — webview
rendering, tray interaction, a detached window, an OS notification — was not exercised in this
headless environment. Bundling a signed `.app`/`.dmg`, notarization, and the update channel are
not part of this task. Windows and Linux have not been built or exercised; the tray,
notification, and window code is Tauri's cross-platform API but only macOS was compiled here.
