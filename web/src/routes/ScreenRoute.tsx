/// The screen page: one frame, captured on request, or the device's reason it cannot.
///
/// An ordinary app captures the screen only with the `MediaProjection` consent the user
/// granted on the device's setup screen. Without it the device answers `consent_required`,
/// and this page shows that as an alert — never a blank image, and never a stale frame from an
/// earlier capture. The frame is not stored: it exists in this response only.

import { useCallback, useEffect, useRef, useState } from "react";

import type { ApiClient, ScreenSnapshotOutput } from "../api";
import { FailureNotice } from "../components/FailureNotice";
import { RouteLink } from "../components/RouteLink";
import { pollCommand } from "../data/commands";
import { failureOfCommand, failureOfError, type Failure } from "../data/failures";
import { formatTime } from "../format";
import { devicePath } from "../routing";

export interface ScreenRouteProps {
  api: ApiClient;
  deviceId: string;
  userId: string;
  /// Poll interval; tests shorten it.
  pollIntervalMs?: number;
}

export function ScreenRoute({ api, deviceId, userId, pollIntervalMs }: ScreenRouteProps) {
  const [snapshot, setSnapshot] = useState<ScreenSnapshotOutput | null>(null);
  const [failure, setFailure] = useState<Failure | null>(null);
  const [capturing, setCapturing] = useState(false);

  const mounted = useRef(true);
  useEffect(() => {
    mounted.current = true;
    return () => {
      mounted.current = false;
    };
  }, []);

  const capture = useCallback(async () => {
    setCapturing(true);
    // The previous frame is dropped before the new command is even accepted: a failure must
    // never leave an old picture looking like the capture the user just asked for.
    setSnapshot(null);
    setFailure(null);
    try {
      const accepted = await api.captureScreen(deviceId, userId);
      const command = await pollCommand(api, userId, accepted.command_id, {
        pollIntervalMs,
        isActive: () => mounted.current,
      });
      if (!mounted.current) return;
      if (command.status !== "ok") {
        setFailure(failureOfCommand(command));
        return;
      }
      const frame = readSnapshot(command.output);
      if (!frame) {
        setFailure({
          code: "invalid_result",
          message: "the device's answer is not a screen frame",
        });
        return;
      }
      setSnapshot(frame);
    } catch (error) {
      if (mounted.current) setFailure(failureOfError(error));
    } finally {
      if (mounted.current) setCapturing(false);
    }
  }, [api, deviceId, userId, pollIntervalMs]);

  return (
    <>
      <nav>
        <RouteLink to={devicePath(deviceId)}>Back to status</RouteLink>
      </nav>
      <h1>Screen</h1>
      <p className="muted">
        A snapshot needs the screen-capture consent granted on the device&apos;s own setup
        screen. Opening this page never prompts the device: without consent the answer is
        <code> consent_required</code>.
      </p>
      <p className="muted">
        The device returns its newest buffered frame, so a screen that has not changed can
        return a frame older than this request; the capture time shown is the time that frame
        was produced.
      </p>

      <section className="panel" aria-labelledby="screen-heading">
        <h2 id="screen-heading">Screen snapshot</h2>
        <div className="actions">
          <button type="button" disabled={capturing} onClick={() => void capture()}>
            {capturing ? "Capturing…" : "Capture screen"}
          </button>
        </div>

        {failure ? <FailureNotice failure={failure} /> : null}
        {capturing && !snapshot ? <p>Capturing one frame…</p> : null}
        {snapshot ? (
          <figure className="snapshot">
            <img
              src={`data:image/png;base64,${snapshot.png_base64}`}
              alt={`Screen snapshot captured at ${formatTime(snapshot.captured_at_ms)}`}
            />
            <figcaption>
              <p>
                Captured at {formatTime(snapshot.captured_at_ms)} ({snapshot.captured_at_ms}).
              </p>
              <p>
                {snapshot.width} × {snapshot.height} px, as captured after any downscale.
              </p>
            </figcaption>
          </figure>
        ) : null}
      </section>
    </>
  );
}

/// A frame the screen can actually render: base64 PNG, positive dimensions, a real timestamp.
function readSnapshot(output: unknown): ScreenSnapshotOutput | null {
  if (typeof output !== "object" || output === null) return null;
  const value = output as Record<string, unknown>;
  if (typeof value.png_base64 !== "string" || value.png_base64.length === 0) return null;
  if (typeof value.width !== "number" || value.width <= 0) return null;
  if (typeof value.height !== "number" || value.height <= 0) return null;
  if (typeof value.captured_at_ms !== "number") return null;
  return {
    png_base64: value.png_base64,
    width: value.width,
    height: value.height,
    captured_at_ms: value.captured_at_ms,
  };
}
