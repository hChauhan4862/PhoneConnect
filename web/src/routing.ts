/// Route matching and in-SPA navigation. The same paths are served by the server as the SPA
/// document, so a reload, a deep link, and a native webview all resolve identically.

import { useEffect, useState } from "react";

export type Route =
  | { name: "devices" }
  | { name: "device"; deviceId: string }
  | { name: "telemetry"; deviceId: string }
  | { name: "commands"; deviceId: string }
  | { name: "unknown"; path: string };

export function devicePath(deviceId: string): string {
  return `/devices/${encodeURIComponent(deviceId)}`;
}

export function liveTelemetryPath(deviceId: string): string {
  return `${devicePath(deviceId)}/telemetry`;
}

export function commandsPath(deviceId: string): string {
  return `${devicePath(deviceId)}/commands`;
}

function decodeSegment(segment: string): string | null {
  try {
    return decodeURIComponent(segment);
  } catch {
    return null;
  }
}

export function matchRoute(pathname: string): Route {
  const segments = pathname.split("/").filter((segment) => segment.length > 0);
  if (segments.length === 0) return { name: "devices" };
  if (segments[0] !== "devices") return { name: "unknown", path: pathname };
  if (segments.length === 1) return { name: "devices" };

  const deviceId = decodeSegment(segments[1]);
  if (!deviceId) return { name: "unknown", path: pathname };
  if (segments.length === 2) return { name: "device", deviceId };
  if (segments.length === 3 && segments[2] === "telemetry") {
    return { name: "telemetry", deviceId };
  }
  if (segments.length === 3 && segments[2] === "commands") {
    return { name: "commands", deviceId };
  }
  return { name: "unknown", path: pathname };
}

export function navigate(path: string): void {
  if (window.location.pathname === path && window.location.search === "") {
    window.dispatchEvent(new PopStateEvent("popstate"));
    return;
  }
  window.history.pushState({}, "", path);
  window.dispatchEvent(new PopStateEvent("popstate"));
}

export function usePathname(): string {
  const [pathname, setPathname] = useState(() => window.location.pathname);
  useEffect(() => {
    const onPopState = () => setPathname(window.location.pathname);
    window.addEventListener("popstate", onPopState);
    return () => window.removeEventListener("popstate", onPopState);
  }, []);
  return pathname;
}

export function useRoute(): Route {
  return matchRoute(usePathname());
}
