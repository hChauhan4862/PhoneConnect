import type { MouseEvent, ReactNode } from "react";

import { navigate } from "../routing";

/// A real link, so a reload or an open-in-new-tab still works through the server's SPA
/// fallback, while a plain click stays inside the SPA.
export function RouteLink({
  to,
  children,
}: {
  to: string;
  children: ReactNode;
}) {
  function onClick(event: MouseEvent<HTMLAnchorElement>) {
    if (
      event.defaultPrevented ||
      event.metaKey ||
      event.ctrlKey ||
      event.shiftKey ||
      event.button !== 0
    ) {
      return;
    }
    event.preventDefault();
    navigate(to);
  }

  return (
    <a href={to} onClick={onClick}>
      {children}
    </a>
  );
}
