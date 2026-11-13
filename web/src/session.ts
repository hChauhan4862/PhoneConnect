/// The browser session for this milestone: the admin bearer token plus the user id the
/// operator acts as. Local password login and MFA replace this store, not the screens.

export interface Session {
  token: string;
  userId: string;
}

const SESSION_KEY = "phoneconnect.session";

export function readSession(): Session | null {
  try {
    const raw = window.sessionStorage.getItem(SESSION_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as Partial<Session>;
    if (typeof parsed.token !== "string" || typeof parsed.userId !== "string") {
      return null;
    }
    if (!parsed.token || !parsed.userId) return null;
    return { token: parsed.token, userId: parsed.userId };
  } catch {
    return null;
  }
}

export function saveSession(session: Session): void {
  window.sessionStorage.setItem(SESSION_KEY, JSON.stringify(session));
}

export function clearSession(): void {
  window.sessionStorage.removeItem(SESSION_KEY);
}
