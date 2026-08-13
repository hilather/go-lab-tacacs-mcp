/** Non-secret principal fields only. Never a bearer or cookie secret. */
export const SESSION_META_KEY = "taclab_ui_principal";

export type SessionMeta = {
  token_id: string;
  scopes: string[];
  expires_at: string;
};

function isMeta(v: unknown): v is SessionMeta {
  if (!v || typeof v !== "object") {
    return false;
  }
  const rec = v as Record<string, unknown>;
  return (
    typeof rec.token_id === "string" &&
    typeof rec.expires_at === "string" &&
    Array.isArray(rec.scopes) &&
    rec.scopes.every((s) => typeof s === "string")
  );
}

export function saveSessionMeta(meta: SessionMeta): void {
  if (typeof sessionStorage === "undefined") {
    return;
  }
  sessionStorage.setItem(SESSION_META_KEY, JSON.stringify(meta));
}

export function loadSessionMeta(): SessionMeta | null {
  if (typeof sessionStorage === "undefined") {
    return null;
  }
  const raw = sessionStorage.getItem(SESSION_META_KEY);
  if (raw === null || raw === "") {
    return null;
  }
  try {
    const parsed: unknown = JSON.parse(raw);
    return isMeta(parsed) ? parsed : null;
  } catch {
    return null;
  }
}

export function clearSessionMeta(): void {
  if (typeof sessionStorage === "undefined") {
    return;
  }
  sessionStorage.removeItem(SESSION_META_KEY);
}
