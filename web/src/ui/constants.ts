export const SCOPES = [
  "state:read",
  "state:write",
  "config:reload",
  "config:export",
  "policy:test",
  "events:read",
  "events:sensitive",
  "tokens:manage",
  "runtime:reset",
] as const;

export const AUTH_METHODS = ["ascii", "pap", "chap", "mschapv1", "mschapv2", "enable"] as const;

export const RADIUS_AUTH_METHODS = ["pap", "chap"] as const;

export const RADIUS_ROLES = ["access", "accounting"] as const;

export const RADIUS_ACCT_STATUS_TYPES = [
  "start",
  "stop",
  "interim_update",
  "accounting_on",
  "accounting_off",
] as const;

export const EVENT_CATEGORIES = [
  "authen",
  "author",
  "acct",
  "config",
  "token",
  "listener",
  "system",
  "api",
  "security",
] as const;

export const EVENT_PROTOCOLS = ["tacacs", "radius", "http"] as const;

export const EVENT_LISTENER_ROLES = [
  "authentication",
  "authorization",
  "accounting",
  "access",
  "admin",
  "aaa",
] as const;

export const RULE_ACTIONS = ["permit_add", "permit_replace", "deny"] as const;

export const TRANSPORTS = ["legacy", "tls"] as const;

export const MATCH_MODES = ["address_and_certificate", "certificate_only"] as const;

export const CONFIG_VIEWS = ["effective", "baseline", "overlay"] as const;

export function splitList(raw: string): string[] {
  return raw
    .split(/[, \n]+/)
    .map((part) => part.trim())
    .filter((part) => part !== "");
}

export function joinList(items: readonly string[] | undefined): string {
  return items && items.length > 0 ? items.join(", ") : "";
}

function pad2(n: number): string {
  return String(n).padStart(2, "0");
}

/** UTC instant → `datetime-local` wall time in the operator zone. */
export function toDatetimeLocal(iso: string | undefined): string {
  if (!iso) {
    return "";
  }
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return "";
  }
  return `${String(d.getFullYear())}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())}T${pad2(d.getHours())}:${pad2(d.getMinutes())}`;
}

/** `datetime-local` wall time in the operator zone → UTC instant. */
export function fromDatetimeLocal(value: string): string | undefined {
  const trimmed = value.trim();
  if (trimmed === "") {
    return undefined;
  }
  const m = /^(\d{4})-(\d{2})-(\d{2})T(\d{2}):(\d{2})(?::(\d{2}))?/.exec(trimmed);
  if (!m) {
    return undefined;
  }
  const d = new Date(
    Number(m[1]),
    Number(m[2]) - 1,
    Number(m[3]),
    Number(m[4]),
    Number(m[5]),
    m[6] !== undefined ? Number(m[6]) : 0,
    0,
  );
  if (Number.isNaN(d.getTime())) {
    return undefined;
  }
  return d.toISOString();
}

export function compact<T extends object>(obj: { [K in keyof T]?: T[K] | undefined }): T {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(obj)) {
    if (value !== undefined) {
      out[key] = value;
    }
  }
  return out as T;
}

export function lifecycleLabel(raw: string): string {
  switch (raw) {
    case "current":
      return "Current";
    case "due_soon":
      return "Due soon";
    case "overdue":
      return "Overdue";
    default:
      return "Unknown";
  }
}
