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
