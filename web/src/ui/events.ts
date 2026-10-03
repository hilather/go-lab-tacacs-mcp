import { listEvents } from "../api/client";
import type { EventView } from "../generated/api";

export const EVENT_RETENTION = 1000;

export type EventKind = "auth" | "acct" | "fail";

export const AUTH_CATEGORIES = ["authen", "author"] as const;
const AAA_CATEGORIES = new Set(["authen", "author", "acct"]);

const FAIL_FAMILY = new Set(["fail", "error", "deny", "reject", "access_reject"]);
const PASS_FAMILY = new Set([
  "pass",
  "ok",
  "success",
  "accept",
  "access_accept",
  "permit_add",
  "permit_replace",
]);

export function eventProtocolToken(ev: EventView): string {
  const raw = ev.protocol?.trim() ?? "";
  if (raw !== "") {
    return raw;
  }
  if (AAA_CATEGORIES.has(ev.category)) {
    return "tacacs";
  }
  return "";
}

export function eventProtocolLabel(token: string): string {
  switch (token) {
    case "tacacs":
      return "TACACS+";
    case "radius":
      return "RADIUS";
    case "http":
      return "HTTP";
    case "":
      return "—";
    default:
      return token;
  }
}

export function eventWho(ev: EventView): string {
  const who = ev.user_id?.trim() ?? "";
  return who === "" ? "—" : who;
}

export function eventWhat(ev: EventView): string {
  const command = ev.command?.trim() ?? "";
  if (command !== "") {
    return command;
  }
  const typ = ev.type?.trim() ?? "";
  const packet = ev.packet_code?.trim() ?? "";
  if (typ !== "" && packet !== "") {
    return `${typ} · ${packet}`;
  }
  return typ === "" ? "—" : typ;
}

export function eventWhere(ev: EventView): string {
  const client = ev.client_id?.trim() ?? "";
  if (client !== "") {
    return client;
  }
  const remote = ev.remote?.trim() ?? "";
  return remote === "" ? "—" : remote;
}

export function eventResult(ev: EventView): string {
  const result = ev.result?.trim() ?? "";
  if (result !== "") {
    return result;
  }
  const outcome = ev.outcome?.trim() ?? "";
  return outcome === "" ? "—" : outcome;
}

export function resultTone(raw: string): "pass" | "fail" | "warn" | "muted" {
  const key = raw.trim().toLowerCase();
  if (key === "must_change") {
    return "warn";
  }
  if (PASS_FAMILY.has(key)) {
    return "pass";
  }
  if (FAIL_FAMILY.has(key)) {
    return "fail";
  }
  return "muted";
}

export function isFailFamily(ev: EventView): boolean {
  return resultTone(eventResult(ev)) === "fail";
}

export function formatEventClock(iso: string, now: Date = new Date()): string {
  const d = new Date(iso);
  if (Number.isNaN(d.getTime())) {
    return iso;
  }
  void now;
  const pad = (n: number) => String(n).padStart(2, "0");
  return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

export function kindMatches(ev: EventView, kind: EventKind): boolean {
  switch (kind) {
    case "auth":
      return ev.category === "authen" || ev.category === "author";
    case "acct":
      return ev.category === "acct";
    case "fail":
      return isFailFamily(ev);
    default:
      return true;
  }
}

export function protocolMatches(ev: EventView, protocol: string): boolean {
  if (protocol.trim() === "") {
    return true;
  }
  return eventProtocolToken(ev) === protocol;
}

export function searchMatches(ev: EventView, raw: string): boolean {
  const want = raw.trim().toLowerCase();
  if (want === "") {
    return true;
  }
  const hay = [
    ev.user_id,
    ev.client_id,
    ev.command,
    ev.type,
    ev.packet_code,
    ev.authen_method,
    ev.remote,
    ev.endpoint_id,
  ]
    .map((v) => (v ?? "").toLowerCase())
    .join("\0");
  return hay.includes(want);
}

export function matchEvent(ev: EventView, f: { kind: EventKind; protocol: string; search: string }): boolean {
  return kindMatches(ev, f.kind) && protocolMatches(ev, f.protocol) && searchMatches(ev, f.search);
}

export function sortNewestFirst(items: EventView[]): EventView[] {
  return [...items].sort((a, b) => b.id - a.id);
}

export function retainEvents(...pages: readonly EventView[][]): EventView[] {
  const byID = new Map<number, EventView>();
  for (const page of pages) {
    for (const event of page) byID.set(event.id, event);
  }
  return sortNewestFirst([...byID.values()]).slice(0, EVENT_RETENTION);
}

/** prev is the newest-first retained window returned by retainEvents/mergeEvent. */
export function mergeEvent(prev: EventView[], incoming: EventView): EventView[] {
  const rows = prev.filter((event) => event.id !== incoming.id);
  const position = rows.findIndex((event) => event.id < incoming.id);
  rows.splice(position < 0 ? rows.length : position, 0, incoming);
  return rows.slice(0, EVENT_RETENTION);
}

export function drainCategories(kind: EventKind): string[] | undefined {
  if (kind === "auth") {
    return [...AUTH_CATEGORIES];
  }
  if (kind === "acct") {
    return ["acct"];
  }
  return undefined;
}

export async function drainRecent(filters: {
  categories?: string[];
  protocol?: string;
}): Promise<{ items: EventView[]; overwritten: number; reset: boolean }> {
  let items: EventView[] = [];
  let cursor: string | undefined;
  let overwritten = 0;
  let reset = false;
  for (let i = 0; i < 64; i += 1) {
    const env = await listEvents({
      limit: 200,
      ...(cursor ? { cursor } : {}),
      ...(filters.categories ? { categories: filters.categories } : {}),
      ...(filters.protocol ? { protocol: filters.protocol } : {}),
    });
    overwritten = env.data.overwritten;
    reset = reset || env.data.reset;
    items = retainEvents(items, env.data.items);
    if (!env.data.next_cursor) {
      break;
    }
    cursor = env.data.next_cursor;
  }
  return { items, overwritten, reset };
}
