import type {
  BuildInfo,
  Envelope,
  EventList,
  ProblemDetails,
  Session,
  Status,
  TokenList,
} from "../generated/api";
import { assertNoTokenStorage } from "./storage";

export const CSRF_COOKIE = "taclab_csrf";
export const CSRF_HEADER = "X-CSRF-Token";

export class APIError extends Error {
  readonly problem: ProblemDetails;

  constructor(problem: ProblemDetails) {
    super(problem.detail || problem.title || "request failed");
    this.name = "APIError";
    this.problem = problem;
  }
}

export function readCsrfCookie(): string {
  if (typeof document === "undefined") {
    return "";
  }
  const parts = document.cookie.split(";");
  for (const part of parts) {
    const trimmed = part.trim();
    if (trimmed.startsWith(`${CSRF_COOKIE}=`)) {
      return decodeURIComponent(trimmed.slice(CSRF_COOKIE.length + 1));
    }
  }
  return "";
}

function problemFrom(status: number, statusText: string, body: unknown): ProblemDetails {
  const fallback: ProblemDetails = {
    type: "about:blank",
    title: statusText || "error",
    status,
    detail: statusText || "request failed",
    code: status === 401 ? "unauthenticated" : status === 403 ? "permission_denied" : "internal",
  };
  if (!body || typeof body !== "object") {
    return fallback;
  }
  const rec = body as Record<string, unknown>;
  return {
    type: typeof rec.type === "string" ? rec.type : fallback.type,
    title: typeof rec.title === "string" ? rec.title : fallback.title,
    status: typeof rec.status === "number" ? rec.status : fallback.status,
    detail: typeof rec.detail === "string" ? rec.detail : fallback.detail,
    code: typeof rec.code === "string" ? rec.code : fallback.code,
    ...(typeof rec.path === "string" ? { path: rec.path } : {}),
    ...(typeof rec.instance === "string" ? { instance: rec.instance } : {}),
  };
}

export async function apiFetch(path: string, init: RequestInit = {}): Promise<Response> {
  assertNoTokenStorage();
  const headers = new Headers(init.headers);
  const method = (init.method ?? "GET").toUpperCase();
  if (method !== "GET" && method !== "HEAD" && !headers.has(CSRF_HEADER)) {
    const csrf = readCsrfCookie();
    if (csrf !== "") {
      headers.set(CSRF_HEADER, csrf);
    }
  }
  if (!headers.has("Accept")) {
    headers.set("Accept", "application/json");
  }
  return fetch(path, {
    ...init,
    credentials: "same-origin",
    headers,
  });
}

export async function readEnvelope<T>(resp: Response): Promise<Envelope<T>> {
  const text = await resp.text();
  let parsed: unknown = undefined;
  if (text !== "") {
    try {
      parsed = JSON.parse(text) as unknown;
    } catch {
      parsed = undefined;
    }
  }
  if (!resp.ok) {
    throw new APIError(problemFrom(resp.status, resp.statusText, parsed));
  }
  if (!parsed || typeof parsed !== "object") {
    throw new APIError(problemFrom(500, "invalid envelope", parsed));
  }
  return parsed as Envelope<T>;
}

export async function createSession(token: string): Promise<Envelope<Session>> {
  const resp = await apiFetch("/api/v1/session", {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
  });
  const env = await readEnvelope<Session>(resp);
  assertNoTokenStorage();
  return env;
}

export async function deleteSession(): Promise<void> {
  const resp = await apiFetch("/api/v1/session", { method: "DELETE" });
  if (resp.status === 401) {
    return;
  }
  await readEnvelope<unknown>(resp);
}

export async function getStatus(): Promise<Envelope<Status>> {
  return readEnvelope<Status>(await apiFetch("/api/v1/status"));
}

export async function getBuild(): Promise<Envelope<BuildInfo>> {
  return readEnvelope<BuildInfo>(await apiFetch("/api/v1/build"));
}

export async function listEvents(limit: number): Promise<Envelope<EventList>> {
  return readEnvelope<EventList>(await apiFetch(`/api/v1/events?limit=${String(limit)}`));
}

export async function listTokens(): Promise<Envelope<TokenList>> {
  return readEnvelope<TokenList>(await apiFetch("/api/v1/tokens"));
}

export function hashPrefix(value: string, n = 12): string {
  if (value.length <= n) {
    return value;
  }
  return value.slice(0, n);
}
