import type {
  AuthenticationTestResult,
  BuildInfo,
  Client,
  ClientList,
  CreateClientRequest,
  CreateGroupRequest,
  CreateTokenRequest,
  CreateUserRequest,
  CreatedToken,
  DeleteResult,
  EffectiveConfig,
  Envelope,
  EvaluatePolicyRequest,
  EventList,
  ExportConfigResult,
  Group,
  GroupList,
  ListEventsRequest,
  PolicyTrace,
  ProblemDetails,
  RadiusAccessTestRequest,
  RadiusAccessTestResult,
  RadiusPolicyEvaluateRequest,
  RadiusPolicyEvaluateResult,
  ReloadConfigResult,
  ResetRuntimeResult,
  Session,
  Status,
  TestAuthenticationRequest,
  TokenList,
  UpdateClientRequest,
  UpdateGroupRequest,
  UpdateUserRequest,
  User,
  UserList,
  ValidateConfigRequest,
  ValidateConfigResult,
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

export function revisionETag(revision: number): string {
  return `"revision-${String(revision)}"`;
}

export function isRevisionMismatch(err: unknown): boolean {
  return err instanceof APIError && (err.problem.code === "revision_mismatch" || err.problem.status === 412);
}

function queryString(params: Record<string, string | number | boolean | undefined | readonly string[]>): string {
  const u = new URLSearchParams();
  for (const [key, value] of Object.entries(params)) {
    if (value === undefined || value === "") {
      continue;
    }
    if (Array.isArray(value)) {
      for (const item of value) {
        if (item !== "") {
          u.append(key, item);
        }
      }
      continue;
    }
    if (typeof value === "boolean") {
      if (value) {
        u.set(key, "true");
      }
      continue;
    }
    u.set(key, String(value));
  }
  const encoded = u.toString();
  return encoded === "" ? "" : `?${encoded}`;
}

export function newIdempotencyKey(): string {
  return crypto.randomUUID();
}

export async function latestRevision(): Promise<number> {
  const env = await getStatus();
  return env.revision;
}

async function sendJSON<T>(
  path: string,
  method: string,
  body: unknown,
  revision?: number,
  idempotencyKey?: string,
): Promise<Envelope<T>> {
  const headers = new Headers({ "Content-Type": "application/json" });
  if (revision !== undefined) {
    headers.set("If-Match", revisionETag(revision));
  }
  if (idempotencyKey !== undefined && idempotencyKey !== "") {
    headers.set("Idempotency-Key", idempotencyKey);
  }
  const init: RequestInit = { method, headers };
  if (body !== undefined) {
    init.body = JSON.stringify(body);
  }
  return readEnvelope<T>(await apiFetch(path, init));
}

export async function listEvents(
  opts: Pick<ListEventsRequest, "cursor" | "limit" | "categories" | "protocol" | "listener_role" | "packet_code" | "outcome"> = {},
): Promise<Envelope<EventList>> {
  const limit = opts.limit ?? 50;
  return readEnvelope<EventList>(
    await apiFetch(
      `/api/v1/events${queryString({
        limit,
        cursor: opts.cursor,
        category: opts.categories,
        protocol: opts.protocol,
        listener_role: opts.listener_role,
        packet_code: opts.packet_code,
        outcome: opts.outcome,
      })}`,
    ),
  );
}

export async function listTokens(opts: { limit?: number; cursor?: string } = {}): Promise<Envelope<TokenList>> {
  return readEnvelope<TokenList>(await apiFetch(`/api/v1/tokens${queryString(opts)}`));
}

export async function createToken(
  body: CreateTokenRequest,
  revision?: number,
  idempotencyKey?: string,
): Promise<Envelope<CreatedToken>> {
  return sendJSON<CreatedToken>("/api/v1/tokens", "POST", body, revision, idempotencyKey);
}

export async function revokeToken(id: string, revision: number, tombstone = false): Promise<Envelope<DeleteResult>> {
  return sendJSON<DeleteResult>(`/api/v1/tokens/${encodeURIComponent(id)}${queryString({ tombstone })}`, "DELETE", undefined, revision);
}

export async function listUsers(opts: { limit?: number; cursor?: string; include_deleted?: boolean } = {}): Promise<Envelope<UserList>> {
  return readEnvelope<UserList>(await apiFetch(`/api/v1/users${queryString(opts)}`));
}

export async function getUser(id: string, includeDeleted = false): Promise<Envelope<User>> {
  return readEnvelope<User>(
    await apiFetch(`/api/v1/users/${encodeURIComponent(id)}${queryString({ include_deleted: includeDeleted })}`),
  );
}

export async function createUser(
  body: CreateUserRequest,
  revision?: number,
  idempotencyKey?: string,
): Promise<Envelope<User>> {
  return sendJSON<User>("/api/v1/users", "POST", body, revision, idempotencyKey);
}

export async function updateUser(id: string, body: UpdateUserRequest, revision: number): Promise<Envelope<User>> {
  return sendJSON<User>(`/api/v1/users/${encodeURIComponent(id)}`, "PATCH", { ...body, id }, revision);
}

export async function deleteUser(id: string, revision: number, tombstone = false): Promise<Envelope<DeleteResult>> {
  return sendJSON<DeleteResult>(`/api/v1/users/${encodeURIComponent(id)}${queryString({ tombstone })}`, "DELETE", undefined, revision);
}

export async function listGroups(opts: { limit?: number; cursor?: string; include_deleted?: boolean } = {}): Promise<Envelope<GroupList>> {
  return readEnvelope<GroupList>(await apiFetch(`/api/v1/groups${queryString(opts)}`));
}

export async function getGroup(id: string, includeDeleted = false): Promise<Envelope<Group>> {
  return readEnvelope<Group>(
    await apiFetch(`/api/v1/groups/${encodeURIComponent(id)}${queryString({ include_deleted: includeDeleted })}`),
  );
}

export async function createGroup(
  body: CreateGroupRequest,
  revision?: number,
  idempotencyKey?: string,
): Promise<Envelope<Group>> {
  return sendJSON<Group>("/api/v1/groups", "POST", body, revision, idempotencyKey);
}

export async function updateGroup(id: string, body: UpdateGroupRequest, revision: number): Promise<Envelope<Group>> {
  return sendJSON<Group>(`/api/v1/groups/${encodeURIComponent(id)}`, "PATCH", { ...body, id }, revision);
}

export async function deleteGroup(id: string, revision: number, tombstone = false): Promise<Envelope<DeleteResult>> {
  return sendJSON<DeleteResult>(`/api/v1/groups/${encodeURIComponent(id)}${queryString({ tombstone })}`, "DELETE", undefined, revision);
}

export async function listClients(opts: { limit?: number; cursor?: string; include_deleted?: boolean } = {}): Promise<Envelope<ClientList>> {
  return readEnvelope<ClientList>(await apiFetch(`/api/v1/clients${queryString(opts)}`));
}

export async function getClient(id: string, includeDeleted = false): Promise<Envelope<Client>> {
  return readEnvelope<Client>(
    await apiFetch(`/api/v1/clients/${encodeURIComponent(id)}${queryString({ include_deleted: includeDeleted })}`),
  );
}

export async function createClient(
  body: CreateClientRequest,
  revision?: number,
  idempotencyKey?: string,
): Promise<Envelope<Client>> {
  return sendJSON<Client>("/api/v1/clients", "POST", body, revision, idempotencyKey);
}

export async function updateClient(id: string, body: UpdateClientRequest, revision: number): Promise<Envelope<Client>> {
  return sendJSON<Client>(`/api/v1/clients/${encodeURIComponent(id)}`, "PATCH", { ...body, id }, revision);
}

export async function deleteClient(id: string, revision: number, tombstone = false): Promise<Envelope<DeleteResult>> {
  return sendJSON<DeleteResult>(`/api/v1/clients/${encodeURIComponent(id)}${queryString({ tombstone })}`, "DELETE", undefined, revision);
}

export async function evaluatePolicy(body: EvaluatePolicyRequest): Promise<Envelope<PolicyTrace>> {
  return sendJSON<PolicyTrace>("/api/v1/policy/evaluate", "POST", body);
}

export async function testAuthentication(body: TestAuthenticationRequest): Promise<Envelope<AuthenticationTestResult>> {
  return sendJSON<AuthenticationTestResult>("/api/v1/authentication/test", "POST", body);
}

export async function testRadiusAccess(body: RadiusAccessTestRequest): Promise<Envelope<RadiusAccessTestResult>> {
  return sendJSON<RadiusAccessTestResult>("/api/v1/radius/access:test", "POST", body);
}

export async function evaluateRadiusPolicy(
  body: RadiusPolicyEvaluateRequest,
): Promise<Envelope<RadiusPolicyEvaluateResult>> {
  return sendJSON<RadiusPolicyEvaluateResult>("/api/v1/radius/policy:evaluate", "POST", body);
}

export async function getEffectiveConfig(view?: string): Promise<Envelope<EffectiveConfig>> {
  return readEnvelope<EffectiveConfig>(await apiFetch(`/api/v1/config/effective${queryString({ view })}`));
}

export async function exportConfig(view?: string): Promise<Envelope<ExportConfigResult>> {
  return readEnvelope<ExportConfigResult>(await apiFetch(`/api/v1/config/export${queryString({ view })}`));
}

export async function validateConfig(body: ValidateConfigRequest): Promise<Envelope<ValidateConfigResult>> {
  return sendJSON<ValidateConfigResult>("/api/v1/config/validate", "POST", body);
}

export async function reloadConfig(
  revision?: number,
  idempotencyKey?: string,
): Promise<Envelope<ReloadConfigResult>> {
  return sendJSON<ReloadConfigResult>("/api/v1/config/reload", "POST", {}, revision, idempotencyKey);
}

export async function resetRuntime(
  revision?: number,
  idempotencyKey?: string,
): Promise<Envelope<ResetRuntimeResult>> {
  return sendJSON<ResetRuntimeResult>("/api/v1/runtime/reset", "POST", {}, revision, idempotencyKey);
}

export function hashPrefix(value: string, n = 12): string {
  if (value.length <= n) {
    return value;
  }
  return value.slice(0, n);
}
