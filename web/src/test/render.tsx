import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, type RenderOptions } from "@testing-library/react";
import { MemoryRouter, Route, Routes } from "react-router-dom";
import type { ReactElement, ReactNode } from "react";
import { Shell } from "../App";
import { AuthProvider } from "../auth/AuthProvider";
import { vi } from "vitest";
import { saveSessionMeta, loadSessionMeta, SESSION_META_KEY } from "../auth/sessionMeta";
import { futureExpiry } from "./time";

export const ALL_SCOPES = [
  "state:read",
  "state:write",
  "config:reload",
  "config:export",
  "policy:test",
  "events:read",
  "events:sensitive",
  "tokens:manage",
  "runtime:reset",
  "radius:dynamic",
];

export function seedSession(scopes: string[] = ALL_SCOPES): void {
  saveSessionMeta({ token_id: "lab", scopes, expires_at: futureExpiry() });
  const raw = sessionStorage.getItem(SESSION_META_KEY);
  sessionStorage.setItem(SESSION_META_KEY, JSON.stringify({ ...JSON.parse(raw ?? "{}") as object, testFixture: true }));
}

export function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": status >= 400 ? "application/problem+json" : "application/json" },
  });
}

export function envelope<T>(data: T, revision = 3): { revision: number; request_id: string; data: T } {
  return { revision, request_id: "t", data };
}

/** seedSession declares the session endpoint; page mocks handle their own operations. */
function installSeededSessionEndpoint() {
  const raw = sessionStorage.getItem(SESSION_META_KEY);
  const fixture = raw ? JSON.parse(raw) as { testFixture?: boolean } : null;
  const principal = loadSessionMeta();
  if (!fixture?.testFixture || !principal) {
    return;
  }
  const backend = globalThis.fetch;
  vi.stubGlobal("fetch", async (input: RequestInfo | URL, init?: RequestInit) => {
    if (String(input) === "/api/v1/session" && (init?.method ?? "GET") === "GET") {
      return json(200, envelope({ ...principal, csrf_token: "", cookie_name: "taclab_session",
        cookie_secure: false, same_site: "strict", cookie_path: "/", cookie_max_age: 1800, revision: 3 }));
    }
    return backend(input, init);
  });
}

export function renderApp(ui: ReactElement, options?: Omit<RenderOptions, "wrapper"> & { route?: string }) {
  installSeededSessionEndpoint();
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const route = options?.route ?? "/";
  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[route]}>
          <AuthProvider>{children}</AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>
    );
  }
  return render(ui, { wrapper: Wrapper, ...options });
}

export function renderShell(ui: ReactElement, options?: Omit<RenderOptions, "wrapper"> & { route?: string }) {
  installSeededSessionEndpoint();
  const client = new QueryClient({
    defaultOptions: { queries: { retry: false } },
  });
  const route = options?.route ?? "/";
  function Wrapper({ children }: { children: ReactNode }) {
    return (
      <QueryClientProvider client={client}>
        <MemoryRouter initialEntries={[route]}>
          <AuthProvider>
            <Routes>
              <Route element={<Shell />}>
                <Route path="*" element={children} />
              </Route>
            </Routes>
          </AuthProvider>
        </MemoryRouter>
      </QueryClientProvider>
    );
  }
  return render(ui, { wrapper: Wrapper, ...options });
}
