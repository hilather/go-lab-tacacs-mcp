import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, type RenderOptions } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement, ReactNode } from "react";
import { AuthProvider } from "../auth/AuthProvider";
import { saveSessionMeta } from "../auth/sessionMeta";
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
];

export function seedSession(scopes: string[] = ALL_SCOPES): void {
  saveSessionMeta({ token_id: "lab", scopes, expires_at: futureExpiry() });
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

export function renderApp(ui: ReactElement, options?: Omit<RenderOptions, "wrapper"> & { route?: string }) {
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
