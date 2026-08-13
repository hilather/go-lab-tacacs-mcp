import { QueryClient, QueryClientProvider } from "@tanstack/react-query";
import { render, type RenderOptions } from "@testing-library/react";
import { MemoryRouter } from "react-router-dom";
import type { ReactElement, ReactNode } from "react";
import { AuthProvider } from "../auth/AuthProvider";

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
