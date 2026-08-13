import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { renderApp } from "../test/render";
import { futureExpiry } from "../test/time";
import { SESSION_META_KEY } from "./sessionMeta";
import { useAuth } from "./AuthProvider";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function AuthProbe() {
  const { state, login } = useAuth();
  return (
    <div>
      <p data-testid="auth-status">{state.status}</p>
      <p data-testid="auth-scopes">{state.status === "signed_in" ? state.session.scopes.join(",") : ""}</p>
      <button
        type="button"
        onClick={() => {
          void login("lab-bootstrap-token-32-bytes!!!");
        }}
      >
        Login
      </button>
    </div>
  );
}

describe("AuthProvider probe vs login", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("does not let a late cookie probe wipe a completed login", async () => {
    const user = userEvent.setup();
    let releaseProbe: ((value: Response) => void) | undefined;
    const probe = new Promise<Response>((resolve) => {
      releaseProbe = resolve;
    });
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status")) {
        return probe;
      }
      if (url.includes("/api/v1/session") && method === "POST") {
        return json(200, {
          revision: 1,
          request_id: "r1",
          data: {
            token_id: "lab",
            scopes: ["state:read", "events:read"],
            expires_at: futureExpiry(),
            csrf_token: "csrf-1",
            cookie_name: "taclab_session",
            cookie_secure: false,
            same_site: "strict",
            cookie_path: "/",
            cookie_max_age: 1800,
            revision: 1,
          },
        });
      }
      return json(404, {
        type: "about:blank",
        title: "not_found",
        status: 404,
        detail: "not found",
        code: "not_found",
      });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderApp(<AuthProbe />);
    expect(screen.getByTestId("auth-status")).toHaveTextContent("loading");
    await user.click(screen.getByRole("button", { name: "Login" }));
    await waitFor(() => {
      expect(screen.getByTestId("auth-status")).toHaveTextContent("signed_in");
    });
    expect(screen.getByTestId("auth-scopes")).toHaveTextContent("state:read,events:read");

    releaseProbe?.(
      json(401, {
        type: "about:blank",
        title: "unauthenticated",
        status: 401,
        detail: "authentication required",
        code: "unauthenticated",
      }),
    );
    await waitFor(() => {
      expect(screen.getByTestId("auth-status")).toHaveTextContent("signed_in");
    });
    expect(screen.getByTestId("auth-scopes")).toHaveTextContent("state:read,events:read");
    expect(sessionStorage.getItem(SESSION_META_KEY)).toContain("events:read");
    expect(localStorage.length).toBe(0);
  });
});
