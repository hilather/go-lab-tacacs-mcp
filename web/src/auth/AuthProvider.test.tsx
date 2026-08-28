import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { RequireScope } from "../components/RequireScope";
import { TokensPage } from "../pages/TokensPage";
import { envelope, json, renderApp } from "../test/render";
import { futureExpiry } from "../test/time";
import { SESSION_META_KEY } from "./sessionMeta";
import { useAuth } from "./AuthProvider";

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

function sessionJSON(scopes: string[]) {
  return json(200, {
    revision: 3,
    request_id: "r-session",
    data: {
      token_id: "lab",
      scopes,
      expires_at: futureExpiry(),
      csrf_token: "",
      cookie_name: "taclab_session",
      cookie_secure: false,
      same_site: "strict",
      cookie_path: "/",
      cookie_max_age: 1800,
      revision: 3,
    },
  });
}

function statusJSON() {
  return json(200, {
    revision: 3,
    request_id: "r-status",
    data: {
      instance_id: "lab",
      revision: 3,
      baseline_hash: "abc",
      overlay_hash: "def",
      compiled_at: "2026-08-12T00:00:00Z",
      listeners: [],
      colocated_topology: false,
      users: 0,
      groups: 0,
      clients: 0,
      tokens: 1,
    },
  });
}

describe("AuthProvider cold load without principal cache", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("rehydrates scopes from GET /session when sessionStorage is empty", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status")) {
        return statusJSON();
      }
      if (url.includes("/api/v1/session") && method === "GET") {
        return sessionJSON(["state:read", "tokens:manage", "events:read", "policy:test"]);
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
    await waitFor(() => {
      expect(screen.getByTestId("auth-status")).toHaveTextContent("signed_in");
    });
    expect(screen.getByTestId("auth-scopes")).toHaveTextContent(
      "state:read,tokens:manage,events:read,policy:test",
    );
    expect(sessionStorage.getItem(SESSION_META_KEY)).toContain("tokens:manage");
    expect(sessionStorage.getItem(SESSION_META_KEY)).not.toBe(
      JSON.stringify({ token_id: "", scopes: ["state:read"], expires_at: "" }),
    );
    expect(fetchMock.mock.calls.some((c) => String(c[0]).includes("/api/v1/session"))).toBe(true);
  });

  it("shows the tokens page on a cold /tokens load when GET /session has tokens:manage", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.includes("/api/v1/status")) {
          return statusJSON();
        }
        if (url.includes("/api/v1/session") && method === "GET") {
          return sessionJSON(["state:read", "tokens:manage"]);
        }
        if (url.includes("/api/v1/tokens")) {
          return json(200, envelope({ revision: 3, items: [] }));
        }
        if (url.includes("/api/v1/events")) {
          return json(200, envelope({ items: [], reset: false, overwritten: 0 }));
        }
        return json(404, {
          type: "about:blank",
          title: "not_found",
          status: 404,
          detail: "not found",
          code: "not_found",
        });
      }),
    );

    renderApp(<TokensPage />, { route: "/tokens" });
    expect(await screen.findByRole("heading", { name: "API tokens" })).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "Not authorized" })).not.toBeInTheDocument();
  });

  it("goes anonymous when GET /session fails after a cookie-ok status probe", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/v1/status")) {
          return statusJSON();
        }
        if (url.includes("/api/v1/session")) {
          return json(401, {
            type: "about:blank",
            title: "unauthenticated",
            status: 401,
            detail: "authentication required",
            code: "unauthenticated",
          });
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );

    renderApp(<AuthProbe />);
    await waitFor(() => {
      expect(screen.getByTestId("auth-status")).toHaveTextContent("anonymous");
    });
    expect(screen.getByTestId("auth-scopes")).toHaveTextContent("");
    expect(sessionStorage.getItem(SESSION_META_KEY)).toBeNull();
  });

  it("still fail-closes RequireScope when the rehydrated token lacks tokens:manage", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.includes("/api/v1/status")) {
          return statusJSON();
        }
        if (url.includes("/api/v1/session") && method === "GET") {
          return sessionJSON(["state:read"]);
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );

    renderApp(
      <RequireScope scope="tokens:manage">
        <main>
          <h1>API tokens</h1>
        </main>
      </RequireScope>,
      { route: "/tokens" },
    );
    expect(await screen.findByRole("heading", { name: "Not authorized" })).toBeInTheDocument();
    expect(screen.getByText(/tokens:manage/)).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: "API tokens" })).not.toBeInTheDocument();
  });
});
