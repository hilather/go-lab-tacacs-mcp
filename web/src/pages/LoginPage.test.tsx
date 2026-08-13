import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { LoginPage } from "./LoginPage";
import { renderApp } from "../test/render";
import { futureExpiry } from "../test/time";
import { SESSION_META_KEY } from "../auth/sessionMeta";

function json(status: number, body: unknown): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

describe("LoginPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("signs in from the keyboard and never stores the token", async () => {
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/api/v1/status")) {
        return json(401, {
          type: "about:blank",
          title: "unauthenticated",
          status: 401,
          detail: "authentication required",
          code: "unauthenticated",
        });
      }
      if (url.includes("/api/v1/session")) {
        return json(200, {
          revision: 1,
          request_id: "r1",
          data: {
            token_id: "lab",
            scopes: ["state:read"],
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
      return json(404, { status: 404, title: "not found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderApp(<LoginPage />, { route: "/login" });
    const field = await screen.findByLabelText(/API bearer token/i);
    await user.type(field, "lab-bootstrap-token-32-bytes!!!");
    await user.keyboard("{Enter}");

    await waitFor(() => {
      expect(fetchMock.mock.calls.some((c) => String(c[0]).includes("/api/v1/session"))).toBe(true);
    });
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.getItem(SESSION_META_KEY)).toContain("lab");
    expect(sessionStorage.getItem(SESSION_META_KEY)).not.toMatch(/bearer/i);
    expect((field as HTMLInputElement).value).toBe("");
  });

  it("shows an error summary when the token is empty", async () => {
    const user = userEvent.setup();
    vi.stubGlobal("fetch", vi.fn(async () => json(401, { status: 401, title: "unauthenticated", detail: "authentication required", code: "unauthenticated", type: "about:blank" })));
    renderApp(<LoginPage />, { route: "/login" });
    await screen.findByLabelText(/API bearer token/i);
    await user.click(screen.getByRole("button", { name: /sign in/i }));
    const alert = await screen.findByRole("alert");
    expect(alert).toHaveTextContent(/enter an api bearer token/i);
    await waitFor(() => {
      expect(alert).toHaveFocus();
    });
  });
});
