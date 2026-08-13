import { afterEach, describe, expect, it, vi } from "vitest";
import { apiFetch, createSession, hashPrefix, isRevisionMismatch, revisionETag, updateUser, APIError } from "./client";
import { futureExpiry } from "../test/time";

describe("API client", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    for (const part of document.cookie.split(";")) {
      const name = part.split("=")[0]?.trim();
      if (name) {
        document.cookie = `${name}=; Max-Age=0; path=/`;
      }
    }
    vi.unstubAllGlobals();
  });

  it("exchanges a bearer for a session without writing web storage", async () => {
    const fetchMock = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>(async () => {
      return new Response(
        JSON.stringify({
          revision: 2,
          request_id: "req-1",
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
            revision: 2,
          },
        }),
        { status: 200, headers: { "Content-Type": "application/json" } },
      );
    });
    vi.stubGlobal("fetch", fetchMock);

    const env = await createSession("lab-bootstrap-token-32-bytes!!!");
    expect(env.data.csrf_token).toBe("csrf-1");
    expect(fetchMock).toHaveBeenCalledTimes(1);
    const init = fetchMock.mock.calls[0]?.[1];
    if (!init) {
      throw new Error("expected fetch init");
    }
    expect(init.credentials).toBe("same-origin");
    const headers = new Headers(init.headers);
    expect(headers.get("Authorization")).toBe("Bearer lab-bootstrap-token-32-bytes!!!");
    expect(localStorage.length).toBe(0);
    expect(sessionStorage.length).toBe(0);
  });

  it("copies the CSRF cookie onto mutating requests", async () => {
    document.cookie = "taclab_csrf=csrf-test";
    const fetchMock = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>(
      async () => new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } }),
    );
    vi.stubGlobal("fetch", fetchMock);
    await apiFetch("/api/v1/session", { method: "DELETE" });
    const init = fetchMock.mock.calls[0]?.[1];
    if (!init) {
      throw new Error("expected fetch init");
    }
    expect(new Headers(init.headers).get("X-CSRF-Token")).toBe("csrf-test");
  });

  it("shortens hashes for display", () => {
    expect(hashPrefix("abcdefghijklmnop", 12)).toBe("abcdefghijkl");
  });

  it("sends If-Match and CSRF on user updates", async () => {
    document.cookie = "taclab_csrf=csrf-mut";
    const fetchMock = vi.fn<(input: RequestInfo | URL, init?: RequestInit) => Promise<Response>>(async () => {
      return new Response(JSON.stringify({ revision: 4, request_id: "r", data: { id: "alice" } }), {
        status: 200,
        headers: { "Content-Type": "application/json" },
      });
    });
    vi.stubGlobal("fetch", fetchMock);
    await updateUser("alice", { id: "alice", display_name: "A" }, 3);
    const init = fetchMock.mock.calls[0]?.[1];
    if (!init) {
      throw new Error("expected fetch init");
    }
    const headers = new Headers(init.headers);
    expect(headers.get("If-Match")).toBe(revisionETag(3));
    expect(headers.get("X-CSRF-Token")).toBe("csrf-mut");
    expect(init.method).toBe("PATCH");
  });

  it("detects revision mismatches", () => {
    expect(
      isRevisionMismatch(
        new APIError({
          type: "about:blank",
          title: "revision_mismatch",
          status: 412,
          detail: "expected revision does not match published snapshot",
          code: "revision_mismatch",
        }),
      ),
    ).toBe(true);
  });
});
