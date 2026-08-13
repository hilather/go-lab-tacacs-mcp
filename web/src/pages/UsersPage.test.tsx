import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { sampleUser } from "../test/fixtures";
import { UsersPage } from "./UsersPage";

function statusOK() {
  return json(
    200,
    envelope({
      instance_id: "lab",
      revision: 3,
      baseline_hash: "abc",
      overlay_hash: "def",
      compiled_at: "2026-08-12T00:00:00Z",
      listeners: [],
      colocated_topology: false,
      users: 1,
      groups: 1,
      clients: 1,
      tokens: 1,
    }),
  );
}

describe("UsersPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("lists users with source badges and capability metadata", async () => {
    seedSession();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/v1/status")) {
          return statusOK();
        }
        if (url.includes("/api/v1/users")) {
          return json(200, envelope({ revision: 3, items: [sampleUser] }));
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<UsersPage />, { route: "/users" });
    expect(await screen.findByRole("heading", { name: "Users" })).toBeInTheDocument();
    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.getByText("CONFIG")).toBeInTheDocument();
    expect(screen.getByText(/ASCII\/PAP/)).toBeInTheDocument();
  });

  it("clears write-only secret fields after a successful save", async () => {
    seedSession();
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status")) {
        return statusOK();
      }
      if (url.includes("/api/v1/users") && method === "PATCH") {
        return json(200, envelope({ ...sampleUser, display_name: "Alicia" }, 4));
      }
      if (url.includes("/api/v1/users")) {
        return json(200, envelope({ revision: 3, items: [sampleUser] }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<UsersPage />, { route: "/users" });
    await user.click(await screen.findByRole("button", { name: "Edit alice" }));
    const secret = await screen.findByLabelText("Secret file path", { selector: "#user-login-file" });
    await user.type(secret, "/run/secrets/alice-login");
    await user.click(screen.getByRole("button", { name: "Save user" }));
    await waitFor(() => {
      const patch = fetchMock.mock.calls.find((c) => String(c[1]?.method ?? "GET").toUpperCase() === "PATCH");
      expect(patch).toBeTruthy();
      expect(String(patch?.[1]?.body)).toContain("/run/secrets/alice-login");
    });
    await waitFor(() => {
      expect(screen.queryByLabelText(/Secret file path/i)).not.toBeInTheDocument();
    });
  });

  it("renders a revision conflict with reload and retry", async () => {
    seedSession();
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status")) {
        return statusOK();
      }
      if (url.includes("/api/v1/users") && method === "PATCH") {
        return json(412, {
          type: "about:blank",
          title: "revision_mismatch",
          status: 412,
          detail: "expected revision does not match published snapshot",
          code: "revision_mismatch",
        });
      }
      if (url.includes("/api/v1/users/alice")) {
        return json(200, envelope(sampleUser, 5));
      }
      if (url.includes("/api/v1/users")) {
        return json(200, envelope({ revision: 3, items: [sampleUser] }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<UsersPage />, { route: "/users" });
    await user.click(await screen.findByRole("button", { name: "Edit alice" }));
    await user.type(screen.getByLabelText("Display name"), " Junior");
    await user.click(screen.getByRole("button", { name: "Save user" }));
    expect(await screen.findByRole("heading", { name: "Revision conflict" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reload latest" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry with current revision" })).toBeInTheDocument();
  });
});
