import { screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderShell, seedSession } from "./test/render";

function statusOK() {
  return json(
    200,
    envelope({
      instance_id: "lab",
      revision: 3,
      baseline_hash: "a",
      overlay_hash: "b",
      compiled_at: "2026-08-12T00:00:00Z",
      listeners: [],
      colocated_topology: false,
      users: 0,
      groups: 0,
      clients: 0,
      tokens: 0,
    }),
  );
}

describe("Shell chrome", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("groups the rail and shows stream plus token id", async () => {
    seedSession();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/v1/status")) {
          return statusOK();
        }
        if (url.includes("/api/v1/events")) {
          return json(200, envelope({ items: [], reset: false, overwritten: 0 }));
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderShell(<main><h1>Status</h1></main>, { route: "/" });
    expect(await screen.findByRole("navigation", { name: "Lab" })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "Directory" })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "TACACS+" })).toBeInTheDocument();
    expect(screen.getByRole("navigation", { name: "RADIUS" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Events" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Tokens" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "About" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Sessions" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "TACACS+ explain" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "RADIUS explain" })).toBeInTheDocument();
    expect(screen.getByRole("link", { name: "RADIUS test" })).toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "RADIUS sessions" })).not.toBeInTheDocument();
    await waitFor(() => {
      expect(screen.getByText("lab")).toBeInTheDocument();
    });
    expect(screen.getByRole("button", { name: "Sign out" })).toBeInTheDocument();
    expect(screen.getByText(/stream/i)).toBeInTheDocument();
  });

  it("omits scoped groups when the token lacks those scopes", async () => {
    seedSession(["state:read"]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/v1/status")) {
          return statusOK();
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderShell(<main><h1>Status</h1></main>, { route: "/" });
    expect(await screen.findByRole("navigation", { name: "Directory" })).toBeInTheDocument();
    expect(screen.queryByRole("navigation", { name: "TACACS+" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Events" })).not.toBeInTheDocument();
    expect(screen.queryByRole("link", { name: "Tokens" })).not.toBeInTheDocument();
    expect(screen.getByRole("link", { name: "Users" })).toBeInTheDocument();
  });
});
