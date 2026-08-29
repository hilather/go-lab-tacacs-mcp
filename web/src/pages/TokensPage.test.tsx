import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { sampleToken } from "../test/fixtures";
import { TokensPage } from "./TokensPage";

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
      users: 0,
      groups: 0,
      clients: 0,
      tokens: 1,
    }),
  );
}

describe("TokensPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("shows the one-time token once and clears it after acknowledge", async () => {
    seedSession();
    const user = userEvent.setup();
    const secret = "ttl-one-time-token-value-never-store";
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input);
        const method = (init?.method ?? "GET").toUpperCase();
        if (url.includes("/api/v1/status")) {
          return statusOK();
        }
        if (url.includes("/api/v1/tokens") && method === "POST") {
          return json(
            200,
            envelope({
              ...sampleToken,
              id: "newtok",
              name: "ci",
              token: secret,
              revision: 4,
            }),
          );
        }
        if (url.includes("/api/v1/tokens")) {
          return json(200, envelope({ revision: 3, items: [sampleToken] }));
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<TokensPage />, { route: "/tokens" });
    await user.type(await screen.findByLabelText("Name"), "ci");
    await user.click(screen.getByRole("button", { name: "Create token" }));
    expect(await screen.findByLabelText("One-time bearer token")).toHaveValue(secret);
    expect(localStorage.length).toBe(0);
    expect(JSON.stringify(sessionStorage)).not.toContain(secret);
    await user.click(screen.getByRole("button", { name: "I have copied the token" }));
    await waitFor(() => {
      expect(screen.queryByLabelText("One-time bearer token")).not.toBeInTheDocument();
    });
    expect(screen.queryByDisplayValue(secret)).not.toBeInTheDocument();
    expect(JSON.stringify(sessionStorage)).not.toContain(secret);
  });

  it("shows a quiet empty state when the token list is empty", async () => {
    seedSession();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/v1/status")) {
          return statusOK();
        }
        if (url.includes("/api/v1/tokens")) {
          return json(200, envelope({ revision: 3, items: [] }));
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<TokensPage />, { route: "/tokens" });
    expect(await screen.findByText("No API tokens in this snapshot.")).toBeInTheDocument();
    expect(document.querySelector(".lede")).toBeTruthy();
  });
});
