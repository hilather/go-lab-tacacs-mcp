import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { sampleRadiusSession } from "../test/fixtures";
import { DAS_FIXTURE_COPY } from "../ui/radius";
import { RadiusSessionsPage } from "./RadiusSessionsPage";

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

describe("RadiusSessionsPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("shows the empty index and inbound DAS residual copy", async () => {
    seedSession();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/v1/status")) {
          return statusOK();
        }
        if (url.includes("/api/v1/radius/sessions")) {
          return json(200, envelope({ items: [] }));
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<RadiusSessionsPage />, { route: "/radius-sessions" });
    expect(await screen.findByRole("heading", { name: "RADIUS sessions" })).toBeInTheDocument();
    expect(await screen.findByText("No in-memory RADIUS sessions.")).toBeInTheDocument();
    expect(screen.getByText(DAS_FIXTURE_COPY, { exact: false })).toBeInTheDocument();
    expect(screen.getAllByText(/does not kick a device/i).length).toBeGreaterThan(0);
    expect(screen.queryByRole("button", { name: /Disconnect/ })).not.toBeInTheDocument();
  });

  it("lists sessions and confirms a CoA send", async () => {
    seedSession();
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status")) {
        return statusOK();
      }
      if (url.includes("/radius/coa:send") && method === "POST") {
        const body = JSON.parse(String(init?.body)) as { session_handle?: string; expected_revision?: number };
        expect(body.session_handle).toBe(sampleRadiusSession.session_handle);
        expect(body.expected_revision).toBeUndefined();
        return json(200, envelope({ outcome: "ack" }));
      }
      if (url.includes("/api/v1/radius/sessions")) {
        return json(200, envelope({ items: [sampleRadiusSession] }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<RadiusSessionsPage />, { route: "/radius-sessions" });
    expect(await screen.findByText(sampleRadiusSession.session_handle)).toBeInTheDocument();
    expect(screen.getByText("alice")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: `CoA ${sampleRadiusSession.session_handle}` }));
    const dialog = await screen.findByRole("dialog", { name: /Send CoA-Request/i });
    expect(dialog).toHaveTextContent(/UDP RADIUS secret \(DAC\)/);
    expect(dialog).not.toHaveTextContent(/does not kick a device/i);
    expect(dialog).not.toHaveTextContent(/test fixture/i);
    await user.click(screen.getByRole("button", { name: "Send CoA" }));
    await waitFor(() => {
      expect(screen.getByText(/Last DAC outcome/i)).toBeInTheDocument();
      expect(screen.getByText("ack")).toBeInTheDocument();
    });
  });

  it("hides mutate buttons without radius:dynamic", async () => {
    seedSession(["state:read"]);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/v1/status")) {
          return statusOK();
        }
        if (url.includes("/api/v1/radius/sessions")) {
          return json(200, envelope({ items: [sampleRadiusSession] }));
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<RadiusSessionsPage />, { route: "/radius-sessions" });
    expect(await screen.findByText(sampleRadiusSession.session_handle)).toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /CoA/ })).not.toBeInTheDocument();
    expect(screen.queryByRole("button", { name: /Disconnect/ })).not.toBeInTheDocument();
  });
});
