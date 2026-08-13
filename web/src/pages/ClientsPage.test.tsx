import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { sampleClient } from "../test/fixtures";
import { ClientsPage } from "./ClientsPage";

describe("ClientsPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("shows lifecycle text and snapshot warnings without fingerprints", async () => {
    seedSession();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/v1/status")) {
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
              clients: 1,
              tokens: 0,
              warnings: ["legacy shared secret is reused by clients lab-switch, lab-router"],
            }),
          );
        }
        if (url.includes("/api/v1/clients")) {
          return json(200, envelope({ revision: 3, items: [sampleClient] }));
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<ClientsPage />, { route: "/clients" });
    expect(await screen.findByText("Due soon")).toBeInTheDocument();
    expect(screen.getByText(/reused by clients lab-switch/i)).toBeInTheDocument();
    expect(screen.getByText("RUNTIME")).toBeInTheDocument();
    expect(screen.getByText(/Removed on restart/)).toBeInTheDocument();
  });

  it("includes default_service on save so a methods patch does not wipe it", async () => {
    seedSession();
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status")) {
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
            clients: 1,
            tokens: 0,
          }),
        );
      }
      if (url.includes("/api/v1/clients") && method === "PATCH") {
        return json(200, envelope(sampleClient, 4));
      }
      if (url.includes("/api/v1/clients")) {
        return json(200, envelope({ revision: 3, items: [sampleClient] }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<ClientsPage />, { route: "/clients" });
    await user.click(await screen.findByRole("button", { name: "Edit lab-switch" }));
    expect(screen.getByLabelText("Default service")).toHaveValue("shell");
    await user.click(screen.getByRole("button", { name: "Save client" }));
    await waitFor(() => {
      const patch = fetchMock.mock.calls.find((c) => String(c[1]?.method ?? "GET").toUpperCase() === "PATCH");
      expect(patch).toBeTruthy();
      const body = JSON.parse(String(patch?.[1]?.body)) as { authentication?: { default_service?: string } };
      expect(body.authentication?.default_service).toBe("shell");
    });
  });
});
