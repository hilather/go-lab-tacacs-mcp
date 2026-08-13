import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { DashboardPage } from "./DashboardPage";
import { renderApp } from "../test/render";

describe("DashboardPage", () => {
  afterEach(() => {
    vi.unstubAllGlobals();
  });

  it("renders listeners, revision, hash prefix, counts, and source badges", async () => {
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/api/v1/status")) {
        return new Response(
          JSON.stringify({
            revision: 7,
            request_id: "r",
            data: {
              instance_id: "lab",
              revision: 7,
              baseline_hash: "abcdef0123456789",
              overlay_hash: "fedcba9876543210",
              compiled_at: "2026-08-12T00:00:00Z",
              listeners: [
                { id: "legacy_tacacs", enabled: true, bind: "0.0.0.0:4949", transport: "legacy" },
                { id: "secure_tacacs", enabled: false, bind: "0.0.0.0:4300", transport: "tls" },
                { id: "http", enabled: true, bind: "0.0.0.0:8080", transport: "http" },
              ],
              colocated_topology: false,
              users: 2,
              groups: 1,
              clients: 1,
              tokens: 1,
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      if (url.includes("/api/v1/build")) {
        return new Response(
          JSON.stringify({
            revision: 7,
            request_id: "r",
            data: {
              version: "dev",
              commit: "abc",
              build_time: "now",
              go_version: "go1.24.5",
              ui_version: "0.0.0",
              schema_version: 1,
              tacacs_conformance: "RFC 8907; RFC 9887",
              mcp_specification: "2026-07-28",
            },
          }),
          { status: 200, headers: { "Content-Type": "application/json" } },
        );
      }
      return new Response("{}", { status: 403 });
    });
    vi.stubGlobal("fetch", fetchMock);

    renderApp(<DashboardPage />, { route: "/" });

    expect(await screen.findByRole("heading", { name: "Status" })).toBeInTheDocument();
    expect(await screen.findByText("legacy_tacacs")).toBeInTheDocument();
    expect(screen.getAllByText("Enabled").length).toBeGreaterThan(0);
    expect(screen.getByText("Disabled")).toBeInTheDocument();
    expect(screen.getByText("7")).toBeInTheDocument();
    expect(screen.getByText("abcdef012345")).toBeInTheDocument();
    expect(screen.getByText("Users")).toBeInTheDocument();
    expect(screen.getByRole("heading", { name: "Source badges" })).toBeInTheDocument();
    expect(screen.getByText("CONFIG")).toBeInTheDocument();
    expect(screen.getByText("RUNTIME")).toBeInTheDocument();
    expect(screen.getByText("OVERRIDE")).toBeInTheDocument();
    expect(screen.getByText(/memory-only/i)).toBeInTheDocument();
    expect(await screen.findByText("go1.24.5")).toBeInTheDocument();
  });
});
