import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { sampleRadiusClient } from "../test/fixtures";
import { DashboardPage } from "./DashboardPage";

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
                {
                  id: "legacy_tacacs",
                  enabled: true,
                  bind: "0.0.0.0:4949",
                  transport: "legacy",
                  protocol: "tacacs",
                  carrier: "tacacs_legacy_tcp",
                  roles: ["aaa"],
                  ready: true,
                  required: true,
                  inflight: 0,
                  queue_depth: 0,
                },
                {
                  id: "secure_tacacs",
                  enabled: false,
                  bind: "0.0.0.0:4300",
                  transport: "tls",
                  protocol: "tacacs",
                  carrier: "tacacs_tls",
                  roles: ["aaa"],
                  ready: false,
                  required: false,
                  inflight: 0,
                  queue_depth: 0,
                },
                {
                  id: "http",
                  enabled: true,
                  bind: "0.0.0.0:8080",
                  transport: "http",
                  protocol: "http",
                  carrier: "http_tcp",
                  roles: ["admin"],
                  ready: true,
                  required: false,
                  inflight: 0,
                  queue_depth: 0,
                },
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
              protocols: {
                tacacs: { standards: ["RFC 8907", "RFC 9887"], conformance_status: "pass" },
                radius: { standards: ["RFC 2865"], conformance_status: "partial" },
              },
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
    expect(screen.getAllByText("Ready").length).toBeGreaterThan(0);
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
    expect(await screen.findByText(/not complete RADIUS/i)).toBeInTheDocument();
  });

  it("shows RADIUS UDP and insecure compatibility badges", async () => {
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
              revision: 7,
              baseline_hash: "abcdef0123456789",
              overlay_hash: "fedcba9876543210",
              compiled_at: "2026-08-12T00:00:00Z",
              listeners: [
                {
                  id: "radius_access",
                  enabled: true,
                  bind: "0.0.0.0:1812",
                  transport: "udp",
                  protocol: "radius",
                  carrier: "radius_udp",
                  roles: ["access"],
                  ready: true,
                  required: true,
                  inflight: 0,
                  queue_depth: 0,
                },
              ],
              colocated_topology: false,
              users: 1,
              groups: 0,
              clients: 1,
              tokens: 0,
              warnings: ["RADIUS Message-Authenticator is optional on lab-radius"],
            }),
          );
        }
        if (url.includes("/api/v1/build")) {
          return json(
            200,
            envelope({
              version: "dev",
              commit: "abc",
              build_time: "now",
              go_version: "go1.24.5",
              ui_version: "0.0.0",
              schema_version: 2,
              tacacs_conformance: "RFC 8907; RFC 9887",
              mcp_specification: "2026-07-28",
              protocols: { radius: { standards: ["RFC 2865"], conformance_status: "partial" } },
            }),
          );
        }
        if (url.includes("/api/v1/clients")) {
          return json(200, envelope({ revision: 7, items: [sampleRadiusClient] }));
        }
        return json(403, { status: 403, title: "forbidden", detail: "no", code: "permission_denied", type: "about:blank" });
      }),
    );
    renderApp(<DashboardPage />, { route: "/" });
    expect(await screen.findByText("radius_access")).toBeInTheDocument();
    expect(screen.getAllByText("UDP").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: /RADIUS UDP/i })).toBeInTheDocument();
    expect(await screen.findByText("insecure RADIUS compatibility")).toBeInTheDocument();
    expect(screen.getByText("Ready")).toBeInTheDocument();
  });
});
