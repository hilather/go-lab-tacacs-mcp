import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { sampleEvent, sampleRadiusClient } from "../test/fixtures";
import { DashboardPage } from "./DashboardPage";

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  readonly listeners = new Map<string, Array<(ev: Event | MessageEvent<string>) => void>>();

  constructor(public url: string) {
    FakeEventSource.instances.push(this);
  }

  addEventListener(type: string, fn: (ev: Event | MessageEvent<string>) => void): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
  }

  removeEventListener(type: string, fn: (ev: Event | MessageEvent<string>) => void): void {
    this.listeners.set(
      type,
      (this.listeners.get(type) ?? []).filter((h) => h !== fn),
    );
  }

  close(): void {}

  emit(type: string, data?: string): void {
    for (const handler of this.listeners.get(type) ?? []) {
      if (type === "message") {
        handler({ data } as MessageEvent<string>);
      } else {
        handler(new Event(type));
      }
    }
  }
}

describe("DashboardPage", () => {
  afterEach(() => {
    FakeEventSource.instances = [];
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
      if (url.includes("/api/v1/events")) {
        return new Response(JSON.stringify({ revision: 7, request_id: "r", data: { items: [], reset: false, overwritten: 0 } }), {
          status: 200,
          headers: { "Content-Type": "application/json" },
        });
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
        if (url.includes("/api/v1/events")) {
          return json(200, envelope({ items: [], reset: false, overwritten: 0 }));
        }
        return json(403, { status: 403, title: "forbidden", detail: "no", code: "permission_denied", type: "about:blank" });
      }),
    );
    renderApp(<DashboardPage />, { route: "/" });
    expect(await screen.findByText("radius_access")).toBeInTheDocument();
    expect(screen.getAllByText("UDP").length).toBeGreaterThan(0);
    expect(screen.getByRole("heading", { name: "Lab posture" })).toBeInTheDocument();
    expect(screen.getAllByText(/RADIUS\/UDP is a controlled-network lab profile/i).length).toBeGreaterThan(0);
    expect(await screen.findByText("insecure RADIUS compatibility")).toBeInTheDocument();
    expect(screen.getByText("Ready")).toBeInTheDocument();
  });

  it("does not treat an enabled RadSec listener as RADIUS UDP", async () => {
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
              baseline_hash: "a",
              overlay_hash: "b",
              compiled_at: "2026-08-12T00:00:00Z",
              listeners: [
                {
                  id: "radius_radsec",
                  enabled: true,
                  bind: "0.0.0.0:2083",
                  transport: "tls",
                  protocol: "radius",
                  carrier: "radius_tls",
                  roles: ["access", "accounting"],
                  ready: true,
                  required: false,
                  inflight: 0,
                  queue_depth: 0,
                },
              ],
              colocated_topology: false,
              users: 0,
              groups: 0,
              clients: 0,
              tokens: 0,
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
              protocols: { radius: { standards: ["RFC 6614"], conformance_status: "partial" } },
            }),
          );
        }
        if (url.includes("/api/v1/events")) {
          return json(200, envelope({ items: [], reset: false, overwritten: 0 }));
        }
        return json(403, { status: 403, title: "forbidden", detail: "no", code: "permission_denied", type: "about:blank" });
      }),
    );
    renderApp(<DashboardPage />, { route: "/" });
    expect(await screen.findByText("radius_radsec")).toBeInTheDocument();
    expect(screen.queryByRole("heading", { name: /RADIUS UDP/i })).not.toBeInTheDocument();
    expect(screen.queryByText(/RADIUS\/UDP is a controlled-network lab profile/i)).not.toBeInTheDocument();
    expect(screen.getByText(/Optional RADIUS\/TLS \(RadSec\)/i)).toBeInTheDocument();
  });

  it("says inbound 3799 is an index-only fixture", async () => {
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
                  id: "radius_dynauth",
                  enabled: true,
                  bind: "0.0.0.0:3799",
                  transport: "udp",
                  protocol: "radius",
                  carrier: "radius_udp",
                  roles: ["dynamic_authorization"],
                  ready: true,
                  required: false,
                  inflight: 0,
                  queue_depth: 0,
                },
              ],
              colocated_topology: false,
              users: 0,
              groups: 0,
              clients: 0,
              tokens: 0,
              warnings: [],
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
              protocols: { radius: { standards: ["RFC 2865"], conformance_status: "partial" } },
            }),
          );
        }
        return json(200, envelope({ revision: 7, items: [] }));
      }),
    );
    renderApp(<DashboardPage />, { route: "/" });
    expect(await screen.findByText(/only updates TacLab/i)).toBeInTheDocument();
    expect(screen.getByText(/To disconnect a device, use Disconnect send/i)).toBeInTheDocument();
  });

  it("shows last-N newest-first including live SSE, not the oldest ring page", async () => {
    seedSession();
    vi.stubGlobal("EventSource", FakeEventSource);
    const oldestFirst = Array.from({ length: 10 }, (_, i) => ({
      ...sampleEvent,
      id: i + 1,
      user_id: `u${String(i + 1)}`,
      time: `2026-08-12T00:00:${String(i).padStart(2, "0")}Z`,
    }));
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
              listeners: [],
              colocated_topology: false,
              users: 0,
              groups: 0,
              clients: 0,
              tokens: 0,
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
        if (url.includes("/api/v1/events")) {
          return json(200, envelope({ items: oldestFirst, reset: false, overwritten: 0 }));
        }
        return json(403, { status: 403, title: "forbidden", detail: "no", code: "permission_denied", type: "about:blank" });
      }),
    );
    renderApp(<DashboardPage />, { route: "/" });
    expect(await screen.findByRole("heading", { name: "Recent events" })).toBeInTheDocument();
    expect(await screen.findByText("u10")).toBeInTheDocument();
    expect(screen.getByText("u3")).toBeInTheDocument();
    expect(screen.queryByText("u1")).not.toBeInTheDocument();
    expect(screen.queryByText("u2")).not.toBeInTheDocument();
    const es = FakeEventSource.instances[0];
    es?.emit(
      "message",
      JSON.stringify({
        schema_version: 1,
        id: 11,
        time: "2026-08-12T00:00:11Z",
        category: "authen",
        type: "Access-Request PAP",
        result: "accept",
        protocol: "radius",
        user_id: "eve",
        client_id: "lab_switches",
        privilege: 1,
        transport: "udp",
      }),
    );
    expect(await screen.findByText("eve")).toBeInTheDocument();
    expect(screen.getByText("eve").closest("tr")).toHaveTextContent("RADIUS");
    expect(screen.queryByText("u3")).not.toBeInTheDocument();
  });
});
