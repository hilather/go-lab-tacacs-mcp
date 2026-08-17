import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { sampleClient, sampleCoAClient, sampleRadiusClient, sampleRadSecClient } from "../test/fixtures";
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

  it("shows RADIUS endpoints and the insecure UDP compatibility badge", async () => {
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
            }),
          );
        }
        if (url.includes("/api/v1/clients")) {
          return json(200, envelope({ revision: 3, items: [sampleRadiusClient] }));
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<ClientsPage />, { route: "/clients" });
    expect(await screen.findByText("lab-radius")).toBeInTheDocument();
    expect(screen.getByText("UDP")).toBeInTheDocument();
    expect(screen.getByText("insecure RADIUS compatibility")).toBeInTheDocument();
    expect(screen.getByText(/radius-udp radius\/udp/i)).toBeInTheDocument();
    expect(screen.getByText(/RADIUS pap, chap, eap, mschapv2/i)).toBeInTheDocument();
  });

  it("shows RadSec and CoA badges without treating TLS as UDP", async () => {
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
              clients: 2,
              tokens: 0,
            }),
          );
        }
        if (url.includes("/api/v1/clients")) {
          return json(200, envelope({ revision: 3, items: [sampleRadSecClient, sampleCoAClient] }));
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<ClientsPage />, { route: "/clients" });
    expect(await screen.findByText("lab-radsec")).toBeInTheDocument();
    expect(screen.getByText("RadSec")).toBeInTheDocument();
    expect(screen.getByText("CoA")).toBeInTheDocument();
    expect(screen.getByText("lab-coa")).toBeInTheDocument();
    expect(screen.getByText(/does not kick a device/i)).toBeInTheDocument();
  });

  it("does not stamp a UDP badge on a TLS-only RADIUS client and save does not send flatten UDP", async () => {
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
        return json(200, envelope(sampleRadSecClient, 4));
      }
      if (url.includes("/api/v1/clients")) {
        return json(200, envelope({ revision: 3, items: [sampleRadSecClient] }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<ClientsPage />, { route: "/clients" });
    expect(await screen.findByText("lab-radsec")).toBeInTheDocument();
    expect(screen.getByText(/radius-tls radius\/tls/i)).toBeInTheDocument();
    expect(screen.queryByText("UDP")).not.toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Edit lab-radsec" }));
    expect(screen.getByLabelText("Enable RADIUS/UDP")).not.toBeChecked();
    await user.click(screen.getByRole("button", { name: "Save client" }));
    await waitFor(() => {
      const patch = fetchMock.mock.calls.find((c) => String(c[1]?.method ?? "GET").toUpperCase() === "PATCH");
      expect(patch).toBeTruthy();
      const body = JSON.parse(String(patch?.[1]?.body)) as { radius?: { enabled?: boolean } };
      expect(body.radius).toBeUndefined();
    });
  });

  it("clears RADIUS secret inputs after a successful save", async () => {
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
        const body = JSON.parse(String(init?.body)) as { radius?: { shared_secret?: { file?: string } } };
        expect(body.radius?.shared_secret?.file).toBe("/run/secrets/radius");
        return json(200, envelope(sampleRadiusClient, 4));
      }
      if (url.includes("/api/v1/clients")) {
        return json(200, envelope({ revision: 3, items: [sampleRadiusClient] }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<ClientsPage />, { route: "/clients" });
    await user.click(await screen.findByRole("button", { name: "Edit lab-radius" }));
    const secretFields = screen.getAllByLabelText("Secret file path");
    expect(secretFields).toHaveLength(2);
    const radiusSecret = secretFields.at(1);
    if (!radiusSecret) {
      throw new Error("expected RADIUS secret file field");
    }
    await user.type(radiusSecret, "/run/secrets/radius");
    await user.click(screen.getByRole("button", { name: "Save client" }));
    await waitFor(() => {
      expect(fetchMock.mock.calls.some((c) => String(c[1]?.method ?? "GET").toUpperCase() === "PATCH")).toBe(true);
    });
    expect(screen.queryByDisplayValue("/run/secrets/radius")).not.toBeInTheDocument();
  });
});
