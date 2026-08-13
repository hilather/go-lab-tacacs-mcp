import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { ConfigPage } from "./ConfigPage";

describe("ConfigPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("requires confirmation before runtime reset and sends CSRF", async () => {
    seedSession();
    document.cookie = "taclab_csrf=csrf-reset";
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status") || url.includes("/config/effective")) {
        return json(
          200,
          envelope({
            instance_id: "lab",
            revision: 3,
            view: "effective",
            baseline_hash: "a",
            overlay_hash: "b",
            compiled_at: "2026-08-12T00:00:00Z",
            listeners: [],
            colocated_topology: false,
            users: [],
            groups: [],
            clients: [],
            tokens: [],
          }),
        );
      }
      if (url.includes("/config/export")) {
        return json(200, envelope({ revision: 3, view: "effective", format: "yaml", yaml: "schema_version: 1\n" }));
      }
      if (url.includes("/api/v1/users") || url.includes("/api/v1/groups") || url.includes("/api/v1/clients")) {
        return json(200, envelope({ revision: 3, items: [] }));
      }
      if (url.includes("/runtime/reset") && method === "POST") {
        return json(200, envelope({ revision: 4, baseline_hash: "a", overlay_hash: "0" }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<ConfigPage />, { route: "/config" });
    await user.click(await screen.findByRole("button", { name: "Reset runtime overlay" }));
    expect(await screen.findByRole("dialog", { name: /reset the runtime overlay/i })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Reset overlay" }));
    await waitFor(() => {
      const call = fetchMock.mock.calls.find((c) => String(c[0]).includes("/runtime/reset"));
      expect(call).toBeTruthy();
      expect(new Headers(call?.[1]?.headers).get("X-CSRF-Token")).toBe("csrf-reset");
      expect(new Headers(call?.[1]?.headers).get("If-Match")).toBe('"revision-3"');
    });
  });

  it("retries a reset 412 against /runtime/reset with a fresh If-Match", async () => {
    seedSession();
    document.cookie = "taclab_csrf=csrf-reset";
    const user = userEvent.setup();
    let statusRev = 3;
    let resets = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status") || url.includes("/config/effective")) {
        return json(
          200,
          envelope({
            instance_id: "lab",
            revision: statusRev,
            view: "effective",
            baseline_hash: "a",
            overlay_hash: "b",
            compiled_at: "2026-08-12T00:00:00Z",
            listeners: [],
            colocated_topology: false,
            users: [],
            groups: [],
            clients: [],
            tokens: [],
          }, statusRev),
        );
      }
      if (url.includes("/config/export")) {
        return json(200, envelope({ revision: statusRev, view: "effective", format: "yaml", yaml: "schema_version: 1\n" }));
      }
      if (url.includes("/api/v1/users") || url.includes("/api/v1/groups") || url.includes("/api/v1/clients")) {
        return json(200, envelope({ revision: statusRev, items: [] }));
      }
      if (url.includes("/config/reload") && method === "POST") {
        throw new Error("retry must not call reload");
      }
      if (url.includes("/runtime/reset") && method === "POST") {
        resets += 1;
        if (resets === 1) {
          statusRev = 7;
          return json(412, {
            type: "about:blank",
            title: "revision_mismatch",
            status: 412,
            detail: "expected revision does not match published snapshot",
            code: "revision_mismatch",
          });
        }
        return json(200, envelope({ revision: 8, baseline_hash: "a", overlay_hash: "0" }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<ConfigPage />, { route: "/config" });
    await user.click(await screen.findByRole("button", { name: "Reset runtime overlay" }));
    await user.click(await screen.findByRole("button", { name: "Reset overlay" }));
    expect(await screen.findByRole("heading", { name: "Revision conflict" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry with current revision" }));
    await waitFor(() => {
      const calls = fetchMock.mock.calls.filter((c) => String(c[0]).includes("/runtime/reset"));
      expect(calls.length).toBe(2);
      expect(new Headers(calls[1]?.[1]?.headers).get("If-Match")).toBe('"revision-7"');
    });
    expect(fetchMock.mock.calls.some((c) => String(c[0]).includes("/config/reload"))).toBe(false);
  });
});
