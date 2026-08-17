import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { sampleGroup } from "../test/fixtures";
import { GroupsPage } from "./GroupsPage";

describe("GroupsPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("shows default-deny copy and preserves AV separator plus exact match", async () => {
    seedSession();
    const user = userEvent.setup();
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
              groups: 1,
              clients: 0,
              tokens: 0,
            }),
          );
        }
        if (url.includes("/api/v1/groups")) {
          return json(200, envelope({ revision: 3, items: [sampleGroup] }));
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<GroupsPage />, { route: "/groups" });
    expect(await screen.findByText(/default-deny/i)).toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Edit administrators" }));
    expect(screen.getByLabelText("Name")).toHaveValue("priv-lvl");
    expect(screen.getByLabelText("Separator")).toHaveValue("=");
    expect(screen.getByDisplayValue("configure")).toBeInTheDocument();
    expect(screen.getAllByLabelText("Exact")[0]).toBeChecked();
    expect(screen.getByText(/must be deny/i)).toBeInTheDocument();
  });

  it("offers a radius_policy_id field and sends the typed policy", async () => {
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
            groups: 1,
            clients: 0,
            tokens: 0,
          }),
        );
      }
      if (url.includes("/api/v1/groups") && method === "PATCH") {
        return json(200, envelope({ ...sampleGroup, radius_policy_id: "default-radius-access" }, 4));
      }
      if (url.includes("/api/v1/groups")) {
        return json(200, envelope({ revision: 3, items: [sampleGroup] }));
      }
      if (url.includes("/api/v1/users")) {
        return json(200, envelope({ revision: 3, items: [] }));
      }
      if (url.includes("/api/v1/clients")) {
        return json(200, envelope({ revision: 3, items: [] }));
      }
      if (url.includes("/config/export")) {
        return json(
          200,
          envelope({
            revision: 3,
            view: "effective",
            format: "yaml",
            yaml: "schema_version: 2\ngroups:\n  - id: administrators\n    radius_policy_id: admins-radius\nusers:\n  - id: alice\n    radius_policy_id: default-radius-access\n",
            source_schema_version: 2,
            effective_schema_version: 2,
            normalized: false,
          }),
        );
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<GroupsPage />, { route: "/groups" });
    expect(await screen.findByText("admins-radius")).toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Edit administrators" }));
    const field = await screen.findByLabelText("RADIUS policy");
    expect(field).toHaveValue("admins-radius");
    await user.clear(field);
    await user.type(field, "default-radius-access");
    await user.click(screen.getByRole("button", { name: "Save group" }));
    await waitFor(() => {
      const patch = fetchMock.mock.calls.find((c) => String(c[1]?.method ?? "GET").toUpperCase() === "PATCH");
      expect(patch).toBeTruthy();
      const body = JSON.parse(String(patch?.[1]?.body)) as { radius_policy_id?: string | null };
      expect(body.radius_policy_id).toBe("default-radius-access");
    });
  });
});
