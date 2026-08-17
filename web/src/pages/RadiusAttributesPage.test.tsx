import { screen } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { RadiusAttributesPage } from "./RadiusAttributesPage";

describe("RadiusAttributesPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("lists dictionary metadata with a source column", async () => {
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
              clients: 0,
              tokens: 0,
            }),
          );
        }
        if (url.includes("/api/v1/radius/attributes")) {
          return json(
            200,
            envelope({
              version: "builtin-mvp-1",
              items: [
                {
                  name: "User-Name",
                  code: 1,
                  vendor: 0,
                  value_kind: "text",
                  allowed_in: ["access-request"],
                  sensitivity: "pii",
                  source: "builtin",
                },
                {
                  name: "Vendor-Lab-Flag",
                  code: 1,
                  vendor: 99999,
                  value_kind: "integer",
                  allowed_in: ["access-accept"],
                  sensitivity: "public",
                  source: "operator:lab-dict",
                },
              ],
            }),
          );
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<RadiusAttributesPage />, { route: "/radius-attributes" });
    expect(await screen.findByRole("columnheader", { name: "Source" })).toBeInTheDocument();
    expect(await screen.findByText("User-Name")).toBeInTheDocument();
    expect(screen.getAllByText("builtin").length).toBeGreaterThan(0);
    expect(screen.getByText("operator:lab-dict")).toBeInTheDocument();
    expect(screen.getByText("builtin-mvp-1", { exact: false })).toBeInTheDocument();
  });
});
