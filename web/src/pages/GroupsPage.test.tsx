import { screen } from "@testing-library/react";
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
});
