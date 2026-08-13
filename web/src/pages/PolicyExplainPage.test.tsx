import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { PolicyExplainPage } from "./PolicyExplainPage";

describe("PolicyExplainPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("renders a policy trace from evaluate", async () => {
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
              users: 1,
              groups: 1,
              clients: 0,
              tokens: 0,
            }),
          );
        }
        if (url.includes("/policy/evaluate")) {
          return json(
            200,
            envelope({
              evaluator: "command",
              user_id: "alice",
              client_id: "",
              service: "shell",
              protocol: "",
              cmd: "configure",
              cmd_args: [],
              display_cmd: "configure",
              request_arguments: [],
              authen_method: "",
              privilege: 1,
              effective_group_ids: ["administrators"],
              steps: [{ source: "group:administrators", rule_id: "permit-all", kind: "command", matched: true, reason: "exact" }],
              winner: { source: "group:administrators", rule_id: "permit-all", action: "permit_add" },
              decision: "permit_add",
              status: "PASS_ADD",
              arguments: [],
            }),
          );
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<PolicyExplainPage />, { route: "/explain" });
    await user.type(await screen.findByLabelText("User ID"), "alice");
    await user.type(screen.getByLabelText("Command"), "configure");
    await user.click(screen.getByRole("button", { name: "Explain authorization" }));
    expect(await screen.findByText("permit_add")).toBeInTheDocument();
    expect(screen.getByText("permit-all")).toBeInTheDocument();
    expect(screen.getByText("PASS_ADD")).toBeInTheDocument();
    expect(screen.getAllByText("command").length).toBeGreaterThan(0);
  });
});
