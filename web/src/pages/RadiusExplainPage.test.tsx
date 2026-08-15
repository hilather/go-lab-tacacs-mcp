import { screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { RadiusExplainPage } from "./RadiusExplainPage";

describe("RadiusExplainPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("renders a RADIUS policy trace from evaluate", async () => {
    seedSession();
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
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
      if (url.includes("/radius/policy:evaluate")) {
        const body = JSON.parse(String(init?.body)) as { user_id: string; method?: string };
        expect(body.user_id).toBe("alice");
        expect(body.method).toBe("pap");
        return json(
          200,
          envelope({
            effect: "permit",
            reason_code: "ok",
            reply_attributes: [{ name: "Session-Timeout", value: "600" }],
            trace: {
              evaluator: "radius_access",
              user_id: "alice",
              client_id: "lab-radius",
              method: "password",
              groups: ["lab-admins"],
              steps: [{ source: "client_policy:default-radius-access", rule_id: "permit-lab-admins", matched: true, reason: "groups_any" }],
              winner: { source: "client_policy:default-radius-access", rule_id: "permit-lab-admins", effect: "permit" },
              effect: "permit",
            },
          }),
        );
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<RadiusExplainPage />, { route: "/radius-explain" });
    await user.type(await screen.findByLabelText("User ID"), "alice");
    await user.click(screen.getByRole("button", { name: "Explain RADIUS policy" }));
    expect(await screen.findByText("permit-lab-admins")).toBeInTheDocument();
    expect(screen.getByText(/Session-Timeout=600/)).toBeInTheDocument();
    expect(screen.getByText("radius_access")).toBeInTheDocument();
  });
});
