import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { RadiusAuthTestPage } from "./RadiusAuthTestPage";

describe("RadiusAuthTestPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("clears PAP password after submit and shows the access outcome", async () => {
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
            groups: 0,
            clients: 0,
            tokens: 0,
          }),
        );
      }
      if (url.includes("/radius/access:test")) {
        expect(String(init?.body)).toContain("super-secret-radius-pw");
        expect(String(init?.body)).toContain("\"type\":\"pap\"");
        return json(
          200,
          envelope({
            outcome: "access_accept",
            reason_code: "ok",
            reply_attributes: [{ name: "Session-Timeout", value: "600" }],
            trace: {
              evaluator: "radius_access",
              user_id: "alice",
              client_id: "lab-radius",
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
    renderApp(<RadiusAuthTestPage />, { route: "/radius-auth-test" });
    await user.type(await screen.findByLabelText("User ID"), "alice");
    const pw = screen.getByLabelText("Password");
    await user.type(pw, "super-secret-radius-pw");
    await user.click(screen.getByRole("button", { name: "Run RADIUS test" }));
    expect(await screen.findByText("access_accept")).toBeInTheDocument();
    expect(screen.getByText("permit-lab-admins")).toBeInTheDocument();
    await waitFor(() => {
      expect(pw).toHaveValue("");
    });
    expect(JSON.stringify(localStorage)).not.toContain("super-secret-radius-pw");
  });

  it("clears CHAP challenge and response after submit", async () => {
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
            groups: 0,
            clients: 0,
            tokens: 0,
          }),
        );
      }
      if (url.includes("/radius/access:test")) {
        const body = JSON.parse(String(init?.body)) as { method: { type: string; challenge?: string; response?: string } };
        expect(body.method.type).toBe("chap");
        expect(body.method.challenge).toBe("Y2hhbA==");
        expect(body.method.response).toBe("cmVzcA==");
        return json(200, envelope({ outcome: "access_reject", reason_code: "reject_bad_credentials", reply_attributes: [] }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<RadiusAuthTestPage />, { route: "/radius-auth-test" });
    await user.type(await screen.findByLabelText("User ID"), "alice");
    await user.selectOptions(screen.getByLabelText("Method"), "chap");
    const challenge = await screen.findByLabelText("CHAP challenge (base64)");
    const response = screen.getByLabelText("CHAP response (base64)");
    await user.type(challenge, "Y2hhbA==");
    await user.type(response, "cmVzcA==");
    await user.click(screen.getByRole("button", { name: "Run RADIUS test" }));
    expect(await screen.findByText("access_reject")).toBeInTheDocument();
    await waitFor(() => {
      expect(challenge).toHaveValue("");
      expect(response).toHaveValue("");
    });
  });
});
