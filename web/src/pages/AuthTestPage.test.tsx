import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { AuthTestPage } from "./AuthTestPage";

describe("AuthTestPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("clears the password after submit and shows the result", async () => {
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
      if (url.includes("/authentication/test")) {
        expect(String(init?.body)).toContain("super-secret-lab-pw");
        return json(
          200,
          envelope({
            status: "fail",
            method: "ascii",
            user_id: "alice",
            ascii_pap_configured: true,
            challenge_configured: false,
            enable_configured: false,
          }),
        );
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<AuthTestPage />, { route: "/auth-test" });
    await user.type(await screen.findByLabelText("User ID"), "alice");
    const pw = screen.getByLabelText("Password");
    await user.type(pw, "super-secret-lab-pw");
    await user.click(screen.getByRole("button", { name: "Run test" }));
    expect(await screen.findByText("fail")).toBeInTheDocument();
    await waitFor(() => {
      expect(pw).toHaveValue("");
    });
  });

  it("displays must_change status as its own result, not a generic fail", async () => {
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
      if (url.includes("/authentication/test")) {
        expect(String(init?.body)).toContain("super-secret-lab-pw");
        return json(
          200,
          envelope({
            status: "must_change",
            method: "ascii",
            user_id: "alice",
            ascii_pap_configured: true,
            challenge_configured: false,
            enable_configured: false,
          }),
        );
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<AuthTestPage />, { route: "/auth-test" });
    await user.type(await screen.findByLabelText("User ID"), "alice");
    const pw = screen.getByLabelText("Password");
    await user.type(pw, "super-secret-lab-pw");
    await user.click(screen.getByRole("button", { name: "Run test" }));
    const status = await screen.findByText("must_change", { selector: ".state" });
    expect(status).toHaveClass("state--warn");
    expect(status).not.toHaveClass("state--off");
    expect(status).not.toHaveClass("state--on");
    expect(screen.getByText(/not a TACACS or RADIUS packet status/i)).toBeInTheDocument();
    await waitFor(() => {
      expect(pw).toHaveValue("");
    });
  });
});
