import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { sampleUser } from "../test/fixtures";
import { UsersPage } from "./UsersPage";

function statusOK() {
  return json(
    200,
    envelope({
      instance_id: "lab",
      revision: 3,
      baseline_hash: "abc",
      overlay_hash: "def",
      compiled_at: "2026-08-12T00:00:00Z",
      listeners: [],
      colocated_topology: false,
      users: 1,
      groups: 1,
      clients: 1,
      tokens: 1,
    }),
  );
}

describe("UsersPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  });

  it("lists users with source badges and capability metadata", async () => {
    seedSession();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/v1/status")) {
          return statusOK();
        }
        if (url.includes("/api/v1/users")) {
          return json(200, envelope({ revision: 3, items: [sampleUser] }));
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<UsersPage />, { route: "/users" });
    expect(await screen.findByRole("heading", { name: "Users" })).toBeInTheDocument();
    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.getByText("CONFIG")).toBeInTheDocument();
    expect(screen.getByText(/ASCII\/PAP/)).toBeInTheDocument();
    expect(screen.queryByText("Must change login")).not.toBeInTheDocument();
    expect(screen.queryByText("Must change enable")).not.toBeInTheDocument();
  });

  it("shows must-change badges next to Enabled when flags are true", async () => {
    seedSession();
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/v1/status")) {
          return statusOK();
        }
        if (url.includes("/api/v1/users")) {
          return json(
            200,
            envelope({
              revision: 3,
              items: [{ ...sampleUser, must_change_login: true, must_change_enable: true }],
            }),
          );
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<UsersPage />, { route: "/users" });
    expect(await screen.findByText("Must change login")).toBeInTheDocument();
    expect(screen.getByText("Must change enable")).toBeInTheDocument();
    expect(screen.getByText("Enabled", { selector: ".state" })).toBeInTheDocument();
    expect(screen.getByText("CONFIG")).toBeInTheDocument();
  });

  it("clears write-only secret fields after a successful save", async () => {
    seedSession();
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status")) {
        return statusOK();
      }
      if (url.includes("/api/v1/users") && method === "PATCH") {
        return json(200, envelope({ ...sampleUser, display_name: "Alicia" }, 4));
      }
      if (url.includes("/api/v1/users")) {
        return json(200, envelope({ revision: 3, items: [sampleUser] }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<UsersPage />, { route: "/users" });
    await user.click(await screen.findByRole("button", { name: "Edit alice" }));
    const secret = await screen.findByLabelText("Secret file path", { selector: "#user-login-file" });
    await user.type(secret, "/run/secrets/alice-login");
    await user.click(screen.getByRole("button", { name: "Save user" }));
    await waitFor(() => {
      const patch = fetchMock.mock.calls.find((c) => String(c[1]?.method ?? "GET").toUpperCase() === "PATCH");
      expect(patch).toBeTruthy();
      expect(String(patch?.[1]?.body)).toContain("/run/secrets/alice-login");
      const body = JSON.parse(String(patch?.[1]?.body)) as {
        must_change_login?: boolean;
        must_change_enable?: boolean;
        login?: { file?: string };
      };
      expect(body.login?.file).toBe("/run/secrets/alice-login");
      expect(body.must_change_login).toBe(false);
      expect(body.must_change_enable).toBe(false);
    });
    await waitFor(() => {
      expect(screen.queryByLabelText(/Secret file path/i)).not.toBeInTheDocument();
    });
  });

  it("sends must_change_login and must_change_enable on save", async () => {
    seedSession();
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status")) {
        return statusOK();
      }
      if (url.includes("/api/v1/users") && method === "PATCH") {
        return json(200, envelope({ ...sampleUser, must_change_login: true }, 4));
      }
      if (url.includes("/api/v1/users")) {
        return json(200, envelope({ revision: 3, items: [sampleUser] }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<UsersPage />, { route: "/users" });
    await user.click(await screen.findByRole("button", { name: "Edit alice" }));
    const loginFlag = await screen.findByRole("checkbox", { name: "Must change login" });
    const enableFlag = screen.getByRole("checkbox", { name: "Must change enable" });
    expect(loginFlag).not.toBeChecked();
    expect(enableFlag).not.toBeChecked();
    await user.click(loginFlag);
    await user.click(screen.getByRole("button", { name: "Save user" }));
    await waitFor(() => {
      const patch = fetchMock.mock.calls.find((c) => String(c[1]?.method ?? "GET").toUpperCase() === "PATCH");
      expect(patch).toBeTruthy();
      const body = JSON.parse(String(patch?.[1]?.body)) as {
        must_change_login?: boolean;
        must_change_enable?: boolean;
      };
      expect(body.must_change_login).toBe(true);
      expect(body.must_change_enable).toBe(false);
    });
  });

  it("renders a revision conflict with reload and retry", async () => {
    seedSession();
    const user = userEvent.setup();
    let statusRev = 3;
    let patches = 0;
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status")) {
        return json(
          200,
          envelope({
            instance_id: "lab",
            revision: statusRev,
            baseline_hash: "abc",
            overlay_hash: "def",
            compiled_at: "2026-08-12T00:00:00Z",
            listeners: [],
            colocated_topology: false,
            users: 1,
            groups: 1,
            clients: 1,
            tokens: 1,
          }, statusRev),
        );
      }
      if (url.includes("/api/v1/users") && method === "PATCH") {
        patches += 1;
        if (patches === 1) {
          statusRev = 7;
          return json(412, {
            type: "about:blank",
            title: "revision_mismatch",
            status: 412,
            detail: "expected revision does not match published snapshot",
            code: "revision_mismatch",
          });
        }
        return json(200, envelope({ ...sampleUser, display_name: "Alice Junior" }, 8));
      }
      if (url.includes("/api/v1/users/alice")) {
        return json(200, envelope(sampleUser, 5));
      }
      if (url.includes("/api/v1/users")) {
        return json(200, envelope({ revision: 3, items: [sampleUser] }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<UsersPage />, { route: "/users" });
    await user.click(await screen.findByRole("button", { name: "Edit alice" }));
    await user.type(screen.getByLabelText("Display name"), " Junior");
    await user.click(screen.getByRole("button", { name: "Save user" }));
    expect(await screen.findByRole("heading", { name: "Revision conflict" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Reload latest" })).toBeInTheDocument();
    expect(screen.getByRole("button", { name: "Retry with current revision" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Retry with current revision" }));
    await waitFor(() => {
      const patches = fetchMock.mock.calls.filter((c) => String(c[1]?.method ?? "GET").toUpperCase() === "PATCH");
      expect(patches.length).toBe(2);
      expect(new Headers(patches[1]?.[1]?.headers).get("If-Match")).toBe('"revision-7"');
    });
  });

  it("keeps valid_after and valid_before on a display-name save", async () => {
    seedSession();
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status")) {
        return statusOK();
      }
      if (url.includes("/api/v1/users") && method === "PATCH") {
        return json(200, envelope({ ...sampleUser, display_name: "Alicia" }, 4));
      }
      if (url.includes("/api/v1/users")) {
        return json(200, envelope({ revision: 3, items: [sampleUser] }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<UsersPage />, { route: "/users" });
    await user.click(await screen.findByRole("button", { name: "Edit alice" }));
    await user.click(screen.getByRole("button", { name: "Save user" }));
    await waitFor(() => {
      const patch = fetchMock.mock.calls.find((c) => String(c[1]?.method ?? "GET").toUpperCase() === "PATCH");
      expect(patch).toBeTruthy();
      const body = JSON.parse(String(patch?.[1]?.body)) as { restrictions?: { valid_after?: string; valid_before?: string } };
      expect(body.restrictions?.valid_after).toBe(sampleUser.restrictions.valid_after);
      expect(body.restrictions?.valid_before).toBe(sampleUser.restrictions.valid_before);
    });
  });

  it("offers a radius_policy_id select and sends the chosen policy", async () => {
    seedSession();
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status")) {
        return statusOK();
      }
      if (url.includes("/api/v1/users") && method === "PATCH") {
        return json(200, envelope({ ...sampleUser, radius_policy_id: "ops-radius" }, 4));
      }
      if (url.includes("/api/v1/users")) {
        return json(200, envelope({ revision: 3, items: [sampleUser] }));
      }
      if (url.includes("/api/v1/groups")) {
        return json(200, envelope({ revision: 3, items: [{ id: "administrators" }] }));
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
            yaml: "schema_version: 2\nusers:\n  - id: alice\n    radius_policy_id: default-radius-access\ngroups:\n  - id: administrators\n    radius_policy_id: admins-radius\n",
            source_schema_version: 2,
            effective_schema_version: 2,
            normalized: false,
          }),
        );
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<UsersPage />, { route: "/users" });
    expect(await screen.findByText("default-radius-access")).toBeInTheDocument();
    await user.click(await screen.findByRole("button", { name: "Edit alice" }));
    const field = await screen.findByLabelText("RADIUS policy");
    expect(field).toHaveValue("default-radius-access");
    await user.clear(field);
    await user.type(field, "ops-radius");
    await user.click(screen.getByRole("button", { name: "Save user" }));
    await waitFor(() => {
      const patch = fetchMock.mock.calls.find((c) => String(c[1]?.method ?? "GET").toUpperCase() === "PATCH");
      expect(patch).toBeTruthy();
      const body = JSON.parse(String(patch?.[1]?.body)) as { radius_policy_id?: string | null };
      expect(body.radius_policy_id).toBe("ops-radius");
    });
  });

  it("includes must-change flags in the stale-write compare", async () => {
    seedSession();
    const user = userEvent.setup();
    const fetchMock = vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input);
      const method = (init?.method ?? "GET").toUpperCase();
      if (url.includes("/api/v1/status")) {
        return statusOK();
      }
      if (url.includes("/api/v1/users") && method === "PATCH") {
        return json(412, {
          type: "about:blank",
          title: "revision_mismatch",
          status: 412,
          detail: "expected revision does not match published snapshot",
          code: "revision_mismatch",
        });
      }
      if (url.includes("/api/v1/users/alice")) {
        return json(200, envelope({ ...sampleUser, must_change_login: false, must_change_enable: true }, 5));
      }
      if (url.includes("/api/v1/users")) {
        return json(200, envelope({ revision: 3, items: [sampleUser] }));
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    renderApp(<UsersPage />, { route: "/users" });
    await user.click(await screen.findByRole("button", { name: "Edit alice" }));
    await user.click(screen.getByRole("checkbox", { name: "Must change login" }));
    await user.click(screen.getByRole("button", { name: "Save user" }));
    expect(await screen.findByRole("heading", { name: "Revision conflict" })).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Reload latest" }));
    await waitFor(() => {
      expect(screen.getByRole("checkbox", { name: "Must change login" })).not.toBeChecked();
      expect(screen.getByRole("checkbox", { name: "Must change enable" })).toBeChecked();
    });
  });
});
