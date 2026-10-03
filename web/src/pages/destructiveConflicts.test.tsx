import { screen, waitFor, within } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { sampleUser, sampleGroup, sampleClient, sampleToken } from "../test/fixtures";
import { UsersPage } from "./UsersPage";
import { GroupsPage } from "./GroupsPage";
import { ClientsPage } from "./ClientsPage";
import { TokensPage } from "./TokensPage";

const cases = [
  { kind: "user", path: "users", item: sampleUser, Page: UsersPage },
  { kind: "group", path: "groups", item: sampleGroup, Page: GroupsPage },
  { kind: "client", path: "clients", item: sampleClient, Page: ClientsPage },
];

afterEach(() => { sessionStorage.clear(); localStorage.clear(); vi.unstubAllGlobals(); });

describe("destructive revision conflict retry", () => {
  for (const fixture of cases) {
    it.each([false, true])(`preserves ${fixture.kind} deletion intent (tombstone=%s)`, async (tombstone) => {
      seedSession();
      const user = userEvent.setup();
      const writes: { method: string; url: string; revision: string | null }[] = [];
      const item = { ...fixture.item, source: tombstone ? "config" : "runtime" };
      vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
        const url = String(input); const method = init?.method ?? "GET";
        if (url === "/api/v1/session") return json(404, {});
        if (url === "/api/v1/status") return json(200, envelope({}, 7));
        if (["PATCH", "POST", "DELETE"].includes(method)) {
          writes.push({ method, url, revision: new Headers(init?.headers).get("If-Match") });
          if (writes.length === 1) return json(412, { code: "revision_mismatch", status: 412 });
          return json(200, envelope({ id: item.id }, 8));
        }
        if (url.startsWith(`/api/v1/${fixture.path}`)) return json(200, envelope({ items: [item] }, 3));
        return json(200, envelope({ items: [], yaml: "" }, 3));
      }));
      renderApp(<fixture.Page />);
      await user.click(await screen.findByRole("button", { name: `Edit ${item.id}` }));
      await user.click(screen.getByRole("button", { name: tombstone ? `Tombstone baseline ${fixture.kind}` : `Delete runtime ${fixture.kind}` }));
      const dialog = await screen.findByRole("dialog");
      await user.click(within(dialog).getByRole("button", { name: `${tombstone ? "Tombstone" : "Delete"} ${fixture.kind}` }));
      await user.click(await screen.findByRole("button", { name: "Retry with current revision" }));
      await waitFor(() => expect(writes).toHaveLength(2));
      expect(writes[1]).toEqual({ method: "DELETE", url: `/api/v1/${fixture.path}/${item.id}${tombstone ? "?tombstone=true" : ""}`, revision: '"revision-7"' });
    });
  }

  it("retries revocation instead of creating an unrelated token", async () => {
    seedSession();
    const user = userEvent.setup();
    const writes: { method: string; url: string }[] = [];
    vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL, init?: RequestInit) => {
      const url = String(input); const method = init?.method ?? "GET";
      if (url === "/api/v1/session") return json(404, {});
      if (url === "/api/v1/status") return json(200, envelope({}, 7));
      if (method === "DELETE" || method === "POST") {
        writes.push({ method, url });
        return writes.length === 1 ? json(412, { code: "revision_mismatch", status: 412 }) : json(200, envelope({}, 8));
      }
      return json(200, envelope({ items: [sampleToken] }, 3));
    }));
    renderApp(<TokensPage />);
    await user.type(await screen.findByLabelText("Name"), "unrelated draft");
    await user.click(await screen.findByRole("button", { name: `Revoke ${sampleToken.id}` }));
    await user.click(within(await screen.findByRole("dialog")).getByRole("button", { name: "Revoke token" }));
    await user.click(await screen.findByRole("button", { name: "Retry with current revision" }));
    await waitFor(() => expect(writes).toHaveLength(2));
    expect(writes[1]).toEqual({ method: "DELETE", url: `/api/v1/tokens/${sampleToken.id}` });
  });
});
