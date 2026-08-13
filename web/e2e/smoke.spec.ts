import { expect, test, type Page, type Route } from "@playwright/test";

const token = "lab-bootstrap-token-32-bytes!!!";

function sessionBody() {
  return {
    revision: 2,
    request_id: "e2e",
    data: {
      token_id: "lab",
      scopes: ["state:read", "events:read"],
      expires_at: new Date(Date.now() + 60 * 60 * 1000).toISOString(),
      csrf_token: "csrf-e2e",
      cookie_name: "taclab_session",
      cookie_secure: false,
      same_site: "strict",
      cookie_path: "/",
      cookie_max_age: 1800,
      revision: 2,
    },
  };
}

const statusBody = {
  revision: 2,
  request_id: "e2e",
  data: {
    instance_id: "lab",
    revision: 2,
    baseline_hash: "abcdef0123456789ffff",
    overlay_hash: "fedcba9876543210aaaa",
    compiled_at: "2026-08-12T00:00:00Z",
    listeners: [
      { id: "legacy_tacacs", enabled: true, bind: "127.0.0.1:4949", transport: "legacy" },
      { id: "secure_tacacs", enabled: false, bind: "127.0.0.1:4300", transport: "tls" },
      { id: "http", enabled: true, bind: "127.0.0.1:8080", transport: "http" },
    ],
    colocated_topology: false,
    users: 1,
    groups: 1,
    clients: 1,
    tokens: 1,
  },
};

const buildBody = {
  revision: 2,
  request_id: "e2e",
  data: {
    version: "dev",
    commit: "abc",
    build_time: "now",
    go_version: "go1.24.5",
    ui_version: "0.0.0",
    schema_version: 1,
    tacacs_conformance: "RFC 8907; RFC 9887",
    mcp_specification: "2026-07-28",
  },
};

async function mockAPI(page: Page): Promise<{ signedIn: { value: boolean }; deleteCsrf: { value: string } }> {
  const signedIn = { value: false };
  const deleteCsrf = { value: "" };
  await page.route("**/api/v1/**", async (route: Route) => {
    const req = route.request();
    const url = req.url();
    const method = req.method();
    if (url.includes("/api/v1/session") && method === "POST") {
      signedIn.value = true;
      const origin = new URL(page.url()).origin;
      await page.context().addCookies([
        { name: "taclab_session", value: "e2e-session", url: origin, httpOnly: true, sameSite: "Strict" },
        { name: "taclab_csrf", value: "csrf-e2e", url: origin, httpOnly: false, sameSite: "Strict" },
      ]);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        headers: {
          "set-cookie": "taclab_csrf=csrf-e2e; Path=/; SameSite=Strict",
        },
        body: JSON.stringify(sessionBody()),
      });
      return;
    }
    if (url.includes("/api/v1/session") && method === "DELETE") {
      deleteCsrf.value = req.headers()["x-csrf-token"] ?? "";
      signedIn.value = false;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ revision: 2, request_id: "e2e", data: { id: "s", revision: 2 } }),
      });
      return;
    }
    if (url.includes("/api/v1/status")) {
      if (!signedIn.value) {
        await route.fulfill({
          status: 401,
          contentType: "application/problem+json",
          body: JSON.stringify({
            type: "about:blank",
            title: "unauthenticated",
            status: 401,
            detail: "authentication required",
            code: "unauthenticated",
          }),
        });
        return;
      }
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(statusBody) });
      return;
    }
    if (url.includes("/api/v1/build")) {
      await route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(buildBody) });
      return;
    }
    if (url.includes("/api/v1/events/stream")) {
      await route.fulfill({ status: 200, contentType: "text/event-stream", body: ": keepalive\n\n" });
      return;
    }
    if (url.includes("/api/v1/events")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ revision: 2, request_id: "e2e", data: { items: [], reset: false, overwritten: 0 } }),
      });
      return;
    }
    await route.fulfill({
      status: 404,
      contentType: "application/problem+json",
      body: JSON.stringify({
        type: "about:blank",
        title: "not_found",
        status: 404,
        detail: "not found",
        code: "not_found",
      }),
    });
  });
  return { signedIn, deleteCsrf };
}

test("keyboard login shows status and stores no token", async ({ page }) => {
  const api = await mockAPI(page);
  await page.goto("/login");

  const tokenField = page.getByLabel(/API bearer token/i);
  await expect(tokenField).toBeVisible();
  await tokenField.focus();
  await expect(tokenField).toBeFocused();
  await tokenField.pressSequentially(token);
  await page.keyboard.press("Enter");

  await expect(page.getByRole("heading", { name: "Status" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Sign in to TacLab" })).toHaveCount(0);
  await expect(page.getByText("legacy_tacacs")).toBeVisible();
  await expect(page.getByText("CONFIG", { exact: true })).toBeVisible();
  await expect(page.getByText("RUNTIME", { exact: true })).toBeVisible();
  await expect(page.getByText("OVERRIDE", { exact: true })).toBeVisible();
  await expect(page.getByText(/memory-only/i)).toBeVisible();
  await expect(page.getByRole("heading", { name: "Status" })).toBeVisible({ timeout: 1500 });

  const stored = await page.evaluate(() => {
    const session: Record<string, string> = {};
    for (let i = 0; i < sessionStorage.length; i += 1) {
      const k = sessionStorage.key(i);
      if (k) {
        session[k] = sessionStorage.getItem(k) ?? "";
      }
    }
    return {
      local: localStorage.length,
      cookie: document.cookie,
      session,
    };
  });
  expect(stored.local).toBe(0);
  expect(stored.cookie).toContain("taclab_csrf=csrf-e2e");
  expect(stored.cookie).not.toContain(token);
  expect(JSON.stringify(stored.session)).not.toMatch(/bearer/i);
  expect(JSON.stringify(stored.session)).not.toContain(token);

  await page.getByRole("button", { name: "Sign out" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: /sign in/i })).toBeVisible();
  expect(api.deleteCsrf.value).toBe("csrf-e2e");
});
