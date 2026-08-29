import { expect, test } from "@playwright/test";
import { ALL_SCOPES, login, mockAPI, token } from "./helpers";

test("keyboard workflows for remaining pages, one-time token, conflict, and reset", async ({ page }) => {
  const api = await mockAPI(page, { scopes: ALL_SCOPES });
  await login(page);

  await page.getByRole("link", { name: "Users" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Edit alice" })).toBeVisible();
  await expect(page.getByText("CONFIG", { exact: true })).toBeVisible();
  await expect(page.getByText("default-radius-access")).toBeVisible();

  await page.getByRole("button", { name: "Edit alice" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByLabel("RADIUS policy")).toBeVisible();
  await expect(page.getByLabel("RADIUS policy")).toHaveValue("default-radius-access");
  const display = page.getByLabel("Display name");
  await display.focus();
  await page.keyboard.type(" Jr");
  await page.getByRole("button", { name: "Save user" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("heading", { name: "Revision conflict" })).toBeVisible();
  await expect(page.getByRole("button", { name: "Reload latest" })).toBeVisible();

  await page.getByRole("link", { name: "Tokens" }).click();
  await expect(page.getByRole("heading", { name: "API tokens" })).toBeVisible();
  await page.getByLabel("Name").fill("ci");
  await page.getByRole("button", { name: "Create token" }).click();
  const once = page.getByLabel("One-time bearer token");
  await expect(once).toHaveValue("e2e-one-time-token-value");
  await page.getByRole("button", { name: "I have copied the token" }).click();
  await expect(once).toHaveCount(0);

  await page.getByRole("link", { name: "Events" }).click();
  await expect(page.getByRole("heading", { name: "Events" })).toBeVisible();
  await expect(page.getByText("ascii.login")).toBeVisible();
  await expect(page.getByRole("group", { name: "Protocol" })).toBeVisible();
  await expect(page.getByRole("group", { name: "Kind" })).toBeVisible();

  await page.getByRole("link", { name: "Clients" }).click();
  await expect(page.getByRole("heading", { name: "Clients" })).toBeVisible();
  await expect(page.getByText("lab-switch", { exact: true })).toBeVisible();
  await expect(page.getByText("Overdue", { exact: true })).toBeVisible();
  await expect(page.getByText("insecure RADIUS compatibility")).toBeVisible();
  await expect(page.getByText("radius-udp radius/udp")).toBeVisible();

  await page.getByRole("link", { name: "Groups" }).click();
  await expect(page.getByRole("heading", { name: "Groups" })).toBeVisible();
  await expect(page.getByText(/default-deny/i)).toBeVisible();
  await page.getByRole("button", { name: "Edit administrators" }).click();
  await expect(page.getByLabel("RADIUS policy")).toBeVisible();
  await expect(page.getByLabel("RADIUS policy")).toHaveValue("admins-radius");

  await page.getByRole("link", { name: "Auth test", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Authentication test" })).toBeVisible();

  await page.getByRole("link", { name: "Sessions" }).click();
  await expect(page.getByRole("heading", { name: "RADIUS sessions" })).toBeVisible();
  await expect(page.getByText("01HXSESSIONHANDLE00", { exact: true })).toBeVisible();
  await expect(page.getByText(/RFC 5176 test fixture/i).first()).toBeVisible();
  await expect(page.getByText(/does not kick a device/i).first()).toBeVisible();
  await page.getByRole("button", { name: "CoA 01HXSESSIONHANDLE00" }).click();
  const dacDialog = page.getByRole("dialog", { name: /Send CoA-Request/i });
  await expect(dacDialog).toBeVisible();
  await expect(dacDialog).toContainText(/UDP RADIUS secret \(DAC\)/);
  await expect(dacDialog).not.toContainText(/does not kick a device/i);
  await page.getByRole("button", { name: "Cancel" }).click();

  await page.getByRole("link", { name: "Attributes" }).click();
  await expect(page.getByRole("heading", { name: "RADIUS attributes" })).toBeVisible();
  await expect(page.getByRole("columnheader", { name: "Source" })).toBeVisible();
  await expect(page.getByText("builtin").first()).toBeVisible();

  await page.getByRole("link", { name: "RADIUS test" }).click();
  await expect(page.getByRole("heading", { name: "RADIUS authentication test" })).toBeVisible();
  await expect(page.getByLabel("Password")).toBeVisible();
  await expect(page.getByRole("option", { name: "pap", exact: true })).toHaveCount(1);
  await expect(page.getByRole("option", { name: "chap", exact: true })).toHaveCount(1);
  await expect(page.getByRole("option", { name: "mschapv1", exact: true })).toHaveCount(1);
  await expect(page.getByRole("option", { name: "mschapv2", exact: true })).toHaveCount(1);
  await expect(page.getByRole("option", { name: "eap", exact: true })).toHaveCount(1);

  await page.getByRole("link", { name: "TACACS+ explain" }).click();
  await expect(page.getByRole("heading", { name: "Policy explain" })).toBeVisible();

  await page.getByRole("link", { name: "RADIUS explain" }).click();
  await expect(page.getByRole("heading", { name: "RADIUS policy explain" })).toBeVisible();

  await page.getByRole("link", { name: "About" }).click();
  await expect(page.getByRole("heading", { name: "About" })).toBeVisible();

  await page.getByRole("link", { name: "Config" }).click();
  await page.getByRole("button", { name: "Reset runtime overlay" }).click();
  await expect(page.getByRole("dialog", { name: /reset the runtime overlay/i })).toBeVisible();
  await page.getByRole("button", { name: "Reset overlay" }).click();
  const reset = api.lastMutations.find((m) => m.url.includes("/runtime/reset"));
  expect(reset?.csrf).toBe("csrf-e2e");
  expect(reset?.ifMatch).toContain("revision-");

  const stored = await page.evaluate(() => {
    const session: Record<string, string> = {};
    for (let i = 0; i < sessionStorage.length; i += 1) {
      const k = sessionStorage.key(i);
      if (k) {
        session[k] = sessionStorage.getItem(k) ?? "";
      }
    }
    return { local: localStorage.length, session, cookie: document.cookie };
  });
  expect(stored.local).toBe(0);
  expect(JSON.stringify(stored.session)).not.toContain(token);
  expect(JSON.stringify(stored.session)).not.toContain("e2e-one-time-token-value");
  expect(stored.cookie).not.toContain(token);
});

test("cold load /tokens without principal cache shows tokens when GET /session has tokens:manage", async ({
  page,
}) => {
  const api = await mockAPI(page, { scopes: ALL_SCOPES });
  await page.goto("/login");
  const origin = new URL(page.url()).origin;
  api.signedIn.value = true;
  await page.context().addCookies([
    { name: "taclab_session", value: "e2e-session", url: origin, httpOnly: true, sameSite: "Strict" },
    { name: "taclab_csrf", value: "csrf-e2e", url: origin, httpOnly: false, sameSite: "Strict" },
  ]);
  await page.evaluate(() => {
    sessionStorage.clear();
  });
  await page.goto("/tokens");
  await expect(page.getByRole("heading", { name: "API tokens" })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Not authorized" })).toHaveCount(0);
  await expect(page.getByRole("link", { name: "Tokens" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Events" })).toBeVisible();
  await page.getByRole("button", { name: "Sign out" }).click();
  await expect(page.getByRole("heading", { name: /sign in/i })).toBeVisible();
});
