import { expect, test } from "@playwright/test";
import { mockAPI, token } from "./helpers";

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
