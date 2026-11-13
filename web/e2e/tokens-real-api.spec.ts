import { expect, test, type Page } from "@playwright/test";
import { execFile, spawn, type ChildProcess } from "node:child_process";
import { mkdtemp, rm, writeFile } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { promisify } from "node:util";
import type { CreatedToken, Envelope, TokenList } from "../src/generated/api";
import { login, mockAPI } from "./helpers";

test.use({ trace: "off", screenshot: "off", video: "off" });

const root = fileURLToPath(new URL("../../", import.meta.url));
const bootstrap = "lab-real-token-api-bootstrap-test-only";
const auth = { Authorization: `Bearer ${bootstrap}` };
let directory = "";
let origin = "";
let server: ChildProcess | undefined;
let closed = true;
let stopped: Promise<void> = Promise.resolve();

function signalGroup(signal: NodeJS.Signals) {
  if (!server?.pid || closed) return;
  try {
    process.kill(-server.pid, signal);
  } catch (error) {
    if ((error as NodeJS.ErrnoException).code !== "ESRCH") throw error;
  }
}

async function cleanup() {
  signalGroup("SIGTERM");
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([stopped, new Promise<void>((resolve) => { timer = setTimeout(resolve, 5_000); })]);
  } finally {
    clearTimeout(timer);
  }
  signalGroup("SIGKILL");
  await stopped;
  if (directory) await rm(directory, { recursive: true, force: true });
  directory = "";
}

test.beforeAll(async ({ request }) => {
  test.setTimeout(300_000);
  const started = performance.now();
  try {
    directory = await mkdtemp(join(tmpdir(), "taclab-tokens-e2e-"));
    const tokenFile = join(directory, "bootstrap");
    const config = join(directory, "lab.yaml");
    const binary = join(directory, "taclabd");
    await writeFile(tokenFile, bootstrap, { mode: 0o600 });
    await writeFile(config, `schema_version: 1
server:
  shutdown_grace: 2s
listeners:
  legacy_tacacs: {enabled: true, bind: "127.0.0.1:0"}
  secure_tacacs: {enabled: false}
  http: {enabled: true, bind: "127.0.0.1:0"}
api:
  bootstrap_tokens:
    - id: lab
      token: {file: ${JSON.stringify(tokenFile)}}
      scopes: [state:read, tokens:manage]
observability:
  metrics: {enabled: false}
events:
  stdout: {enabled: false}
`, { mode: 0o600 });
    await promisify(execFile)("go", ["build", "-buildvcs=false", "-o", binary, "./cmd/taclabd"], {
      cwd: root, timeout: 180_000,
    });
    server = spawn(binary, ["serve", "--config", config], {
      cwd: root, detached: true, stdio: ["ignore", "pipe", "ignore"],
    });
    closed = false;
    let rejectStartup: (reason: Error) => void;
    stopped = new Promise<void>((resolve) => {
      server!.once("error", () => {
        rejectStartup(new Error("real token API server failed to start"));
      });
      server!.once("close", (code, signal) => {
        closed = true;
        rejectStartup(new Error(`real token API server stopped (${code ?? signal})`));
        resolve();
      });
    });
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      origin = await new Promise<string>((resolve, reject) => {
        rejectStartup = reject;
        timer = setTimeout(() => reject(new Error("real token API address discovery timed out")), 30_000);
        let pending = "";
        server!.stdout!.on("data", (chunk: Buffer) => {
          pending += chunk.toString();
          if (pending.length > 16_384) {
            pending = "";
            return reject(new Error("server stdout exceeded discovery buffer"));
          }
          let newline: number;
          while ((newline = pending.indexOf("\n")) >= 0) {
            const line = pending.slice(0, newline).trim();
            pending = pending.slice(newline + 1);
            const match = /^listening http (127\.0\.0\.1:\d+)$/.exec(line);
            if (match) resolve(`http://${match[1]}`);
          }
        });
      });
    } finally {
      clearTimeout(timer);
    }
    await expect.poll(async () => {
      if (closed) throw new Error("real token API exited before readiness");
      const response = await request.get(`${origin}/health/ready`, { timeout: 1_000 }).catch(() => null);
      const ready = response?.status() === 200;
      await response?.dispose();
      return ready;
    }, { timeout: 60_000, intervals: [100, 250, 500] }).toBe(true);
    console.info(`Real token API setup: ${Math.round(performance.now() - started)} ms`);
  } catch (error) {
    await cleanup();
    throw error;
  }
});

test.afterAll(async () => {
  test.setTimeout(20_000);
  await cleanup();
});

async function clearTokenAndClosePage(page: Page) {
  try {
    if (!page.isClosed()) {
      await page.locator("#once-token").evaluateAll((nodes) => {
        for (const node of nodes) (node as HTMLInputElement).value = "";
      });
    }
  } catch (error) {
    if (!page.isClosed()) throw error;
  } finally {
    await page.close({ runBeforeUnload: false });
  }
}

test.afterEach(async ({ page }) => {
  await clearTokenAndClosePage(page);
});

test("creates a token without an idempotency key against the real API and refreshes its metadata", async ({ page, request }) => {
  test.setTimeout(60_000);
  const id = "real-api-token";
  const name = "Real API regression";
  const lists: { afterCreate: boolean; body: Envelope<TokenList>; text: string }[] = [];
  let created = false;
  let browserHeaders: Record<string, string> = {};
  let createBody: Buffer | null = null;
  try {
    page.setDefaultTimeout(5_000);
    await mockAPI(page, { scopes: ["state:read", "tokens:manage"] });
    // Registered last so only token GET/POST bypass the shared browser mocks.
    await page.route((url) => url.pathname === "/api/v1/tokens", async (route) => {
      const browserRequest = route.request();
      const method = browserRequest.method();
      if (method !== "GET" && method !== "POST") return route.fallback();
      const headers = await browserRequest.allHeaders();
      if (method === "POST") {
        browserHeaders = headers;
        createBody = browserRequest.postDataBuffer();
      }
      const url = new URL(browserRequest.url());
      const afterCreate = created;
      const response = await route.fetch({
        url: `${origin}${url.pathname}${url.search}`, method,
        headers: { ...headers, ...auth },
        ...(method === "POST" ? { postData: createBody! } : {}),
        timeout: 5_000, maxRedirects: 0, maxRetries: 0,
      });
      if (method === "POST" && response.status() === 200) created = true;
      if (method === "GET") {
        lists.push({ afterCreate, body: await response.json(), text: await response.text() });
      }
      await route.fulfill({ response });
    });
    await login(page);
    await page.getByRole("link", { name: "Tokens", exact: true }).click();
    await expect.poll(() => lists.length, { timeout: 5_000 }).toBeGreaterThan(0);
    await expect(page.getByRole("table").getByRole("rowheader", { name: "lab", exact: true })).toBeVisible();
    const initialRevision = lists[0]!.body.revision;
    await page.getByLabel("Token ID (optional)").fill(id);
    await page.getByLabel("Name", { exact: true }).fill(name);
    const post = page.waitForResponse((r) => new URL(r.url()).pathname === "/api/v1/tokens" && r.request().method() === "POST", { timeout: 5_000 });
    await page.getByRole("button", { name: "Create token", exact: true }).click();
    const response = await post;
    expect(response.status()).toBe(200);
    expect(Object.hasOwn(browserHeaders, "idempotency-key")).toBe(false);
    expect(browserHeaders["if-match"]).toBe(`"revision-${initialRevision}"`);
    const issued = (await response.json() as Envelope<CreatedToken>).data.token;
    expect(typeof issued === "string" && issued.length > 0).toBe(true);
    const bearerField = page.locator("#once-token");
    // Scalar assertions avoid Playwright's bearer-bearing ARIA failure snapshots.
    await expect.poll(() => page.getByRole("heading", { name: "Copy this token now" }).isVisible(), { timeout: 5_000 }).toBe(true);
    await expect.poll(async () => (await bearerField.inputValue({ timeout: 1_000 })) === issued, { timeout: 5_000 }).toBe(true);
    await expect.poll(() => lists.some((list) => list.afterCreate), { timeout: 5_000 }).toBe(true);
    const refreshed = lists.find((list) => list.afterCreate)!;
    expect(refreshed.body.revision).toBe(initialRevision + 1);
    expect(refreshed.body.data.items.some((item) => item.id === id && item.name === name)).toBe(true);
    expect(refreshed.text.includes(issued) || refreshed.body.data.items.some((item) => Object.hasOwn(item, "token"))).toBe(false);
    const row = page.getByRole("table").getByRole("row").filter({ has: page.getByRole("rowheader", { name: id, exact: true }) });
    await expect.poll(() => row.getByRole("cell", { name, exact: true }).isVisible(), { timeout: 5_000 }).toBe(true);
    await expect.poll(() => row.getByText("RUNTIME", { exact: true }).isVisible(), { timeout: 5_000 }).toBe(true);
    await page.getByRole("button", { name: "I have copied the token" }).click();
    await expect.poll(() => bearerField.count(), { timeout: 5_000 }).toBe(0);

    const listDirectly = async () => {
      const result = await request.get(`${origin}/api/v1/tokens`, { headers: auth, timeout: 5_000 });
      expect(result.status()).toBe(200);
      return await result.json() as Envelope<TokenList>;
    };
    const before = await listDirectly();
    const rejected = await request.post(`${origin}/api/v1/tokens`, {
      headers: { ...auth, "Content-Type": "application/json", "If-Match": `"revision-${before.revision}"`, "Idempotency-Key": "unsupported-token-replay" },
      data: createBody!, timeout: 5_000, maxRedirects: 0, maxRetries: 0,
    });
    expect(rejected.status()).toBe(400);
    expect(rejected.headers()["content-type"]?.split(";")[0]).toBe("application/problem+json");
    const problem = await rejected.json();
    expect(problem.code === "invalid_argument" && problem.title === "invalid_argument").toBe(true);
    expect(problem.detail === "operation does not support idempotency keys").toBe(true);
    const after = await listDirectly();
    expect(after.revision).toBe(before.revision);
    expect(after.data.items.map((item) => item.id)).toEqual(before.data.items.map((item) => item.id));
    expect(after.data.items.length).toBe(before.data.items.length);
  } finally {
    await clearTokenAndClosePage(page);
  }
});
