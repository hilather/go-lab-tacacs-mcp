import { type Page, type Route } from "@playwright/test";

export const token = "lab-bootstrap-token-32-bytes!!!";

export const ALL_SCOPES = [
  "state:read",
  "state:write",
  "config:reload",
  "config:export",
  "policy:test",
  "events:read",
  "events:sensitive",
  "tokens:manage",
  "runtime:reset",
  "radius:dynamic",
];

export function sessionBody(scopes: string[] = ["state:read", "events:read"]) {
  return {
    revision: 2,
    request_id: "e2e",
    data: {
      token_id: "lab",
      scopes,
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

export const statusBody = {
  revision: 2,
  request_id: "e2e",
  data: {
    instance_id: "lab",
    revision: 2,
    baseline_hash: "abcdef0123456789ffff",
    overlay_hash: "fedcba9876543210aaaa",
    compiled_at: "2026-08-12T00:00:00Z",
    listeners: [
      {
        id: "legacy_tacacs",
        enabled: true,
        bind: "127.0.0.1:4949",
        transport: "legacy",
        protocol: "tacacs",
        carrier: "tacacs_legacy_tcp",
        roles: ["aaa"],
        ready: true,
        required: true,
        inflight: 0,
        queue_depth: 0,
      },
      {
        id: "secure_tacacs",
        enabled: false,
        bind: "127.0.0.1:4300",
        transport: "tls",
        protocol: "tacacs",
        carrier: "tacacs_tls",
        roles: ["aaa"],
        ready: false,
        required: false,
        inflight: 0,
        queue_depth: 0,
      },
      {
        id: "http",
        enabled: true,
        bind: "127.0.0.1:8080",
        transport: "http",
        protocol: "http",
        carrier: "http_tcp",
        roles: ["admin"],
        ready: true,
        required: false,
        inflight: 0,
        queue_depth: 0,
      },
      {
        id: "radius_access",
        enabled: true,
        bind: "127.0.0.1:1812",
        transport: "udp",
        protocol: "radius",
        carrier: "radius_udp",
        roles: ["access"],
        ready: true,
        required: false,
        inflight: 0,
        queue_depth: 0,
      },
      {
        id: "radius_dynauth",
        enabled: true,
        bind: "127.0.0.1:3799",
        transport: "udp",
        protocol: "radius",
        carrier: "radius_udp",
        roles: ["dynamic_authorization"],
        ready: true,
        required: false,
        inflight: 0,
        queue_depth: 0,
      },
    ],
    warnings: ["legacy shared secret rotation is overdue", "RADIUS Message-Authenticator is optional on lab-switch"],
    colocated_topology: false,
    users: 1,
    groups: 1,
    clients: 1,
    tokens: 1,
  },
};

export const buildBody = {
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
    protocols: {
      tacacs: { standards: ["RFC 8907", "RFC 9887"], conformance_status: "pass" },
      radius: { standards: ["RFC 2865", "RFC 2866"], conformance_status: "partial" },
    },
  },
};

const alice = {
  id: "alice",
  display_name: "Alice",
  enabled: true,
  source: "config",
  revision_created: 1,
  revision_updated: 1,
  effective_revision: 2,
  group_ids: ["administrators"],
  rules: { services: [], command_rules: [] },
  restrictions: {},
  ascii_pap_configured: true,
  challenge_configured: false,
  enable_configured: false,
  radius_policy_id: "default-radius-access",
  created_at: "2026-08-12T00:00:00Z",
  updated_at: "2026-08-12T00:00:00Z",
};

export async function mockAPI(
  page: Page,
  opts: { scopes?: string[] } = {},
): Promise<{ signedIn: { value: boolean }; deleteCsrf: { value: string }; lastMutations: { method: string; url: string; csrf: string; ifMatch: string }[] }> {
  const signedIn = { value: false };
  const deleteCsrf = { value: "" };
  const lastMutations: { method: string; url: string; csrf: string; ifMatch: string }[] = [];
  const scopes = opts.scopes ?? ["state:read", "events:read"];
  let userRevision = 2;
  let conflictOnce = true;

  await page.route("**/api/v1/**", async (route: Route) => {
    const req = route.request();
    const url = req.url();
    const method = req.method();
    const csrf = req.headers()["x-csrf-token"] ?? "";
    const ifMatch = req.headers()["if-match"] ?? "";
    if (method !== "GET" && method !== "HEAD") {
      lastMutations.push({ method, url, csrf, ifMatch });
    }
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
        headers: { "set-cookie": "taclab_csrf=csrf-e2e; Path=/; SameSite=Strict" },
        body: JSON.stringify(sessionBody(scopes)),
      });
      return;
    }
    if (url.includes("/api/v1/session") && method === "DELETE") {
      deleteCsrf.value = csrf;
      signedIn.value = false;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ revision: 2, request_id: "e2e", data: { id: "s", revision: 2 } }),
      });
      return;
    }
    if (!signedIn.value && !url.includes("/api/v1/session")) {
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
    if (url.includes("/api/v1/status")) {
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
        body: JSON.stringify({
          revision: 2,
          request_id: "e2e",
          data: {
            items: [
              {
                schema_version: 1,
                id: 1,
                time: "2026-08-12T00:00:00Z",
                category: "authen",
                type: "ascii.login",
                result: "pass",
                transport: "legacy",
                protocol: "tacacs",
                listener_role: "aaa",
                client_id: "lab-switch",
                privilege: 1,
                user_id: "alice",
              },
              {
                schema_version: 1,
                id: 2,
                time: "2026-08-12T00:00:01Z",
                category: "authen",
                type: "radius.access",
                result: "reject",
                transport: "udp",
                protocol: "radius",
                listener_role: "access",
                client_id: "lab-switch",
                privilege: 1,
                user_id: "alice",
              },
            ],
            reset: false,
            overwritten: 0,
          },
        }),
      });
      return;
    }
    if (url.includes("/api/v1/users") && method === "PATCH") {
      if (conflictOnce) {
        conflictOnce = false;
        await route.fulfill({
          status: 412,
          contentType: "application/problem+json",
          body: JSON.stringify({
            type: "about:blank",
            title: "revision_mismatch",
            status: 412,
            detail: "expected revision does not match published snapshot",
            code: "revision_mismatch",
          }),
        });
        return;
      }
      userRevision += 1;
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ revision: userRevision, request_id: "e2e", data: { ...alice, display_name: "Alice Jr" } }),
      });
      return;
    }
    if (url.includes("/api/v1/radius/coa:send") && method === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ revision: 2, request_id: "e2e", data: { outcome: "ack" } }),
      });
      return;
    }
    if (url.includes("/api/v1/radius/disconnect:send") && method === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ revision: 2, request_id: "e2e", data: { outcome: "ack" } }),
      });
      return;
    }
    if (url.includes("/api/v1/radius/sessions")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          revision: 2,
          request_id: "e2e",
          data: {
            items: [
              {
                session_handle: "01HXSESSIONHANDLE00",
                client_id: "lab-switch",
                user_id: "alice",
                peer: "192.0.2.10",
                nas_identifier: "edge-1",
                last_update: "2026-08-12T00:01:00Z",
              },
            ],
          },
        }),
      });
      return;
    }
    if (url.includes("/api/v1/radius/attributes")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          revision: 2,
          request_id: "e2e",
          data: {
            version: "builtin-mvp-1",
            items: [
              {
                name: "User-Name",
                code: 1,
                vendor: 0,
                value_kind: "text",
                allowed_in: ["access-request"],
                sensitivity: "pii",
                source: "builtin",
              },
            ],
          },
        }),
      });
      return;
    }
    if (url.includes("/api/v1/users")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ revision: userRevision, request_id: "e2e", data: { revision: userRevision, items: [alice] } }),
      });
      return;
    }
    if (url.includes("/api/v1/groups")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ revision: 2, request_id: "e2e", data: { revision: 2, items: [] } }),
      });
      return;
    }
    if (url.includes("/api/v1/clients")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          revision: 2,
          request_id: "e2e",
          data: {
            revision: 2,
            items: [
              {
                id: "lab-switch",
                enabled: true,
                priority: 10,
                source: "config",
                revision_created: 1,
                revision_updated: 1,
                effective_revision: 2,
                match: { source_cidrs: ["192.0.2.0/24"], transports: ["legacy"], certificate: {} },
                shared_secret_configured: true,
                shared_secret_lifecycle: "overdue",
                authentication: {},
                authorization: {},
                accounting: { enabled: true, accept_start: true, accept_stop: true, accept_watchdog: true },
                protocols: {
                  tacacs: { legacy_enabled: true, tls_enabled: false, shared_secret_configured: true },
                  radius: {
                    enabled: true,
                    roles: ["access"],
                    shared_secret_configured: true,
                    require_message_authenticator: false,
                    limit_proxy_state: true,
                    allowed_methods: ["pap", "chap"],
                  },
                },
                endpoints: [{ id: "radius-udp", protocol: "radius", transport: "udp", roles: ["access"] }],
                created_at: "2026-08-12T00:00:00Z",
                updated_at: "2026-08-12T00:00:00Z",
              },
            ],
          },
        }),
      });
      return;
    }
    if (url.includes("/api/v1/tokens") && method === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          revision: 3,
          request_id: "e2e",
          data: {
            id: "newtok",
            name: "ci",
            scopes: ["state:read"],
            enabled: true,
            source: "runtime",
            revision_created: 3,
            revision_updated: 3,
            effective_revision: 3,
            created_at: "2026-08-12T00:00:00Z",
            updated_at: "2026-08-12T00:00:00Z",
            token: "e2e-one-time-token-value",
            revision: 3,
          },
        }),
      });
      return;
    }
    if (url.includes("/api/v1/tokens")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          revision: 2,
          request_id: "e2e",
          data: {
            revision: 2,
            items: [
              {
                id: "lab",
                name: "lab",
                scopes: scopes,
                enabled: true,
                source: "config",
                revision_created: 1,
                revision_updated: 1,
                effective_revision: 2,
                created_at: "2026-08-12T00:00:00Z",
                updated_at: "2026-08-12T00:00:00Z",
              },
            ],
          },
        }),
      });
      return;
    }
    if (url.includes("/config/effective")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          revision: 2,
          request_id: "e2e",
          data: {
            revision: 2,
            view: "effective",
            baseline_hash: "a",
            overlay_hash: "b",
            compiled_at: "2026-08-12T00:00:00Z",
            instance_id: "lab",
            users: [alice],
            groups: [],
            clients: [],
            tokens: [],
          },
        }),
      });
      return;
    }
    if (url.includes("/config/export")) {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          revision: 2,
          request_id: "e2e",
          data: {
            revision: 2,
            view: "effective",
            format: "yaml",
            yaml: "schema_version: 2\nradius_policies:\n  - id: default-radius-access\n  - id: admins-radius\n",
          },
        }),
      });
      return;
    }
    if (url.includes("/runtime/reset") && method === "POST") {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ revision: 3, request_id: "e2e", data: { revision: 3, baseline_hash: "a", overlay_hash: "0" } }),
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
  return { signedIn, deleteCsrf, lastMutations };
}

export async function login(page: Page): Promise<void> {
  await page.goto("/login");
  const tokenField = page.getByLabel(/API bearer token/i);
  await tokenField.focus();
  await tokenField.pressSequentially(token);
  await page.keyboard.press("Enter");
  await page.getByRole("heading", { name: "Status" }).waitFor();
}
