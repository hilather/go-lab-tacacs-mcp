import type { Client, EventView, Group, TokenView, User } from "../generated/api";

export const sampleUser: User = {
  id: "alice",
  display_name: "Alice",
  enabled: true,
  source: "config",
  revision_created: 1,
  revision_updated: 1,
  effective_revision: 3,
  group_ids: ["administrators"],
  rules: { services: [], command_rules: [] },
  restrictions: {},
  ascii_pap_configured: true,
  challenge_configured: false,
  enable_configured: false,
  created_at: "2026-08-12T00:00:00Z",
  updated_at: "2026-08-12T00:00:00Z",
};

export const sampleGroup: Group = {
  id: "administrators",
  display_name: "Admins",
  enabled: true,
  priority: 10,
  source: "config",
  revision_created: 1,
  revision_updated: 1,
  effective_revision: 3,
  services: [{ service: "shell", action: "permit_add", reply_attributes: [{ name: "priv-lvl", separator: "=", value: "15" }] }],
  command_rules: [{ id: "permit-all", priority: 10, action: "permit_add", command: { exact: "configure" }, arguments: {} }],
  created_at: "2026-08-12T00:00:00Z",
  updated_at: "2026-08-12T00:00:00Z",
};

export const sampleClient: Client = {
  id: "lab-switch",
  display_name: "Lab switch",
  enabled: true,
  priority: 10,
  source: "runtime",
  revision_created: 2,
  revision_updated: 2,
  effective_revision: 3,
  match: {
    source_cidrs: ["192.0.2.0/24"],
    transports: ["legacy"],
    mode: "address_and_certificate",
    certificate: {},
  },
  shared_secret_configured: true,
  shared_secret_lifecycle: "due_soon",
  authentication: { allowed_methods: ["ascii", "pap"] },
  authorization: { default_group_ids: ["readonly"] },
  accounting: { enabled: true, accept_start: true, accept_stop: true, accept_watchdog: true },
  created_at: "2026-08-12T00:00:00Z",
  updated_at: "2026-08-12T00:00:00Z",
};

export const sampleToken: TokenView = {
  id: "lab",
  name: "lab",
  scopes: ["state:read"],
  enabled: true,
  source: "runtime",
  revision_created: 1,
  revision_updated: 1,
  effective_revision: 3,
  created_at: "2026-08-12T00:00:00Z",
  updated_at: "2026-08-12T00:00:00Z",
};

export const sampleEvent: EventView = {
  schema_version: 1,
  id: 9,
  time: "2026-08-12T00:00:00Z",
  category: "authen",
  type: "ascii.login",
  result: "fail",
  transport: "legacy",
  client_id: "lab-switch",
  privilege: 1,
  user_id: "alice",
};
