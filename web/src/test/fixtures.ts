import type { Client, EventView, Group, RadiusSessionView, TokenView, User } from "../generated/api";

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
  restrictions: { valid_after: "2026-01-01T00:00:00.000Z", valid_before: "2027-01-01T00:00:00.000Z" },
  ascii_pap_configured: true,
  challenge_configured: false,
  enable_configured: false,
  must_change_login: false,
  must_change_enable: false,
  radius_policy_id: "default-radius-access",
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
  radius_policy_id: "admins-radius",
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
  authentication: { allowed_methods: ["ascii", "pap"], default_service: "shell" },
  authorization: { default_group_ids: ["readonly"] },
  accounting: { enabled: true, accept_start: true, accept_stop: true, accept_watchdog: true },
  protocols: {
    tacacs: { legacy_enabled: true, tls_enabled: false, shared_secret_configured: true },
    radius: {
      enabled: false,
      roles: [],
      shared_secret_configured: false,
      require_message_authenticator: true,
      limit_proxy_state: true,
    },
  },
  created_at: "2026-08-12T00:00:00Z",
  updated_at: "2026-08-12T00:00:00Z",
};

export const sampleRadiusClient: Client = {
  ...sampleClient,
  id: "lab-radius",
  display_name: "Lab RADIUS NAS",
  protocols: {
    tacacs: { legacy_enabled: false, tls_enabled: false, shared_secret_configured: false },
    radius: {
      enabled: true,
      roles: ["access", "accounting"],
      shared_secret_configured: true,
      secret_lifecycle: "current",
      require_message_authenticator: false,
      limit_proxy_state: true,
      allowed_methods: ["pap", "chap", "eap", "mschapv2"],
      access_policy_id: "default-radius-access",
      accept_status_types: ["start", "stop"],
    },
  },
  endpoints: [
    {
      id: "radius-udp",
      protocol: "radius",
      transport: "udp",
      roles: ["access", "accounting"],
      radius: {
        enabled: true,
        roles: ["access", "accounting"],
        shared_secret_configured: true,
        require_message_authenticator: false,
        limit_proxy_state: true,
        allowed_methods: ["pap", "chap", "eap", "mschapv2"],
      },
    },
  ],
};

export const sampleCoAClient: Client = {
  ...sampleRadiusClient,
  id: "lab-coa",
  display_name: "Lab CoA NAS",
  protocols: {
    tacacs: { legacy_enabled: false, tls_enabled: false, shared_secret_configured: false },
    radius: {
      enabled: true,
      roles: ["access", "accounting", "dynamic_authorization"],
      shared_secret_configured: true,
      secret_lifecycle: "current",
      require_message_authenticator: true,
      limit_proxy_state: true,
      allowed_methods: ["pap", "chap"],
      access_policy_id: "default-radius-access",
    },
  },
  endpoints: [
    {
      id: "radius-udp",
      protocol: "radius",
      transport: "udp",
      roles: ["access", "accounting", "dynamic_authorization"],
      radius: {
        enabled: true,
        roles: ["access", "accounting", "dynamic_authorization"],
        shared_secret_configured: true,
        require_message_authenticator: true,
        limit_proxy_state: true,
        allowed_methods: ["pap", "chap"],
      },
    },
  ],
};

export const sampleRadSecClient: Client = {
  ...sampleClient,
  id: "lab-radsec",
  display_name: "Lab RadSec NAS",
  match: {
    source_cidrs: [],
    transports: [],
    mode: "certificate_only",
    certificate: { dns_sans: ["nas.lab.example"] },
  },
  protocols: {
    tacacs: { legacy_enabled: false, tls_enabled: false, shared_secret_configured: false },
    radius: {
      enabled: false,
      roles: [],
      shared_secret_configured: false,
      require_message_authenticator: true,
      limit_proxy_state: true,
    },
  },
  endpoints: [
    {
      id: "radius-tls",
      protocol: "radius",
      transport: "tls",
      roles: ["access", "accounting"],
      radius: {
        enabled: true,
        roles: ["access", "accounting"],
        shared_secret_configured: true,
        require_message_authenticator: true,
        limit_proxy_state: true,
        allowed_methods: ["pap", "chap"],
      },
    },
  ],
};

export const sampleRadiusSession: RadiusSessionView = {
  session_handle: "01HXSESSIONHANDLE00",
  client_id: "lab-radius",
  user_id: "alice",
  endpoint_id: "radius-udp",
  nas_ip: "192.0.2.10",
  nas_identifier: "edge-1",
  peer: "192.0.2.10",
  started_at: "2026-08-12T00:00:00Z",
  last_update: "2026-08-12T00:01:00Z",
  acct_session_id: "sess-1",
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
  protocol: "tacacs",
  listener_role: "aaa",
  client_id: "lab-switch",
  privilege: 1,
  user_id: "alice",
};
