import type { Client, Group, ListenerStatus, RadiusAttributeValue, User } from "../generated/api";

export const INSECURE_RADIUS_LABEL = "insecure RADIUS compatibility";

export const UDP_RADIUS_HINT =
  "RADIUS/UDP is a controlled-network lab profile. It is not TLS and is not complete RADIUS.";

export const RADSEC_HINT =
  "Optional RADIUS/TLS (RadSec) is a TLS 1.3 stream on TCP 2083 (transport: tls). Configure it in YAML or endpoints[]; the flatten checkbox stays UDP-only. It is not a TLS wrap of UDP.";

export const UDP_DYNAUTH_HINT =
  "Inbound :3799 is an RFC 5176 test fixture; it does not kick a device. It only updates TacLab’s memory index. To disconnect a device, use Disconnect send.";

export const DAS_FIXTURE_COPY =
  "RFC 5176 test fixture; does not kick a device. Inbound :3799 never forwards to a NAS.";

export function listenerState(listener: ListenerStatus): "ready" | "degraded" | "disabled" {
  if (!listener.enabled) {
    return "disabled";
  }
  return listener.ready ? "ready" : "degraded";
}

export function listenerStateLabel(state: ReturnType<typeof listenerState>): string {
  switch (state) {
    case "ready":
      return "Ready";
    case "degraded":
      return "Degraded";
    default:
      return "Disabled";
  }
}

export function isRadiusUDPListener(listener: ListenerStatus): boolean {
  return listener.carrier === "radius_udp" || listener.transport === "udp";
}

export function isRadiusTLSListener(listener: ListenerStatus): boolean {
  return listener.carrier === "radius_tls" || (listener.protocol === "radius" && listener.transport === "tls");
}

export function clientRADIUS(client: Client) {
  return client.protocols?.radius;
}

export function clientHasRADIUS(client: Client): boolean {
  if (client.protocols?.radius?.enabled) {
    return true;
  }
  return (client.endpoints ?? []).some((ep) => ep.protocol === "radius" && (ep.radius?.enabled ?? true));
}

export function clientHasRADIUSUDP(client: Client): boolean {
  const endpoints = client.endpoints ?? [];
  if (endpoints.some((ep) => ep.protocol === "radius" && ep.transport === "udp")) {
    return true;
  }
  if (endpoints.length === 0) {
    return client.protocols?.radius?.enabled === true;
  }
  return false;
}

export function clientHasRADIUSTLS(client: Client): boolean {
  return (client.endpoints ?? []).some((ep) => ep.protocol === "radius" && ep.transport === "tls");
}

export function clientHasDynAuth(client: Client): boolean {
  if ((clientRADIUS(client)?.roles ?? []).includes("dynamic_authorization")) {
    return true;
  }
  return (client.endpoints ?? []).some((ep) => {
    if (ep.protocol !== "radius") {
      return false;
    }
    const roles = ep.roles ?? ep.radius?.roles ?? [];
    return roles.includes("dynamic_authorization");
  });
}

export function clientRADIUSMethods(client: Client): string[] {
  const fromView = clientRADIUS(client)?.allowed_methods ?? [];
  if (fromView.length > 0) {
    return fromView;
  }
  for (const ep of client.endpoints ?? []) {
    if (ep.protocol === "radius" && (ep.radius?.allowed_methods ?? []).length > 0) {
      return ep.radius?.allowed_methods ?? [];
    }
  }
  return [];
}

export function collectRadiusPolicyIDs(args: {
  users?: readonly User[];
  groups?: readonly Group[];
  clients?: readonly Client[];
  yaml?: string;
  extra?: readonly string[];
}): string[] {
  const ids = new Set<string>();
  for (const user of args.users ?? []) {
    if (user.radius_policy_id) {
      ids.add(user.radius_policy_id);
    }
  }
  for (const group of args.groups ?? []) {
    if (group.radius_policy_id) {
      ids.add(group.radius_policy_id);
    }
  }
  for (const client of args.clients ?? []) {
    const fromView = clientRADIUS(client)?.access_policy_id;
    if (fromView) {
      ids.add(fromView);
    }
    for (const ep of client.endpoints ?? []) {
      if (ep.radius?.access_policy_id) {
        ids.add(ep.radius.access_policy_id);
      }
    }
  }
  for (const id of policyIDsFromYAML(args.yaml ?? "")) {
    ids.add(id);
  }
  for (const id of args.extra ?? []) {
    if (id !== "") {
      ids.add(id);
    }
  }
  return [...ids].sort((a, b) => a.localeCompare(b));
}

export function policyIDsFromYAML(yaml: string): string[] {
  if (yaml.trim() === "") {
    return [];
  }
  const ids: string[] = [];
  // Export/effective YAML never emits a radius_policies catalog. IDs appear on users/groups
  // (radius_policy_id) and client endpoints (access_policy_id).
  for (const match of yaml.matchAll(/^[ \t]+(?:radius_policy_id|access_policy_id):[ \t]*(\S+)/gm)) {
    const raw = match[1]?.replace(/^['"]|['"]$/g, "") ?? "";
    if (raw !== "" && raw !== "null" && raw !== "~") {
      ids.push(raw);
    }
  }
  return ids;
}

export function radiusRequiresMessageAuthenticator(client: Client): boolean {
  const endpoints = (client.endpoints ?? []).filter((ep) => ep.protocol === "radius" && ep.radius);
  if (endpoints.length > 0) {
    return endpoints.every((ep) => ep.radius?.require_message_authenticator !== false);
  }
  const view = client.protocols?.radius;
  if (view?.enabled) {
    return view.require_message_authenticator;
  }
  return true;
}

export function radiusInsecureCompatibility(client: Client): boolean {
  return clientHasRADIUS(client) && !radiusRequiresMessageAuthenticator(client);
}

export function warningLooksInsecureRADIUS(warning: string): boolean {
  return /message.?authenticator|allow_missing|insecure RADIUS/i.test(warning);
}

export function parseAttributeLines(raw: string): { attrs: RadiusAttributeValue[]; error?: string } {
  const attrs: RadiusAttributeValue[] = [];
  const lines = raw.split(/\r?\n/);
  for (let i = 0; i < lines.length; i += 1) {
    const trimmed = lines[i]?.trim() ?? "";
    if (trimmed === "") {
      continue;
    }
    const eq = trimmed.indexOf("=");
    if (eq <= 0) {
      return { attrs: [], error: `Attribute line ${String(i + 1)} must be Name=value.` };
    }
    const name = trimmed.slice(0, eq).trim();
    const value = trimmed.slice(eq + 1).trim();
    if (name === "") {
      return { attrs: [], error: `Attribute line ${String(i + 1)} is missing a name.` };
    }
    attrs.push({ name, value });
  }
  return { attrs };
}

export function formatRadiusAttr(attr: RadiusAttributeValue): string {
  const value = attr.value ?? attr.value_hex ?? "";
  if (attr.name) {
    return `${attr.name}=${value}`;
  }
  const vendor = attr.vendor ?? 0;
  const code = attr.code ?? 0;
  return `vendor=${String(vendor)} code=${String(code)} ${value}`.trim();
}
