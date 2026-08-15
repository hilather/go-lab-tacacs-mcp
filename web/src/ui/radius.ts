import type { Client, ListenerStatus, RadiusAttributeValue } from "../generated/api";

export const INSECURE_RADIUS_LABEL = "insecure RADIUS compatibility";

export const UDP_RADIUS_HINT =
  "RADIUS/UDP is a controlled-network lab profile. It is not TLS and is not complete RADIUS.";

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
  return listener.protocol === "radius" || listener.transport === "udp" || listener.carrier === "radius_udp";
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

export function radiusRequiresMessageAuthenticator(client: Client): boolean {
  const view = client.protocols?.radius;
  if (view?.enabled) {
    return view.require_message_authenticator;
  }
  for (const ep of client.endpoints ?? []) {
    if (ep.protocol === "radius" && ep.radius) {
      return ep.radius.require_message_authenticator;
    }
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
