import { describe, expect, it } from "vitest";
import { sampleRadSecClient, sampleRadiusClient } from "../test/fixtures";
import {
  clientHasRADIUS,
  clientHasRADIUSTLS,
  clientHasRADIUSUDP,
  isRadiusTLSListener,
  isRadiusUDPListener,
  parseAttributeLines,
  radiusInsecureCompatibility,
  radiusRequiresMessageAuthenticator,
  warningLooksInsecureRADIUS,
} from "./radius";

describe("radius UI helpers", () => {
  it("parses Name=value attribute lines and rejects malformed rows", () => {
    expect(parseAttributeLines("Service-Type=Login-User\nNAS-Identifier=edge-1").attrs).toEqual([
      { name: "Service-Type", value: "Login-User" },
      { name: "NAS-Identifier", value: "edge-1" },
    ]);
    expect(parseAttributeLines("not-a-pair").error).toMatch(/Name=value/);
  });

  it("detects insecure RADIUS compatibility from the client view", () => {
    expect(radiusRequiresMessageAuthenticator(sampleRadiusClient)).toBe(false);
    expect(radiusInsecureCompatibility(sampleRadiusClient)).toBe(true);
    expect(warningLooksInsecureRADIUS("RADIUS Message-Authenticator is optional on lab-switch")).toBe(true);
  });

  it("classifies UDP listeners by carrier or udp transport only", () => {
    expect(
      isRadiusUDPListener({
        id: "radius_access",
        enabled: true,
        bind: "0.0.0.0:1812",
        transport: "udp",
        protocol: "radius",
        carrier: "radius_udp",
        roles: ["access"],
        ready: true,
        required: false,
        inflight: 0,
        queue_depth: 0,
      }),
    ).toBe(true);
    expect(
      isRadiusUDPListener({
        id: "radius_radsec",
        enabled: true,
        bind: "0.0.0.0:2083",
        transport: "tls",
        protocol: "radius",
        carrier: "radius_tls",
        roles: ["access", "accounting"],
        ready: true,
        required: false,
        inflight: 0,
        queue_depth: 0,
      }),
    ).toBe(false);
    expect(
      isRadiusTLSListener({
        id: "radius_radsec",
        enabled: true,
        bind: "0.0.0.0:2083",
        transport: "tls",
        protocol: "radius",
        carrier: "radius_tls",
        roles: ["access"],
        ready: true,
        required: false,
        inflight: 0,
        queue_depth: 0,
      }),
    ).toBe(true);
  });

  it("does not treat a TLS-only RADIUS client as UDP", () => {
    expect(clientHasRADIUS(sampleRadSecClient)).toBe(true);
    expect(clientHasRADIUSUDP(sampleRadSecClient)).toBe(false);
    expect(clientHasRADIUSTLS(sampleRadSecClient)).toBe(true);
    expect(clientHasRADIUSUDP(sampleRadiusClient)).toBe(true);
  });
});
