import { describe, expect, it } from "vitest";
import { sampleCoAClient, sampleRadSecClient, sampleRadiusClient, sampleUser } from "../test/fixtures";
import {
  clientHasDynAuth,
  clientHasRADIUS,
  clientHasRADIUSTLS,
  clientHasRADIUSUDP,
  clientRADIUSMethods,
  collectRadiusPolicyIDs,
  DAS_FIXTURE_COPY,
  isRadiusTLSListener,
  isRadiusUDPListener,
  parseAttributeLines,
  policyIDsFromYAML,
  RADSEC_HINT,
  radiusInsecureCompatibility,
  radiusRequiresMessageAuthenticator,
  UDP_DYNAUTH_HINT,
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

  it("describes RadSec as YAML or endpoints[], not YAML-only", () => {
    expect(RADSEC_HINT).toMatch(/YAML or endpoints\[\]/);
    expect(RADSEC_HINT).toMatch(/flatten checkbox stays UDP-only/);
    expect(RADSEC_HINT).not.toMatch(/YAML-configured in this slice/);
  });

  it("does not treat a TLS-only RADIUS client as UDP", () => {
    expect(clientHasRADIUS(sampleRadSecClient)).toBe(true);
    expect(clientHasRADIUSUDP(sampleRadSecClient)).toBe(false);
    expect(clientHasRADIUSTLS(sampleRadSecClient)).toBe(true);
    expect(clientHasRADIUSUDP(sampleRadiusClient)).toBe(true);
  });

  it("classifies CoA by role and never treats protocol===radius as UDP", () => {
    expect(clientHasDynAuth(sampleCoAClient)).toBe(true);
    expect(clientHasDynAuth(sampleRadiusClient)).toBe(false);
    expect(clientRADIUSMethods(sampleRadiusClient)).toEqual(["pap", "chap", "eap", "mschapv2"]);
    expect(
      isRadiusUDPListener({
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
    ).toBe(false);
  });

  it("collects radius_policy_id options from objects and YAML", () => {
    expect(policyIDsFromYAML("radius_policies:\n  - id: default-radius-access\n  - id: admins-radius\n")).toEqual([
      "default-radius-access",
      "admins-radius",
    ]);
    expect(
      collectRadiusPolicyIDs({
        users: [sampleUser],
        clients: [sampleRadiusClient],
        yaml: "radius_policies:\n  - id: extra-policy\n",
        extra: ["admins-radius"],
      }),
    ).toEqual(["admins-radius", "default-radius-access", "extra-policy"]);
  });

  it("describes inbound DAS as a fixture that does not kick a device", () => {
    expect(UDP_DYNAUTH_HINT).toMatch(/RFC 5176 test fixture/i);
    expect(UDP_DYNAUTH_HINT).toMatch(/does not kick a device/i);
    expect(DAS_FIXTURE_COPY).toMatch(/does not kick a device/i);
  });
});
