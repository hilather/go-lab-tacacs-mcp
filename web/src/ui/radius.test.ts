import { describe, expect, it } from "vitest";
import { sampleRadiusClient } from "../test/fixtures";
import {
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
});
