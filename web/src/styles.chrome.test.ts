import { describe, expect, it } from "vitest";
import { CHROME } from "./ui/chrome";

describe("operator chrome tokens", () => {
  it("exports the approved dark LabMail family and rejects paper/forest/violet leftovers", () => {
    expect(CHROME.bg).toBe("#0b0c0e");
    expect(CHROME.elevated).toBe("#121317");
    expect(CHROME.panel).toBe("#181a1f");
    expect(CHROME.fg).toBe("#ecece8");
    expect(CHROME.muted).toBe("#9a9b97");
    expect(CHROME.tacacs).toBe("#4aa384");
    expect(CHROME.radius).toBe("#8b74c7");
    expect(CHROME.fail).toBe("#c45c5c");
    expect(CHROME.fontSans).toBe("IBM Plex Sans");
    expect(CHROME.fontMono).toBe("IBM Plex Mono");
    expect(Object.values(CHROME)).not.toContain("#f4f1ea");
    expect(Object.values(CHROME)).not.toContain("#1f4b3a");
    expect(Object.values(CHROME)).not.toContain("#6b3fa0");
  });
});
