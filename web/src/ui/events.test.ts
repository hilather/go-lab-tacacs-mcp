import { describe, expect, it } from "vitest";
import { sampleEvent } from "../test/fixtures";
import {
  eventProtocolLabel,
  eventProtocolToken,
  eventWhat,
  eventWho,
  formatEventClock,
  matchEvent,
  resultTone,
} from "./events";

describe("event presentation", () => {
  it("treats omitted protocol on AAA rows as TACACS+", () => {
    const ev = { ...sampleEvent };
    delete ev.protocol;
    expect(eventProtocolToken(ev)).toBe("tacacs");
    expect(eventProtocolLabel(eventProtocolToken(ev))).toBe("TACACS+");
    expect(matchEvent(ev, { kind: "auth", protocol: "tacacs", search: "" })).toBe(true);
  });

  it("does not paint API events as TACACS+", () => {
    const ev = { ...sampleEvent, category: "api", type: "users.list" };
    delete ev.protocol;
    delete ev.user_id;
    expect(eventProtocolToken(ev)).toBe("");
    expect(eventProtocolLabel(eventProtocolToken(ev))).toBe("—");
  });

  it("shows omitted sensitive user as an em dash, not a redaction sentinel", () => {
    const noUser = { ...sampleEvent };
    delete noUser.user_id;
    const noCmd = { ...sampleEvent, type: "ascii_login" };
    delete noCmd.command;
    expect(eventWho(noUser)).toBe("—");
    expect(eventWhat(noCmd)).toBe("ascii_login");
  });

  it("classifies fail-family results including reject and deny", () => {
    expect(resultTone("reject")).toBe("fail");
    expect(resultTone("deny")).toBe("fail");
    expect(resultTone("permit_add")).toBe("pass");
    expect(resultTone("must_change")).toBe("warn");
  });

  it("formats clock from local Date getters", () => {
    const iso = "2026-08-12T00:00:00.000Z";
    const d = new Date(iso);
    const pad = (n: number) => String(n).padStart(2, "0");
    expect(formatEventClock(iso)).toBe(`${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`);
  });

  it("matches search against type and packet_code", () => {
    const ev = { ...sampleEvent, type: "radius.access", packet_code: "access-request" };
    delete ev.command;
    expect(matchEvent(ev, { kind: "auth", protocol: "", search: "access-request" })).toBe(true);
    expect(matchEvent(ev, { kind: "auth", protocol: "", search: "bob" })).toBe(false);
  });
});
