import { describe, expect, it } from "vitest";
import { fromDatetimeLocal, toDatetimeLocal } from "./constants";

describe("datetime-local UTC conversion", () => {
  it("round-trips a minute-aligned UTC instant through the operator zone", () => {
    const iso = "2026-01-01T00:00:00.000Z";
    expect(fromDatetimeLocal(toDatetimeLocal(iso))).toBe(iso);
  });

  it("round-trips a mid-day UTC instant that is a different calendar day in US zones", () => {
    const iso = "2026-07-04T02:15:00.000Z";
    expect(fromDatetimeLocal(toDatetimeLocal(iso))).toBe(iso);
  });

  it("formats with local getters, not a UTC ISO slice", () => {
    const iso = "2026-01-01T00:00:00.000Z";
    const d = new Date(iso);
    const pad = (n: number) => String(n).padStart(2, "0");
    expect(toDatetimeLocal(iso)).toBe(
      `${String(d.getFullYear())}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`,
    );
    // Slicing "…T00:00:00.000Z" to 16 chars is only correct when offset is 0.
    if (d.getTimezoneOffset() !== 0) {
      expect(toDatetimeLocal(iso)).not.toBe(iso.slice(0, 16));
      expect(fromDatetimeLocal(iso.slice(0, 16))).not.toBe(iso);
    }
  });

  it("parses datetime-local as local wall time, not as a UTC clock face", () => {
    const wall = "2026-01-01T00:00";
    expect(fromDatetimeLocal(wall)).toBe(new Date(2026, 0, 1, 0, 0, 0, 0).toISOString());
  });
});
