import { afterEach, describe, expect, it } from "vitest";
import { assertNoTokenStorage } from "./storage";

describe("assertNoTokenStorage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
  });

  it("passes when storage is empty", () => {
    expect(() => assertNoTokenStorage()).not.toThrow();
  });

  it("rejects a token key in localStorage", () => {
    localStorage.setItem("taclab_token", "secret");
    expect(() => assertNoTokenStorage()).toThrow(/localStorage/);
  });

  it("rejects a bearer value in sessionStorage", () => {
    sessionStorage.setItem("note", "Authorization: Bearer abc.def");
    expect(() => assertNoTokenStorage()).toThrow(/sessionStorage/);
  });
});
