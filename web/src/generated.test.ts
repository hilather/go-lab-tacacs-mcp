import { describe, expect, it } from "vitest";
import type { ProblemDetails, Status } from "./generated/api";

describe("generated OpenAPI types", () => {
  it("accepts a problem-details object", () => {
    const problem: ProblemDetails = {
      type: "about:blank",
      title: "invalid_argument",
      status: 400,
      detail: "invalid request body",
      code: "invalid_argument",
    };
    expect(problem.status).toBe(400);
  });

  it("accepts a status payload", () => {
    const status: Status = {
      instance_id: "lab",
      revision: 1,
      baseline_hash: "x",
      overlay_hash: "y",
      compiled_at: "2026-08-12T00:00:00Z",
      listeners: [],
      colocated_topology: false,
      users: 0,
      groups: 0,
      clients: 0,
      tokens: 0,
    };
    expect(status.revision).toBe(1);
  });
});
