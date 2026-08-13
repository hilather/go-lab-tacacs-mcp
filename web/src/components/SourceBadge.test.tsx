import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { SourceBadge, SourceKey } from "./SourceBadge";

describe("SourceBadge", () => {
  it("renders CONFIG, RUNTIME, and OVERRIDE with text labels", () => {
    const { rerender } = render(<SourceBadge source="config" />);
    expect(screen.getByText("CONFIG")).toBeInTheDocument();
    rerender(<SourceBadge source="runtime" />);
    expect(screen.getByText("RUNTIME")).toBeInTheDocument();
    rerender(<SourceBadge source="override" />);
    expect(screen.getByText("OVERRIDE")).toBeInTheDocument();
  });

  it("includes a non-color description for screen readers", () => {
    render(<SourceKey />);
    expect(screen.getByRole("heading", { name: "Source badges" })).toBeInTheDocument();
    expect(screen.getAllByText(/Ephemeral runtime object/i).length).toBeGreaterThan(0);
    expect(screen.getAllByText(/runtime overlay/i).length).toBeGreaterThan(0);
  });
});
