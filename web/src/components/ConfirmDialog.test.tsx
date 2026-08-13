import { render, screen } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { describe, expect, it, vi } from "vitest";
import { ConfirmDialog } from "./ConfirmDialog";

describe("ConfirmDialog", () => {
  it("is keyboard reachable and describes the destructive action", async () => {
    const user = userEvent.setup();
    const onConfirm = vi.fn();
    const onCancel = vi.fn();
    render(
      <ConfirmDialog title="Delete runtime user?" confirmLabel="Delete user" onConfirm={onConfirm} onCancel={onCancel}>
        <p>This runtime user is removed from the overlay.</p>
      </ConfirmDialog>,
    );
    const dialog = screen.getByRole("dialog", { name: "Delete runtime user?" });
    expect(dialog).toHaveFocus();
    expect(screen.getByText(/removed from the overlay/i)).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "Delete user" }));
    expect(onConfirm).toHaveBeenCalledTimes(1);
  });
});
