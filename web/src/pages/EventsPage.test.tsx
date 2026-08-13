import { screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, describe, expect, it, vi } from "vitest";
import { envelope, json, renderApp, seedSession } from "../test/render";
import { sampleEvent } from "../test/fixtures";
import { EventsPage } from "./EventsPage";

class FakeEventSource {
  static instances: FakeEventSource[] = [];
  readonly listeners = new Map<string, Array<(ev: Event | MessageEvent<string>) => void>>();

  constructor(public url: string) {
    FakeEventSource.instances.push(this);
  }

  addEventListener(type: string, fn: (ev: Event | MessageEvent<string>) => void): void {
    this.listeners.set(type, [...(this.listeners.get(type) ?? []), fn]);
  }

  removeEventListener(type: string, fn: (ev: Event | MessageEvent<string>) => void): void {
    this.listeners.set(
      type,
      (this.listeners.get(type) ?? []).filter((h) => h !== fn),
    );
  }

  close(): void {}

  emit(type: string, data?: string): void {
    for (const handler of this.listeners.get(type) ?? []) {
      if (type === "message") {
        handler({ data } as MessageEvent<string>);
      } else {
        handler(new Event(type));
      }
    }
  }
}

describe("EventsPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    FakeEventSource.instances = [];
    vi.unstubAllGlobals();
  });

  it("filters events and shows reconnect plus reset state", async () => {
    seedSession();
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/v1/status")) {
          return json(
            200,
            envelope({
              instance_id: "lab",
              revision: 3,
              baseline_hash: "a",
              overlay_hash: "b",
              compiled_at: "2026-08-12T00:00:00Z",
              listeners: [],
              colocated_topology: false,
              users: 0,
              groups: 0,
              clients: 0,
              tokens: 0,
            }),
          );
        }
        if (url.includes("/api/v1/events")) {
          return json(200, envelope({ items: [sampleEvent, { ...sampleEvent, id: 10, result: "pass", user_id: "bob" }], reset: false, overwritten: 2 }));
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    const user = userEvent.setup();
    renderApp(<EventsPage />, { route: "/events" });
    expect(await screen.findByText("alice")).toBeInTheDocument();
    await user.type(screen.getByLabelText("User"), "bob");
    expect(screen.queryByText("alice")).not.toBeInTheDocument();
    expect(screen.getByText("bob")).toBeInTheDocument();
    expect(screen.getByText(/overwritten count/i)).toBeInTheDocument();

    const es = FakeEventSource.instances[0];
    es?.emit("error");
    expect(await screen.findByText(/Reconnecting/)).toBeInTheDocument();
    es?.emit("open");
    await waitFor(() => {
      expect(screen.getByText("Connected")).toBeInTheDocument();
    });
    es?.emit("reset");
    expect(await screen.findByRole("heading", { name: /cursor reset/i })).toBeInTheDocument();
  });
});
