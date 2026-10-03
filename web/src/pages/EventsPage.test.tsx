import { act, screen, waitFor } from "@testing-library/react";
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

function statusOK() {
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

describe("EventsPage", () => {
  afterEach(() => {
    localStorage.clear();
    sessionStorage.clear();
    FakeEventSource.instances = [];
    vi.unstubAllGlobals();
  });

  it("sends protocol and Auth categories to events.list", async () => {
    seedSession();
    vi.stubGlobal("EventSource", FakeEventSource);
    const fetchMock = vi.fn(async (input: RequestInfo | URL) => {
      const url = String(input);
      if (url.includes("/api/v1/status")) {
        return statusOK();
      }
      if (url.includes("/api/v1/events")) {
        return json(
          200,
          envelope({
            items: [{ ...sampleEvent, id: 12, protocol: "radius", type: "radius.access", user_id: "carol" }],
            reset: false,
            overwritten: 0,
          }),
        );
      }
      return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
    });
    vi.stubGlobal("fetch", fetchMock);
    const user = userEvent.setup();
    renderApp(<EventsPage />, { route: "/events" });
    expect(await screen.findByText("carol")).toBeInTheDocument();
    await user.click(screen.getByRole("button", { name: "RADIUS" }));
    await waitFor(() => {
      const urls = fetchMock.mock.calls.map((c) => String(c[0]));
      expect(urls.some((u) => u.includes("protocol=radius") && u.includes("category=authen"))).toBe(true);
    });
  });

  it("filters events and shows reconnect plus reset state", async () => {
    seedSession();
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/v1/status")) {
          return statusOK();
        }
        if (url.includes("/api/v1/events")) {
          return json(
            200,
            envelope({
              items: [sampleEvent, { ...sampleEvent, id: 10, result: "pass", user_id: "bob" }],
              reset: false,
              overwritten: 2,
            }),
          );
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    const user = userEvent.setup();
    renderApp(<EventsPage />, { route: "/events" });
    expect(await screen.findByText("alice")).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "When" })).toBeInTheDocument();
    expect(screen.getByRole("columnheader", { name: "Who" })).toBeInTheDocument();
    expect(screen.queryByRole("columnheader", { name: "ID" })).not.toBeInTheDocument();
    const rows = screen.getAllByRole("row");
    expect(rows[1]).toHaveTextContent("bob");
    await user.type(screen.getByLabelText("Search"), "bob");
    expect(screen.queryByText("alice")).not.toBeInTheDocument();
    expect(screen.getByText("bob")).toBeInTheDocument();
    expect(screen.getByText(/overwritten count/i)).toBeInTheDocument();

    await user.clear(screen.getByLabelText("Search"));
    const es = FakeEventSource.instances[0];
    es?.emit(
      "message",
      JSON.stringify({
        schema_version: 1,
        id: 11,
        time: "2026-08-12T00:00:01Z",
        category: "authen",
        type: "ascii.login",
        result: "pass",
        transport: "legacy",
        privilege: 1,
        user_id: "carol",
      }),
    );
    expect(await screen.findByText("carol")).toBeInTheDocument();
    expect(screen.getAllByRole("row")[1]).toHaveTextContent("carol");
    expect(screen.getAllByText("TACACS+").length).toBeGreaterThan(0);

    es?.emit("error");
    expect(await screen.findByText(/Reconnecting/)).toBeInTheDocument();
    es?.emit("open");
    await waitFor(() => {
      expect(screen.getByText("Connected")).toBeInTheDocument();
    });
    es?.emit("reset");
    expect(await screen.findByRole("heading", { name: /cursor reset/i })).toBeInTheDocument();
  });

  it("renders omitted sensitive fields as dashes and a type-only what", async () => {
    seedSession();
    vi.stubGlobal("EventSource", FakeEventSource);
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const url = String(input);
        if (url.includes("/api/v1/status")) {
          return statusOK();
        }
        if (url.includes("/api/v1/events")) {
          return json(
            200,
            envelope({
              items: [
                (() => {
                  const rest = { ...sampleEvent, type: "ascii_login" };
                  delete rest.user_id;
                  delete rest.command;
                  delete rest.protocol;
                  return rest;
                })(),
              ],
              reset: false,
              overwritten: 0,
            }),
          );
        }
        return json(404, { status: 404, title: "not_found", detail: "not found", code: "not_found", type: "about:blank" });
      }),
    );
    renderApp(<EventsPage />, { route: "/events" });
    expect(await screen.findByText("ascii_login")).toBeInTheDocument();
    expect(screen.getAllByText("TACACS+").length).toBeGreaterThan(0);
    expect(screen.queryByText("<redacted>")).not.toBeInTheDocument();
  });
});


it("keeps a live event received while the initial snapshot is pending", async () => {
  seedSession();
  vi.stubGlobal("EventSource", FakeEventSource);
  let finish: ((response: Response) => void) | undefined;
  vi.stubGlobal("fetch", vi.fn(async (input: RequestInfo | URL) => {
    if (String(input).includes("/api/v1/events")) return new Promise<Response>((resolve) => { finish = resolve; });
    return json(404, {});
  }));
  renderApp(<EventsPage />);
  await waitFor(() => expect(finish).toBeDefined());
  FakeEventSource.instances.at(-1)?.emit("message", JSON.stringify({ ...sampleEvent, id: 1000, user_id: "live-user" }));
  expect(await screen.findByText("live-user")).toBeInTheDocument();
  finish?.(json(200, envelope({ items: [sampleEvent], overwritten: 0, reset: false })));
  await waitFor(() => expect(screen.queryByText("Loading events…")).not.toBeInTheDocument());
  expect(screen.getByText("live-user")).toBeInTheDocument();
  sessionStorage.clear();
  vi.unstubAllGlobals();
});


it("preserves matching history under unrelated traffic and every event in a batched burst", async () => {
  seedSession();
  vi.stubGlobal("EventSource", FakeEventSource);
  vi.stubGlobal("fetch", vi.fn(async () => json(200, envelope({ items: [sampleEvent], overwritten: 0, reset: false }))));
  renderApp(<EventsPage />);
  await screen.findByText("alice");
  await act(async () => {
    for (let id = 10; id <= 1020; id += 1) {
      FakeEventSource.instances.at(-1)?.emit("message", JSON.stringify({ ...sampleEvent, id, category: "acct", user_id: "unrelated" }));
    }
  });
  expect(screen.getByText("alice")).toBeInTheDocument();
  await act(async () => {
    for (let id = 1021; id <= 1030; id += 1) FakeEventSource.instances.at(-1)?.emit("message", JSON.stringify({ ...sampleEvent, id, user_id: `burst-${String(id)}` }));
  });
  for (let id = 1021; id <= 1030; id += 1) expect(screen.getByText(`burst-${String(id)}`)).toBeInTheDocument();
  sessionStorage.clear();
  vi.unstubAllGlobals();
});


it("expires highlights even when more events arrive before the deadline", async () => {
  seedSession();
  vi.stubGlobal("EventSource", FakeEventSource);
  vi.stubGlobal("fetch", vi.fn(async () => json(200, envelope({ items: [], overwritten: 0, reset: false }))));
  renderApp(<EventsPage />);
  await screen.findByText("No events match the filters.");
  vi.useFakeTimers();
  try {
    await act(async () => FakeEventSource.instances.at(-1)?.emit("message", JSON.stringify({ ...sampleEvent, id: 100, user_id: "first-flash" })));
    expect(screen.getByText("first-flash").closest("tr")).toHaveClass("event-row--new");
    await act(async () => { vi.advanceTimersByTime(800); });
    await act(async () => FakeEventSource.instances.at(-1)?.emit("message", JSON.stringify({ ...sampleEvent, id: 101, user_id: "second-flash" })));
    await act(async () => { vi.advanceTimersByTime(600); });
    expect(screen.getByText("first-flash").closest("tr")).not.toHaveClass("event-row--new");
  } finally {
    vi.useRealTimers();
    sessionStorage.clear();
    vi.unstubAllGlobals();
  }
});
