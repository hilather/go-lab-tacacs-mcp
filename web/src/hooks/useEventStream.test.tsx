import { useQuery } from "@tanstack/react-query";
import { act, screen, waitFor } from "@testing-library/react";
import { afterEach, expect, it, vi } from "vitest";
import { renderApp, seedSession, json, envelope } from "../test/render";
import { useEventStream } from "./useEventStream";

class FakeEventSource {
  static current: FakeEventSource;
  handlers = new Map<string, EventListener>();
  constructor() { FakeEventSource.current = this; }
  addEventListener(type: string, fn: EventListener) { this.handlers.set(type, fn); }
  removeEventListener(type: string) { this.handlers.delete(type); }
  close() {}
  emit(type: string, data?: object) {
    this.handlers.get(type)?.(new MessageEvent(type, { data: JSON.stringify(data) }));
  }
}

function SessionsProbe({ read }: { read: () => Promise<number> }) {
  useEventStream();
  const query = useQuery({ queryKey: ["radius-sessions"], queryFn: read });
  return <p>{query.data === undefined ? "loading" : `sessions-${String(query.data)}`}</p>;
}

afterEach(() => { sessionStorage.clear(); vi.unstubAllGlobals(); });

it.each(["accounting", "revision", "reset"])("refreshes sessions after %s notification", async (kind) => {
  seedSession();
  vi.stubGlobal("EventSource", FakeEventSource);
  vi.stubGlobal("fetch", vi.fn(async () => json(404, {})));
  let count = 0;
  const read = vi.fn(async () => ++count);
  renderApp(<SessionsProbe read={read} />);
  await screen.findByText("sessions-1");
  await waitFor(() => expect(FakeEventSource.current).toBeDefined());
  act(() => {
    FakeEventSource.current.emit(kind === "reset" ? "reset" : "message", {
      id: 1, category: kind === "accounting" ? "acct" : "config",
      protocol: kind === "accounting" ? "radius" : "http", result: "ok", revision: 4,
      type: kind === "accounting" ? "start" : "state.revision.changed",
    });
  });
  await screen.findByText("sessions-2");
  expect(read).toHaveBeenCalledTimes(2);
});

it("coalesces a burst of accounting notifications into one session refetch", async () => {
  seedSession();
  vi.stubGlobal("EventSource", FakeEventSource);
  vi.stubGlobal("fetch", vi.fn(async () => json(404, envelope({}))));
  let count = 0;
  const read = vi.fn(async () => ++count);
  renderApp(<SessionsProbe read={read} />);
  await screen.findByText("sessions-1");
  act(() => {
    for (let id = 1; id <= 30; id += 1) FakeEventSource.current.emit("message", { id, category: "acct", protocol: "radius", type: "interim_update" });
  });
  await screen.findByText("sessions-2");
  expect(read).toHaveBeenCalledTimes(2);
});
