import { useEffect, useId, useMemo, useState } from "react";
import { listEvents } from "../api/client";
import { RequireScope } from "../components/RequireScope";
import type { EventView } from "../generated/api";
import { useEventStream } from "../hooks/useEventStream";
import { EVENT_CATEGORIES } from "../ui/constants";
import { errorDetail } from "../ui/errors";

const PAGE = 100;

export function EventsPage() {
  return (
    <RequireScope scope="events:read">
      <EventsBody />
    </RequireScope>
  );
}

function EventsBody() {
  const stream = useEventStream();
  const [category, setCategory] = useState("");
  const [transport, setTransport] = useState("");
  const [result, setResult] = useState("");
  const [client, setClient] = useState("");
  const [user, setUser] = useState("");
  const [type, setType] = useState("");
  const [buffer, setBuffer] = useState<EventView[]>([]);
  const [visible, setVisible] = useState(PAGE);
  const [overwritten, setOverwritten] = useState(0);
  const [reset, setReset] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [pending, setPending] = useState(true);
  const catId = useId();

  useEffect(() => {
    let cancelled = false;
    setPending(true);
    void drainRecent(category === "" ? undefined : [category])
      .then((page) => {
        if (cancelled) {
          return;
        }
        setBuffer(sortNewestFirst(page.items));
        setOverwritten(page.overwritten);
        setReset(page.reset);
        setVisible(PAGE);
        setLoadError(null);
      })
      .catch((err: unknown) => {
        if (!cancelled) {
          setLoadError(errorDetail(err, "Unable to load events."));
        }
      })
      .finally(() => {
        if (!cancelled) {
          setPending(false);
        }
      });
    return () => {
      cancelled = true;
    };
  }, [category, stream.reset]);

  useEffect(() => {
    const incoming = stream.lastEvent;
    if (!incoming) {
      return;
    }
    setBuffer((prev) => mergeEvent(prev, incoming));
  }, [stream.lastEvent]);

  const items = useMemo(() => {
    return buffer
      .filter((ev) => matchEvent(ev, { transport, result, client, user, type }))
      .slice(0, visible);
  }, [buffer, transport, result, client, user, type, visible]);

  const filteredCount = buffer.filter((ev) => matchEvent(ev, { transport, result, client, user, type })).length;

  return (
    <main className="page page--wide">
      <h1>Events</h1>
      <p>Newest ring records first, plus live SSE bodies. Device and user strings are rendered as text only.</p>
      <p role="status">
        Stream:{" "}
        <span className={stream.connected ? "state state--on" : "state state--off"}>
          {stream.connected ? "Connected" : stream.reconnecting ? "Reconnecting" : "Not connected"}
        </span>
        {stream.reconnecting ? " — waiting for the event stream to return." : ""}
      </p>
      {reset || stream.reset ? (
        <section className="banner banner--warn" role="status">
          <h2>Event cursor reset</h2>
          <p>The ring evicted the previous cursor or a slow subscriber was dropped. Showing the latest page.</p>
        </section>
      ) : null}
      {overwritten > 0 ? (
        <p>
          Ring overwritten count: <strong>{String(overwritten)}</strong>
        </p>
      ) : null}
      {loadError ? (
        <div className="error-summary" role="alert">
          <h2>Could not load events</h2>
          <p>{loadError}</p>
        </div>
      ) : null}

      <form className="toolbar" onSubmit={(ev) => ev.preventDefault()}>
        <div className="field">
          <label htmlFor={catId}>Category</label>
          <select
            id={catId}
            value={category}
            onChange={(ev) => {
              setCategory(ev.target.value);
            }}
          >
            <option value="">All</option>
            {EVENT_CATEGORIES.map((c) => (
              <option key={c} value={c}>
                {c}
              </option>
            ))}
          </select>
        </div>
        <FilterField id="ev-transport" label="Transport" value={transport} onChange={setTransport} />
        <FilterField id="ev-result" label="Result" value={result} onChange={setResult} />
        <FilterField id="ev-client" label="Client" value={client} onChange={setClient} />
        <FilterField id="ev-user" label="User" value={user} onChange={setUser} />
        <FilterField id="ev-type" label="Type" value={type} onChange={setType} />
      </form>

      {pending ? <p role="status">Loading events…</p> : null}
      <table className="data">
        <caption>Redacted event bodies, newest first</caption>
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Time</th>
            <th scope="col">Category</th>
            <th scope="col">Type</th>
            <th scope="col">Result</th>
            <th scope="col">Transport</th>
            <th scope="col">Client</th>
            <th scope="col">User</th>
            <th scope="col">Command</th>
          </tr>
        </thead>
        <tbody>
          {items.map((ev) => (
            <tr key={String(ev.id)}>
              <th scope="row">{String(ev.id)}</th>
              <td>{ev.time}</td>
              <td>{ev.category}</td>
              <td>{ev.type}</td>
              <td>{ev.result}</td>
              <td>{ev.transport || "—"}</td>
              <td>{ev.client_id || "—"}</td>
              <td>{ev.user_id || "—"}</td>
              <td>{ev.command || "—"}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {items.length === 0 && !pending ? <p>No events match the filters.</p> : null}
      {visible < filteredCount ? (
        <button type="button" onClick={() => setVisible((n) => n + PAGE)}>
          Load older
        </button>
      ) : null}
    </main>
  );
}

function FilterField({
  id,
  label,
  value,
  onChange,
}: {
  id: string;
  label: string;
  value: string;
  onChange: (v: string) => void;
}) {
  return (
    <div className="field">
      <label htmlFor={id}>{label}</label>
      <input id={id} type="search" value={value} onChange={(ev) => onChange(ev.target.value)} />
    </div>
  );
}

function matchEvent(
  ev: EventView,
  f: { transport: string; result: string; client: string; user: string; type: string },
): boolean {
  const checks: Array<[string, string | undefined]> = [
    [f.transport, ev.transport],
    [f.result, ev.result],
    [f.client, ev.client_id],
    [f.user, ev.user_id],
    [f.type, ev.type],
  ];
  return checks.every(([want, got]) => want.trim() === "" || (got ?? "").toLowerCase().includes(want.trim().toLowerCase()));
}

function sortNewestFirst(items: EventView[]): EventView[] {
  return [...items].sort((a, b) => b.id - a.id);
}

function mergeEvent(prev: EventView[], incoming: EventView): EventView[] {
  return sortNewestFirst([incoming, ...prev.filter((ev) => ev.id !== incoming.id)]);
}

async function drainRecent(categories?: string[]): Promise<{ items: EventView[]; overwritten: number; reset: boolean }> {
  const items: EventView[] = [];
  let cursor: string | undefined;
  let overwritten = 0;
  let reset = false;
  for (let i = 0; i < 64; i += 1) {
    const env = await listEvents({
      limit: 200,
      ...(cursor ? { cursor } : {}),
      ...(categories ? { categories } : {}),
    });
    overwritten = env.data.overwritten;
    reset = reset || env.data.reset;
    items.push(...env.data.items);
    if (!env.data.next_cursor) {
      break;
    }
    cursor = env.data.next_cursor;
  }
  return { items, overwritten, reset };
}
