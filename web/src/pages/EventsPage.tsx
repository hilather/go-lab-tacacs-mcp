import { useQuery } from "@tanstack/react-query";
import { useId, useMemo, useState } from "react";
import { listEvents } from "../api/client";
import { RequireScope } from "../components/RequireScope";
import type { EventView } from "../generated/api";
import { useEventStream } from "../hooks/useEventStream";
import { EVENT_CATEGORIES } from "../ui/constants";
import { errorDetail } from "../ui/errors";

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
  const [code, setCode] = useState("");
  const [cursor, setCursor] = useState<string | undefined>(undefined);
  const catId = useId();
  const query = useQuery({
    queryKey: ["events", category, cursor],
    queryFn: () =>
      listEvents({
        limit: 100,
        ...(cursor !== undefined ? { cursor } : {}),
        ...(category === "" ? {} : { categories: [category] }),
      }),
  });
  const items = useMemo(() => {
    const raw = query.data?.data.items ?? [];
    return raw.filter((ev) => matchEvent(ev, { transport, result, client, user, type, code }));
  }, [query.data, transport, result, client, user, type, code]);

  const overwritten = query.data?.data.overwritten ?? 0;
  const reset = query.data?.data.reset || stream.reset;

  return (
    <main className="page page--wide">
      <h1>Events</h1>
      <p>Recent ring records plus the live SSE stream. Device and user strings are rendered as text only.</p>
      <p role="status">
        Stream:{" "}
        <span className={stream.connected ? "state state--on" : "state state--off"}>
          {stream.connected ? "Connected" : stream.reconnecting ? "Reconnecting" : "Not connected"}
        </span>
        {stream.reconnecting ? " — waiting for the event stream to return." : ""}
      </p>
      {reset ? (
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
      {query.isError ? (
        <div className="error-summary" role="alert">
          <h2>Could not load events</h2>
          <p>{errorDetail(query.error, "Unable to load events.")}</p>
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
              setCursor(undefined);
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
        <FilterField id="ev-code" label="Error / result code" value={code} onChange={setCode} />
      </form>

      {query.isPending ? <p role="status">Loading events…</p> : null}
      <table className="data">
        <caption>Redacted event bodies</caption>
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
      {items.length === 0 && !query.isPending ? <p>No events match the filters.</p> : null}
      {query.data?.data.next_cursor ? (
        <button type="button" onClick={() => setCursor(query.data?.data.next_cursor)}>
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
  f: { transport: string; result: string; client: string; user: string; type: string; code: string },
): boolean {
  const checks: Array<[string, string | undefined]> = [
    [f.transport, ev.transport],
    [f.result, ev.result],
    [f.client, ev.client_id],
    [f.user, ev.user_id],
    [f.type, ev.type],
    [f.code, ev.result],
  ];
  return checks.every(([want, got]) => want.trim() === "" || (got ?? "").toLowerCase().includes(want.trim().toLowerCase()));
}
