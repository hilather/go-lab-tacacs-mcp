import { useEffect, useId, useMemo, useState } from "react";
import { EventRow, EventTableHead } from "../components/EventRow";
import { RequireScope } from "../components/RequireScope";
import type { EventView } from "../generated/api";
import { useEventStream } from "../hooks/useEventStream";
import { errorDetail } from "../ui/errors";
import {
  drainCategories,
  drainRecent,
  type EventKind,
  matchEvent,
  mergeEvent,
  sortNewestFirst,
} from "../ui/events";

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
  const [kind, setKind] = useState<EventKind>("auth");
  const [protocol, setProtocol] = useState("");
  const [search, setSearch] = useState("");
  const [buffer, setBuffer] = useState<EventView[]>([]);
  const [visible, setVisible] = useState(PAGE);
  const [overwritten, setOverwritten] = useState(0);
  const [reset, setReset] = useState(false);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [pending, setPending] = useState(true);
  const [flashIds, setFlashIds] = useState<Set<number>>(new Set());
  const searchId = useId();
  const drainKey = `${kind}\0${protocol}\0${String(stream.reset)}`;
  const [trackedDrainKey, setTrackedDrainKey] = useState(drainKey);
  if (trackedDrainKey !== drainKey) {
    setTrackedDrainKey(drainKey);
    setPending(true);
  }

  const incoming = stream.lastEvent;
  const [seenEvent, setSeenEvent] = useState(incoming);
  if (incoming !== null && incoming !== seenEvent) {
    setSeenEvent(incoming);
    setBuffer((prev) => mergeEvent(prev, incoming));
    setFlashIds((prev) => new Set(prev).add(incoming.id));
  }

  useEffect(() => {
    if (flashIds.size === 0) {
      return;
    }
    const timer = window.setTimeout(() => {
      setFlashIds(new Set());
    }, 1300);
    return () => {
      window.clearTimeout(timer);
    };
  }, [flashIds]);

  useEffect(() => {
    let cancelled = false;
    const categories = drainCategories(kind);
    void drainRecent({
      ...(categories ? { categories } : {}),
      ...(protocol === "" ? {} : { protocol }),
    })
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
  }, [kind, protocol, stream.reset]);

  const items = useMemo(() => {
    return buffer.filter((ev) => matchEvent(ev, { kind, protocol, search })).slice(0, visible);
  }, [buffer, kind, protocol, search, visible]);

  const filteredCount = buffer.filter((ev) => matchEvent(ev, { kind, protocol, search })).length;

  return (
    <main className="page page--wide">
      <h1>Events</h1>
      <p className="lede">
        Live AAA. Newest first. Sensitive fields stay redacted without events:sensitive.
      </p>
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

      <form className="chip-bar" onSubmit={(ev) => ev.preventDefault()}>
        <div className="seg" role="group" aria-label="Protocol">
          <Chip pressed={protocol === ""} onClick={() => setProtocol("")}>
            All
          </Chip>
          <Chip pressed={protocol === "tacacs"} onClick={() => setProtocol("tacacs")}>
            TACACS+
          </Chip>
          <Chip pressed={protocol === "radius"} onClick={() => setProtocol("radius")}>
            RADIUS
          </Chip>
        </div>
        <div className="seg" role="group" aria-label="Kind">
          <Chip pressed={kind === "auth"} onClick={() => setKind("auth")}>
            Auth
          </Chip>
          <Chip pressed={kind === "acct"} onClick={() => setKind("acct")}>
            Acct
          </Chip>
          <Chip pressed={kind === "fail"} onClick={() => setKind("fail")}>
            Fail
          </Chip>
        </div>
        <div className="field search-field">
          <label htmlFor={searchId}>Search</label>
          <input
            id={searchId}
            type="search"
            value={search}
            placeholder="User, NAS, or command"
            onChange={(ev) => setSearch(ev.target.value)}
          />
        </div>
      </form>

      {pending ? <p role="status">Loading events…</p> : null}
      <table className="data">
        <caption>Redacted event bodies, newest first</caption>
        <EventTableHead />
        <tbody>
          {items.map((ev) => (
            <EventRow key={String(ev.id)} ev={ev} flash={flashIds.has(ev.id)} />
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

function Chip({
  pressed,
  onClick,
  children,
}: {
  pressed: boolean;
  onClick: () => void;
  children: string;
}) {
  return (
    <button type="button" aria-pressed={pressed} onClick={onClick}>
      {children}
    </button>
  );
}
