import type { EventView } from "../generated/api";
import {
  eventProtocolLabel,
  eventProtocolToken,
  eventResult,
  eventWhat,
  eventWhere,
  eventWho,
  formatEventClock,
  resultTone,
} from "../ui/events";
import { ProtocolBadge } from "./ProtocolBadge";

export function EventTableHead() {
  return (
    <thead>
      <tr>
        <th scope="col">When</th>
        <th scope="col">Who</th>
        <th scope="col">What</th>
        <th scope="col">Where</th>
        <th scope="col">Proto</th>
        <th scope="col">Result</th>
      </tr>
    </thead>
  );
}

export function EventRow({ ev, flash = false }: { ev: EventView; flash?: boolean }) {
  const token = eventProtocolToken(ev);
  const result = eventResult(ev);
  const tone = resultTone(result);
  return (
    <tr className={flash ? "event-row--new" : undefined}>
      <td>
        <time dateTime={ev.time} title={ev.time}>
          {formatEventClock(ev.time)}
        </time>
      </td>
      <td>{eventWho(ev)}</td>
      <td>{eventWhat(ev)}</td>
      <td>{eventWhere(ev)}</td>
      <td>{token !== "" ? <ProtocolBadge protocol={token} label={eventProtocolLabel(token)} /> : "—"}</td>
      <td>
        <span className={`state state--${tone === "pass" ? "on" : tone === "fail" ? "off" : tone}`}>{result}</span>
      </td>
    </tr>
  );
}
