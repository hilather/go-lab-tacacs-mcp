import { useQuery } from "@tanstack/react-query";
import { useEffect, useMemo, useState, type ReactNode } from "react";
import { APIError, getBuild, getStatus, hashPrefix, listClients, listTokens } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { EventRow, EventTableHead } from "../components/EventRow";
import { InsecureRadiusBadge, ProtocolBadge, RoleBadge, UDPWarningBadge } from "../components/ProtocolBadge";
import { parseObjectSource, SourceBadge, SourceKey } from "../components/SourceBadge";
import type { BuildInfo, Client, EventView, ListenerStatus, Status } from "../generated/api";
import { useEventStream } from "../hooks/useEventStream";
import { drainRecent, mergeEvent, sortNewestFirst } from "../ui/events";
import {
  isRadiusUDPListener,
  listenerState,
  listenerStateLabel,
  radiusInsecureCompatibility,
  isRadiusTLSListener,
  RADSEC_HINT,
  UDP_DYNAUTH_HINT,
  UDP_RADIUS_HINT,
  warningLooksInsecureRADIUS,
} from "../ui/radius";

function listenerStateClass(state: ReturnType<typeof listenerState>): string {
  switch (state) {
    case "ready":
      return "state state--on";
    case "degraded":
      return "state state--warn";
    default:
      return "state state--off";
  }
}

function hasUDPRadiusListener(status: Status): boolean {
  return status.listeners.some((l) => l.enabled && isRadiusUDPListener(l));
}

function hasDynAuthListener(status: Status): boolean {
  return status.listeners.some(
    (l) => l.enabled && (l.id === "radius_dynauth" || (l.roles ?? []).includes("dynamic_authorization")),
  );
}

function hasInsecureRadius(status: Status, clients: Client[]): boolean {
  if ((status.warnings ?? []).some(warningLooksInsecureRADIUS)) {
    return true;
  }
  return clients.some(radiusInsecureCompatibility);
}

function protocolEntries(build: BuildInfo): Array<[string, BuildInfo["protocols"][string]]> {
  return Object.entries(build.protocols ?? {}).sort(([a], [b]) => a.localeCompare(b));
}

export function DashboardPage() {
  const stream = useEventStream();
  const { hasScope, logout } = useAuth();
  const statusQuery = useQuery({
    queryKey: ["status"],
    queryFn: getStatus,
  });
  const buildQuery = useQuery({
    queryKey: ["build"],
    queryFn: getBuild,
  });
  const eventsQuery = useQuery({
    queryKey: ["events", "status-recent"],
    queryFn: () => drainRecent({}),
    enabled: hasScope("events:read"),
    retry: false,
  });
  const [liveEvents, setLiveEvents] = useState<EventView[]>([]);
  const incoming = stream.lastEvent;
  const [seenEvent, setSeenEvent] = useState(incoming);
  if (incoming !== null && incoming !== seenEvent) {
    setSeenEvent(incoming);
    setLiveEvents((prev) => mergeEvent(prev, incoming));
  }
  const tokensQuery = useQuery({
    queryKey: ["tokens"],
    queryFn: () => listTokens(),
    enabled: hasScope("tokens:manage"),
    retry: false,
  });
  const clientsQuery = useQuery({
    queryKey: ["clients"],
    queryFn: () => listClients({ limit: 200 }),
    enabled: hasScope("state:read"),
    retry: false,
  });
  const recent = useMemo(() => {
    let items = eventsQuery.data?.items ?? [];
    for (const ev of liveEvents) {
      items = mergeEvent(items, ev);
    }
    return sortNewestFirst(items).slice(0, 8);
  }, [eventsQuery.data, liveEvents]);

  useEffect(() => {
    if (statusQuery.error instanceof APIError && statusQuery.error.problem.status === 401) {
      void logout();
    }
  }, [statusQuery.error, logout]);

  if (statusQuery.isPending) {
    return (
      <main className="page">
        <h1>Status</h1>
        <p role="status">Loading snapshot…</p>
      </main>
    );
  }
  if (statusQuery.isError) {
    const detail =
      statusQuery.error instanceof APIError
        ? statusQuery.error.problem.detail
        : "Unable to load status.";
    return (
      <main className="page">
        <h1>Status</h1>
        <div className="error-summary" role="alert">
          <h2>Status unavailable</h2>
          <p>{detail}</p>
        </div>
      </main>
    );
  }

  const status = statusQuery.data.data;
  const build = buildQuery.data?.data;
  const overwritten = eventsQuery.data?.overwritten ?? 0;
  const tokens = tokensQuery.data?.data.items ?? [];
  const clients = clientsQuery.data?.data.items ?? [];
  const udpEnabled = hasUDPRadiusListener(status);
  const dynAuthEnabled = hasDynAuthListener(status);
  const insecureRadius = hasInsecureRadius(status, clients);
  const postureFlags: Array<{ key: string; node: ReactNode }> = [];
  if (status.colocated_topology || status.topology_warning) {
    postureFlags.push({
      key: "topology",
      node: status.topology_warning ?? "Legacy and secure TACACS+ listeners are both enabled.",
    });
  }
  if (udpEnabled) {
    postureFlags.push({
      key: "udp",
      node: (
        <>
          RADIUS UDP <UDPWarningBadge /> {UDP_RADIUS_HINT}
        </>
      ),
    });
  }
  if (dynAuthEnabled) {
    postureFlags.push({ key: "dynauth", node: UDP_DYNAUTH_HINT });
  }
  if (insecureRadius) {
    postureFlags.push({
      key: "insecure",
      node: (
        <>
          <InsecureRadiusBadge /> At least one RADIUS endpoint has Message-Authenticator optional. This compatibility
          mode is for lab interop only and is not a secure RADIUS configuration.
        </>
      ),
    });
  }
  for (const w of status.warnings ?? []) {
    if (warningLooksInsecureRADIUS(w) && insecureRadius) {
      continue;
    }
    postureFlags.push({ key: `warn:${w}`, node: w });
  }

  return (
    <main className="page">
      <h1>Status</h1>
      <p className="visually-hidden" role="status">
        Snapshot revision {String(status.revision)} loaded.
      </p>
      <p className="lede">
        Memory-only overlay. Baseline restored on restart. This is not a highly available production control plane.
      </p>

      <section className="posture" aria-labelledby="lab-posture-heading">
        <h2 id="lab-posture-heading">Lab posture</h2>
        {postureFlags.length === 0 ? (
          <p className="quiet">No extra warnings. Listener badges in the table below are the lab posture.</p>
        ) : (
          <ul>
            {postureFlags.map((flag) => (
              <li key={flag.key}>{flag.node}</li>
            ))}
          </ul>
        )}
      </section>

      <section className="panel" aria-labelledby="listeners-heading">
        <h2 id="listeners-heading">Listeners</h2>
        {status.listeners.some((l) => l.enabled && isRadiusTLSListener(l)) ? (
          <p className="hint">{RADSEC_HINT}</p>
        ) : null}
        <table className="data">
          <caption>Configured listener identity from the published snapshot, with live ready state</caption>
          <thead>
            <tr>
              <th scope="col">ID</th>
              <th scope="col">Protocol</th>
              <th scope="col">Roles</th>
              <th scope="col">Transport</th>
              <th scope="col">Bind</th>
              <th scope="col">State</th>
            </tr>
          </thead>
          <tbody>
            {status.listeners.map((l) => (
              <ListenerRow key={l.id} listener={l} />
            ))}
          </tbody>
        </table>
      </section>

      <section className="panel" aria-labelledby="snapshot-heading">
        <h2 id="snapshot-heading">Effective snapshot</h2>
        <dl className="kv">
          <div>
            <dt>Instance</dt>
            <dd>{status.instance_id || "—"}</dd>
          </div>
          <div>
            <dt>Revision</dt>
            <dd>{String(status.revision)}</dd>
          </div>
          <div>
            <dt>Baseline hash</dt>
            <dd>
              <code>{hashPrefix(status.baseline_hash)}</code>
            </dd>
          </div>
          <div>
            <dt>Overlay hash</dt>
            <dd>
              <code>{hashPrefix(status.overlay_hash)}</code>
            </dd>
          </div>
          <div>
            <dt>Compiled at</dt>
            <dd>{status.compiled_at}</dd>
          </div>
        </dl>
      </section>

      <section className="panel" aria-labelledby="counts-heading">
        <h2 id="counts-heading">Runtime object counts</h2>
        <ul className="counts">
          <li>
            Users <strong>{String(status.users)}</strong>
          </li>
          <li>
            Groups <strong>{String(status.groups)}</strong>
          </li>
          <li>
            Clients <strong>{String(status.clients)}</strong>
          </li>
          <li>
            Tokens <strong>{String(status.tokens)}</strong>
          </li>
        </ul>
        <p>
          Event drops (ring overwritten): <strong>{String(overwritten)}</strong>
        </p>
      </section>

      {hasScope("events:read") ? (
        <section className="panel" aria-labelledby="recent-events-heading">
          <h2 id="recent-events-heading">Recent events</h2>
          <p className="quiet">Newest first. Unfiltered last 8 from the ring plus live SSE.</p>
          {eventsQuery.isError ? (
            <p>Unable to load recent events.</p>
          ) : null}
          <table className="data">
            <caption>Last events, newest first</caption>
            <EventTableHead />
            <tbody>
              {recent.map((ev) => (
                <EventRow key={String(ev.id)} ev={ev} />
              ))}
            </tbody>
          </table>
          {recent.length === 0 && !eventsQuery.isPending ? <p className="quiet">No events in the ring.</p> : null}
        </section>
      ) : null}

      <section className="panel" aria-labelledby="build-heading">
        <h2 id="build-heading">Build</h2>
        {buildQuery.isPending ? <p role="status">Loading build metadata…</p> : null}
        {build ? (
          <dl className="kv">
            <div>
              <dt>Version</dt>
              <dd>{build.version}</dd>
            </div>
            <div>
              <dt>Commit</dt>
              <dd>{build.commit}</dd>
            </div>
            <div>
              <dt>Go</dt>
              <dd>{build.go_version}</dd>
            </div>
            <div>
              <dt>UI</dt>
              <dd>{build.ui_version || "0.0.0"}</dd>
            </div>
            <div>
              <dt>Schema</dt>
              <dd>{String(build.schema_version)}</dd>
            </div>
            <div>
              <dt>TACACS</dt>
              <dd>{build.tacacs_conformance}</dd>
            </div>
            <div>
              <dt>MCP</dt>
              <dd>{build.mcp_specification}</dd>
            </div>
            {protocolEntries(build).map(([name, proto]) => (
              <div key={name}>
                <dt>
                  <ProtocolBadge protocol={name} /> conformance
                </dt>
                <dd>
                  {(proto.standards ?? []).join("; ") || "—"} — {proto.conformance_status}
                  {name === "radius" ? " (not complete RADIUS)" : ""}
                </dd>
              </div>
            ))}
          </dl>
        ) : null}
      </section>

      <SourceKey />

      {tokens.length > 0 ? (
        <section className="panel" aria-labelledby="token-src-heading">
          <h2 id="token-src-heading">Token sources</h2>
          <ul className="token-sources">
            {tokens.map((tok) => {
              const src = parseObjectSource(tok.source);
              return (
                <li key={tok.id}>
                  <code>{tok.id}</code> {src ? <SourceBadge source={src} /> : tok.source}
                </li>
              );
            })}
          </ul>
        </section>
      ) : null}
    </main>
  );
}

function ListenerRow({ listener }: { listener: ListenerStatus }) {
  const state = listenerState(listener);
  const roles = listener.roles ?? [];
  return (
    <tr>
      <th scope="row">{listener.id}</th>
      <td>
        {listener.protocol ? <ProtocolBadge protocol={listener.protocol} /> : "—"}
        {isRadiusUDPListener(listener) ? <UDPWarningBadge /> : null}
      </td>
      <td>
        {roles.length > 0
          ? roles.map((role) => <RoleBadge key={role} role={role} />)
          : "—"}
      </td>
      <td>{listener.transport}</td>
      <td>
        {listener.bind}
        {listener.advertised_port !== undefined ? ` (advertised ${String(listener.advertised_port)})` : ""}
      </td>
      <td>
        <span className={listenerStateClass(state)}>{listenerStateLabel(state)}</span>
        {listener.enabled && (listener.inflight > 0 || listener.queue_depth > 0) ? (
          <span className="hint-inline">
            {" "}
            inflight {String(listener.inflight)} queue {String(listener.queue_depth)}
          </span>
        ) : null}
        {listener.last_error_code ? <span className="hint-inline"> {listener.last_error_code}</span> : null}
      </td>
    </tr>
  );
}
