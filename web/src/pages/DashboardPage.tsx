import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { APIError, getBuild, getStatus, hashPrefix, listClients, listEvents, listTokens } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { InsecureRadiusBadge, ProtocolBadge, RoleBadge, UDPWarningBadge } from "../components/ProtocolBadge";
import { parseObjectSource, SourceBadge, SourceKey } from "../components/SourceBadge";
import type { BuildInfo, Client, ListenerStatus, Status } from "../generated/api";
import { useEventStream } from "../hooks/useEventStream";
import {
  isRadiusUDPListener,
  listenerState,
  listenerStateLabel,
  radiusInsecureCompatibility,
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
  useEventStream();
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
    queryKey: ["events"],
    queryFn: () => listEvents({ limit: 1 }),
    enabled: hasScope("events:read"),
    retry: false,
  });
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
  const overwritten = eventsQuery.data?.data.overwritten ?? 0;
  const tokens = tokensQuery.data?.data.items ?? [];
  const clients = clientsQuery.data?.data.items ?? [];
  const udpEnabled = hasUDPRadiusListener(status);
  const insecureRadius = hasInsecureRadius(status, clients);

  return (
    <main className="page">
      <h1>Status</h1>
      <p className="visually-hidden" role="status">
        Snapshot revision {String(status.revision)} loaded.
      </p>

      <section className="banner" aria-labelledby="lab-banner-heading">
        <h2 id="lab-banner-heading">Lab appliance</h2>
        <p>
          Runtime overlay is memory-only and is discarded on restart. The configured baseline is
          restored. This is not a highly available production control plane.
        </p>
      </section>

      {status.colocated_topology || status.topology_warning ? (
        <section className="banner banner--warn" role="status" aria-labelledby="topo-heading">
          <h2 id="topo-heading">Co-located topology</h2>
          <p>{status.topology_warning ?? "Legacy and secure TACACS+ listeners are both enabled."}</p>
        </section>
      ) : null}

      {udpEnabled ? (
        <section className="banner banner--warn" role="status" aria-labelledby="udp-heading">
          <h2 id="udp-heading">
            RADIUS UDP <UDPWarningBadge />
          </h2>
          <p>{UDP_RADIUS_HINT}</p>
        </section>
      ) : null}

      {insecureRadius ? (
        <section className="banner banner--warn" role="status" aria-labelledby="insecure-radius-heading">
          <h2 id="insecure-radius-heading">
            <InsecureRadiusBadge />
          </h2>
          <p>
            At least one RADIUS endpoint has Message-Authenticator optional. This compatibility mode is
            for lab interop only and is not a secure RADIUS configuration.
          </p>
        </section>
      ) : null}

      {status.warnings && status.warnings.length > 0 ? (
        <section className="banner banner--warn" aria-labelledby="warn-heading">
          <h2 id="warn-heading">Snapshot warnings</h2>
          <ul>
            {status.warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </section>
      ) : null}

      <section className="panel" aria-labelledby="listeners-heading">
        <h2 id="listeners-heading">Listeners</h2>
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
