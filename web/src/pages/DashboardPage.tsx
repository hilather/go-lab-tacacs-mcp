import { useQuery } from "@tanstack/react-query";
import { useEffect } from "react";
import { APIError, getBuild, getStatus, hashPrefix, listEvents, listTokens } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { parseObjectSource, SourceBadge, SourceKey } from "../components/SourceBadge";
import { useEventStream } from "../hooks/useEventStream";

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
    queryFn: () => listEvents(1),
    enabled: hasScope("events:read"),
    retry: false,
  });
  const tokensQuery = useQuery({
    queryKey: ["tokens"],
    queryFn: listTokens,
    enabled: hasScope("tokens:manage"),
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
          <caption>Configured listener identity from the published snapshot</caption>
          <thead>
            <tr>
              <th scope="col">ID</th>
              <th scope="col">Transport</th>
              <th scope="col">Bind</th>
              <th scope="col">State</th>
            </tr>
          </thead>
          <tbody>
            {status.listeners.map((l) => (
              <tr key={l.id}>
                <th scope="row">{l.id}</th>
                <td>{l.transport}</td>
                <td>
                  {l.bind}
                  {l.advertised_port !== undefined ? ` (advertised ${String(l.advertised_port)})` : ""}
                </td>
                <td>
                  <span className={l.enabled ? "state state--on" : "state state--off"}>
                    {l.enabled ? "Enabled" : "Disabled"}
                  </span>
                </td>
              </tr>
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
