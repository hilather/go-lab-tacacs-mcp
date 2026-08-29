import { useQuery } from "@tanstack/react-query";
import { getBuild, getStatus } from "../api/client";
import { ProtocolBadge } from "../components/ProtocolBadge";
import { RequireScope } from "../components/RequireScope";
import { errorDetail } from "../ui/errors";

export function AboutPage() {
  return (
    <RequireScope scope="state:read">
      <AboutBody />
    </RequireScope>
  );
}

function AboutBody() {
  const build = useQuery({ queryKey: ["build"], queryFn: getBuild });
  const status = useQuery({ queryKey: ["status"], queryFn: getStatus });
  const info = build.data?.data;
  return (
    <main className="page">
      <h1>About</h1>
      <p className="lede">Build metadata and specification versions. This is a lab appliance, not a complete TACACS+ claim.</p>
      {build.isError ? (
        <div className="error-summary" role="alert">
          <h2>Build unavailable</h2>
          <p>{errorDetail(build.error, "Unable to load build metadata.")}</p>
        </div>
      ) : null}
      {build.isPending ? <p role="status">Loading build metadata…</p> : null}
      {info ? (
        <section className="panel" aria-labelledby="about-build-heading">
        <h2 id="about-build-heading" className="visually-hidden">Build</h2>
        <dl className="kv">
          <div>
            <dt>Version</dt>
            <dd>{info.version}</dd>
          </div>
          <div>
            <dt>Commit</dt>
            <dd>{info.commit}</dd>
          </div>
          <div>
            <dt>Build time</dt>
            <dd>{info.build_time}</dd>
          </div>
          <div>
            <dt>Go</dt>
            <dd>{info.go_version}</dd>
          </div>
          <div>
            <dt>UI</dt>
            <dd>{info.ui_version || "0.0.0"}</dd>
          </div>
          <div>
            <dt>Config schema</dt>
            <dd>{String(info.schema_version)}</dd>
          </div>
          <div>
            <dt>TACACS conformance</dt>
            <dd>{info.tacacs_conformance}</dd>
          </div>
          <div>
            <dt>MCP specification</dt>
            <dd>{info.mcp_specification}</dd>
          </div>
          {Object.entries(info.protocols ?? {})
            .sort(([a], [b]) => a.localeCompare(b))
            .map(([name, proto]) => (
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
          <div>
            <dt>Snapshot revision</dt>
            <dd>{status.data ? String(status.data.data.revision) : "—"}</dd>
          </div>
        </dl>
        </section>
      ) : null}
    </main>
  );
}
