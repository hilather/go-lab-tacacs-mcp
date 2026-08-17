import { useId, useState } from "react";
import { useQuery } from "@tanstack/react-query";
import { listRadiusAttributes } from "../api/client";
import { RequireScope } from "../components/RequireScope";
import { errorDetail, matchesFilter } from "../ui/errors";

export function RadiusAttributesPage() {
  return (
    <RequireScope scope="state:read">
      <RadiusAttributesBody />
    </RequireScope>
  );
}

function RadiusAttributesBody() {
  const [filter, setFilter] = useState("");
  const filterId = useId();
  const list = useQuery({
    queryKey: ["radius-attributes"],
    queryFn: listRadiusAttributes,
  });
  const items = (list.data?.data.items ?? []).filter((attr) =>
    matchesFilter(filter, [attr.name, attr.source, attr.value_kind, attr.sensitivity, String(attr.code), String(attr.vendor)]),
  );

  return (
    <main className="page page--wide">
      <h1>RADIUS attributes</h1>
      <p>
        Dictionary metadata only. Values and secrets are omitted. <code>source</code> is{" "}
        <code>builtin</code> or <code>operator:&lt;id&gt;</code>. This is not complete RADIUS.
      </p>
      {list.isError ? (
        <div className="error-summary" role="alert">
          <h2>Could not load RADIUS attributes</h2>
          <p>{errorDetail(list.error, "Unable to load RADIUS attributes.")}</p>
        </div>
      ) : null}
      <div className="toolbar">
        <div className="field">
          <label htmlFor={filterId}>Filter</label>
          <input id={filterId} type="search" value={filter} onChange={(ev) => setFilter(ev.target.value)} />
        </div>
      </div>
      {list.isPending ? <p role="status">Loading RADIUS attributes…</p> : null}
      {list.data ? <p className="hint">Dictionary version {list.data.data.version}</p> : null}
      <table className="data">
        <caption>RADIUS dictionary metadata</caption>
        <thead>
          <tr>
            <th scope="col">Name</th>
            <th scope="col">Code</th>
            <th scope="col">Vendor</th>
            <th scope="col">Kind</th>
            <th scope="col">Allowed in</th>
            <th scope="col">Sensitivity</th>
            <th scope="col">Source</th>
          </tr>
        </thead>
        <tbody>
          {items.map((attr) => (
            <tr key={`${attr.source}:${attr.vendor}:${attr.code}:${attr.name}`}>
              <th scope="row">{attr.name}</th>
              <td>{String(attr.code)}</td>
              <td>{String(attr.vendor)}</td>
              <td>{attr.value_kind}</td>
              <td>{(attr.allowed_in ?? []).join(", ") || "—"}</td>
              <td>{attr.sensitivity}</td>
              <td>{attr.source}</td>
            </tr>
          ))}
        </tbody>
      </table>
      {items.length === 0 && !list.isPending ? <p>No RADIUS attributes match the filter.</p> : null}
    </main>
  );
}
