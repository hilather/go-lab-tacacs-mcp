import { parseObjectSource, SourceBadge } from "./SourceBadge";

export function ObjectMeta({
  source,
  deleted,
  shadows,
  revision,
}: {
  source: string;
  deleted?: boolean | undefined;
  shadows?: string | undefined;
  revision?: number | undefined;
}) {
  const parsed = parseObjectSource(source);
  return (
    <span className="object-meta">
      {parsed ? <SourceBadge source={parsed} /> : source}
      {deleted ? (
        <span className="state state--off" title="Tombstone; hidden unless include_deleted">
          Deleted
        </span>
      ) : null}
      {source === "runtime" && !deleted ? (
        <span className="hint-inline">Removed on restart</span>
      ) : null}
      {source === "override" ? (
        <span className="hint-inline">
          Shadows {shadows && shadows !== "" ? shadows : "baseline"}
        </span>
      ) : null}
      {revision !== undefined ? <span className="hint-inline">rev {String(revision)}</span> : null}
    </span>
  );
}
