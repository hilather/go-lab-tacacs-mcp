export type ObjectSource = "config" | "runtime" | "override";

const LABELS: Record<ObjectSource, string> = {
  config: "CONFIG",
  runtime: "RUNTIME",
  override: "OVERRIDE",
};

const DESCRIPTIONS: Record<ObjectSource, string> = {
  config: "Baseline configuration object",
  runtime: "Ephemeral runtime object; removed on restart",
  override: "Baseline object with a runtime overlay",
};

export function parseObjectSource(raw: string): ObjectSource | null {
  switch (raw) {
    case "config":
    case "runtime":
    case "override":
      return raw;
    default:
      return null;
  }
}

export function SourceBadge({ source }: { source: ObjectSource }) {
  return (
    <span className={`source-badge source-badge--${source}`} title={DESCRIPTIONS[source]}>
      <span className="source-badge__mark" aria-hidden="true" />
      <span className="source-badge__label">{LABELS[source]}</span>
      <span className="visually-hidden"> ({DESCRIPTIONS[source]})</span>
    </span>
  );
}

export function SourceKey() {
  return (
    <section className="panel" aria-labelledby="source-key-heading">
      <h2 id="source-key-heading">Source badges</h2>
      <ul className="source-key">
        {(["config", "runtime", "override"] as const).map((source) => (
          <li key={source}>
            <SourceBadge source={source} /> {DESCRIPTIONS[source]}
          </li>
        ))}
      </ul>
    </section>
  );
}
