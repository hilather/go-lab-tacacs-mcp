export function RadiusTraceTable({
  evaluator,
  effect,
  groups,
  winner,
  steps,
}: {
  evaluator: string;
  effect?: string | undefined;
  groups?: string[] | undefined;
  winner?: { source: string; rule_id: string; effect: string } | undefined;
  steps: Array<{ source: string; rule_id: string; matched: boolean; reason: string }>;
}) {
  return (
    <>
      <dl className="kv">
        <div>
          <dt>Evaluator</dt>
          <dd>{evaluator}</dd>
        </div>
        <div>
          <dt>Effect</dt>
          <dd>
            <span className={effect === "permit" ? "state state--on" : "state state--off"}>{effect || "—"}</span>
          </dd>
        </div>
        <div>
          <dt>Winner</dt>
          <dd>{winner ? `${winner.source} / ${winner.rule_id} / ${winner.effect}` : "none"}</dd>
        </div>
        <div>
          <dt>Groups</dt>
          <dd>{(groups ?? []).join(", ") || "—"}</dd>
        </div>
      </dl>
      <table className="data">
        <caption>RADIUS policy steps in declared order</caption>
        <thead>
          <tr>
            <th scope="col">Source</th>
            <th scope="col">Rule</th>
            <th scope="col">Matched</th>
            <th scope="col">Reason</th>
          </tr>
        </thead>
        <tbody>
          {steps.map((step, i) => (
            <tr key={`${step.rule_id}-${String(i)}`}>
              <td>{step.source}</td>
              <td>{step.rule_id}</td>
              <td>{step.matched ? "yes" : "no"}</td>
              <td>{step.reason}</td>
            </tr>
          ))}
        </tbody>
      </table>
    </>
  );
}
