import { FormEvent, useEffect, useId, useRef, useState } from "react";
import { evaluatePolicy } from "../api/client";
import { ErrorSummary } from "../components/ErrorSummary";
import { RequireScope } from "../components/RequireScope";
import type { EvaluatePolicyRequest, PolicyTrace } from "../generated/api";
import { compact, splitList } from "../ui/constants";
import { errorDetail } from "../ui/errors";

export function PolicyExplainPage() {
  return (
    <RequireScope scope="policy:test">
      <PolicyExplainBody />
    </RequireScope>
  );
}

function PolicyExplainBody() {
  const [userId, setUserId] = useState("");
  const [clientId, setClientId] = useState("");
  const [service, setService] = useState("shell");
  const [protocol, setProtocol] = useState("");
  const [cmd, setCmd] = useState("");
  const [cmdArgs, setCmdArgs] = useState("");
  const [privilege, setPrivilege] = useState("");
  const [messages, setMessages] = useState<string[]>([]);
  const [trace, setTrace] = useState<PolicyTrace | null>(null);
  const [busy, setBusy] = useState(false);
  const summaryRef = useRef<HTMLDivElement>(null);
  const ids = {
    user: useId(),
    client: useId(),
    service: useId(),
    protocol: useId(),
    cmd: useId(),
    args: useId(),
    priv: useId(),
  };

  useEffect(() => {
    if (messages.length > 0) {
      summaryRef.current?.focus();
    }
  }, [messages]);

  async function onSubmit(ev: FormEvent) {
    ev.preventDefault();
    if (userId.trim() === "") {
      setMessages(["Enter a user id."]);
      return;
    }
    setMessages([]);
    setBusy(true);
    try {
      const env = await evaluatePolicy(
        compact<EvaluatePolicyRequest>({
          user_id: userId.trim(),
          client_id: clientId.trim() || undefined,
          service: service.trim(),
          protocol: protocol.trim() || undefined,
          cmd: cmd.trim() || undefined,
          cmd_args: splitList(cmdArgs),
          privilege: privilege === "" ? undefined : Number(privilege),
        }),
      );
      setTrace(env.data);
    } catch (err) {
      setTrace(null);
      setMessages([errorDetail(err, "Policy evaluation failed.")]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="page page--wide">
      <h1>Policy explain</h1>
      <p>
        Calls <code>policy.evaluate</code>. An empty command is a session/service request. A non-empty command uses only
        command rules. Default deny is independent for each evaluator.
      </p>
      <ErrorSummary ref={summaryRef} id="policy-errors" title="Could not evaluate policy" messages={messages} />
      <form className="stack" onSubmit={(e) => void onSubmit(e)} noValidate>
        <div className="rule-grid">
          <div className="field">
            <label htmlFor={ids.user}>User ID</label>
            <input id={ids.user} type="text" value={userId} required onChange={(ev) => setUserId(ev.target.value)} />
          </div>
          <div className="field">
            <label htmlFor={ids.client}>Client ID</label>
            <input id={ids.client} type="text" value={clientId} onChange={(ev) => setClientId(ev.target.value)} />
          </div>
          <div className="field">
            <label htmlFor={ids.service}>Service</label>
            <input id={ids.service} type="text" value={service} onChange={(ev) => setService(ev.target.value)} />
          </div>
          <div className="field">
            <label htmlFor={ids.protocol}>Protocol</label>
            <input id={ids.protocol} type="text" value={protocol} onChange={(ev) => setProtocol(ev.target.value)} />
          </div>
          <div className="field">
            <label htmlFor={ids.cmd}>Command</label>
            <input id={ids.cmd} type="text" value={cmd} onChange={(ev) => setCmd(ev.target.value)} />
          </div>
          <div className="field">
            <label htmlFor={ids.args}>Command arguments</label>
            <input id={ids.args} type="text" value={cmdArgs} onChange={(ev) => setCmdArgs(ev.target.value)} />
          </div>
          <div className="field">
            <label htmlFor={ids.priv}>Privilege</label>
            <input id={ids.priv} type="number" value={privilege} onChange={(ev) => setPrivilege(ev.target.value)} />
          </div>
        </div>
        <button type="submit" disabled={busy}>
          {busy ? "Evaluating…" : "Explain authorization"}
        </button>
      </form>
      {trace ? (
        <section className="panel" aria-labelledby="trace-heading">
          <h2 id="trace-heading">Trace</h2>
          <dl className="kv">
            <div>
              <dt>Evaluator</dt>
              <dd>{trace.evaluator}</dd>
            </div>
            <div>
              <dt>Decision</dt>
              <dd>
                <span className={trace.decision === "deny" ? "state state--off" : "state state--on"}>{trace.decision}</span>
              </dd>
            </div>
            <div>
              <dt>Status</dt>
              <dd>{trace.status}</dd>
            </div>
            <div>
              <dt>Default deny</dt>
              <dd>{trace.default_deny || "—"}</dd>
            </div>
            <div>
              <dt>Winner</dt>
              <dd>
                {trace.winner
                  ? `${trace.winner.source} / ${trace.winner.rule_id} / ${trace.winner.action}`
                  : "none"}
              </dd>
            </div>
            <div>
              <dt>Groups</dt>
              <dd>{trace.effective_group_ids.join(", ") || "—"}</dd>
            </div>
          </dl>
          <table className="data">
            <caption>Evaluation steps in declared order</caption>
            <thead>
              <tr>
                <th scope="col">Source</th>
                <th scope="col">Rule</th>
                <th scope="col">Kind</th>
                <th scope="col">Matched</th>
                <th scope="col">Reason</th>
              </tr>
            </thead>
            <tbody>
              {trace.steps.map((step, i) => (
                <tr key={`${step.rule_id}-${String(i)}`}>
                  <td>{step.source}</td>
                  <td>{step.rule_id}</td>
                  <td>{step.kind}</td>
                  <td>{step.matched ? "yes" : "no"}</td>
                  <td>{step.reason}</td>
                </tr>
              ))}
            </tbody>
          </table>
          {trace.arguments.length > 0 ? (
            <p>
              Reply AVs:{" "}
              {trace.arguments.map((a) => `${a.name}${a.separator}${a.value}`).join(", ")}
            </p>
          ) : null}
        </section>
      ) : null}
    </main>
  );
}
