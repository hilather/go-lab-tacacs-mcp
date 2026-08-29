import { FormEvent, useEffect, useId, useRef, useState } from "react";
import { evaluateRadiusPolicy } from "../api/client";
import { ErrorSummary } from "../components/ErrorSummary";
import { RequireScope } from "../components/RequireScope";
import type { RadiusPolicyEvaluateRequest, RadiusPolicyEvaluateResult } from "../generated/api";
import { compact, RADIUS_AUTH_METHODS } from "../ui/constants";
import { errorDetail } from "../ui/errors";
import { RadiusTraceTable } from "../components/RadiusTraceTable";
import { formatRadiusAttr, parseAttributeLines } from "../ui/radius";

export function RadiusExplainPage() {
  return (
    <RequireScope scope="policy:test">
      <RadiusExplainBody />
    </RequireScope>
  );
}

function RadiusExplainBody() {
  const [userId, setUserId] = useState("");
  const [clientId, setClientId] = useState("");
  const [endpointId, setEndpointId] = useState("");
  const [method, setMethod] = useState<(typeof RADIUS_AUTH_METHODS)[number] | "">("pap");
  const [attrLines, setAttrLines] = useState("");
  const [messages, setMessages] = useState<string[]>([]);
  const [result, setResult] = useState<RadiusPolicyEvaluateResult | null>(null);
  const [busy, setBusy] = useState(false);
  const summaryRef = useRef<HTMLDivElement>(null);
  const ids = {
    user: useId(),
    client: useId(),
    endpoint: useId(),
    method: useId(),
    attrs: useId(),
    attrsHelp: useId(),
  };

  useEffect(() => {
    if (messages.length > 0) {
      summaryRef.current?.focus();
    }
  }, [messages]);

  async function onSubmit(ev: FormEvent) {
    ev.preventDefault();
    const errs: string[] = [];
    if (userId.trim() === "") {
      errs.push("Enter a user id.");
    }
    const parsed = parseAttributeLines(attrLines);
    if (parsed.error) {
      errs.push(parsed.error);
    }
    if (errs.length > 0) {
      setMessages(errs);
      return;
    }
    setMessages([]);
    setBusy(true);
    try {
      const env = await evaluateRadiusPolicy(
        compact<RadiusPolicyEvaluateRequest>({
          user_id: userId.trim(),
          client_id: clientId.trim() || undefined,
          endpoint_id: endpointId.trim() || undefined,
          method: method === "" ? undefined : method,
          request_attributes: parsed.attrs.length > 0 ? parsed.attrs : undefined,
        }),
      );
      setResult(env.data);
    } catch (err) {
      setResult(null);
      setMessages([errorDetail(err, "RADIUS policy evaluation failed.")]);
    } finally {
      setBusy(false);
    }
  }

  return (
    <main className="page page--wide">
      <h1>RADIUS policy explain</h1>
      <p className="lede">
        Calls <code>radius.policy.evaluate</code> on the compiled RADIUS engine. The UI does not evaluate policy. This
        is not complete RADIUS.
      </p>
      <ErrorSummary ref={summaryRef} id="radius-policy-errors" title="Could not evaluate RADIUS policy" messages={messages} />
      <section className="panel">
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
            <label htmlFor={ids.endpoint}>Endpoint ID</label>
            <input id={ids.endpoint} type="text" value={endpointId} onChange={(ev) => setEndpointId(ev.target.value)} />
          </div>
          <div className="field">
            <label htmlFor={ids.method}>Method</label>
            <select
              id={ids.method}
              value={method}
              onChange={(ev) => setMethod(ev.target.value as (typeof RADIUS_AUTH_METHODS)[number] | "")}
            >
              <option value="">Any</option>
              {RADIUS_AUTH_METHODS.map((m) => (
                <option key={m} value={m}>
                  {m}
                </option>
              ))}
            </select>
          </div>
        </div>
        <div className="field">
          <label htmlFor={ids.attrs}>Request attributes</label>
          <textarea
            id={ids.attrs}
            rows={4}
            value={attrLines}
            aria-describedby={ids.attrsHelp}
            onChange={(ev) => setAttrLines(ev.target.value)}
          />
          <p id={ids.attrsHelp} className="hint">
            Optional dictionary names, one <code>Name=value</code> per line.
          </p>
        </div>
        <button type="submit" disabled={busy}>
          {busy ? "Evaluating…" : "Explain RADIUS policy"}
        </button>
      </form>
      </section>
      {result ? (
        <section className="panel" aria-labelledby="radius-trace-heading">
          <h2 id="radius-trace-heading">Trace</h2>
          <dl className="kv">
            <div>
              <dt>Effect</dt>
              <dd>
                <span className={result.effect === "permit" ? "state state--on" : "state state--off"}>
                  {result.effect}
                </span>
              </dd>
            </div>
            <div>
              <dt>Reason</dt>
              <dd>{result.reason_code}</dd>
            </div>
          </dl>
          {result.reply_attributes.length > 0 ? (
            <p>Reply attributes: {result.reply_attributes.map(formatRadiusAttr).join(", ")}</p>
          ) : null}
          <RadiusTraceTable
            evaluator={result.trace.evaluator}
            effect={result.trace.effect ?? result.effect}
            groups={result.trace.groups ?? []}
            winner={result.trace.winner}
            steps={result.trace.steps}
          />
        </section>
      ) : null}
    </main>
  );
}
