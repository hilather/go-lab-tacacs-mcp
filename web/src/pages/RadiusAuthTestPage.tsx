import { FormEvent, useEffect, useId, useRef, useState } from "react";
import { testRadiusAccess } from "../api/client";
import { ErrorSummary } from "../components/ErrorSummary";
import { RadiusTraceTable } from "../components/RadiusTraceTable";
import { RequireScope } from "../components/RequireScope";
import type { RadiusAccessTestRequest, RadiusAccessTestResult, RadiusAuthMethod } from "../generated/api";
import { compact, RADIUS_AUTH_METHODS } from "../ui/constants";
import { errorDetail } from "../ui/errors";
import { formatRadiusAttr, parseAttributeLines } from "../ui/radius";

function methodSecretLabel(method: (typeof RADIUS_AUTH_METHODS)[number], suffix: string): string {
  switch (method) {
    case "chap":
      return `CHAP ${suffix}`;
    case "mschapv1":
      return `MS-CHAPv1 ${suffix}`;
    case "mschapv2":
      return `MS-CHAPv2 ${suffix}`;
    case "eap":
      return suffix.startsWith("identifier") ? "EAP identifier (optional)" : `EAP ${suffix}`;
    default:
      return `${method} ${suffix}`;
  }
}

export function RadiusAuthTestPage() {
  return (
    <RequireScope scope="policy:test">
      <RadiusAuthTestBody />
    </RequireScope>
  );
}

function RadiusAuthTestBody() {
  const [userId, setUserId] = useState("");
  const [clientId, setClientId] = useState("");
  const [method, setMethod] = useState<(typeof RADIUS_AUTH_METHODS)[number]>("pap");
  const [password, setPassword] = useState("");
  const [chapId, setChapId] = useState("1");
  const [challenge, setChallenge] = useState("");
  const [response, setResponse] = useState("");
  const [attrLines, setAttrLines] = useState("");
  const [explain, setExplain] = useState(true);
  const [messages, setMessages] = useState<string[]>([]);
  const [result, setResult] = useState<RadiusAccessTestResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [announce, setAnnounce] = useState("");
  const passwordRef = useRef<HTMLInputElement>(null);
  const challengeRef = useRef<HTMLInputElement>(null);
  const responseRef = useRef<HTMLInputElement>(null);
  const summaryRef = useRef<HTMLDivElement>(null);
  const ids = {
    user: useId(),
    client: useId(),
    method: useId(),
    password: useId(),
    passwordHelp: useId(),
    chapId: useId(),
    challenge: useId(),
    challengeHelp: useId(),
    response: useId(),
    responseHelp: useId(),
    attrs: useId(),
    attrsHelp: useId(),
  };

  useEffect(() => {
    if (messages.length > 0) {
      summaryRef.current?.focus();
    }
  }, [messages]);

  function wipeSecrets() {
    setPassword("");
    setChallenge("");
    setResponse("");
    if (passwordRef.current) {
      passwordRef.current.value = "";
    }
    if (challengeRef.current) {
      challengeRef.current.value = "";
    }
    if (responseRef.current) {
      responseRef.current.value = "";
    }
  }

  async function onSubmit(ev: FormEvent) {
    ev.preventDefault();
    const errs: string[] = [];
    if (userId.trim() === "") {
      errs.push("Enter a user id.");
    }
    let authMethod: RadiusAuthMethod;
    if (method === "pap") {
      authMethod = compact<RadiusAuthMethod>({
        type: "pap",
        password: password === "" ? undefined : password,
      });
    } else if (method === "eap") {
      const id = Number(chapId);
      if (chapId.trim() !== "" && (!Number.isInteger(id) || id < 0 || id > 255)) {
        errs.push("EAP identifier must be an integer from 0 to 255.");
      }
      authMethod = compact<RadiusAuthMethod>({
        type: "eap",
        id: chapId.trim() === "" ? undefined : id,
        challenge: challenge === "" ? undefined : challenge,
        response: response === "" ? undefined : response,
      });
    } else {
      const id = Number(chapId);
      if (!Number.isInteger(id) || id < 0 || id > 255) {
        errs.push("Challenge identifier must be an integer from 0 to 255.");
      }
      authMethod = compact<RadiusAuthMethod>({
        type: method,
        id,
        challenge: challenge === "" ? undefined : challenge,
        response: response === "" ? undefined : response,
      });
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
      const env = await testRadiusAccess(
        compact<RadiusAccessTestRequest>({
          user_id: userId.trim(),
          client_id: clientId.trim() || undefined,
          method: authMethod,
          request_attributes: parsed.attrs.length > 0 ? parsed.attrs : undefined,
          explain,
        }),
      );
      setResult(env.data);
      setAnnounce(`RADIUS access test ${env.data.outcome}.`);
    } catch (err) {
      setResult(null);
      setMessages([errorDetail(err, "RADIUS access test failed.")]);
    } finally {
      wipeSecrets();
      setBusy(false);
    }
  }

  return (
    <main className="page">
      <h1>RADIUS authentication test</h1>
      <p>
        Runs <code>radius.access.test</code> against the published snapshot using the same access path as UDP. PAP,
        CHAP, MS-CHAP, and EAP secrets are write-only and are cleared after submit. Challenge outcomes show{" "}
        <code>state_present</code> only — never State bytes or EAP payload. This is not complete RADIUS.
      </p>
      <p className="visually-hidden" role="status">
        {announce}
      </p>
      <ErrorSummary ref={summaryRef} id="radius-auth-test-errors" title="Could not run RADIUS test" messages={messages} />
      <form className="stack" onSubmit={(e) => void onSubmit(e)} noValidate>
        <div className="field">
          <label htmlFor={ids.user}>User ID</label>
          <input id={ids.user} type="text" value={userId} required onChange={(ev) => setUserId(ev.target.value)} />
        </div>
        <div className="field">
          <label htmlFor={ids.client}>Client ID (optional)</label>
          <input id={ids.client} type="text" value={clientId} onChange={(ev) => setClientId(ev.target.value)} />
        </div>
        <div className="field">
          <label htmlFor={ids.method}>Method</label>
          <select
            id={ids.method}
            value={method}
            onChange={(ev) => setMethod(ev.target.value as (typeof RADIUS_AUTH_METHODS)[number])}
          >
            {RADIUS_AUTH_METHODS.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </div>
        {method === "pap" ? (
          <div className="field">
            <label htmlFor={ids.password}>Password</label>
            <input
              ref={passwordRef}
              id={ids.password}
              type="password"
              autoComplete="off"
              value={password}
              aria-describedby={ids.passwordHelp}
              onChange={(ev) => setPassword(ev.target.value)}
            />
            <p id={ids.passwordHelp} className="hint">
              Write-only PAP password. Cleared from this form after submit. Never stored.
            </p>
          </div>
        ) : (
          <>
            <div className="field">
              <label htmlFor={ids.chapId}>{methodSecretLabel(method, "identifier")}</label>
              <input
                id={ids.chapId}
                type="number"
                min={0}
                max={255}
                value={chapId}
                onChange={(ev) => setChapId(ev.target.value)}
              />
            </div>
            <div className="field">
              <label htmlFor={ids.challenge}>{methodSecretLabel(method, "challenge (base64)")}</label>
              <input
                ref={challengeRef}
                id={ids.challenge}
                type="password"
                autoComplete="off"
                spellCheck={false}
                value={challenge}
                aria-describedby={ids.challengeHelp}
                onChange={(ev) => setChallenge(ev.target.value)}
              />
              <p id={ids.challengeHelp} className="hint">
                Write-only. Cleared after submit.
                {method === "eap" ? " Omit challenge and response for EAP Identity (access_challenge)." : ""}
              </p>
            </div>
            <div className="field">
              <label htmlFor={ids.response}>{methodSecretLabel(method, "response (base64)")}</label>
              <input
                ref={responseRef}
                id={ids.response}
                type="password"
                autoComplete="off"
                spellCheck={false}
                value={response}
                aria-describedby={ids.responseHelp}
                onChange={(ev) => setResponse(ev.target.value)}
              />
              <p id={ids.responseHelp} className="hint">
                Write-only. Cleared after submit.
              </p>
            </div>
          </>
        )}
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
            Optional dictionary names, one <code>Name=value</code> per line. The server evaluates policy; this form
            does not.
          </p>
        </div>
        <label className="check">
          <input type="checkbox" checked={explain} onChange={(ev) => setExplain(ev.target.checked)} />
          Include policy trace
        </label>
        <button type="submit" disabled={busy}>
          {busy ? "Testing…" : "Run RADIUS test"}
        </button>
      </form>
      {result ? (
        <section className="panel" aria-labelledby="radius-auth-result-heading">
          <h2 id="radius-auth-result-heading">Result</h2>
          <dl className="kv">
            <div>
              <dt>Outcome</dt>
              <dd>
                <span className={result.outcome === "access_accept" ? "state state--on" : "state state--off"}>
                  {result.outcome}
                </span>
              </dd>
            </div>
            <div>
              <dt>Reason</dt>
              <dd>{result.reason_code}</dd>
            </div>
            {result.outcome === "access_challenge" ? (
              <div>
                <dt>Challenge state</dt>
                <dd>{result.state_present ? "present" : "absent"}</dd>
              </div>
            ) : null}
          </dl>
          {result.reply_attributes.length > 0 ? (
            <p>Reply attributes: {result.reply_attributes.map(formatRadiusAttr).join(", ")}</p>
          ) : null}
          {result.trace ? (
            <RadiusTraceTable
              evaluator={result.trace.evaluator}
              effect={result.trace.effect}
              groups={result.trace.groups}
              winner={result.trace.winner}
              steps={result.trace.steps}
            />
          ) : null}
        </section>
      ) : null}
    </main>
  );
}
