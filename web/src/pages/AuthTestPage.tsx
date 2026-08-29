import { FormEvent, useEffect, useId, useRef, useState } from "react";
import { testAuthentication } from "../api/client";
import { ErrorSummary } from "../components/ErrorSummary";
import { RequireScope } from "../components/RequireScope";
import type { AuthenticationTestResult, TestAuthenticationRequest } from "../generated/api";
import { AUTH_METHODS, compact } from "../ui/constants";
import { errorDetail } from "../ui/errors";

function authTestStatusClass(status: AuthenticationTestResult["status"]): string {
  if (status === "pass") {
    return "state state--on";
  }
  if (status === "must_change") {
    return "state state--warn";
  }
  return "state state--off";
}

export function AuthTestPage() {
  return (
    <RequireScope scope="policy:test">
      <AuthTestBody />
    </RequireScope>
  );
}

function AuthTestBody() {
  const [userId, setUserId] = useState("");
  const [clientId, setClientId] = useState("");
  const [method, setMethod] = useState("ascii");
  const [password, setPassword] = useState("");
  const [messages, setMessages] = useState<string[]>([]);
  const [result, setResult] = useState<AuthenticationTestResult | null>(null);
  const [busy, setBusy] = useState(false);
  const [announce, setAnnounce] = useState("");
  const passwordRef = useRef<HTMLInputElement>(null);
  const summaryRef = useRef<HTMLDivElement>(null);
  const userField = useId();
  const clientField = useId();
  const methodField = useId();
  const passwordField = useId();
  const passwordHelp = useId();

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
    if (errs.length > 0) {
      setMessages(errs);
      return;
    }
    setMessages([]);
    setBusy(true);
    try {
      const env = await testAuthentication(
        compact<TestAuthenticationRequest>({
          user_id: userId.trim(),
          client_id: clientId.trim() || undefined,
          method,
          password: password === "" ? undefined : password,
        }),
      );
      setResult(env.data);
      setAnnounce(`Authentication test ${env.data.status}.`);
    } catch (err) {
      setResult(null);
      setMessages([errorDetail(err, "Authentication test failed.")]);
    } finally {
      setPassword("");
      if (passwordRef.current) {
        passwordRef.current.value = "";
      }
      setBusy(false);
    }
  }

  return (
    <main className="page">
      <h1>Authentication test</h1>
      <p className="lede">
        Runs <code>authentication.test</code> against the published snapshot. The password is write-only and is cleared
        after submit. Challenge methods need wire <code>data</code> from a TACACS client, not this form. Status{" "}
        <code>must_change</code> means the password verified and a must-change flag is set.
      </p>
      <p className="visually-hidden" role="status">
        {announce}
      </p>
      <ErrorSummary ref={summaryRef} id="auth-test-errors" title="Could not run test" messages={messages} />
      <section className="panel">
      <form className="stack" onSubmit={(e) => void onSubmit(e)} noValidate>
        <div className="field">
          <label htmlFor={userField}>User ID</label>
          <input id={userField} type="text" value={userId} required onChange={(ev) => setUserId(ev.target.value)} />
        </div>
        <div className="field">
          <label htmlFor={clientField}>Client ID (optional)</label>
          <input id={clientField} type="text" value={clientId} onChange={(ev) => setClientId(ev.target.value)} />
        </div>
        <div className="field">
          <label htmlFor={methodField}>Method</label>
          <select id={methodField} value={method} onChange={(ev) => setMethod(ev.target.value)}>
            {AUTH_METHODS.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor={passwordField}>Password</label>
          <input
            ref={passwordRef}
            id={passwordField}
            type="password"
            autoComplete="off"
            value={password}
            aria-describedby={passwordHelp}
            onChange={(ev) => setPassword(ev.target.value)}
          />
          <p id={passwordHelp} className="hint">
            Used for ASCII, PAP, and ENABLE. Cleared from this form after submit. Never stored.
          </p>
        </div>
        <button type="submit" disabled={busy}>
          {busy ? "Testing…" : "Run test"}
        </button>
      </form>
      </section>
      {result ? (
        <section className="panel" aria-labelledby="auth-result-heading">
          <h2 id="auth-result-heading">Result</h2>
          <dl className="kv">
            <div>
              <dt>Status</dt>
              <dd>
                <span className={authTestStatusClass(result.status)}>{result.status}</span>
                {result.status === "must_change" ? (
                  <p className="hint">Password change required after a successful verify. Not a TACACS or RADIUS packet status.</p>
                ) : null}
              </dd>
            </div>
            <div>
              <dt>Method</dt>
              <dd>{result.method}</dd>
            </div>
            <div>
              <dt>User</dt>
              <dd>{result.user_id}</dd>
            </div>
            <div>
              <dt>Client</dt>
              <dd>{result.client_id || "—"}</dd>
            </div>
            <div>
              <dt>ASCII/PAP configured</dt>
              <dd>{result.ascii_pap_configured ? "yes" : "no"}</dd>
            </div>
            <div>
              <dt>Challenge configured</dt>
              <dd>{result.challenge_configured ? "yes" : "no"}</dd>
            </div>
            <div>
              <dt>ENABLE configured</dt>
              <dd>{result.enable_configured ? "yes" : "no"}</dd>
            </div>
          </dl>
        </section>
      ) : null}
    </main>
  );
}
