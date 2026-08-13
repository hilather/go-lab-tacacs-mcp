import { FormEvent, useId, useRef, useState } from "react";
import { useNavigate } from "react-router-dom";
import { z } from "zod";
import { APIError } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { ErrorSummary } from "../components/ErrorSummary";

const schema = z.object({
  token: z.string().trim().min(1, "Enter an API bearer token."),
});

export function LoginPage() {
  const { login } = useAuth();
  const navigate = useNavigate();
  const tokenId = useId();
  const helpId = useId();
  const errorId = useId();
  const summaryId = "login-errors";
  const inputRef = useRef<HTMLInputElement>(null);
  const summaryRef = useRef<HTMLDivElement>(null);
  const [fieldError, setFieldError] = useState("");
  const [formError, setFormError] = useState("");
  const [busy, setBusy] = useState(false);

  async function onSubmit(ev: FormEvent<HTMLFormElement>) {
    ev.preventDefault();
    const fd = new FormData(ev.currentTarget);
    const raw = String(fd.get("token") ?? "");
    const parsed = schema.safeParse({ token: raw });
    if (!parsed.success) {
      const msg = parsed.error.issues[0]?.message ?? "Enter an API bearer token.";
      setFieldError(msg);
      setFormError("");
      summaryRef.current?.focus();
      return;
    }
    setFieldError("");
    setFormError("");
    setBusy(true);
    try {
      await login(parsed.data.token);
      if (inputRef.current) {
        inputRef.current.value = "";
      }
      ev.currentTarget.reset();
      void navigate("/", { replace: true });
    } catch (err) {
      const detail =
        err instanceof APIError
          ? err.problem.detail || "Sign-in failed."
          : "Sign-in failed. Check the token and try again.";
      setFormError(detail);
      summaryRef.current?.focus();
    } finally {
      setBusy(false);
    }
  }

  const messages = [fieldError, formError].filter((m) => m !== "");

  return (
    <main className="page page--narrow">
      <h1>Sign in to TacLab</h1>
      <p>
        Exchange a scoped API token for an HttpOnly session cookie. The token is not written to
        localStorage or sessionStorage.
      </p>
      <div ref={summaryRef}>
        <ErrorSummary id={summaryId} title="Could not sign in" messages={messages} />
      </div>
      <form className="stack" onSubmit={(e) => void onSubmit(e)} noValidate>
        <div className="field">
          <label htmlFor={tokenId}>API bearer token</label>
          <input
            ref={inputRef}
            id={tokenId}
            name="token"
            type="password"
            autoComplete="off"
            autoCapitalize="off"
            spellCheck={false}
            required
            aria-required="true"
            aria-invalid={fieldError !== ""}
            aria-describedby={`${helpId}${fieldError !== "" ? ` ${errorId}` : ""}`}
          />
          <p id={helpId} className="hint">
            The server sets a <code>taclab_session</code> cookie and a CSRF token. Paste the token
            once; it is cleared from this form after submit.
          </p>
          {fieldError !== "" ? (
            <p id={errorId} className="field-error">
              {fieldError}
            </p>
          ) : null}
        </div>
        <button type="submit" disabled={busy}>
          {busy ? "Signing in…" : "Sign in"}
        </button>
      </form>
    </main>
  );
}
