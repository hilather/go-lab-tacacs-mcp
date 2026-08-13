import { useMutation, useQueryClient } from "@tanstack/react-query";
import { FormEvent, useEffect, useId, useRef, useState } from "react";
import { createToken, isRevisionMismatch, latestRevision, listTokens, newIdempotencyKey, revokeToken } from "../api/client";
import { assertNoTokenStorage } from "../api/storage";
import { useAuth } from "../auth/AuthProvider";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ErrorSummary } from "../components/ErrorSummary";
import { ObjectMeta } from "../components/ObjectMeta";
import { RequireScope } from "../components/RequireScope";
import { RevisionConflict } from "../components/RevisionConflict";
import type { CreateTokenRequest, CreatedToken } from "../generated/api";
import { useEventStream } from "../hooks/useEventStream";
import { usePagedList } from "../hooks/usePagedList";
import { compact, fromDatetimeLocal, SCOPES } from "../ui/constants";
import { errorDetail } from "../ui/errors";

export function TokensPage() {
  return (
    <RequireScope scope="tokens:manage">
      <TokensBody />
    </RequireScope>
  );
}

function TokensBody() {
  useEventStream();
  const { hasScope } = useAuth();
  const queryClient = useQueryClient();
  const canManage = hasScope("tokens:manage");
  const list = usePagedList(["tokens"], (cursor) => listTokens({ limit: 200, ...(cursor ? { cursor } : {}) }));
  const [id, setId] = useState("");
  const [name, setName] = useState("");
  const [scopes, setScopes] = useState<string[]>(["state:read"]);
  const [expires, setExpires] = useState("");
  const [messages, setMessages] = useState<string[]>([]);
  const [conflict, setConflict] = useState<string | null>(null);
  const [once, setOnce] = useState<CreatedToken | null>(null);
  const [acked, setAcked] = useState(false);
  const [revokeId, setRevokeId] = useState<string | null>(null);
  const [announce, setAnnounce] = useState("");
  const tokenInputRef = useRef<HTMLInputElement>(null);
  const summaryRef = useRef<HTMLDivElement>(null);
  const headingId = useId();

  useEffect(() => {
    return () => {
      setOnce(null);
    };
  }, []);

  useEffect(() => {
    if (messages.length > 0 || conflict) {
      summaryRef.current?.focus();
    }
  }, [messages, conflict]);

  function clearOnce() {
    setOnce(null);
    setAcked(true);
    create.reset();
    setAnnounce("One-time token cleared from this page.");
    assertNoTokenStorage();
  }

  const create = useMutation({
    mutationFn: async (revision: number) => {
      assertNoTokenStorage();
      return createToken(
        compact<CreateTokenRequest>({
          id: id.trim(),
          name: name.trim(),
          scopes,
          expires_at: fromDatetimeLocal(expires),
        }),
        revision,
        newIdempotencyKey(),
      );
    },
    onSuccess: async (env) => {
      setId("");
      setName("");
      setExpires("");
      setMessages([]);
      setConflict(null);
      setAcked(false);
      setOnce(env.data);
      setAnnounce("Token created. Copy the value now; it will not be shown again.");
      assertNoTokenStorage();
      queueMicrotask(() => {
        create.reset();
      });
      await queryClient.invalidateQueries({ queryKey: ["tokens"] });
    },
    onError: (err) => {
      if (isRevisionMismatch(err)) {
        setConflict(errorDetail(err, "expected revision does not match published snapshot"));
        return;
      }
      setMessages([errorDetail(err, "Create failed.")]);
    },
  });

  const revoke = useMutation({
    mutationFn: async (args: { id: string; revision: number }) => revokeToken(args.id, args.revision, false),
    onSuccess: async () => {
      setRevokeId(null);
      setAnnounce("Token revoked.");
      await queryClient.invalidateQueries({ queryKey: ["tokens"] });
    },
    onError: (err) => {
      setRevokeId(null);
      if (isRevisionMismatch(err)) {
        setConflict(errorDetail(err, "expected revision does not match published snapshot"));
        return;
      }
      setMessages([errorDetail(err, "Revoke failed.")]);
    },
  });

  function onSubmit(ev: FormEvent) {
    ev.preventDefault();
    const errs: string[] = [];
    if (name.trim() === "") {
      errs.push("Enter a token name.");
    }
    if (scopes.length === 0) {
      errs.push("Select at least one scope.");
    }
    if (errs.length > 0) {
      setMessages(errs);
      return;
    }
    create.mutate(list.revision);
  }

  async function copyToken() {
    const value = once?.token;
    if (!value) {
      return;
    }
    try {
      await navigator.clipboard.writeText(value);
      setAnnounce("Token copied to clipboard. Acknowledge when you have stored it elsewhere.");
    } catch {
      tokenInputRef.current?.select();
      setAnnounce("Select and copy the token from the field. It is not stored in the browser.");
    }
    assertNoTokenStorage();
  }

  return (
    <main className="page page--wide">
      <h1>API tokens</h1>
      <p>
        The bearer is returned once. It is never written to localStorage or sessionStorage. After you acknowledge, this
        page forgets the value.
      </p>
      <p className="visually-hidden" role="status">
        {announce}
      </p>
      <ErrorSummary ref={summaryRef} id="token-errors" title="Token action failed" messages={messages} />
      {conflict ? (
        <RevisionConflict
          detail={conflict}
          onReload={() => {
            setConflict(null);
          }}
          onRetry={() => {
            void latestRevision().then((revision) => {
              create.mutate(revision);
            });
          }}
        />
      ) : null}

      {once && !acked ? (
        <section className="banner banner--warn" aria-labelledby="once-heading">
          <h2 id="once-heading">Copy this token now</h2>
          <p>This is the only time TacLab will display the bearer. Store it in your secret manager, then acknowledge.</p>
          <div className="field">
            <label htmlFor="once-token">One-time bearer token</label>
            <input ref={tokenInputRef} id="once-token" type="text" readOnly value={once.token} autoComplete="off" />
          </div>
          <div className="actions">
            <button type="button" onClick={() => void copyToken()}>
              Copy token
            </button>
            <button type="button" onClick={clearOnce}>
              I have copied the token
            </button>
          </div>
        </section>
      ) : null}

      {canManage ? (
        <section className="panel" aria-labelledby={headingId}>
          <h2 id={headingId}>Create token</h2>
          <form className="stack" onSubmit={onSubmit} noValidate>
            <div className="field">
              <label htmlFor="tok-id">Token ID (optional)</label>
              <input id="tok-id" type="text" value={id} onChange={(ev) => setId(ev.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="tok-name">Name</label>
              <input id="tok-name" type="text" value={name} required onChange={(ev) => setName(ev.target.value)} />
            </div>
            <div className="field">
              <label htmlFor="tok-exp">Expires</label>
              <input id="tok-exp" type="datetime-local" value={expires} onChange={(ev) => setExpires(ev.target.value)} />
            </div>
            <fieldset className="fieldset">
              <legend>Scopes</legend>
              {SCOPES.map((scope) => (
                <label key={scope} className="check">
                  <input
                    type="checkbox"
                    checked={scopes.includes(scope)}
                    onChange={(ev) => {
                      setScopes(ev.target.checked ? [...scopes, scope] : scopes.filter((s) => s !== scope));
                    }}
                  />
                  {scope}
                </label>
              ))}
            </fieldset>
            <button type="submit" disabled={create.isPending}>
              {create.isPending ? "Creating…" : "Create token"}
            </button>
          </form>
        </section>
      ) : null}

      {list.isPending ? <p role="status">Loading tokens…</p> : null}
      <table className="data">
        <caption>Token metadata (no secret values)</caption>
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Name</th>
            <th scope="col">Source</th>
            <th scope="col">Scopes</th>
            <th scope="col">Expires</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {list.items.map((tok) => (
            <tr key={tok.id}>
              <th scope="row">
                <code>{tok.id}</code>
              </th>
              <td>{tok.name || tok.display_name || "—"}</td>
              <td>
                <ObjectMeta source={tok.source} deleted={tok.deleted} shadows={tok.shadows_source} />
              </td>
              <td>{tok.scopes.join(", ")}</td>
              <td>{tok.expires_at || "none"}</td>
              <td>
                {canManage && tok.source === "runtime" && !tok.deleted ? (
                  <button type="button" className="danger" onClick={() => setRevokeId(tok.id)}>
                    Revoke {tok.id}
                  </button>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {list.hasMore ? (
        <button type="button" onClick={() => void list.loadMore()}>
          Load more
        </button>
      ) : null}

      {revokeId ? (
        <ConfirmDialog
          title="Revoke this token?"
          confirmLabel="Revoke token"
          busy={revoke.isPending}
          onCancel={() => setRevokeId(null)}
          onConfirm={() => revoke.mutate({ id: revokeId, revision: list.revision })}
        >
          <p>
            Revoking <code>{revokeId}</code> immediately rejects that bearer. Sessions already issued from it stay until
            they expire or you sign out.
          </p>
        </ConfirmDialog>
      ) : null}
    </main>
  );
}
