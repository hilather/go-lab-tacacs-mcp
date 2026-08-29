import { useMutation, useQueryClient } from "@tanstack/react-query";
import { useId, useState } from "react";
import { listRadiusSessions, sendRadiusCoA, sendRadiusDisconnect } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ErrorSummary } from "../components/ErrorSummary";
import { RequireScope } from "../components/RequireScope";
import type { RadiusDynamicAuthResult, RadiusSessionView } from "../generated/api";
import { useEventStream } from "../hooks/useEventStream";
import { usePagedList } from "../hooks/usePagedList";
import { DAS_FIXTURE_COPY, UDP_DYNAUTH_HINT } from "../ui/radius";
import { errorDetail, matchesFilter } from "../ui/errors";

type PendingAction = { kind: "coa" | "disconnect"; session: RadiusSessionView };

export function RadiusSessionsPage() {
  return (
    <RequireScope scope="state:read">
      <RadiusSessionsBody />
    </RequireScope>
  );
}

function RadiusSessionsBody() {
  useEventStream();
  const { hasScope } = useAuth();
  const canMutate = hasScope("radius:dynamic");
  const queryClient = useQueryClient();
  const [filter, setFilter] = useState("");
  const [pending, setPending] = useState<PendingAction | null>(null);
  const [result, setResult] = useState<RadiusDynamicAuthResult | null>(null);
  const [messages, setMessages] = useState<string[]>([]);
  const list = usePagedList(["radius-sessions"], (cursor) =>
    listRadiusSessions({ limit: 200, ...(cursor ? { cursor } : {}) }),
  );
  const items = list.items.filter((s) =>
    matchesFilter(filter, [
      s.session_handle,
      s.client_id,
      s.user_id,
      s.endpoint_id,
      s.nas_ip,
      s.nas_identifier,
      s.peer,
      s.acct_session_id,
    ]),
  );
  const filterId = useId();

  const send = useMutation({
    mutationFn: async (action: PendingAction) => {
      const body = { session_handle: action.session.session_handle };
      if (action.kind === "disconnect") {
        return sendRadiusDisconnect(body);
      }
      return sendRadiusCoA(body);
    },
    onSuccess: async (env) => {
      setResult(env.data);
      setPending(null);
      setMessages([]);
      await queryClient.invalidateQueries({ queryKey: ["radius-sessions"] });
    },
    onError: (err) => {
      setResult(null);
      setMessages([errorDetail(err, "Dynamic authorization send failed.")]);
      setPending(null);
    },
  });

  return (
    <main className="page page--wide">
      <h1>RADIUS sessions</h1>
      <p>
        In-memory accounting sessions only. Access-Accept never inserts a row. Restart or{" "}
        <code>runtime.reset</code> wipes the index. This is not complete RADIUS.
      </p>
      <p>{UDP_DYNAUTH_HINT}</p>
      <p className="hint">{DAS_FIXTURE_COPY} DAC CoA and Disconnect always use the client&apos;s UDP RADIUS secret.</p>
      {list.isError ? (
        <div className="error-summary" role="alert">
          <h2>Could not load RADIUS sessions</h2>
          <p>{errorDetail(list.error, "Unable to load RADIUS sessions.")}</p>
        </div>
      ) : null}
      <ErrorSummary id="radius-session-errors" title="Could not send dynamic authorization" messages={messages} />
      {result ? (
        <p role="status">
          Last DAC outcome: <strong>{result.outcome}</strong>
          {result.error_cause !== undefined ? ` (Error-Cause ${String(result.error_cause)})` : ""}
        </p>
      ) : null}
      <div className="toolbar">
        <div className="field">
          <label htmlFor={filterId}>Filter</label>
          <input id={filterId} type="search" value={filter} onChange={(ev) => setFilter(ev.target.value)} />
        </div>
      </div>
      {list.isPending ? <p role="status">Loading RADIUS sessions…</p> : null}
      <table className="data">
        <caption>In-memory RADIUS accounting sessions</caption>
        <thead>
          <tr>
            <th scope="col">Handle</th>
            <th scope="col">Client</th>
            <th scope="col">User</th>
            <th scope="col">Peer</th>
            <th scope="col">NAS</th>
            <th scope="col">Updated</th>
            <th scope="col">Acct-Session-Id</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {items.map((session) => (
            <tr key={session.session_handle}>
              <th scope="row">
                <code>{session.session_handle}</code>
              </th>
              <td>{session.client_id || "—"}</td>
              <td>{session.user_id || "—"}</td>
              <td>{session.peer || "—"}</td>
              <td>
                {session.nas_identifier || session.nas_ip || "—"}
                {session.nas_port !== undefined ? ` :${String(session.nas_port)}` : ""}
              </td>
              <td>{session.last_update || session.started_at || "—"}</td>
              <td>{session.acct_session_id || "—"}</td>
              <td>
                {canMutate ? (
                  <>
                    <button type="button" onClick={() => setPending({ kind: "disconnect", session })}>
                      Disconnect {session.session_handle}
                    </button>{" "}
                    <button type="button" onClick={() => setPending({ kind: "coa", session })}>
                      CoA {session.session_handle}
                    </button>
                  </>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {items.length === 0 && !list.isPending ? <p>No in-memory RADIUS sessions.</p> : null}
      {list.hasMore ? (
        <button type="button" onClick={() => void list.loadMore()}>
          Load more
        </button>
      ) : null}
      {pending ? (
        <ConfirmDialog
          title={
            pending.kind === "disconnect"
              ? `Send Disconnect-Request for ${pending.session.session_handle}?`
              : `Send CoA-Request for ${pending.session.session_handle}?`
          }
          confirmLabel={pending.kind === "disconnect" ? "Send Disconnect" : "Send CoA"}
          busy={send.isPending}
          onCancel={() => setPending(null)}
          onConfirm={() => send.mutate(pending)}
        >
          <p>
            This originates a {pending.kind === "disconnect" ? "Disconnect-Request" : "CoA-Request"} to the NAS
            using the client&apos;s UDP RADIUS secret (DAC). It can disconnect a live session.
          </p>
        </ConfirmDialog>
      ) : null}
    </main>
  );
}
