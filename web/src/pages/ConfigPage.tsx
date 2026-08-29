import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FormEvent, useEffect, useId, useRef, useState } from "react";
import {
  exportConfig,
  getEffectiveConfig,
  isRevisionMismatch,
  latestRevision,
  listClients,
  listGroups,
  listUsers,
  newIdempotencyKey,
  reloadConfig,
  resetRuntime,
  validateConfig,
} from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ErrorSummary } from "../components/ErrorSummary";
import { ObjectMeta } from "../components/ObjectMeta";
import { RequireScope } from "../components/RequireScope";
import { RevisionConflict } from "../components/RevisionConflict";
import { useEventStream } from "../hooks/useEventStream";
import type { Envelope } from "../generated/api";
import { CONFIG_VIEWS } from "../ui/constants";
import { errorDetail } from "../ui/errors";

async function drainObjects<T>(
  fetchPage: (cursor?: string) => Promise<Envelope<{ items: T[]; next_cursor?: string }>>,
): Promise<T[]> {
  const all: T[] = [];
  let cursor: string | undefined;
  for (let i = 0; i < 64; i += 1) {
    const env = await fetchPage(cursor);
    all.push(...env.data.items);
    if (!env.data.next_cursor) {
      break;
    }
    cursor = env.data.next_cursor;
  }
  return all;
}

export function ConfigPage() {
  return (
    <RequireScope scope="state:read">
      <ConfigBody />
    </RequireScope>
  );
}

function ConfigBody() {
  useEventStream();
  const { hasScope } = useAuth();
  const queryClient = useQueryClient();
  const canExport = hasScope("config:export");
  const canReload = hasScope("config:reload");
  const canValidate = hasScope("state:write");
  const canReset = hasScope("runtime:reset");
  const [view, setView] = useState("effective");
  const [yaml, setYaml] = useState("");
  const [messages, setMessages] = useState<string[]>([]);
  const [conflict, setConflict] = useState<string | null>(null);
  const [announce, setAnnounce] = useState("");
  const [confirm, setConfirm] = useState<"reload" | "reset" | null>(null);
  const [failedAction, setFailedAction] = useState<"reload" | "reset" | null>(null);
  const summaryRef = useRef<HTMLDivElement>(null);
  const viewId = useId();
  const yamlId = useId();

  const effective = useQuery({
    queryKey: ["config", "effective", view],
    queryFn: () => getEffectiveConfig(view),
  });
  const exported = useQuery({
    queryKey: ["config", "export", view],
    queryFn: () => exportConfig(view),
    enabled: canExport,
  });
  const tombstones = useQuery({
    queryKey: ["config", "tombstones"],
    queryFn: async () => {
      const [users, groups, clients] = await Promise.all([
        drainObjects((cursor) => listUsers({ include_deleted: true, limit: 200, ...(cursor ? { cursor } : {}) })),
        drainObjects((cursor) => listGroups({ include_deleted: true, limit: 200, ...(cursor ? { cursor } : {}) })),
        drainObjects((cursor) => listClients({ include_deleted: true, limit: 200, ...(cursor ? { cursor } : {}) })),
      ]);
      return {
        users: users.filter((u) => u.deleted || u.source === "override" || u.source === "runtime"),
        groups: groups.filter((g) => g.deleted || g.source === "override" || g.source === "runtime"),
        clients: clients.filter((c) => c.deleted || c.source === "override" || c.source === "runtime"),
      };
    },
  });

  useEffect(() => {
    if (messages.length > 0 || conflict) {
      summaryRef.current?.focus();
    }
  }, [messages, conflict]);

  const validate = useMutation({
    mutationFn: () => validateConfig({ yaml }),
    onSuccess: (env) => {
      if (env.data.valid) {
        setMessages([]);
        setAnnounce("Candidate YAML is valid. Validate does not publish state.");
      } else {
        setMessages((env.data.errors ?? []).map((e) => `${e.code}${e.path ? ` ${e.path}` : ""}: ${e.message}`));
      }
    },
    onError: (err) => {
      setMessages([errorDetail(err, "Validate failed.")]);
    },
  });

  const reload = useMutation({
    mutationFn: (revision: number) => reloadConfig(revision, newIdempotencyKey()),
    onSuccess: async (env) => {
      setConfirm(null);
      setFailedAction(null);
      setConflict(null);
      setAnnounce(`Reloaded baseline. Revision ${String(env.data.revision)}.`);
      await queryClient.invalidateQueries();
    },
    onError: (err) => {
      setConfirm(null);
      if (isRevisionMismatch(err)) {
        setFailedAction("reload");
        setConflict(errorDetail(err, "expected revision does not match published snapshot"));
        return;
      }
      setMessages([errorDetail(err, "Reload failed. The previous snapshot is still active.")]);
    },
  });

  const reset = useMutation({
    mutationFn: (revision: number) => resetRuntime(revision, newIdempotencyKey()),
    onSuccess: async (env) => {
      setConfirm(null);
      setFailedAction(null);
      setConflict(null);
      setAnnounce(`Runtime overlay reset. Revision ${String(env.data.revision)}.`);
      await queryClient.invalidateQueries();
    },
    onError: (err) => {
      setConfirm(null);
      if (isRevisionMismatch(err)) {
        setFailedAction("reset");
        setConflict(errorDetail(err, "expected revision does not match published snapshot"));
        return;
      }
      setMessages([errorDetail(err, "Reset failed. The previous snapshot is still active.")]);
    },
  });

  function onValidate(ev: FormEvent) {
    ev.preventDefault();
    setMessages([]);
    validate.mutate();
  }

  return (
    <main className="page page--wide">
      <h1>Config and runtime</h1>
      <p className="lede">
        The YAML baseline is immutable at runtime. Overlay objects are memory-only. Invalid reload or reset candidates
        keep the published snapshot.
      </p>
      <p className="visually-hidden" role="status">
        {announce}
      </p>
      <ErrorSummary ref={summaryRef} id="config-errors" title="Config action failed" messages={messages} />
      {conflict ? (
        <RevisionConflict
          detail={conflict}
          onReload={() => {
            void effective.refetch();
            setConflict(null);
          }}
          onRetry={() => {
            void (async () => {
              const revision = await latestRevision();
              if (failedAction === "reset") {
                reset.mutate(revision);
                return;
              }
              reload.mutate(revision);
            })();
          }}
        />
      ) : null}

      <div className="field">
        <label htmlFor={viewId}>View</label>
        <select id={viewId} value={view} onChange={(ev) => setView(ev.target.value)}>
          {CONFIG_VIEWS.map((v) => (
            <option key={v} value={v}>
              {v}
            </option>
          ))}
        </select>
      </div>

      <section className="panel" aria-labelledby="effective-heading">
        <h2 id="effective-heading">Effective configuration (redacted)</h2>
        {effective.isPending ? <p role="status">Loading effective config…</p> : null}
        {effective.data ? (
          <pre className="code-block">{JSON.stringify(effective.data.data, null, 2)}</pre>
        ) : null}
      </section>

      {canExport ? (
        <section className="panel" aria-labelledby="export-heading">
          <h2 id="export-heading">Export YAML</h2>
          {exported.isPending ? <p role="status">Loading export…</p> : null}
          {exported.data ? <pre className="code-block">{exported.data.data.yaml}</pre> : null}
        </section>
      ) : (
        <p>Export requires <code>config:export</code>.</p>
      )}

      <section className="panel" aria-labelledby="overlay-heading">
        <h2 id="overlay-heading">Runtime overlay and tombstones</h2>
        {tombstones.isPending ? <p role="status">Loading overlay objects…</p> : null}
        <ul>
          {(tombstones.data?.users ?? []).map((u) => (
            <li key={`u-${u.id}`}>
              user <code>{u.id}</code> <ObjectMeta source={u.source} deleted={u.deleted} shadows={u.shadows_source} />
            </li>
          ))}
          {(tombstones.data?.groups ?? []).map((g) => (
            <li key={`g-${g.id}`}>
              group <code>{g.id}</code> <ObjectMeta source={g.source} deleted={g.deleted} shadows={g.shadows_source} />
            </li>
          ))}
          {(tombstones.data?.clients ?? []).map((c) => (
            <li key={`c-${c.id}`}>
              client <code>{c.id}</code> <ObjectMeta source={c.source} deleted={c.deleted} shadows={c.shadows_source} />
            </li>
          ))}
        </ul>
        {(tombstones.data?.users.length ?? 0) +
          (tombstones.data?.groups.length ?? 0) +
          (tombstones.data?.clients.length ?? 0) ===
        0 ? (
          <p className="quiet">No runtime, override, or tombstone objects in this snapshot.</p>
        ) : null}
      </section>

      {canValidate ? (
        <section className="panel" aria-labelledby="validate-heading">
          <h2 id="validate-heading">Validate candidate YAML</h2>
          <p className="hint">
            Preview only. This does not publish a new snapshot. An empty document validates the mounted baseline.
          </p>
          <form className="stack" onSubmit={onValidate}>
            <div className="field">
              <label htmlFor={yamlId}>YAML document</label>
              <textarea id={yamlId} rows={10} value={yaml} onChange={(ev) => setYaml(ev.target.value)} />
            </div>
            <button type="submit" disabled={validate.isPending}>
              {validate.isPending ? "Validating…" : "Validate"}
            </button>
          </form>
        </section>
      ) : null}

      <div className="actions">
        {canReload ? (
          <button type="button" onClick={() => setConfirm("reload")}>
            Reload baseline
          </button>
        ) : null}
        {canReset ? (
          <button type="button" className="danger" onClick={() => setConfirm("reset")}>
            Reset runtime overlay
          </button>
        ) : null}
      </div>

      {confirm === "reload" ? (
        <ConfirmDialog
          title="Reload the mounted baseline?"
          confirmLabel="Reload baseline"
          busy={reload.isPending}
          onCancel={() => setConfirm(null)}
          onConfirm={() => reload.mutate(effective.data?.revision ?? 0)}
        >
          <p>
            Reload remounts the baseline YAML and rebases the current overlay. An invalid candidate keeps revision{" "}
            {String(effective.data?.revision ?? "unknown")}.
          </p>
        </ConfirmDialog>
      ) : null}
      {confirm === "reset" ? (
        <ConfirmDialog
          title="Reset the runtime overlay?"
          confirmLabel="Reset overlay"
          busy={reset.isPending}
          onCancel={() => setConfirm(null)}
          onConfirm={() => reset.mutate(effective.data?.revision ?? 0)}
        >
          <p>
            This drops TacLab’s memory overlay only — every runtime object, override, and tombstone. It does not send
            RADIUS to a NAS or kick a device. Baseline identities return. The change cannot be undone without recreating
            overlay objects. Current revision {String(effective.data?.revision ?? "unknown")}.
          </p>
        </ConfirmDialog>
      ) : null}
    </main>
  );
}
