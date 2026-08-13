import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FormEvent, useEffect, useId, useRef, useState } from "react";
import { APIError, createGroup, deleteGroup, getGroup, isRevisionMismatch, listGroups, updateGroup } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ErrorSummary } from "../components/ErrorSummary";
import { ObjectMeta } from "../components/ObjectMeta";
import { RequireScope } from "../components/RequireScope";
import { RevisionConflict } from "../components/RevisionConflict";
import { emptyRules, RulesEditor } from "../components/RulesEditor";
import type { CommandRuleView, CreateGroupRequest, Group, RuleSetView, ServiceRuleView, UpdateGroupRequest } from "../generated/api";
import { useEventStream } from "../hooks/useEventStream";
import { compact } from "../ui/constants";
import { errorDetail, matchesFilter } from "../ui/errors";

type EditorMode = { kind: "create" } | { kind: "edit"; group: Group };

export function GroupsPage() {
  return (
    <RequireScope scope="state:read">
      <GroupsBody />
    </RequireScope>
  );
}

function GroupsBody() {
  useEventStream();
  const { hasScope } = useAuth();
  const canWrite = hasScope("state:write");
  const [filter, setFilter] = useState("");
  const [includeDeleted, setIncludeDeleted] = useState(false);
  const [editor, setEditor] = useState<EditorMode | null>(null);
  const list = useQuery({
    queryKey: ["groups", includeDeleted],
    queryFn: () => listGroups({ include_deleted: includeDeleted, limit: 200 }),
  });
  const items = (list.data?.data.items ?? []).filter((g) => matchesFilter(filter, [g.id, g.display_name, g.source]));
  const filterId = useId();

  return (
    <main className="page page--wide">
      <h1>Groups</h1>
      <p>
        Groups are flat. Command and service rules are separate first-match lists. Default-deny applies when nothing
        matches. <code>default_command_action</code> must be deny in 1.0.
      </p>
      {list.isError ? (
        <div className="error-summary" role="alert">
          <h2>Could not load groups</h2>
          <p>{errorDetail(list.error, "Unable to load groups.")}</p>
        </div>
      ) : null}
      <div className="toolbar">
        <div className="field">
          <label htmlFor={filterId}>Filter</label>
          <input id={filterId} type="search" value={filter} onChange={(ev) => setFilter(ev.target.value)} />
        </div>
        <label className="check">
          <input type="checkbox" checked={includeDeleted} onChange={(ev) => setIncludeDeleted(ev.target.checked)} />
          Include deleted / tombstones
        </label>
        {canWrite ? (
          <button type="button" onClick={() => setEditor({ kind: "create" })}>
            Create group
          </button>
        ) : null}
      </div>
      {list.isPending ? <p role="status">Loading groups…</p> : null}
      <table className="data">
        <caption>Authorization groups</caption>
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Priority</th>
            <th scope="col">Source</th>
            <th scope="col">Enabled</th>
            <th scope="col">Rules</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {items.map((g) => (
            <tr key={g.id}>
              <th scope="row">
                <code>{g.id}</code>
              </th>
              <td>{String(g.priority)}</td>
              <td>
                <ObjectMeta source={g.source} deleted={g.deleted} shadows={g.shadows_source} />
              </td>
              <td>
                <span className={g.enabled ? "state state--on" : "state state--off"}>
                  {g.enabled ? "Enabled" : "Disabled"}
                </span>
              </td>
              <td>
                {(g.services ?? []).length} service / {(g.command_rules ?? []).length} command
              </td>
              <td>
                {canWrite && !g.deleted ? (
                  <button type="button" onClick={() => setEditor({ kind: "edit", group: g })}>
                    Edit {g.id}
                  </button>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {editor ? (
        <GroupEditor
          mode={editor}
          revision={list.data?.revision ?? 0}
          canWrite={canWrite}
          onClose={() => setEditor(null)}
        />
      ) : null}
    </main>
  );
}

function GroupEditor({
  mode,
  revision,
  canWrite,
  onClose,
}: {
  mode: EditorMode;
  revision: number;
  canWrite: boolean;
  onClose: () => void;
}) {
  const queryClient = useQueryClient();
  const creating = mode.kind === "create";
  const existing = mode.kind === "edit" ? mode.group : null;
  const [id, setId] = useState(existing?.id ?? "");
  const [displayName, setDisplayName] = useState(existing?.display_name ?? "");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [priority, setPriority] = useState(String(existing?.priority ?? 100));
  const [override, setOverride] = useState(false);
  const [rules, setRules] = useState<RuleSetView>({
    services: existing?.services ?? [],
    command_rules: existing?.command_rules ?? [],
  });
  const [loadedRevision, setLoadedRevision] = useState(existing?.effective_revision ?? revision);
  const [messages, setMessages] = useState<string[]>([]);
  const [conflict, setConflict] = useState<string | null>(null);
  const [compare, setCompare] = useState<{ field: string; yours: string; server: string }[] | undefined>();
  const [pendingDelete, setPendingDelete] = useState<"remove" | "tombstone" | null>(null);
  const summaryRef = useRef<HTMLDivElement>(null);
  const headingId = useId();

  useEffect(() => {
    if (messages.length > 0 || conflict) {
      summaryRef.current?.focus();
    }
  }, [messages, conflict]);

  function validateRules(): string[] {
    const errs: string[] = [];
    for (const rule of rules.command_rules ?? []) {
      const cmd = rule.command;
      if (cmd.exact && cmd.pattern) {
        errs.push(`Command rule ${rule.id || "(unnamed)"} cannot set both exact and regex.`);
      }
      if (rule.arguments.exact && rule.arguments.pattern) {
        errs.push(`Command rule ${rule.id || "(unnamed)"} arguments cannot set both exact and regex.`);
      }
    }
    return errs;
  }

  const save = useMutation({
    mutationFn: async () => {
      const services = (rules.services ?? []) as ServiceRuleView[];
      const command_rules = (rules.command_rules ?? []) as CommandRuleView[];
      const prio = Number(priority);
      if (creating) {
        const req = compact<CreateGroupRequest>({
          id: id.trim(),
          display_name: displayName.trim() || undefined,
          enabled,
          priority: Number.isFinite(prio) ? prio : 100,
          services,
          command_rules,
          default_command_action: "deny",
          override,
        });
        return createGroup(req, loadedRevision);
      }
      const req = compact<UpdateGroupRequest>({
        id: existing?.id ?? id,
        display_name: displayName.trim() || undefined,
        enabled,
        priority: Number.isFinite(prio) ? prio : 100,
        services,
        command_rules,
        default_command_action: "deny",
      });
      return updateGroup(existing?.id ?? id, req, loadedRevision);
    },
    onSuccess: async () => {
      await queryClient.invalidateQueries({ queryKey: ["groups"] });
      onClose();
    },
    onError: (err) => {
      if (isRevisionMismatch(err)) {
        setConflict(errorDetail(err, "expected revision does not match published snapshot"));
        return;
      }
      setMessages([errorDetail(err, "Save failed.")]);
    },
  });

  const remove = useMutation({
    mutationFn: async (tombstone: boolean) => {
      if (!existing) {
        throw new APIError({
          type: "about:blank",
          title: "invalid_argument",
          status: 400,
          detail: "no group selected",
          code: "invalid_argument",
        });
      }
      return deleteGroup(existing.id, loadedRevision, tombstone);
    },
    onSuccess: async () => {
      setPendingDelete(null);
      await queryClient.invalidateQueries({ queryKey: ["groups"] });
      onClose();
    },
    onError: (err) => {
      setPendingDelete(null);
      if (isRevisionMismatch(err)) {
        setConflict(errorDetail(err, "expected revision does not match published snapshot"));
        return;
      }
      setMessages([errorDetail(err, "Delete failed.")]);
    },
  });

  function onSubmit(ev: FormEvent) {
    ev.preventDefault();
    const errs = [...validateRules()];
    if (creating && id.trim() === "") {
      errs.push("Enter a group id.");
    }
    if (errs.length > 0) {
      setMessages(errs);
      return;
    }
    setMessages([]);
    save.mutate();
  }

  async function reloadLatest() {
    if (!existing) {
      return;
    }
    const env = await getGroup(existing.id, true);
    setCompare([
      { field: "display_name", yours: displayName, server: env.data.display_name ?? "" },
      { field: "priority", yours: priority, server: String(env.data.priority) },
    ]);
    setDisplayName(env.data.display_name ?? "");
    setEnabled(env.data.enabled);
    setPriority(String(env.data.priority));
    setRules({ services: env.data.services ?? [], command_rules: env.data.command_rules ?? [] });
    setLoadedRevision(env.revision);
    setConflict(null);
  }

  async function retryWithCurrent() {
    const env = await listGroups({ limit: 1 });
    setLoadedRevision(env.revision);
    setConflict(null);
    save.mutate();
  }

  return (
    <section className="panel" aria-labelledby={headingId}>
      <h2 id={headingId}>{creating ? "Create group" : `Edit ${existing?.id ?? ""}`}</h2>
      <ErrorSummary ref={summaryRef} id="group-errors" title="Could not save group" messages={messages} />
      {conflict ? (
        <RevisionConflict
          detail={conflict}
          compare={compare}
          onReload={() => {
            void reloadLatest();
          }}
          onRetry={() => {
            void retryWithCurrent();
          }}
        />
      ) : null}
      <form className="stack" onSubmit={onSubmit} noValidate>
        {creating ? (
          <div className="field">
            <label htmlFor="group-id">Group ID</label>
            <input id="group-id" type="text" value={id} required onChange={(ev) => setId(ev.target.value)} />
          </div>
        ) : null}
        <div className="field">
          <label htmlFor="group-display">Display name</label>
          <input id="group-display" type="text" value={displayName} onChange={(ev) => setDisplayName(ev.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="group-priority">Priority</label>
          <input
            id="group-priority"
            type="number"
            value={priority}
            onChange={(ev) => setPriority(ev.target.value)}
            aria-describedby="group-priority-hint"
          />
          <p id="group-priority-hint" className="hint">
            Lower numeric priority wins when comparing groups. Duplicate priorities inside one rule list are rejected.
          </p>
        </div>
        <label className="check">
          <input type="checkbox" checked={enabled} onChange={(ev) => setEnabled(ev.target.checked)} />
          Enabled
        </label>
        {creating ? (
          <label className="check">
            <input type="checkbox" checked={override} onChange={(ev) => setOverride(ev.target.checked)} />
            Override baseline identity if it already exists
          </label>
        ) : null}
        <p>
          Default command action is <strong>deny</strong> (required in 1.0). It does not add a hidden permit.
        </p>
        <RulesEditor id="group-rules" value={creating && rules.services === undefined ? emptyRules() : rules} onChange={setRules} disabled={!canWrite} />
        <div className="actions">
          {canWrite ? (
            <button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving…" : creating ? "Create group" : "Save group"}
            </button>
          ) : null}
          <button type="button" onClick={onClose}>
            Close
          </button>
        </div>
      </form>
      {canWrite && existing ? (
        <div className="actions">
          {existing.source === "runtime" ? (
            <button type="button" className="danger" onClick={() => setPendingDelete("remove")}>
              Delete runtime group
            </button>
          ) : null}
          {existing.source === "config" || existing.source === "override" ? (
            <button type="button" className="danger" onClick={() => setPendingDelete("tombstone")}>
              Tombstone baseline group
            </button>
          ) : null}
          {existing.source === "override" ? (
            <button type="button" onClick={() => setPendingDelete("remove")}>
              Reveal baseline
            </button>
          ) : null}
        </div>
      ) : null}
      {pendingDelete ? (
        <ConfirmDialog
          title="Confirm group change"
          confirmLabel={pendingDelete === "tombstone" ? "Tombstone group" : "Delete group"}
          busy={remove.isPending}
          onCancel={() => setPendingDelete(null)}
          onConfirm={() => remove.mutate(pendingDelete === "tombstone")}
        >
          <p>
            {pendingDelete === "tombstone"
              ? "A tombstone hides this baseline group until runtime reset."
              : "Runtime groups are removed. Override delete without tombstone reveals the baseline."}
          </p>
        </ConfirmDialog>
      ) : null}
    </section>
  );
}
