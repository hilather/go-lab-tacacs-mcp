import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FormEvent, useEffect, useId, useRef, useState } from "react";
import { APIError, createUser, deleteUser, getUser, isRevisionMismatch, listUsers, updateUser } from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ErrorSummary } from "../components/ErrorSummary";
import { ObjectMeta } from "../components/ObjectMeta";
import { RequireScope } from "../components/RequireScope";
import { RevisionConflict } from "../components/RevisionConflict";
import { emptyRules, RulesEditor } from "../components/RulesEditor";
import { emptySecret, SecretRefFields, secretPayload, type SecretDraft } from "../components/SecretRefFields";
import type { CreateUserRequest, RuleSetView, UpdateUserRequest, User } from "../generated/api";
import { useEventStream } from "../hooks/useEventStream";
import { errorDetail, matchesFilter } from "../ui/errors";
import { compact, joinList, splitList } from "../ui/constants";

type EditorMode = { kind: "create" } | { kind: "edit"; user: User };

export function UsersPage() {
  return (
    <RequireScope scope="state:read">
      <UsersBody />
    </RequireScope>
  );
}

function UsersBody() {
  useEventStream();
  const { hasScope } = useAuth();
  const canWrite = hasScope("state:write");
  const [filter, setFilter] = useState("");
  const [includeDeleted, setIncludeDeleted] = useState(false);
  const [editor, setEditor] = useState<EditorMode | null>(null);
  const list = useQuery({
    queryKey: ["users", includeDeleted],
    queryFn: () => listUsers({ include_deleted: includeDeleted, limit: 200 }),
  });
  const items = (list.data?.data.items ?? []).filter((u) =>
    matchesFilter(filter, [u.id, u.display_name, u.source, ...(u.group_ids ?? [])]),
  );
  const filterId = useId();

  return (
    <main className="page page--wide">
      <h1>Users</h1>
      <p>
        Runtime users vanish on restart. Updating a baseline user writes an overlay (
        <code>OVERRIDE</code>). Tombstoning hides a baseline identity until reset.
      </p>
      {list.isError ? (
        <div className="error-summary" role="alert">
          <h2>Could not load users</h2>
          <p>{errorDetail(list.error, "Unable to load users.")}</p>
        </div>
      ) : null}
      <div className="toolbar">
        <div className="field">
          <label htmlFor={filterId}>Filter</label>
          <input
            id={filterId}
            type="search"
            value={filter}
            onChange={(ev) => {
              setFilter(ev.target.value);
            }}
          />
        </div>
        <label className="check">
          <input
            type="checkbox"
            checked={includeDeleted}
            onChange={(ev) => {
              setIncludeDeleted(ev.target.checked);
            }}
          />
          Include deleted / tombstones
        </label>
        {canWrite ? (
          <button type="button" onClick={() => setEditor({ kind: "create" })}>
            Create user
          </button>
        ) : null}
      </div>
      {list.isPending ? <p role="status">Loading users…</p> : null}
      <table className="data">
        <caption>Users in the published snapshot</caption>
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Display name</th>
            <th scope="col">Source</th>
            <th scope="col">Enabled</th>
            <th scope="col">Credentials</th>
            <th scope="col">Groups</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {items.map((u) => (
            <tr key={u.id}>
              <th scope="row">
                <code>{u.id}</code>
              </th>
              <td>{u.display_name || "—"}</td>
              <td>
                <ObjectMeta source={u.source} deleted={u.deleted} shadows={u.shadows_source} />
              </td>
              <td>
                <span className={u.enabled ? "state state--on" : "state state--off"}>
                  {u.enabled ? "Enabled" : "Disabled"}
                </span>
              </td>
              <td>
                {u.ascii_pap_configured ? "ASCII/PAP " : ""}
                {u.challenge_configured ? "CHAP " : ""}
                {u.enable_configured ? "ENABLE" : ""}
                {!u.ascii_pap_configured && !u.challenge_configured && !u.enable_configured ? "none" : ""}
              </td>
              <td>{joinList(u.group_ids) || "—"}</td>
              <td>
                {canWrite && !u.deleted ? (
                  <button type="button" onClick={() => setEditor({ kind: "edit", user: u })}>
                    Edit {u.id}
                  </button>
                ) : null}
              </td>
            </tr>
          ))}
        </tbody>
      </table>
      {items.length === 0 && !list.isPending ? <p>No users match the filter.</p> : null}
      {editor ? (
        <UserEditor
          mode={editor}
          revision={list.data?.revision ?? 0}
          canWrite={canWrite}
          onClose={() => setEditor(null)}
        />
      ) : null}
    </main>
  );
}

function UserEditor({
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
  const existing = mode.kind === "edit" ? mode.user : null;
  const [id, setId] = useState(existing?.id ?? "");
  const [displayName, setDisplayName] = useState(existing?.display_name ?? "");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [override, setOverride] = useState(false);
  const [groupIds, setGroupIds] = useState(joinList(existing?.group_ids));
  const [clientIds, setClientIds] = useState(joinList(existing?.restrictions.client_ids));
  const [rules, setRules] = useState<RuleSetView>(existing?.rules ?? emptyRules());
  const [login, setLogin] = useState<SecretDraft>(emptySecret());
  const [challenge, setChallenge] = useState<SecretDraft>(emptySecret());
  const [enable, setEnable] = useState<SecretDraft>(emptySecret());
  const [loadedRevision, setLoadedRevision] = useState(existing?.effective_revision ?? revision);
  const [messages, setMessages] = useState<string[]>([]);
  const [conflict, setConflict] = useState<string | null>(null);
  const [compare, setCompare] = useState<{ field: string; yours: string; server: string }[] | undefined>();
  const [pendingDelete, setPendingDelete] = useState<"remove" | "tombstone" | null>(null);
  const [announce, setAnnounce] = useState("");
  const summaryRef = useRef<HTMLDivElement>(null);
  const headingId = useId();

  useEffect(() => {
    if (messages.length > 0 || conflict) {
      summaryRef.current?.focus();
    }
  }, [messages, conflict]);

  const save = useMutation({
    mutationFn: async () => {
      const bodyBase = {
        display_name: displayName.trim() === "" ? undefined : displayName.trim(),
        enabled,
        group_ids: splitList(groupIds),
        rules,
        login: secretPayload(login),
        challenge: secretPayload(challenge),
        enable: secretPayload(enable),
        restrictions: { client_ids: splitList(clientIds) },
      };
      if (creating) {
        const req = compact<CreateUserRequest>({ id: id.trim(), ...bodyBase, override });
        return createUser(req, loadedRevision);
      }
      const req = compact<UpdateUserRequest>({ id: existing?.id ?? id, ...bodyBase });
      return updateUser(existing?.id ?? id, req, loadedRevision);
    },
    onSuccess: async () => {
      setLogin(emptySecret());
      setChallenge(emptySecret());
      setEnable(emptySecret());
      setConflict(null);
      setMessages([]);
      setAnnounce(creating ? "User created." : "User updated.");
      await queryClient.invalidateQueries({ queryKey: ["users"] });
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
          detail: "no user selected",
          code: "invalid_argument",
        });
      }
      return deleteUser(existing.id, loadedRevision, tombstone);
    },
    onSuccess: async () => {
      setPendingDelete(null);
      setAnnounce("User deleted.");
      await queryClient.invalidateQueries({ queryKey: ["users"] });
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

  async function reloadLatest() {
    if (!existing) {
      return;
    }
    const env = await getUser(existing.id, true);
    const server = env.data;
    setCompare([
      { field: "display_name", yours: displayName, server: server.display_name ?? "" },
      { field: "enabled", yours: enabled ? "true" : "false", server: server.enabled ? "true" : "false" },
      { field: "group_ids", yours: groupIds, server: joinList(server.group_ids) },
    ]);
    setDisplayName(server.display_name ?? "");
    setEnabled(server.enabled);
    setGroupIds(joinList(server.group_ids));
    setClientIds(joinList(server.restrictions.client_ids));
    setRules(server.rules ?? emptyRules());
    setLoadedRevision(env.revision);
    setConflict(null);
    setAnnounce("Reloaded latest user.");
  }

  async function retryWithCurrent() {
    const env = await listUsers({ limit: 1 });
    setLoadedRevision(env.revision);
    setConflict(null);
    save.mutate();
  }

  function onSubmit(ev: FormEvent) {
    ev.preventDefault();
    const errs: string[] = [];
    if (creating && id.trim() === "") {
      errs.push("Enter a user id (TACACS username).");
    }
    if (errs.length > 0) {
      setMessages(errs);
      return;
    }
    setMessages([]);
    save.mutate();
  }

  return (
    <section className="panel" aria-labelledby={headingId}>
      <h2 id={headingId}>{creating ? "Create user" : `Edit ${existing?.id ?? ""}`}</h2>
      <p className="visually-hidden" role="status">
        {announce}
      </p>
      <ErrorSummary ref={summaryRef} id="user-errors" title="Could not save user" messages={messages} />
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
            <label htmlFor="user-id">User ID</label>
            <input
              id="user-id"
              type="text"
              value={id}
              required
              autoComplete="off"
              onChange={(ev) => setId(ev.target.value)}
            />
          </div>
        ) : null}
        <div className="field">
          <label htmlFor="user-display">Display name</label>
          <input id="user-display" type="text" value={displayName} onChange={(ev) => setDisplayName(ev.target.value)} />
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
        <div className="field">
          <label htmlFor="user-groups">Group IDs</label>
          <input
            id="user-groups"
            type="text"
            value={groupIds}
            onChange={(ev) => setGroupIds(ev.target.value)}
            aria-describedby="user-groups-hint"
          />
          <p id="user-groups-hint" className="hint">
            Comma-separated group ids, evaluated in listed order.
          </p>
        </div>
        <div className="field">
          <label htmlFor="user-clients">Restricted client IDs</label>
          <input id="user-clients" type="text" value={clientIds} onChange={(ev) => setClientIds(ev.target.value)} />
        </div>
        {existing ? (
          <p>
            Capability metadata: ASCII/PAP {existing.ascii_pap_configured ? "configured" : "absent"}, challenge{" "}
            {existing.challenge_configured ? "configured" : "absent"}, ENABLE{" "}
            {existing.enable_configured ? "configured" : "absent"}. Secret values are never displayed.
          </p>
        ) : null}
        <SecretRefFields
          id="user-login"
          label="Login verifier (ASCII/PAP)"
          hint="File or environment reference for the Argon2id verifier."
          value={login}
          onChange={setLogin}
        />
        <SecretRefFields
          id="user-challenge"
          label="Challenge secret (CHAP / MS-CHAP)"
          hint="Separate clear-equivalent challenge material. Never derived from the login verifier."
          value={challenge}
          onChange={setChallenge}
        />
        <SecretRefFields
          id="user-enable"
          label="ENABLE verifier"
          hint="Distinct ENABLE material."
          value={enable}
          onChange={setEnable}
        />
        <RulesEditor id="user-rules" value={rules} onChange={setRules} disabled={!canWrite} />
        <div className="actions">
          {canWrite ? (
            <button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving…" : creating ? "Create user" : "Save user"}
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
              Delete runtime user
            </button>
          ) : null}
          {existing.source === "config" || existing.source === "override" ? (
            <button type="button" className="danger" onClick={() => setPendingDelete("tombstone")}>
              Tombstone baseline user
            </button>
          ) : null}
          {existing.source === "override" ? (
            <button type="button" onClick={() => setPendingDelete("remove")}>
              Reveal baseline (drop overlay)
            </button>
          ) : null}
        </div>
      ) : null}
      {pendingDelete ? (
        <ConfirmDialog
          title={pendingDelete === "tombstone" ? "Tombstone this user?" : "Delete this user?"}
          confirmLabel={pendingDelete === "tombstone" ? "Tombstone user" : "Delete user"}
          busy={remove.isPending}
          onCancel={() => setPendingDelete(null)}
          onConfirm={() => remove.mutate(pendingDelete === "tombstone")}
        >
          <p>
            {pendingDelete === "tombstone"
              ? "The baseline identity stays in the YAML. A tombstone hides it from the effective snapshot until runtime reset."
              : existing?.source === "override"
                ? "Dropping the overlay reveals the baseline user. Runtime-only objects are removed."
                : "This runtime user is removed from the overlay and disappears on restart anyway."}
          </p>
        </ConfirmDialog>
      ) : null}
    </section>
  );
}
