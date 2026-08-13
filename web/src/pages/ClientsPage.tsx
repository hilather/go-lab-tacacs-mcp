import { useMutation, useQuery, useQueryClient } from "@tanstack/react-query";
import { FormEvent, useEffect, useId, useRef, useState } from "react";
import {
  APIError,
  createClient,
  deleteClient,
  getClient,
  getStatus,
  isRevisionMismatch,
  latestRevision,
  listClients,
  newIdempotencyKey,
  updateClient,
} from "../api/client";
import { useAuth } from "../auth/AuthProvider";
import { ConfirmDialog } from "../components/ConfirmDialog";
import { ErrorSummary } from "../components/ErrorSummary";
import { ObjectMeta } from "../components/ObjectMeta";
import { RequireScope } from "../components/RequireScope";
import { RevisionConflict } from "../components/RevisionConflict";
import { emptySecret, SecretRefFields, secretPayload, type SecretDraft } from "../components/SecretRefFields";
import type { Client, CreateClientRequest, UpdateClientRequest } from "../generated/api";
import { useEventStream } from "../hooks/useEventStream";
import { usePagedList } from "../hooks/usePagedList";
import {
  AUTH_METHODS,
  compact,
  fromDatetimeLocal,
  joinList,
  lifecycleLabel,
  MATCH_MODES,
  splitList,
  TRANSPORTS,
} from "../ui/constants";
import { errorDetail, matchesFilter } from "../ui/errors";

type EditorMode = { kind: "create" } | { kind: "edit"; client: Client };

export function ClientsPage() {
  return (
    <RequireScope scope="state:read">
      <ClientsBody />
    </RequireScope>
  );
}

function ClientsBody() {
  useEventStream();
  const { hasScope } = useAuth();
  const canWrite = hasScope("state:write");
  const [filter, setFilter] = useState("");
  const [includeDeleted, setIncludeDeleted] = useState(false);
  const [editor, setEditor] = useState<EditorMode | null>(null);
  const list = usePagedList(["clients", includeDeleted], (cursor) =>
    listClients({ include_deleted: includeDeleted, limit: 200, ...(cursor ? { cursor } : {}) }),
  );
  const status = useQuery({ queryKey: ["status"], queryFn: getStatus });
  const warnings = status.data?.data.warnings ?? [];
  const items = list.items.filter((c) =>
    matchesFilter(filter, [c.id, c.display_name, c.source, c.shared_secret_lifecycle, ...(c.match.source_cidrs ?? [])]),
  );
  const filterId = useId();

  return (
    <main className="page page--wide">
      <h1>Clients</h1>
      <p>
        Client match is fail-closed: transport, certificate constraints, longest CIDR, then lowest priority. Ties are a
        configuration error. Shared-secret values are never displayed.
      </p>
      {warnings.length > 0 ? (
        <section className="banner banner--warn" aria-labelledby="client-warn-heading">
          <h2 id="client-warn-heading">Validation and rotation warnings</h2>
          <p className="hint">
            Rotate reused or overdue legacy secrets by writing a new file reference. Fingerprints are not shown.
          </p>
          <ul>
            {warnings.map((w) => (
              <li key={w}>{w}</li>
            ))}
          </ul>
        </section>
      ) : null}
      {list.isError ? (
        <div className="error-summary" role="alert">
          <h2>Could not load clients</h2>
          <p>{errorDetail(list.error, "Unable to load clients.")}</p>
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
            Create client
          </button>
        ) : null}
      </div>
      {list.isPending ? <p role="status">Loading clients…</p> : null}
      <table className="data">
        <caption>Network clients</caption>
        <thead>
          <tr>
            <th scope="col">ID</th>
            <th scope="col">Source</th>
            <th scope="col">Match</th>
            <th scope="col">Secret</th>
            <th scope="col">Methods</th>
            <th scope="col">Actions</th>
          </tr>
        </thead>
        <tbody>
          {items.map((c) => (
            <tr key={c.id}>
              <th scope="row">
                <code>{c.id}</code>
              </th>
              <td>
                <ObjectMeta source={c.source} deleted={c.deleted} shadows={c.shadows_source} />
              </td>
              <td>
                {(c.match.transports ?? []).join(", ") || "—"} / {c.match.mode || "address_and_certificate"} /{" "}
                {(c.match.source_cidrs ?? []).join(", ") || "no CIDR"}
              </td>
              <td>
                <span className={`lifecycle lifecycle--${c.shared_secret_lifecycle || "unknown"}`}>
                  {c.shared_secret_configured ? lifecycleLabel(c.shared_secret_lifecycle) : "Not configured"}
                </span>
              </td>
              <td>{joinList(c.authentication.allowed_methods) || "default"}</td>
              <td>
                {canWrite && !c.deleted ? (
                  <button type="button" onClick={() => setEditor({ kind: "edit", client: c })}>
                    Edit {c.id}
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
      {editor ? (
        <ClientEditor
          mode={editor}
          revision={list.revision}
          canWrite={canWrite}
          onClose={() => setEditor(null)}
        />
      ) : null}
    </main>
  );
}

function ClientEditor({
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
  const existing = mode.kind === "edit" ? mode.client : null;
  const [id, setId] = useState(existing?.id ?? "");
  const [displayName, setDisplayName] = useState(existing?.display_name ?? "");
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [priority, setPriority] = useState(String(existing?.priority ?? 100));
  const [override, setOverride] = useState(false);
  const [cidrs, setCidrs] = useState(joinList(existing?.match.source_cidrs));
  const [transports, setTransports] = useState<string[]>(existing?.match.transports ?? ["legacy"]);
  const [modeMatch, setModeMatch] = useState(existing?.match.mode ?? "address_and_certificate");
  const [dnsSans, setDnsSans] = useState(joinList(existing?.match.certificate.dns_sans));
  const [ipSans, setIpSans] = useState(joinList(existing?.match.certificate.ip_sans));
  const [methods, setMethods] = useState<string[]>(existing?.authentication.allowed_methods ?? []);
  const [defaultService, setDefaultService] = useState(existing?.authentication.default_service ?? "");
  const [defaultGroups, setDefaultGroups] = useState(joinList(existing?.authorization.default_group_ids));
  const [compare, setCompare] = useState<{ field: string; yours: string; server: string }[] | undefined>();
  const [secret, setSecret] = useState<SecretDraft>(emptySecret());
  const [rotatedAt, setRotatedAt] = useState("");
  const [interval, setInterval] = useState("");
  const [loadedRevision, setLoadedRevision] = useState(existing?.effective_revision ?? revision);
  const [messages, setMessages] = useState<string[]>([]);
  const [conflict, setConflict] = useState<string | null>(null);
  const [pendingDelete, setPendingDelete] = useState<"remove" | "tombstone" | null>(null);
  const summaryRef = useRef<HTMLDivElement>(null);
  const headingId = useId();

  useEffect(() => {
    if (messages.length > 0 || conflict) {
      summaryRef.current?.focus();
    }
  }, [messages, conflict]);

  const save = useMutation({
    mutationFn: async (revision: number) => {
      const match = {
        source_cidrs: splitList(cidrs),
        transports,
        mode: modeMatch,
        certificate: { dns_sans: splitList(dnsSans), ip_sans: splitList(ipSans) },
      };
      const authentication = compact({
        allowed_methods: methods,
        default_service: defaultService.trim() !== "" ? defaultService.trim() : undefined,
      });
      const authorization = { default_group_ids: splitList(defaultGroups) };
      const shared_secret = secretPayload(secret);
      const rotated = rotatedAt !== "" ? fromDatetimeLocal(rotatedAt) : undefined;
      const lifecycle =
        rotated !== undefined || interval !== ""
          ? {
              ...(rotated !== undefined ? { last_rotated_at: rotated } : {}),
              ...(interval !== "" ? { rotation_interval: interval } : {}),
            }
          : undefined;
      const prio = Number(priority);
      if (creating) {
        const req = compact<CreateClientRequest>({
          id: id.trim(),
          display_name: displayName.trim(),
          enabled,
          priority: Number.isFinite(prio) ? prio : 100,
          match,
          shared_secret,
          shared_secret_lifecycle: lifecycle,
          authentication,
          authorization,
          override,
        });
        return createClient(req, revision, newIdempotencyKey());
      }
      const req = compact<UpdateClientRequest>({
        id: existing?.id ?? id,
        display_name: displayName.trim(),
        enabled,
        priority: Number.isFinite(prio) ? prio : 100,
        match,
        shared_secret,
        shared_secret_lifecycle: lifecycle,
        authentication,
        authorization,
      });
      return updateClient(existing?.id ?? id, req, revision);
    },
    onSuccess: async () => {
      setSecret(emptySecret());
      await queryClient.invalidateQueries({ queryKey: ["clients"] });
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
    mutationFn: async (args: { tombstone: boolean; revision: number }) => {
      if (!existing) {
        throw new APIError({
          type: "about:blank",
          title: "invalid_argument",
          status: 400,
          detail: "no client selected",
          code: "invalid_argument",
        });
      }
      return deleteClient(existing.id, args.revision, args.tombstone);
    },
    onSuccess: async () => {
      setPendingDelete(null);
      await queryClient.invalidateQueries({ queryKey: ["clients"] });
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
    const errs: string[] = [];
    if (creating && id.trim() === "") {
      errs.push("Enter a client id.");
    }
    if (errs.length > 0) {
      setMessages(errs);
      return;
    }
    setMessages([]);
    save.mutate(loadedRevision);
  }

  async function reloadLatest() {
    if (!existing) {
      return;
    }
    const env = await getClient(existing.id, true);
    const server = env.data;
    setCompare([
      { field: "display_name", yours: displayName, server: server.display_name ?? "" },
      { field: "priority", yours: priority, server: String(server.priority) },
      { field: "default_service", yours: defaultService, server: server.authentication.default_service ?? "" },
    ]);
    setDisplayName(server.display_name ?? "");
    setEnabled(server.enabled);
    setPriority(String(server.priority));
    setCidrs(joinList(server.match.source_cidrs));
    setTransports(server.match.transports ?? ["legacy"]);
    setModeMatch(server.match.mode ?? "address_and_certificate");
    setDnsSans(joinList(server.match.certificate.dns_sans));
    setIpSans(joinList(server.match.certificate.ip_sans));
    setMethods(server.authentication.allowed_methods ?? []);
    setDefaultService(server.authentication.default_service ?? "");
    setDefaultGroups(joinList(server.authorization.default_group_ids));
    setLoadedRevision(env.revision);
    setConflict(null);
  }

  async function retryWithCurrent() {
    const revision = await latestRevision();
    setLoadedRevision(revision);
    setConflict(null);
    save.mutate(revision);
  }

  return (
    <section className="panel" aria-labelledby={headingId}>
      <h2 id={headingId}>{creating ? "Create client" : `Edit ${existing?.id ?? ""}`}</h2>
      <ErrorSummary ref={summaryRef} id="client-errors" title="Could not save client" messages={messages} />
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
            <label htmlFor="client-id">Client ID</label>
            <input id="client-id" type="text" value={id} required onChange={(ev) => setId(ev.target.value)} />
          </div>
        ) : null}
        <div className="field">
          <label htmlFor="client-display">Display name</label>
          <input id="client-display" type="text" value={displayName} onChange={(ev) => setDisplayName(ev.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="client-priority">Priority</label>
          <input id="client-priority" type="number" value={priority} onChange={(ev) => setPriority(ev.target.value)} />
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
          <label htmlFor="client-cidrs">Source CIDRs</label>
          <input
            id="client-cidrs"
            type="text"
            value={cidrs}
            onChange={(ev) => setCidrs(ev.target.value)}
            aria-describedby="client-cidrs-hint"
          />
          <p id="client-cidrs-hint" className="hint">
            IPv4 and IPv6 prefixes. Ignored as a match key when mode is certificate_only.
          </p>
        </div>
        <fieldset className="fieldset">
          <legend>Transports</legend>
          {TRANSPORTS.map((t) => (
            <label key={t} className="check">
              <input
                type="checkbox"
                checked={transports.includes(t)}
                onChange={(ev) => {
                  setTransports(ev.target.checked ? [...transports, t] : transports.filter((x) => x !== t));
                }}
              />
              {t}
            </label>
          ))}
        </fieldset>
        <div className="field">
          <label htmlFor="client-mode">Match mode</label>
          <select id="client-mode" value={modeMatch} onChange={(ev) => setModeMatch(ev.target.value)}>
            {MATCH_MODES.map((m) => (
              <option key={m} value={m}>
                {m}
              </option>
            ))}
          </select>
        </div>
        <div className="field">
          <label htmlFor="client-dns">Certificate DNS SANs</label>
          <input id="client-dns" type="text" value={dnsSans} onChange={(ev) => setDnsSans(ev.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="client-ips">Certificate IP SANs</label>
          <input id="client-ips" type="text" value={ipSans} onChange={(ev) => setIpSans(ev.target.value)} />
        </div>
        <fieldset className="fieldset">
          <legend>Allowed authentication methods</legend>
          {AUTH_METHODS.map((m) => (
            <label key={m} className="check">
              <input
                type="checkbox"
                checked={methods.includes(m)}
                onChange={(ev) => {
                  setMethods(ev.target.checked ? [...methods, m] : methods.filter((x) => x !== m));
                }}
              />
              {m}
            </label>
          ))}
        </fieldset>
        <div className="field">
          <label htmlFor="client-default-service">Default service</label>
          <input
            id="client-default-service"
            type="text"
            value={defaultService}
            onChange={(ev) => setDefaultService(ev.target.value)}
            aria-describedby="client-default-service-hint"
          />
          <p id="client-default-service-hint" className="hint">
            Preserved on save when left as loaded. Clearing this field removes the baseline default service.
          </p>
        </div>
        <div className="field">
          <label htmlFor="client-groups">Default group IDs</label>
          <input
            id="client-groups"
            type="text"
            value={defaultGroups}
            onChange={(ev) => setDefaultGroups(ev.target.value)}
            aria-describedby="client-groups-hint"
          />
          <p id="client-groups-hint" className="hint">
            Appended after the user&apos;s groups and de-duplicated. Extra membership, not a replacement.
          </p>
        </div>
        {existing ? (
          <p>
            Shared secret {existing.shared_secret_configured ? "configured" : "absent"}; rotation status{" "}
            <strong>{lifecycleLabel(existing.shared_secret_lifecycle)}</strong>.
          </p>
        ) : null}
        <SecretRefFields
          id="client-secret"
          label="Legacy shared secret"
          hint="Write-only file or environment reference. Rotate by pointing at a new secret file."
          value={secret}
          onChange={setSecret}
        />
        <div className="field">
          <label htmlFor="client-rotated">Last rotated at</label>
          <input id="client-rotated" type="datetime-local" value={rotatedAt} onChange={(ev) => setRotatedAt(ev.target.value)} />
        </div>
        <div className="field">
          <label htmlFor="client-interval">Rotation interval</label>
          <input
            id="client-interval"
            type="text"
            value={interval}
            placeholder="720h"
            onChange={(ev) => setInterval(ev.target.value)}
          />
        </div>
        <div className="actions">
          {canWrite ? (
            <button type="submit" disabled={save.isPending}>
              {save.isPending ? "Saving…" : creating ? "Create client" : "Save client"}
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
              Delete runtime client
            </button>
          ) : null}
          {existing.source === "config" || existing.source === "override" ? (
            <button type="button" className="danger" onClick={() => setPendingDelete("tombstone")}>
              Tombstone baseline client
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
          title="Confirm client change"
          confirmLabel={pendingDelete === "tombstone" ? "Tombstone client" : "Delete client"}
          busy={remove.isPending}
          onCancel={() => setPendingDelete(null)}
          onConfirm={() => remove.mutate({ tombstone: pendingDelete === "tombstone", revision: loadedRevision })}
        >
          <p>
            {pendingDelete === "tombstone"
              ? "A tombstone hides this baseline client until runtime reset."
              : "Runtime clients are removed. Override delete without tombstone reveals the baseline."}
          </p>
        </ConfirmDialog>
      ) : null}
    </section>
  );
}
