import type { CommandRuleView, MatchView, PolicyTraceAV, RuleSetView, ServiceRuleView } from "../generated/api";
import { RULE_ACTIONS } from "../ui/constants";

export function emptyRules(): RuleSetView {
  return { services: [], command_rules: [] };
}

function emptyService(): ServiceRuleView {
  return { service: "shell", action: "permit_add", reply_attributes: [] };
}

function emptyCommand(): CommandRuleView {
  return {
    id: "",
    priority: 10,
    action: "deny",
    command: { exact: "" },
    arguments: { exact: "" },
  };
}

function matchMode(m: MatchView | undefined): "exact" | "pattern" {
  return m?.pattern && m.pattern !== "" ? "pattern" : "exact";
}

function matchValue(m: MatchView | undefined): string {
  if (m?.pattern && m.pattern !== "") {
    return m.pattern;
  }
  return m?.exact ?? "";
}

function toMatch(mode: "exact" | "pattern", value: string): MatchView {
  const trimmed = value.trim();
  if (trimmed === "") {
    return {};
  }
  return mode === "pattern" ? { pattern: trimmed } : { exact: trimmed };
}

export function RulesEditor({
  id,
  value,
  onChange,
  disabled,
}: {
  id: string;
  value: RuleSetView;
  onChange: (next: RuleSetView) => void;
  disabled?: boolean;
}) {
  const services = value.services ?? [];
  const commands = value.command_rules ?? [];

  function setServices(next: ServiceRuleView[]) {
    onChange({ ...value, services: next });
  }
  function setCommands(next: CommandRuleView[]) {
    onChange({ ...value, command_rules: next });
  }

  return (
    <div className="stack">
      <p className="hint">
        Session/service rules never authorize a non-empty command. Command rules never decide a
        session request. Each list is first-match; unmatched requests default-deny.
      </p>
      <fieldset className="fieldset" disabled={disabled}>
        <legend>Service rules</legend>
        {services.map((rule, index) => (
          <ServiceRow
            key={`svc-${String(index)}`}
            id={`${id}-svc-${String(index)}`}
            rule={rule}
            onChange={(next) => {
              const copy = [...services];
              copy[index] = next;
              setServices(copy);
            }}
            onRemove={() => {
              setServices(services.filter((_, i) => i !== index));
            }}
            onMove={(dir) => {
              const dest = index + dir;
              if (dest < 0 || dest >= services.length) {
                return;
              }
              const copy = [...services];
              const [item] = copy.splice(index, 1);
              if (item) {
                copy.splice(dest, 0, item);
              }
              setServices(copy);
            }}
          />
        ))}
        <button type="button" onClick={() => setServices([...services, emptyService()])}>
          Add service rule
        </button>
      </fieldset>
      <fieldset className="fieldset" disabled={disabled}>
        <legend>Command rules</legend>
        {commands.map((rule, index) => (
          <CommandRow
            key={`cmd-${String(index)}`}
            id={`${id}-cmd-${String(index)}`}
            rule={rule}
            onChange={(next) => {
              const copy = [...commands];
              copy[index] = next;
              setCommands(copy);
            }}
            onRemove={() => {
              setCommands(commands.filter((_, i) => i !== index));
            }}
            onMove={(dir) => {
              const dest = index + dir;
              if (dest < 0 || dest >= commands.length) {
                return;
              }
              const copy = [...commands];
              const [item] = copy.splice(index, 1);
              if (item) {
                copy.splice(dest, 0, item);
              }
              setCommands(copy);
            }}
          />
        ))}
        <button type="button" onClick={() => setCommands([...commands, emptyCommand()])}>
          Add command rule
        </button>
      </fieldset>
    </div>
  );
}

function ServiceRow({
  id,
  rule,
  onChange,
  onRemove,
  onMove,
}: {
  id: string;
  rule: ServiceRuleView;
  onChange: (next: ServiceRuleView) => void;
  onRemove: () => void;
  onMove: (dir: -1 | 1) => void;
}) {
  const attrs = rule.reply_attributes ?? [];
  return (
    <div className="rule-card">
      <div className="rule-grid">
        <div className="field">
          <label htmlFor={`${id}-service`}>Service</label>
          <input
            id={`${id}-service`}
            type="text"
            value={rule.service}
            onChange={(ev) => {
              onChange({ ...rule, service: ev.target.value });
            }}
          />
        </div>
        <div className="field">
          <label htmlFor={`${id}-protocol`}>Protocol</label>
          <input
            id={`${id}-protocol`}
            type="text"
            value={rule.protocol ?? ""}
            onChange={(ev) => {
              const protocol = ev.target.value;
              const next: ServiceRuleView = { ...rule };
              if (protocol === "") {
                delete next.protocol;
              } else {
                next.protocol = protocol;
              }
              onChange(next);
            }}
          />
        </div>
        <div className="field">
          <label htmlFor={`${id}-action`}>Action</label>
          <select
            id={`${id}-action`}
            value={rule.action}
            onChange={(ev) => {
              onChange({ ...rule, action: ev.target.value });
            }}
          >
            {RULE_ACTIONS.map((action) => (
              <option key={action} value={action}>
                {action}
              </option>
            ))}
          </select>
        </div>
      </div>
      <fieldset className="fieldset">
        <legend>Reply AV pairs (order and = / * preserved)</legend>
        {attrs.map((av, index) => (
          <AVRow
            key={`${id}-av-${String(index)}`}
            id={`${id}-av-${String(index)}`}
            value={av}
            onChange={(next) => {
              const copy = [...attrs];
              copy[index] = next;
              onChange({ ...rule, reply_attributes: copy });
            }}
            onRemove={() => {
              onChange({ ...rule, reply_attributes: attrs.filter((_, i) => i !== index) });
            }}
          />
        ))}
        <button
          type="button"
          onClick={() => {
            onChange({
              ...rule,
              reply_attributes: [...attrs, { name: "", separator: "=", value: "" }],
            });
          }}
        >
          Add AV pair
        </button>
      </fieldset>
      <div className="actions">
        <button type="button" onClick={() => onMove(-1)}>
          Move up
        </button>
        <button type="button" onClick={() => onMove(1)}>
          Move down
        </button>
        <button type="button" onClick={onRemove}>
          Remove service rule
        </button>
      </div>
    </div>
  );
}

function CommandRow({
  id,
  rule,
  onChange,
  onRemove,
  onMove,
}: {
  id: string;
  rule: CommandRuleView;
  onChange: (next: CommandRuleView) => void;
  onRemove: () => void;
  onMove: (dir: -1 | 1) => void;
}) {
  const cmdMode = matchMode(rule.command);
  const argMode = matchMode(rule.arguments);
  return (
    <div className="rule-card">
      <div className="rule-grid">
        <div className="field">
          <label htmlFor={`${id}-id`}>Rule ID</label>
          <input
            id={`${id}-id`}
            type="text"
            value={rule.id}
            onChange={(ev) => {
              onChange({ ...rule, id: ev.target.value });
            }}
          />
        </div>
        <div className="field">
          <label htmlFor={`${id}-priority`}>Priority</label>
          <input
            id={`${id}-priority`}
            type="number"
            value={rule.priority}
            onChange={(ev) => {
              onChange({ ...rule, priority: Number(ev.target.value) });
            }}
          />
        </div>
        <div className="field">
          <label htmlFor={`${id}-action`}>Action</label>
          <select
            id={`${id}-action`}
            value={rule.action}
            onChange={(ev) => {
              onChange({ ...rule, action: ev.target.value });
            }}
          >
            {RULE_ACTIONS.map((action) => (
              <option key={action} value={action}>
                {action}
              </option>
            ))}
          </select>
        </div>
      </div>
      <MatchFields
        id={`${id}-cmd`}
        label="Command match"
        mode={cmdMode}
        value={matchValue(rule.command)}
        onChange={(mode, val) => {
          onChange({ ...rule, command: toMatch(mode, val) });
        }}
      />
      <MatchFields
        id={`${id}-args`}
        label="Argument match"
        mode={argMode}
        value={matchValue(rule.arguments)}
        onChange={(mode, val) => {
          onChange({ ...rule, arguments: toMatch(mode, val) });
        }}
      />
      <div className="field">
        <label htmlFor={`${id}-reason`}>Reason</label>
        <input
          id={`${id}-reason`}
          type="text"
          value={rule.reason ?? ""}
          onChange={(ev) => {
            const next: CommandRuleView = { ...rule };
            if (ev.target.value === "") {
              delete next.reason;
            } else {
              next.reason = ev.target.value;
            }
            onChange(next);
          }}
        />
      </div>
      <div className="actions">
        <button type="button" onClick={() => onMove(-1)}>
          Move up
        </button>
        <button type="button" onClick={() => onMove(1)}>
          Move down
        </button>
        <button type="button" onClick={onRemove}>
          Remove command rule
        </button>
      </div>
    </div>
  );
}

function MatchFields({
  id,
  label,
  mode,
  value,
  onChange,
}: {
  id: string;
  label: string;
  mode: "exact" | "pattern";
  value: string;
  onChange: (mode: "exact" | "pattern", value: string) => void;
}) {
  return (
    <fieldset className="fieldset">
      <legend>{label}</legend>
      <div className="choice-row">
        <label>
          <input
            type="radio"
            name={`${id}-mode`}
            checked={mode === "exact"}
            onChange={() => {
              onChange("exact", value);
            }}
          />{" "}
          Exact
        </label>
        <label>
          <input
            type="radio"
            name={`${id}-mode`}
            checked={mode === "pattern"}
            onChange={() => {
              onChange("pattern", value);
            }}
          />{" "}
          Regex (RE2)
        </label>
      </div>
      <div className="field">
        <label htmlFor={`${id}-value`}>{mode === "pattern" ? "Pattern" : "Exact value"}</label>
        <input
          id={`${id}-value`}
          type="text"
          value={value}
          onChange={(ev) => {
            onChange(mode, ev.target.value);
          }}
        />
      </div>
    </fieldset>
  );
}

function AVRow({
  id,
  value,
  onChange,
  onRemove,
}: {
  id: string;
  value: PolicyTraceAV;
  onChange: (next: PolicyTraceAV) => void;
  onRemove: () => void;
}) {
  return (
    <div className="av-row">
      <div className="field">
        <label htmlFor={`${id}-name`}>Name</label>
        <input
          id={`${id}-name`}
          type="text"
          value={value.name}
          onChange={(ev) => {
            onChange({ ...value, name: ev.target.value });
          }}
        />
      </div>
      <div className="field">
        <label htmlFor={`${id}-sep`}>Separator</label>
        <select
          id={`${id}-sep`}
          value={value.separator === "*" ? "*" : "="}
          onChange={(ev) => {
            onChange({ ...value, separator: ev.target.value });
          }}
        >
          <option value="=">= mandatory</option>
          <option value="*">* optional</option>
        </select>
      </div>
      <div className="field">
        <label htmlFor={`${id}-val`}>Value</label>
        <input
          id={`${id}-val`}
          type="text"
          value={value.value}
          onChange={(ev) => {
            onChange({ ...value, value: ev.target.value });
          }}
        />
      </div>
      <button type="button" onClick={onRemove}>
        Remove AV
      </button>
    </div>
  );
}
