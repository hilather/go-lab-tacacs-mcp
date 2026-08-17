type RadiusPolicySelectProps = {
  id: string;
  value: string;
  options: readonly string[];
  onChange: (next: string) => void;
  disabled?: boolean;
};

export function RadiusPolicySelect({ id, value, options, onChange, disabled }: RadiusPolicySelectProps) {
  const items = [...new Set(options.filter((policyId) => policyId !== ""))].sort((a, b) => a.localeCompare(b));
  const hintId = `${id}-hint`;
  const listId = `${id}-list`;
  return (
    <div className="field">
      <label htmlFor={id}>RADIUS policy</label>
      <input
        id={id}
        type="text"
        list={listId}
        value={value}
        disabled={disabled}
        autoComplete="off"
        spellCheck={false}
        aria-describedby={hintId}
        onChange={(ev) => onChange(ev.target.value)}
      />
      <datalist id={listId}>
        {items.map((policyId) => (
          <option key={policyId} value={policyId}>
            {policyId}
          </option>
        ))}
      </datalist>
      <p id={hintId} className="hint">
        Schema v2 only. Walk is user, then groups, then client, then fallback, then default deny. Empty
        clears the attachment. Type an id that exists on the snapshot; unknown ids fail the mutation.
      </p>
    </div>
  );
}
