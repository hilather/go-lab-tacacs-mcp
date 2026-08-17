type RadiusPolicySelectProps = {
  id: string;
  value: string;
  options: readonly string[];
  onChange: (next: string) => void;
  disabled?: boolean;
};

export function RadiusPolicySelect({ id, value, options, onChange, disabled }: RadiusPolicySelectProps) {
  const items = [...new Set([...(value !== "" ? [value] : []), ...options])].sort((a, b) => a.localeCompare(b));
  const hintId = `${id}-hint`;
  return (
    <div className="field">
      <label htmlFor={id}>RADIUS policy</label>
      <select
        id={id}
        value={value}
        disabled={disabled}
        aria-describedby={hintId}
        onChange={(ev) => onChange(ev.target.value)}
      >
        <option value="">None</option>
        {items.map((policyId) => (
          <option key={policyId} value={policyId}>
            {policyId}
          </option>
        ))}
      </select>
      <p id={hintId} className="hint">
        Schema v2 only. Walk is user, then groups, then client, then fallback, then default deny. Empty
        clears the attachment.
      </p>
    </div>
  );
}
