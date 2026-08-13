import type { OptionalSecret } from "../generated/api";

export type SecretDraft = { file: string; environment: string };

export function emptySecret(): SecretDraft {
  return { file: "", environment: "" };
}

export function secretPayload(draft: SecretDraft): OptionalSecret | undefined {
  const file = draft.file.trim();
  const environment = draft.environment.trim();
  if (file === "" && environment === "") {
    return undefined;
  }
  return {
    ...(file !== "" ? { file } : {}),
    ...(environment !== "" ? { environment } : {}),
  };
}

export function SecretRefFields({
  id,
  label,
  hint,
  value,
  onChange,
}: {
  id: string;
  label: string;
  hint: string;
  value: SecretDraft;
  onChange: (next: SecretDraft) => void;
}) {
  const fileId = `${id}-file`;
  const envId = `${id}-env`;
  const hintId = `${id}-hint`;
  return (
    <fieldset className="fieldset">
      <legend>{label}</legend>
      <p id={hintId} className="hint">
        {hint} Leave both blank to retain existing material. Values are write-only and are cleared after submit.
      </p>
      <div className="field">
        <label htmlFor={fileId}>Secret file path</label>
        <input
          id={fileId}
          name={`${id}-file`}
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={value.file}
          aria-describedby={hintId}
          onChange={(ev) => {
            onChange({ ...value, file: ev.target.value });
          }}
        />
      </div>
      <div className="field">
        <label htmlFor={envId}>Secret environment name</label>
        <input
          id={envId}
          name={`${id}-env`}
          type="password"
          autoComplete="off"
          spellCheck={false}
          value={value.environment}
          aria-describedby={hintId}
          onChange={(ev) => {
            onChange({ ...value, environment: ev.target.value });
          }}
        />
      </div>
    </fieldset>
  );
}
