export function RevisionConflict({
  detail,
  onReload,
  onRetry,
  compare,
}: {
  detail?: string | undefined;
  onReload: () => void;
  onRetry: () => void;
  compare?: { field: string; yours: string; server: string }[] | undefined;
}) {
  return (
    <section className="error-summary" role="alert" tabIndex={-1} aria-labelledby="revision-conflict-heading">
      <h2 id="revision-conflict-heading">Revision conflict</h2>
      <p>
        {detail && detail !== ""
          ? detail
          : "The published snapshot changed. Reload the latest object or retry your unsaved form against the new revision."}
      </p>
      {compare && compare.length > 0 ? (
        <table className="data">
          <caption>Compare unsaved edits with the latest server object</caption>
          <thead>
            <tr>
              <th scope="col">Field</th>
              <th scope="col">Your edit</th>
              <th scope="col">Latest server</th>
            </tr>
          </thead>
          <tbody>
            {compare.map((row) => (
              <tr key={row.field}>
                <th scope="row">{row.field}</th>
                <td>{row.yours}</td>
                <td>{row.server}</td>
              </tr>
            ))}
          </tbody>
        </table>
      ) : null}
      <div className="actions">
        <button type="button" onClick={onReload}>
          Reload latest
        </button>
        <button type="button" onClick={onRetry}>
          Retry with current revision
        </button>
      </div>
    </section>
  );
}
