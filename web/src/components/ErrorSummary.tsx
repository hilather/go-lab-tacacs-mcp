export function ErrorSummary({
  id,
  title,
  messages,
}: {
  id: string;
  title: string;
  messages: string[];
}) {
  if (messages.length === 0) {
    return null;
  }
  return (
    <div className="error-summary" id={id} role="alert" tabIndex={-1}>
      <h2>{title}</h2>
      <ul>
        {messages.map((msg) => (
          <li key={msg}>{msg}</li>
        ))}
      </ul>
    </div>
  );
}
