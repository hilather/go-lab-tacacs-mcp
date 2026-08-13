import { forwardRef } from "react";

export const ErrorSummary = forwardRef<
  HTMLDivElement,
  { id: string; title: string; messages: string[] }
>(function ErrorSummary({ id, title, messages }, ref) {
  if (messages.length === 0) {
    return null;
  }
  return (
    <div ref={ref} className="error-summary" id={id} role="alert" tabIndex={-1}>
      <h2>{title}</h2>
      <ul>
        {messages.map((msg) => (
          <li key={msg}>{msg}</li>
        ))}
      </ul>
    </div>
  );
});
