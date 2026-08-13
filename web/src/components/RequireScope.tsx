import type { ReactNode } from "react";
import { useAuth } from "../auth/AuthProvider";

export function RequireScope({ scope, children }: { scope: string; children: ReactNode }) {
  const { hasScope } = useAuth();
  if (!hasScope(scope)) {
    return (
      <main className="page">
        <h1>Not authorized</h1>
        <div className="error-summary" role="alert">
          <h2>Missing scope</h2>
          <p>
            This page requires <code>{scope}</code>. The signed-in token does not include it.
          </p>
        </div>
      </main>
    );
  }
  return children;
}
