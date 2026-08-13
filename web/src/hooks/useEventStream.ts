import { useQueryClient } from "@tanstack/react-query";
import { useEffect } from "react";
import { useAuth } from "../auth/AuthProvider";

const REVISION_CHANGED = "state.revision.changed";

export function useEventStream(): void {
  const queryClient = useQueryClient();
  const { hasScope, state } = useAuth();
  const signedIn = state.status === "signed_in";
  const canRead = hasScope("events:read");

  useEffect(() => {
    if (!signedIn || !canRead) {
      return;
    }
    const es = new EventSource("/api/v1/events/stream");
    const onMessage = (ev: MessageEvent<string>) => {
      if (!ev.data) {
        return;
      }
      try {
        const payload = JSON.parse(ev.data) as { type?: string; revision?: number };
        if (payload.type === REVISION_CHANGED || typeof payload.revision === "number") {
          void queryClient.invalidateQueries({ queryKey: ["status"] });
          void queryClient.invalidateQueries({ queryKey: ["build"] });
          void queryClient.invalidateQueries({ queryKey: ["events"] });
          void queryClient.invalidateQueries({ queryKey: ["tokens"] });
        }
      } catch {
        // ignore malformed frames
      }
    };
    es.addEventListener("message", onMessage);
    return () => {
      es.removeEventListener("message", onMessage);
      es.close();
    };
  }, [signedIn, canRead, queryClient]);
}
