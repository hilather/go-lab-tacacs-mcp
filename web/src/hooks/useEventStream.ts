import { useQueryClient } from "@tanstack/react-query";
import { useContext, useEffect, useState } from "react";
import { useAuth } from "../auth/AuthProvider";
import type { EventView } from "../generated/api";
import { EventStreamContext, type StreamState } from "./eventStreamContext";

const REVISION_CHANGED = "state.revision.changed";

export const RESOURCE_QUERY_KEYS = [
  ["status"],
  ["build"],
  ["events"],
  ["tokens"],
  ["users"],
  ["groups"],
  ["clients"],
  ["config"],
] as const;

export type { StreamState };

function isEventView(v: unknown): v is EventView {
  if (!v || typeof v !== "object") {
    return false;
  }
  const rec = v as Record<string, unknown>;
  return typeof rec.id === "number" && typeof rec.type === "string" && typeof rec.category === "string";
}

function invalidateResources(queryClient: ReturnType<typeof useQueryClient>): void {
  for (const key of RESOURCE_QUERY_KEYS) {
    void queryClient.invalidateQueries({ queryKey: [...key] });
  }
}

const idle: StreamState = { connected: false, reconnecting: false, reset: false, lastEvent: null };

/** Always calls the same hooks. When enabled is false, no EventSource is opened. */
export function useOwnedEventStream(enabled: boolean): StreamState {
  const queryClient = useQueryClient();
  const { hasScope, state } = useAuth();
  const signedIn = state.status === "signed_in";
  const canRead = hasScope("events:read");
  const [stream, setStream] = useState<StreamState>(idle);

  useEffect(() => {
    if (!enabled || !signedIn || !canRead) {
      return;
    }
    const es = new EventSource("/api/v1/events/stream");
    const onOpen = () => {
      setStream((prev) => ({ ...prev, connected: true, reconnecting: false }));
    };
    const onError = () => {
      setStream((prev) => ({ ...prev, connected: false, reconnecting: true }));
    };
    const onReset = () => {
      setStream((prev) => ({ ...prev, reset: true }));
      invalidateResources(queryClient);
    };
    const onMessage = (ev: MessageEvent<string>) => {
      if (!ev.data) {
        return;
      }
      try {
        const payload = JSON.parse(ev.data) as { type?: string; revision?: number; reset?: boolean };
        if (payload.reset === true) {
          onReset();
          return;
        }
        if (isEventView(payload)) {
          setStream((prev) => ({ ...prev, lastEvent: payload, reset: false }));
        }
        if (payload.type === REVISION_CHANGED) {
          invalidateResources(queryClient);
        }
      } catch {
        // ignore malformed frames
      }
    };
    es.addEventListener("open", onOpen);
    es.addEventListener("error", onError);
    es.addEventListener("message", onMessage);
    es.addEventListener("reset", onReset);
    return () => {
      es.removeEventListener("open", onOpen);
      es.removeEventListener("error", onError);
      es.removeEventListener("message", onMessage);
      es.removeEventListener("reset", onReset);
      es.close();
    };
  }, [enabled, signedIn, canRead, queryClient]);

  return stream;
}

export function useEventStream(): StreamState {
  const ctx = useContext(EventStreamContext);
  const local = useOwnedEventStream(ctx === null);
  return ctx ?? local;
}
