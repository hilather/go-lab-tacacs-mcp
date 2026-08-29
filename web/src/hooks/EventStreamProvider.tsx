import type { ReactNode } from "react";
import { EventStreamContext } from "./eventStreamContext";
import { useOwnedEventStream } from "./useEventStream";

export function EventStreamProvider({ children }: { children: ReactNode }) {
  const stream = useOwnedEventStream(true);
  return <EventStreamContext.Provider value={stream}>{children}</EventStreamContext.Provider>;
}
