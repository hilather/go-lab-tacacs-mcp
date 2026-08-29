import { createContext } from "react";
import type { EventView } from "../generated/api";

export type StreamState = {
  connected: boolean;
  reconnecting: boolean;
  reset: boolean;
  lastEvent: EventView | null;
};

export const EventStreamContext = createContext<StreamState | null>(null);
