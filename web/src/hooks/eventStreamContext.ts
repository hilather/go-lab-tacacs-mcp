import { createContext } from "react";
import type { EventView } from "../generated/api";

export type StreamState = {
  connected: boolean;
  reconnecting: boolean;
  reset: boolean;
  resetGeneration: number;
  lastEvent: EventView | null;
  recentEvents: EventView[];
};

export const EventStreamContext = createContext<StreamState | null>(null);
