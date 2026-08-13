import { APIError } from "../api/client";

export function errorDetail(err: unknown, fallback: string): string {
  if (err instanceof APIError) {
    return err.problem.detail || err.problem.title || fallback;
  }
  if (err instanceof Error && err.message !== "") {
    return err.message;
  }
  return fallback;
}

export function matchesFilter(filter: string, parts: Array<string | undefined>): boolean {
  const q = filter.trim().toLowerCase();
  if (q === "") {
    return true;
  }
  return parts.some((part) => (part ?? "").toLowerCase().includes(q));
}
