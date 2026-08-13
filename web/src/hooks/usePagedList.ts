import { useQuery } from "@tanstack/react-query";
import { useEffect, useState } from "react";
import type { Envelope } from "../generated/api";

type Page<T> = { items: T[]; next_cursor?: string };

export function usePagedList<T>(
  queryKey: readonly unknown[],
  fetchPage: (cursor?: string) => Promise<Envelope<Page<T>>>,
) {
  const first = useQuery({
    queryKey: [...queryKey],
    queryFn: () => fetchPage(undefined),
  });
  const [more, setMore] = useState<T[]>([]);
  const [cursor, setCursor] = useState<string | undefined>();

  useEffect(() => {
    setMore([]);
    setCursor(first.data?.data.next_cursor);
  }, [first.data]);

  async function loadMore(): Promise<void> {
    if (cursor === undefined || cursor === "") {
      return;
    }
    const env = await fetchPage(cursor);
    setMore((prev) => [...prev, ...env.data.items]);
    setCursor(env.data.next_cursor);
  }

  return {
    items: [...(first.data?.data.items ?? []), ...more],
    revision: first.data?.revision ?? 0,
    isPending: first.isPending,
    isError: first.isError,
    error: first.error,
    hasMore: cursor !== undefined && cursor !== "",
    loadMore,
  };
}
