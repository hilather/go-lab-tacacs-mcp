import { useQuery } from "@tanstack/react-query";
import { useState } from "react";
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
  const firstData = first.data;
  const [extra, setExtra] = useState<{
    source: typeof firstData;
    more: T[];
    cursor: string | undefined;
  }>(() => ({
    source: firstData,
    more: [],
    cursor: firstData?.data.next_cursor,
  }));
  const more = extra.source === firstData ? extra.more : [];
  const cursor = extra.source === firstData ? extra.cursor : firstData?.data.next_cursor;

  async function loadMore(): Promise<void> {
    if (cursor === undefined || cursor === "") {
      return;
    }
    const env = await fetchPage(cursor);
    setExtra((prev) => ({
      source: firstData,
      more: [...(prev.source === firstData ? prev.more : []), ...env.data.items],
      cursor: env.data.next_cursor,
    }));
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
