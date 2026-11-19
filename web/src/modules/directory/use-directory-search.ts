import { useCallback, useEffect, useState } from "react";

import { ApiError, type createApiClient, problemOf } from "../../api/client";
import { type Failure } from "./search-model";
import {
  PAGE_SIZE,
  type SearchResult,
  readSearchResult,
  type SearchType,
  searchFailureOf,
} from "./search-results-model";

export type ApiClient = ReturnType<typeof createApiClient>;

export type DirectorySearchState =
  | { readonly status: "idle" }
  | { readonly status: "loading" }
  | { readonly status: "done"; readonly result: SearchResult }
  | { readonly status: "failed"; readonly failure: Failure };

/** An answer tagged with the request it belongs to, so a stale one is never shown for a new request. */
type Settled = { readonly for: string } & (
  | { readonly status: "done"; readonly result: SearchResult }
  | { readonly status: "failed"; readonly failure: Failure }
);

export interface DirectorySearch {
  readonly state: DirectorySearchState;
  readonly retry: () => void;
  /** The 1-based page of the chosen type that is showing. Always 1 when all types are shown. */
  readonly page: number;
  /** Loads the next page of the chosen type; undefined when there is none. */
  readonly next: (() => void) | undefined;
  /** Goes back one page; undefined on the first. */
  readonly previous: (() => void) | undefined;
  /** Returns to the first page; undefined when already there. */
  readonly first: (() => void) | undefined;
  /** The group counts of the last all-types answer to this same text: the API's trimmed numbers. */
  readonly counts: Readonly<Partial<Record<string, number>>>;
}

/**
 * Searches the directory for `q` (the committed, already validated text; "" means no search).
 * Without `type` it asks for every kind, one page each. With `type` it pages that one kind by the
 * API's cursor, 50 at a time; the cursors stay here, never in the address bar. Each request aborts
 * the one before it, so a slow early answer can never overwrite a newer one.
 */
export function useDirectorySearch(
  client: ApiClient,
  q: string,
  type: SearchType | undefined,
): DirectorySearch {
  const key = `${q}\n${type ?? ""}`;
  const [paging, setPaging] = useState<{ key: string; trail: readonly string[] }>({
    key,
    trail: [],
  });
  const trail = paging.key === key ? paging.trail : [];
  const cursor = trail[trail.length - 1];
  const [settled, setSettled] = useState<Settled | undefined>(undefined);
  const [attempt, setAttempt] = useState(0);
  const [known, setKnown] = useState<{ q: string; counts: Partial<Record<string, number>> }>({
    q: "",
    counts: {},
  });
  // The request this render asks for: its cursor is part of it, so paging reads as loading too.
  const requestKey = `${key}\n${cursor ?? ""}\n${attempt}`;

  useEffect(() => {
    if (q === "") return;
    const controller = new AbortController();
    client
      .POST("/directory/search", {
        body: {
          q,
          groupLimit: PAGE_SIZE,
          ...(type === undefined ? {} : { type }),
          ...(cursor === undefined ? {} : { cursor }),
        },
        signal: controller.signal,
      })
      .then(({ data, error, response }): SearchResult => {
        if (!response.ok) throw new ApiError(problemOf(error, response), response.status);
        return readSearchResult(data, response.headers.get("X-Trace-Id") ?? undefined);
      })
      .then(
        (result) => {
          if (controller.signal.aborted) return;
          setSettled({ for: requestKey, status: "done", result });
          if (type === undefined && !result.refine) {
            const counts: Partial<Record<string, number>> = {};
            for (const g of result.groups) if (g.count !== undefined) counts[g.type] = g.count;
            setKnown({ q, counts });
          }
        },
        (error: unknown) => {
          if (!controller.signal.aborted) {
            setSettled({ for: requestKey, status: "failed", failure: searchFailureOf(error) });
          }
        },
      );
    return () => controller.abort();
  }, [client, q, type, cursor, requestKey]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);

  const state: DirectorySearchState =
    q === ""
      ? { status: "idle" }
      : settled !== undefined && settled.for === requestKey
        ? settled
        : { status: "loading" };
  let nextCursor: string | undefined;
  if (state.status === "done" && type !== undefined) {
    nextCursor = state.result.groups.find((g) => g.type === type)?.nextCursor;
  }
  const next =
    nextCursor === undefined
      ? undefined
      : () => setPaging({ key, trail: [...trail, nextCursor as string] });
  const previous =
    trail.length === 0 ? undefined : () => setPaging({ key, trail: trail.slice(0, -1) });

  const first = trail.length === 0 ? undefined : () => setPaging({ key, trail: [] });

  return {
    state,
    retry,
    page: trail.length + 1,
    next,
    previous,
    first,
    counts: known.q === q ? known.counts : {},
  };
}
