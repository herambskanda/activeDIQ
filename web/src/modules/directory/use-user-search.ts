import { useCallback, useEffect, useState } from "react";

import { type createApiClient, unwrap } from "../../api/client";
import type { components } from "../../api/schema.gen";
import { type Failure, failureOf, SEARCH_LIMIT } from "./search-model";

export type DirectoryUser = components["schemas"]["DirectoryUser"];
export type ApiClient = ReturnType<typeof createApiClient>;

export type SearchState =
  | { readonly status: "idle" }
  | { readonly status: "loading" }
  | { readonly status: "done"; readonly users: readonly DirectoryUser[] }
  | { readonly status: "failed"; readonly failure: Failure };

/**
 * Searches users for the committed query. Each query aborts the one before it, so a slow early
 * answer can never overwrite a newer one. `retry` repeats the current query.
 */
export function useUserSearch(
  client: ApiClient,
  query: string,
): { state: SearchState; retry: () => void } {
  const [state, setState] = useState<SearchState>({ status: "idle" });
  const [attempt, setAttempt] = useState(0);

  useEffect(() => {
    if (query === "") {
      setState({ status: "idle" });
      return;
    }
    const controller = new AbortController();
    setState({ status: "loading" });
    unwrap(
      client.GET("/directory/users", {
        params: { query: { q: query, limit: SEARCH_LIMIT } },
        signal: controller.signal,
      }),
    ).then(
      (list) => {
        if (!controller.signal.aborted) setState({ status: "done", users: list.items });
      },
      (error: unknown) => {
        if (!controller.signal.aborted) setState({ status: "failed", failure: failureOf(error) });
      },
    );
    return () => controller.abort();
  }, [client, query, attempt]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);
  return { state, retry };
}
