import { useCallback, useEffect, useRef, useState } from "react";

import {
  type ApiClient,
  type DefinitionSummary,
  type Failure,
  failureOf,
  listDefinitions,
} from "./api";

export type DefinitionsState =
  | { readonly status: "loading" }
  | { readonly status: "failed"; readonly failure: Failure }
  | {
      readonly status: "ready";
      readonly items: readonly DefinitionSummary[];
      readonly more: boolean;
      readonly loadingMore: boolean;
      /** The query these items answer: a search waits for its own answer, not the previous one. */
      readonly query: string;
    };

/**
 * The library for a query and category, a page at a time from the server. A newer query aborts the
 * one before it, so a slow early answer can never replace a newer one.
 */
export function useDefinitions(
  client: ApiClient,
  query: { readonly q: string; readonly category: string },
  enabled = true,
): { state: DefinitionsState; retry: () => void; loadMore: () => void } {
  const [state, setState] = useState<DefinitionsState>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);
  const cursor = useRef<string | null>(null);
  const items = useRef<readonly DefinitionSummary[]>([]);
  const busy = useRef(false);
  const controller = useRef<AbortController | null>(null);
  const { q, category } = query;

  useEffect(() => {
    if (!enabled) return;
    const c = new AbortController();
    controller.current = c;
    setState({ status: "loading" });
    busy.current = false;
    listDefinitions(client, { q, category }, c.signal).then(
      (list) => {
        if (c.signal.aborted) return;
        items.current = list.items;
        cursor.current = list.page.nextCursor;
        setState({
          status: "ready",
          items: list.items,
          more: list.page.nextCursor !== null,
          loadingMore: false,
          query: q,
        });
      },
      (error: unknown) => {
        if (!c.signal.aborted) setState({ status: "failed", failure: failureOf(error) });
      },
    );
    return () => c.abort();
  }, [client, q, category, attempt, enabled]);

  const loadMore = useCallback(() => {
    const c = controller.current;
    const next = cursor.current;
    if (!c || c.signal.aborted || next === null || busy.current) return;
    busy.current = true;
    setState((s) => (s.status === "ready" ? { ...s, loadingMore: true } : s));
    listDefinitions(client, { q, category, cursor: next }, c.signal).then(
      (list) => {
        if (c.signal.aborted) return;
        busy.current = false;
        items.current = [...items.current, ...list.items];
        cursor.current = list.page.nextCursor;
        setState({
          status: "ready",
          items: items.current,
          more: list.page.nextCursor !== null,
          loadingMore: false,
          query: q,
        });
      },
      (error: unknown) => {
        if (c.signal.aborted) return;
        busy.current = false;
        setState({ status: "failed", failure: failureOf(error) });
      },
    );
  }, [client, q, category]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);
  return { state, retry, loadMore };
}
