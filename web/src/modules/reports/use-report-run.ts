import { useCallback, useEffect, useRef, useState } from "react";

import {
  type ApiClient,
  cancelRun,
  type Definition,
  type Failure,
  failureOf,
  getRun,
  listRows,
  type Row,
  type ColumnInfo,
  type Run,
  retryRun,
  startRun,
} from "./api";
import { buildRunBody, runKey, type View } from "./model";

/** How long to wait between looks at a run that has not finished. */
export const POLL_MS = 1000;

export type RunState =
  | { readonly status: "starting" }
  | { readonly status: "failed"; readonly failure: Failure }
  | { readonly status: "run"; readonly run: Run };

const active = (run: Run) => run.state === "queued" || run.state === "running";

const sleep = (ms: number, signal: AbortSignal) =>
  new Promise<void>((resolve) => {
    const t = setTimeout(resolve, ms);
    signal.addEventListener("abort", () => {
      clearTimeout(t);
      resolve();
    });
  });

/**
 * Opening a report starts its run (no Generate step, FR-04) and follows it until it ends. A change of
 * preset, period, columns or filters is a new run; the sort is not part of the key. Leaving the page
 * stops looking, not the run: it keeps going on the server.
 */
export function useReportRun(client: ApiClient, definition: Definition | null, view: View) {
  const [state, setState] = useState<RunState>({ status: "starting" });
  const [nonce, setNonce] = useState(0);
  const adopted = useRef<Run | null>(null);
  const key = runKey(view);
  const definitionId = definition?.id;

  useEffect(() => {
    if (!definition) return;
    const c = new AbortController();
    const seed = adopted.current;
    adopted.current = null;
    const follow = async (first: Run) => {
      let run = first;
      setState({ status: "run", run });
      while (active(run) && !c.signal.aborted) {
        await sleep(POLL_MS, c.signal);
        if (c.signal.aborted) return;
        run = await getRun(client, run.id, c.signal);
        if (!c.signal.aborted) setState({ status: "run", run });
      }
    };
    const begin = async () => {
      if (seed) return follow(seed);
      setState({ status: "starting" });
      const preset = definition.presets.find((p) => p.id === view.preset);
      const body = buildRunBody(definition, preset, view);
      return follow(await startRun(client, body, c.signal));
    };
    begin().catch((error: unknown) => {
      if (!c.signal.aborted) setState({ status: "failed", failure: failureOf(error) });
    });
    return () => c.abort();
    // The view enters through its key; the sort must not start a run.
  }, [client, definitionId, key, nonce]);

  const adoptRun = useCallback((run: Run) => {
    adopted.current = run;
    setNonce((n) => n + 1);
  }, []);
  /** A new run with the same settings. */
  const rerun = useCallback(() => setNonce((n) => n + 1), []);
  const cancel = useCallback(
    (runId: string) =>
      cancelRun(client, runId).then(
        (run) => setState({ status: "run", run }),
        (error: unknown) => setState({ status: "failed", failure: failureOf(error) }),
      ),
    [client],
  );
  const retry = useCallback(
    (runId: string) =>
      retryRun(client, runId).then(adoptRun, (error: unknown) =>
        setState({ status: "failed", failure: failureOf(error) }),
      ),
    [client, adoptRun],
  );
  return { state, rerun, cancel, retry };
}

export type RowsState =
  | { readonly status: "idle" }
  | { readonly status: "loading" }
  | { readonly status: "failed"; readonly failure: Failure }
  | {
      readonly status: "ready";
      readonly columns: readonly ColumnInfo[];
      readonly rows: readonly Row[];
      readonly more: boolean;
      readonly loadingMore: boolean;
      /** A re-sort is on its way; the rows shown are the previous order. */
      readonly busy: boolean;
    };

/**
 * The stored rows of a succeeded run, a page at a time. Sorting asks the server again for the same
 * run from its first row (the cursor is bound to a sort); nothing is sorted or filtered in the browser.
 */
export function useRows(
  client: ApiClient,
  runId: string | null,
  sort: { readonly key: string; readonly order: "asc" | "desc" } | null,
) {
  const [state, setState] = useState<RowsState>({ status: "idle" });
  const [attempt, setAttempt] = useState(0);
  const cursor = useRef<string | null>(null);
  const loaded = useRef<readonly Row[]>([]);
  const busy = useRef(false);
  const ctl = useRef<AbortController | null>(null);
  const sortKey = sort?.key ?? null;
  const sortOrder = sort?.order ?? "asc";

  useEffect(() => {
    if (runId === null) {
      setState({ status: "idle" });
      return;
    }
    const c = new AbortController();
    ctl.current = c;
    busy.current = false;
    setState((s) => (s.status === "ready" ? { ...s, busy: true } : { status: "loading" }));
    listRows(client, runId, sortKey ? { sortBy: sortKey, order: sortOrder } : {}, c.signal).then(
      (page) => {
        if (c.signal.aborted) return;
        loaded.current = page.rows;
        cursor.current = page.page.nextCursor;
        setState({
          status: "ready",
          columns: page.columns,
          rows: page.rows,
          more: page.page.nextCursor !== null,
          loadingMore: false,
          busy: false,
        });
      },
      (error: unknown) => {
        if (!c.signal.aborted) setState({ status: "failed", failure: failureOf(error) });
      },
    );
    return () => c.abort();
  }, [client, runId, sortKey, sortOrder, attempt]);

  const loadMore = useCallback(() => {
    const c = ctl.current;
    const next = cursor.current;
    if (!c || c.signal.aborted || runId === null || next === null || busy.current) return;
    busy.current = true;
    setState((s) => (s.status === "ready" ? { ...s, loadingMore: true } : s));
    listRows(
      client,
      runId,
      { cursor: next, ...(sortKey ? { sortBy: sortKey, order: sortOrder } : {}) },
      c.signal,
    ).then(
      (page) => {
        if (c.signal.aborted) return;
        busy.current = false;
        loaded.current = [...loaded.current, ...page.rows];
        cursor.current = page.page.nextCursor;
        setState({
          status: "ready",
          columns: page.columns,
          rows: loaded.current,
          more: page.page.nextCursor !== null,
          loadingMore: false,
          busy: false,
        });
      },
      (error: unknown) => {
        if (c.signal.aborted) return;
        busy.current = false;
        setState({ status: "failed", failure: failureOf(error) });
      },
    );
  }, [client, runId, sortKey, sortOrder]);

  const retry = useCallback(() => setAttempt((n) => n + 1), []);
  return { state, loadMore, retry };
}
