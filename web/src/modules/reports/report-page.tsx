import { type ReactNode, useEffect, useMemo, useState } from "react";

import { api } from "../../api/client";
import { navigate, useLocation } from "../../app/location";
import {
  Banner,
  Button,
  Chip,
  DataGrid,
  type DataGridColumn,
  Progress,
  Skeleton,
  StatePanel,
} from "../../ds/components";
import {
  type ApiClient,
  type Definition,
  type Failure,
  failureOf,
  getDefinition,
  type Row,
  type Run,
} from "./api";
import { Controls } from "./controls";
import { ReportsFrame } from "./frame";
import {
  ageText,
  cellText,
  failureText,
  filtersTest,
  formatCount,
  formatTime,
  freshnessTone,
  OPERATOR_LABEL,
  parseView,
  SERVICE_ACCOUNT_COLUMN,
  viewToSearch,
  type View,
} from "./model";
import { type RunState, useReportRun, useRows } from "./use-report-run";

type DefinitionState =
  | { readonly status: "loading" }
  | { readonly status: "failed"; readonly failure: Failure }
  | { readonly status: "ready"; readonly definition: Definition };

function useDefinition(client: ApiClient, id: string) {
  const [state, setState] = useState<DefinitionState>({ status: "loading" });
  const [attempt, setAttempt] = useState(0);
  useEffect(() => {
    const c = new AbortController();
    setState({ status: "loading" });
    getDefinition(client, id, c.signal).then(
      (definition) => !c.signal.aborted && setState({ status: "ready", definition }),
      (e: unknown) => !c.signal.aborted && setState({ status: "failed", failure: failureOf(e) }),
    );
    return () => c.abort();
  }, [client, id, attempt]);
  return { state, retry: () => setAttempt((n) => n + 1) };
}

/** A report needs objects named by GUID (a group, a user) that the console cannot offer yet. */
const needsSubjects = (d: Definition) => d.subjectKind !== "" && d.subjectKind !== "none";

function FailurePanel({
  failure,
  onRetry,
  retryLabel = "Retry",
}: {
  readonly failure: Failure;
  readonly onRetry?: () => void;
  readonly retryLabel?: string;
}) {
  const calm = failure.kind === "forbidden" || failure.kind === "not-found";
  const actions =
    onRetry && !calm ? (
      <Button variant="primary" onClick={onRetry}>
        {retryLabel}
      </Button>
    ) : undefined;
  return (
    <StatePanel tone={calm ? "neutral" : "error"} title={failure.title} actions={actions}>
      <p>{failure.detail}</p>
      {failure.traceId !== undefined && (
        <p>
          Trace ID <span className="diq-mono">{failure.traceId}</span>
        </p>
      )}
    </StatePanel>
  );
}

function CopyRequest({ text }: { readonly text: string }) {
  const [done, setDone] = useState<"idle" | "copied" | "failed">("idle");
  return (
    <>
      <Button
        onClick={() => {
          navigator.clipboard.writeText(text).then(
            () => setDone("copied"),
            () => setDone("failed"),
          );
        }}
      >
        Copy a request for your administrator
      </Button>
      <span role="status" className="diq-hint">
        {done === "copied" && "Copied."}
        {done === "failed" && "Could not copy. Select the text and copy it yourself."}
      </span>
    </>
  );
}

function RunStrip({ run }: { readonly run: Run }) {
  const tone = freshnessTone(run);
  return (
    <dl className="rp-strip">
      <div>
        <dt>Data</dt>
        <dd>
          <Chip tone={tone}>{run.freshness.label}</Chip>
        </dd>
      </div>
      {run.scopeApplied !== null && (
        <div>
          <dt>Scope</dt>
          <dd>{run.scopeApplied}</dd>
        </div>
      )}
      {run.rowCount !== null && (
        <div>
          <dt>Rows</dt>
          <dd className="diq-mono">
            {formatCount(run.rowCount)}
            {run.objectsChecked !== null && ` of ${formatCount(run.objectsChecked)} checked`}
          </dd>
        </div>
      )}
      {run.asOf !== null && (
        <div>
          <dt>As of</dt>
          <dd className="diq-mono">{formatTime(run.asOf)}</dd>
        </div>
      )}
      <div>
        <dt>Run</dt>
        <dd className="diq-mono" title={run.id}>
          {run.id.slice(0, 8)}
        </dd>
      </div>
    </dl>
  );
}

function Banners({
  run,
  view,
  definition,
  change,
}: {
  readonly run: Run;
  readonly view: View;
  readonly definition: Definition;
  readonly change: (n: Partial<View>) => void;
}) {
  const out: ReactNode[] = [];
  if (run.freshness.state === "stale") {
    const asOfIso = run.asOf;
    const asOf = asOfIso !== null ? new Date(asOfIso) : null;
    out.push(
      <Banner key="stale" tone="warn" title="Stale data">
        <p>
          {run.freshness.label}
          {asOf !== null &&
            ` (data as of ${formatTime(asOfIso as string)}, ${ageText(asOf, new Date())})`}
          . This report ran on what activeDIQ last saw. Exports and scheduled deliveries carry this
          warning.
        </p>
      </Banner>,
    );
  }
  if (run.skippedConnections.length > 0) {
    const n = run.skippedConnections.length;
    out.push(
      <Banner key="skipped" tone="info" title="Not synced yet">
        <p>
          {n === 1 ? "1 connection has" : `${n} connections have`} not finished a first sync, so{" "}
          {n === 1 ? "it is" : "they are"} skipped. The rows below cover the others.
        </p>
      </Banner>,
    );
  }
  if (run.coverage && !run.coverage.complete) {
    const { dcsAnswered: a, dcsInScope: m } = run.coverage;
    out.push(
      <Banner key="dc" tone="warn" title={`Read from ${a} of ${m} domain controllers`}>
        <p>
          {m - a} did not answer. Dates are the latest logon found, “at least”: no value from the{" "}
          {a} that answered does not mean the account never logged on.
        </p>
      </Banner>,
    );
  }
  const preset = definition.presets.find((p) => p.id === (view.preset ?? run.presetId));
  const presetHides = preset !== undefined && filtersTest(preset.filters, SERVICE_ACCOUNT_COLUMN);
  if (
    presetHides &&
    !view.showServiceAccounts &&
    filtersTest(run.parameters.filters, SERVICE_ACCOUNT_COLUMN)
  ) {
    out.push(
      <Banner
        key="svc"
        tone="info"
        title="Probable service accounts are hidden"
        actions={<Button onClick={() => change({ showServiceAccounts: true })}>Show them</Button>}
      >
        <p>
          This preset leaves out accounts that look like service accounts. They are not deleted from
          the data.
        </p>
      </Banner>,
    );
  } else if (presetHides && view.showServiceAccounts) {
    out.push(
      <Banner
        key="svc"
        tone="info"
        title="Probable service accounts are included"
        actions={<Button onClick={() => change({ showServiceAccounts: false })}>Hide them</Button>}
      />,
    );
  }
  return <>{out}</>;
}

function Grid({
  definition,
  run,
  view,
  rows,
  onSort,
}: {
  readonly definition: Definition;
  readonly run: Run;
  readonly view: View;
  readonly rows: ReturnType<typeof useRows>;
  readonly onSort: (key: string) => void;
}) {
  const s = rows.state;
  const columns = useMemo<DataGridColumn<Row>[]>(
    () =>
      s.status !== "ready"
        ? []
        : s.columns.map((c, i) => ({
            key: c.id,
            header: c.label,
            sortable: c.sortable,
            width: i === 0 ? 26 : 18,
            ...(c.type === "integer" ? { align: "end" as const, mono: true } : {}),
            ...(c.type === "time" ? { mono: true } : {}),
            cell: (row: Row) => {
              const cell = row.cells[i];
              return cell ? cellText(cell, c) : "";
            },
          })),
    [s],
  );
  if (s.status === "loading" || s.status === "idle")
    return <Skeleton label="Loading rows" rows={8} />;
  if (s.status === "failed") {
    const f = s.failure;
    if (f.kind === "expired" || f.kind === "scope-changed") return null; // the run panel above says it
    return <FailurePanel failure={f} onRetry={rows.retry} />;
  }
  return (
    <>
      <DataGrid
        caption={`${definition.name}: ${formatCount(run.rowCount ?? s.rows.length)} rows`}
        columns={columns}
        rows={s.rows}
        rowKey={(r) => r.rowKey}
        sort={view.sort ? { key: view.sort, dir: view.order } : null}
        onSort={onSort}
        busy={s.busy}
        resizable
        visibleRows={18}
      />
      <p className="rp-pager" role="status">
        Showing {formatCount(s.rows.length)} of {formatCount(run.rowCount ?? s.rows.length)} rows
        {s.more && (
          <>
            {" "}
            <Button loading={s.loadingMore} onClick={rows.loadMore}>
              Load more rows
            </Button>
          </>
        )}
      </p>
    </>
  );
}

function RunBody({
  client,
  definition,
  view,
  change,
  rs,
  rerun,
  cancel,
  retry,
}: {
  readonly client: ApiClient;
  readonly definition: Definition;
  readonly view: View;
  readonly change: (n: Partial<View>) => void;
  readonly rs: RunState;
  readonly rerun: () => void;
  readonly cancel: (id: string) => void;
  readonly retry: (id: string) => void;
}) {
  const run = rs.status === "run" ? rs.run : null;
  const showRows =
    run !== null && run.state === "succeeded" && (run.rowCount ?? 0) > 0 && !run.emptyReason;
  const rows = useRows(
    client,
    showRows ? run.id : null,
    view.sort ? { key: view.sort, order: view.order } : null,
  );

  const onSort = (key: string) => {
    if (view.sort !== key) change({ sort: key, order: "asc" });
    else if (view.order === "asc") change({ order: "desc" });
    else change({ sort: null, order: "asc" });
  };

  if (rs.status === "starting") return <Skeleton label="Starting the report" rows={8} />;
  if (rs.status === "failed")
    return <FailurePanel failure={rs.failure} onRetry={rerun} retryLabel="Retry (new run)" />;
  const r = rs.run;

  if (r.state === "queued" || r.state === "running") {
    return (
      <div aria-busy="true">
        <p role="status">
          {definition.perDc ? "Reading domain controllers…" : "Running…"} The first page appears as
          soon as it is ready.
        </p>
        <Progress
          label={`Run progress: ${r.progress.stage.replace(/_/g, " ")}`}
          value={r.progress.percent}
        />
        {definition.perDc && (
          <p className="diq-hint">
            This runs in the background; you can leave the page and it keeps going.
          </p>
        )}
        <Skeleton label="Waiting for the first page" rows={6} />
        <Button onClick={() => cancel(r.id)}>Cancel run</Button>
      </div>
    );
  }
  if (r.state === "failed") {
    const why = r.failure ? failureText(r.failure.reason, r.failure.message) : "an internal error";
    return (
      <StatePanel
        tone="error"
        title={`This run failed: ${why}`}
        actions={
          <Button variant="primary" onClick={() => retry(r.id)}>
            Retry (new run)
          </Button>
        }
      >
        <p>
          Nothing was changed and no file or e-mail was sent. Run{" "}
          <span className="diq-mono">{r.id.slice(0, 8)}</span> is kept with this reason.
        </p>
      </StatePanel>
    );
  }
  if (r.state === "cancelled") {
    return (
      <StatePanel
        title="Run cancelled"
        actions={
          <Button variant="primary" onClick={rerun}>
            Run again
          </Button>
        }
      >
        <p>Nothing was changed. No partial result is kept as current.</p>
      </StatePanel>
    );
  }
  if (
    r.state === "expired" ||
    (rows.state.status === "failed" && rows.state.failure.kind === "expired")
  ) {
    return (
      <StatePanel
        title="This result has expired"
        actions={
          <Button variant="primary" onClick={rerun}>
            Run again with the same settings
          </Button>
        }
      >
        <p>
          {r.startedAt !== null ? `This run started on ${formatTime(r.startedAt)}. ` : ""}It is no
          longer kept and is not shown as current. Run it again to see today’s data.
        </p>
      </StatePanel>
    );
  }
  if (rows.state.status === "failed" && rows.state.failure.kind === "scope-changed") {
    return (
      <StatePanel
        title={rows.state.failure.title}
        actions={
          <Button variant="primary" onClick={rerun}>
            Run again
          </Button>
        }
      >
        <p>{rows.state.failure.detail}</p>
      </StatePanel>
    );
  }

  const request = `Please give my role a scope that reports can use (a domain or an OU). The scope I run reports with now: ${r.scopeApplied ?? "none"}.`;
  let body: ReactNode;
  if (r.emptyReason === "scope_grants_nothing") {
    body = (
      <StatePanel
        title="Your role covers no directory objects"
        actions={<CopyRequest text={request} />}
      >
        <p>
          Ask an administrator to grant a scope. There are zero rows because nothing is in your
          scope; this is not an error and nothing is broken.
        </p>
      </StatePanel>
    );
  } else if (r.emptyReason) {
    body = (
      <StatePanel
        title="Reports can’t use your role’s scope yet"
        actions={<CopyRequest text={request} />}
      >
        <p>
          Your role is scoped in a way reports don’t support at this stage. Reports return nothing
          rather than guess, so there are zero rows. Ask an administrator to scope your role by
          domain or OU.
        </p>
      </StatePanel>
    );
  } else if ((r.rowCount ?? 0) === 0) {
    body = (
      <StatePanel
        title="No rows match"
        actions={
          view.filters.length > 0 ? (
            <Button onClick={() => change({ filters: [] })}>
              Remove {view.filters.length === 1 ? "the filter" : "all filters"}
            </Button>
          ) : undefined
        }
      >
        <p>
          {r.objectsChecked !== null
            ? `${formatCount(r.objectsChecked)} objects were checked`
            : "The objects in scope were checked"}
          {r.asOf !== null ? ` as of ${formatTime(r.asOf)}` : ""}. The filters on this report
          matched none of them.
        </p>
      </StatePanel>
    );
  } else {
    body = <Grid definition={definition} run={r} view={view} rows={rows} onSort={onSort} />;
  }
  return (
    <>
      <Banners run={r} view={view} definition={definition} change={change} />
      {body}
    </>
  );
}

/**
 * One report (spec §5, FR-04): opening it runs its preset and shows the first page, with no Generate
 * step. The preset, period, columns, filters and sort are in the address bar; all but the sort make a
 * new run, and the sort re-orders the same run on the server.
 */
export function ReportPage({ client = api }: { readonly client?: ApiClient }) {
  const { pathname, search } = useLocation();
  const id = decodeURIComponent(pathname.split("/")[2] ?? "");
  const searchText = search.toString();
  const view = useMemo(() => parseView(new URLSearchParams(searchText)), [searchText]);
  const { state: def, retry: retryDefinition } = useDefinition(client, id);
  const definition = def.status === "ready" ? def.definition : null;
  const runnable = definition !== null && !needsSubjects(definition) ? definition : null;
  const { state: rs, rerun, cancel, retry } = useReportRun(client, runnable, view);
  const run = rs.status === "run" ? rs.run : null;

  const change = (next: Partial<View>) =>
    navigate(`/reports/${encodeURIComponent(id)}${viewToSearch({ ...view, ...next })}`);

  let content: ReactNode;
  if (def.status === "loading") content = <Skeleton label="Loading the report" rows={8} />;
  else if (def.status === "failed")
    content = <FailurePanel failure={def.failure} onRetry={retryDefinition} />;
  else {
    const d = def.definition;
    const presetId = view.preset ?? run?.presetId ?? null;
    const alias = d.alsoKnownAs.find(
      (m) => m.presetId === presetId && view.preset !== null,
    )?.meName;
    content = (
      <>
        <h2 className="rp-title">{d.name}</h2>
        {alias !== undefined && <p className="diq-hint">Also known as: {alias}</p>}
        {run !== null && <RunStrip run={run} />}
        {needsSubjects(d) ? (
          <StatePanel title="This report is about a specific group or user">
            <p>
              Choosing the {d.subjectKind} it covers needs an object picker, which the console does
              not have yet. Nothing has been run.
            </p>
          </StatePanel>
        ) : (
          <>
            <Controls definition={d} run={run} view={view} change={change} />
            {view.filters.length > 0 && (
              <ul className="rp-applied" aria-label="Filters applied">
                {view.filters.map((f, i) => {
                  const col = d.columns.find((c) => c.id === f.column)?.label ?? f.column;
                  const text = `${col} ${OPERATOR_LABEL[f.operator] ?? f.operator}${f.value ? ` ${f.value}` : ""}`;
                  return (
                    <li key={`${f.column}${f.operator}${f.value}${i}`}>
                      <Button
                        onClick={() => change({ filters: view.filters.filter((_, j) => j !== i) })}
                      >
                        <span className="diq-sr-only">Remove filter: </span>
                        {text} ✕
                      </Button>
                    </li>
                  );
                })}
              </ul>
            )}
            <RunBody
              client={client}
              definition={d}
              view={view}
              change={change}
              rs={rs}
              rerun={rerun}
              cancel={(rid) => void cancel(rid)}
              retry={(rid) => void retry(rid)}
            />
          </>
        )}
      </>
    );
  }
  return <ReportsFrame client={client}>{content}</ReportsFrame>;
}
