// The reports module's whole contact with the API: the generated client, typed. Nothing else in the
// module calls it, and nothing here invents data (ADR-0004 rule 12).
import { ApiError, type createApiClient, type Problem, unwrap } from "../../api/client";
import type { components } from "../../api/schema.gen";

export type ApiClient = ReturnType<typeof createApiClient>;
type S = components["schemas"];

export type DefinitionSummary = S["ReportDefinitionSummary"];
export type Definition = S["ReportDefinition"];
export type Preset = S["ReportPreset"];
export type ColumnInfo = S["ReportColumnInfo"];
export type Run = S["ReportRun"];
export type RowPage = S["ReportRowPage"];
export type Row = S["ReportRow"];
export type Cell = S["ReportCell"];
export type Filter = S["ReportFilter"];
export type FilterView = S["ReportFilterView"];
export type Value = S["ReportValue"];
export type RunParameters = S["ReportRunParameters"];

/** The library page size and the rows page size. The API caps both at 1000. */
export const DEFINITIONS_LIMIT = 50;
export const ROWS_LIMIT = 500;

export function listDefinitions(
  client: ApiClient,
  query: { q?: string; category?: string; cursor?: string; limit?: number },
  signal?: AbortSignal,
) {
  const params: { q?: string; category?: S["ReportCategory"]; cursor?: string; limit?: number } = {
    limit: query.limit ?? DEFINITIONS_LIMIT,
  };
  if (query.q) params.q = query.q;
  if (query.category) params.category = query.category as S["ReportCategory"];
  if (query.cursor) params.cursor = query.cursor;
  return unwrap(
    client.GET("/reports/definitions", {
      params: { query: params },
      ...(signal ? { signal } : {}),
    }),
  );
}

export function getDefinition(client: ApiClient, id: string, signal?: AbortSignal) {
  return unwrap(
    client.GET("/reports/definitions/{definitionId}", {
      params: { path: { definitionId: id } },
      ...(signal ? { signal } : {}),
    }),
  );
}

export function startRun(
  client: ApiClient,
  body: S["ReportRunCreate"],
  signal?: AbortSignal,
): Promise<Run> {
  return unwrap(client.POST("/reports/runs", { body, ...(signal ? { signal } : {}) }));
}

export function getRun(client: ApiClient, runId: string, signal?: AbortSignal): Promise<Run> {
  return unwrap(
    client.GET("/reports/runs/{runId}", {
      params: { path: { runId } },
      ...(signal ? { signal } : {}),
    }),
  );
}

export function cancelRun(client: ApiClient, runId: string): Promise<Run> {
  return unwrap(client.POST("/reports/runs/{runId}/cancel", { params: { path: { runId } } }));
}

export function retryRun(client: ApiClient, runId: string): Promise<Run> {
  return unwrap(client.POST("/reports/runs/{runId}/retry", { params: { path: { runId } } }));
}

export function listRows(
  client: ApiClient,
  runId: string,
  query: { cursor?: string; sortBy?: string; order?: "asc" | "desc" },
  signal?: AbortSignal,
): Promise<RowPage> {
  const params: {
    limit: number;
    cursor?: string;
    sortBy?: S["ReportColumnId"];
    order?: S["ReportSortOrder"];
  } = { limit: ROWS_LIMIT };
  if (query.cursor) params.cursor = query.cursor;
  if (query.sortBy) {
    params.sortBy = query.sortBy as S["ReportColumnId"];
    params.order = query.order ?? "asc";
  }
  return unwrap(
    client.GET("/reports/runs/{runId}/rows", {
      params: { path: { runId }, query: params },
      ...(signal ? { signal } : {}),
    }),
  );
}

/** What went wrong, in the kinds the screens show differently. */
export type FailureKind =
  | "forbidden" // no reports.run (or the scope is gone): the API answered 403
  | "unauthenticated"
  | "not-found"
  | "expired" // 410: the stored result is past its retention
  | "scope-changed" // 409 scope_changed_rerun: the role's scope changed since the run
  | "not-ready" // 409 run_not_ready / run_failed
  | "too-many-jobs" // 429 too_many_report_jobs
  | "rate-limited"
  | "invalid"
  | "unreachable"
  | "error";

export interface Failure {
  readonly kind: FailureKind;
  readonly title: string;
  readonly detail: string;
  readonly traceId?: string;
}

/** The typed code of a problem: its own `code`, or the first error's. Clients branch on this, not on the status. */
export function problemCode(problem: Problem): string | undefined {
  return problem.code ?? problem.errors?.[0]?.code;
}

export function failureOf(error: unknown): Failure {
  if (!(error instanceof ApiError)) {
    return {
      kind: "unreachable",
      title: "Can't reach the server",
      detail: "Check your connection, then retry.",
    };
  }
  const trace = error.problem.traceId;
  const withId = typeof trace === "string" ? { traceId: trace } : {};
  const code = problemCode(error.problem);
  switch (error.status) {
    case 401:
      return {
        kind: "unauthenticated",
        title: "Your session has ended",
        detail: "Sign in again; you will come back to this page.",
        ...withId,
      };
    case 403:
      return {
        kind: "forbidden",
        title: "You don't have access to reports",
        detail:
          "Your role does not include running reports (reports.run). Ask an administrator to add it to your role. Nothing here was changed.",
        ...withId,
      };
    case 404:
      return {
        kind: "not-found",
        title: "That report or run was not found",
        detail: "It may have been retired, or it belongs to another account.",
        ...withId,
      };
    case 410:
      return {
        kind: "expired",
        title: "This result has expired",
        detail: "Results are kept for a limited time. Run it again with the same settings.",
        ...withId,
      };
    case 409:
      if (code === "scope_changed_rerun") {
        return {
          kind: "scope-changed",
          title: "Your access changed since this run",
          detail:
            "Your role's scope is not the one this result was trimmed with, so it is not shown. Run it again to see what your role covers now.",
          ...withId,
        };
      }
      return {
        kind: "not-ready",
        title: "This result is not ready",
        detail: error.problem.detail ?? error.problem.title,
        ...withId,
      };
    case 429:
      if (code === "too_many_report_jobs") {
        return {
          kind: "too-many-jobs",
          title: "Too many reports are running",
          detail:
            "Your organisation has four runs and exports still in progress. Retry when one finishes.",
          ...withId,
        };
      }
      return {
        kind: "rate-limited",
        title: "Too many requests",
        detail: "Wait a moment, then retry.",
        ...withId,
      };
    case 400:
      return {
        kind: "invalid",
        title: "The server rejected that request",
        detail: error.problem.detail ?? error.problem.title,
        ...withId,
      };
    default:
      return {
        kind: "error",
        title: "The request failed",
        detail:
          "The server could not answer. Retry; if it keeps failing, quote the trace ID to your administrator.",
        ...withId,
      };
  }
}
