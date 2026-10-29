import { ApiError, type Problem } from "../../api/client";

/** How many users one search asks for. The API defaults to 25 and caps at 100. */
export const SEARCH_LIMIT = 25;

/** The API's longest accepted `q` (searchDirectoryUsers). */
export const MAX_QUERY_LENGTH = 256;

// The API refuses these characters in q (`( ) * \ & | = ! < > ~` and control characters). The
// console checks the same set so the admin sees the reason beside the box instead of a round trip;
// the server still decides. The pattern comes from api/openapi/modules/directory.yaml.
// eslint-disable-next-line no-control-regex
const REFUSED_CHARACTERS = /[()*\\&|=!<>~\x00-\x1f\x7f]/;

/** Answers why `q` would be refused, or undefined when it can be sent. An empty q is not an error: it is no search. */
export function validateQuery(q: string): string | undefined {
  if (q.length > MAX_QUERY_LENGTH) {
    return `Search text can be at most ${MAX_QUERY_LENGTH} characters.`;
  }
  if (REFUSED_CHARACTERS.test(q)) {
    return "Search text can't contain ( ) * \\ & | = ! < > ~ or control characters.";
  }
  return undefined;
}

/** The failure kinds the page shows differently. */
export type FailureKind =
  "denied" | "unauthenticated" | "invalid" | "rate-limited" | "unreachable" | "error";

export interface Failure {
  readonly kind: FailureKind;
  readonly title: string;
  readonly detail: string;
  /** The server trace ID when the problem carries one, so an admin can quote it. */
  readonly traceId?: string;
}

function traceIdOf(problem: Problem): string | undefined {
  const id = problem.traceId;
  return typeof id === "string" ? id : undefined;
}

/** Maps an API failure to what the page says. Never exposes a stack trace or an unknown payload. */
export function failureOf(error: unknown): Failure {
  if (error instanceof ApiError) {
    const traceId = traceIdOf(error.problem);
    const withId = traceId === undefined ? {} : { traceId };
    switch (error.status) {
      case 403:
        return {
          kind: "denied",
          title: "You don't have permission to search users",
          detail:
            "Searching directory users needs the directory.read permission. Ask an administrator to grant it.",
          ...withId,
        };
      case 401:
        return {
          kind: "unauthenticated",
          title: "Your session has ended",
          detail: "Sign in again, then retry the search.",
          ...withId,
        };
      case 400:
        return {
          kind: "invalid",
          title: "The server rejected that search",
          detail: error.problem.detail ?? error.problem.title,
          ...withId,
        };
      case 429:
        return {
          kind: "rate-limited",
          title: "Too many searches",
          detail: "Wait a moment, then retry.",
          ...withId,
        };
      default:
        return {
          kind: "error",
          title: "The search failed",
          detail:
            "The server could not answer. Retry; if it keeps failing, quote the trace ID to your administrator.",
          ...withId,
        };
    }
  }
  return {
    kind: "unreachable",
    title: "Can't reach the server",
    detail: "Check your connection, then retry.",
  };
}
