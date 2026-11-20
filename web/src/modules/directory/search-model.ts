/** The longest `q` a link to the user search may carry. */
export const MAX_QUERY_LENGTH = 256;

// A row links to the user search only through an identifier made of plain characters (no
// `( ) * \ & | = ! < > ~` or control characters), so a link never carries filter-like syntax.
// eslint-disable-next-line no-control-regex
const REFUSED_CHARACTERS = /[()*\\&|=!<>~\x00-\x1f\x7f]/;

/** Answers why `q` is not a plain identifier a link may carry, or undefined when it is. */
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
