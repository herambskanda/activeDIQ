// The console's one way to call the API (ADR-0004 rule 12). It is the only hand-written file in this
// directory: the base URL, the CSRF header and problem decoding. Every operation, path and type
// comes from schema.gen.d.ts, which is generated from the same bundle the server embeds, so the
// console can call nothing the contract does not declare.
import createClient, { type Middleware } from "openapi-fetch";
import type { components, paths } from "./schema.gen";

/** An RFC 9457 problem as the server sends it (ADR-0004 rule 8). */
export type Problem = components["schemas"]["Problem"];

/** The API's base path: the contract's one server. */
export const API_BASE_URL = "/api/v1";

const CSRF_HEADER = "X-CSRF-Token";
const SAFE_METHODS = new Set(["GET", "HEAD", "OPTIONS"]);

let csrfToken: string | undefined;

/** Sets the session's CSRF token; the session code calls it on sign-in and clears it on sign-out. */
export function setCsrfToken(token: string | undefined): void {
  csrfToken = token;
}

/**
 * Adds the CSRF token to every request that changes state. A bearer token is exempt on the server,
 * but the console always runs on a session cookie.
 */
export function csrfMiddleware(getToken: () => string | undefined = () => csrfToken): Middleware {
  return {
    onRequest({ request }) {
      const token = getToken();
      if (token !== undefined && !SAFE_METHODS.has(request.method.toUpperCase())) {
        request.headers.set(CSRF_HEADER, token);
      }
      return request;
    },
  };
}

/** A failed call: the server's problem, or one made up from the status when the body was not one. */
export class ApiError extends Error {
  readonly problem: Problem;
  readonly status: number;

  constructor(problem: Problem, status: number) {
    super(problem.title);
    this.name = "ApiError";
    this.problem = problem;
    this.status = status;
  }
}

function isProblem(value: unknown): value is Problem {
  if (typeof value !== "object" || value === null) return false;
  const v = value as Record<string, unknown>;
  return (
    typeof v["type"] === "string" &&
    typeof v["title"] === "string" &&
    typeof v["status"] === "number"
  );
}

/** Reads the problem out of an error body; anything else becomes `about:blank` with the status text. */
export function problemOf(error: unknown, response: Response): Problem {
  if (isProblem(error)) return error;
  return {
    type: "about:blank",
    title: response.statusText || `HTTP ${response.status}`,
    status: response.status,
  };
}

/**
 * Resolves an openapi-fetch call to its data, or throws an ApiError carrying the problem. Use it
 * when a failure should reach an error boundary; read `{ data, error }` yourself to handle one.
 */
export async function unwrap<T>(
  call: Promise<{ data?: T; error?: unknown; response: Response }>,
): Promise<T> {
  const { data, error, response } = await call;
  if (!response.ok) throw new ApiError(problemOf(error, response), response.status);
  return data as T;
}

export interface ApiClientOptions {
  /** Replaces the base URL, for tests that run outside a browser (the default is relative). */
  baseUrl?: string;
  /** Replaces `fetch`, for tests. */
  fetch?: (request: Request) => Promise<Response>;
}

/** Builds a client over the generated paths. */
export function createApiClient(options: ApiClientOptions = {}) {
  const client = createClient<paths>({
    baseUrl: options.baseUrl ?? API_BASE_URL,
    credentials: "same-origin",
    ...(options.fetch ? { fetch: options.fetch } : {}),
  });
  client.use(csrfMiddleware());
  return client;
}

/** The console's client. */
export const api = createApiClient();
