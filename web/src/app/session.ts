// The console session: whether one exists, and how one is established (AN-8 then AN-10). The
// session itself is an HttpOnly cookie the browser holds; the console only learns whether the
// server accepts it, and keeps the session's CSRF value for mutations.
import { ApiError, type createApiClient, problemOf, setCsrfToken } from "../api/client";

export const SIGN_IN_PATH = "/sign-in";

/** The API surface the session code needs; the real client satisfies it. */
export type SessionClient = Pick<ReturnType<typeof createApiClient>, "GET" | "POST">;

/** Asks the server whether the cookie is a live session and, if so, keeps its CSRF value. */
export async function loadSession(client: SessionClient): Promise<boolean> {
  const { data, response } = await client.GET("/auth/csrf");
  if (response.status === 401) return false;
  if (!response.ok || data === undefined) {
    throw new ApiError(problemOf(undefined, response), response.status);
  }
  setCsrfToken(data.value);
  return true;
}

/** First factor. Resolves on 204 (a pending sign-in exists); throws ApiError otherwise. */
export async function submitPassword(
  client: SessionClient,
  username: string,
  password: string,
): Promise<void> {
  const { error, response } = await client.POST("/auth/break-glass/password", {
    body: { username, password },
  });
  if (!response.ok) throw new ApiError(problemOf(error, response), response.status);
}

/** Second factor. On success a session exists and its CSRF value is loaded. */
export async function submitTotp(client: SessionClient, code: string): Promise<void> {
  const { error, response } = await client.POST("/auth/second-factor/totp/verify", {
    body: { code },
    // The contract lists the pending-sign-in cookie as a parameter. The browser sends the real
    // HttpOnly cookie itself; the client never serialises cookie parameters.
    params: { cookie: { "__Host-adiq_pending": "" } },
  });
  if (!response.ok) throw new ApiError(problemOf(error, response), response.status);
  if (!(await loadSession(client))) {
    throw new ApiError(problemOf(undefined, response), 401);
  }
}

/**
 * The page to open after sign-in: the `next` value when it is a path on this console, otherwise
 * the default. A value naming another origin (`//host`, `https:`, backslashes) is never followed.
 */
export function safeNext(next: string | null, fallback: string): string {
  if (next === null || !next.startsWith("/") || next.startsWith("//") || next.includes("\\")) {
    return fallback;
  }
  if (next === SIGN_IN_PATH || next.startsWith(`${SIGN_IN_PATH}?`)) return fallback;
  return next;
}
