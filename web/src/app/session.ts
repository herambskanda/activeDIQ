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

/** The browser's credential store; injectable so tests can stand in for a security key. */
export type CredentialStore = Pick<CredentialsContainer, "get">;

const B64 = /^[A-Za-z0-9_-]+$/;

/** base64url (RFC 4648 section 5) without padding, the form the contract uses. */
export function toBase64Url(bytes: ArrayBuffer): string {
  let bin = "";
  for (const b of new Uint8Array(bytes)) bin += String.fromCharCode(b);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64Url(text: string): Uint8Array<ArrayBuffer> {
  if (!B64.test(text)) throw new TypeError("not base64url");
  const std = text.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(std + "=".repeat((4 - (std.length % 4)) % 4));
  return Uint8Array.from(bin, (c) => c.charCodeAt(0));
}

/** True when this browser can use a security key. */
export function webAuthnAvailable(store: CredentialStore | undefined = browserCredentials()) {
  return store !== undefined;
}

function browserCredentials(): CredentialStore | undefined {
  return typeof navigator !== "undefined" && typeof window !== "undefined" && window.isSecureContext
    ? navigator.credentials
    : undefined;
}

/** The user dismissed or the browser refused the key prompt; nothing was sent to the server. */
export class KeyPromptError extends Error {}

/**
 * Second factor with a security key: asks the server for the challenge, has the browser sign it,
 * and sends the assertion for the server to verify. The session exists only if the server says so.
 */
export async function submitWebAuthn(
  client: SessionClient,
  store: CredentialStore | undefined = browserCredentials(),
): Promise<void> {
  if (store === undefined) throw new KeyPromptError("no credential store");
  const cookie = { params: { cookie: { "__Host-adiq_pending": "" } } };
  const ch = await client.POST("/auth/second-factor/webauthn/challenge", cookie);
  if (!ch.response.ok || ch.data === undefined) {
    throw new ApiError(problemOf(ch.error, ch.response), ch.response.status);
  }
  const opts = ch.data;
  if (opts.allowCredentials.length === 0) {
    throw new ApiError(problemOf(undefined, ch.response), 401);
  }
  let cred: Credential | null;
  try {
    cred = await store.get({
      publicKey: {
        challenge: fromBase64Url(opts.challenge),
        rpId: opts.rpId,
        timeout: opts.timeoutMs,
        userVerification: opts.userVerification as UserVerificationRequirement,
        allowCredentials: opts.allowCredentials.map((c) => ({
          type: "public-key" as const,
          id: fromBase64Url(c.id),
        })),
      },
    });
  } catch {
    throw new KeyPromptError("key prompt failed");
  }
  const resp = (cred as PublicKeyCredential | null)?.response;
  if (cred === null || !(resp && "signature" in resp)) throw new KeyPromptError("no assertion");
  const a = resp as AuthenticatorAssertionResponse;
  const { error, response } = await client.POST("/auth/second-factor/webauthn/verify", {
    ...cookie,
    body: {
      credentialId: toBase64Url((cred as PublicKeyCredential).rawId),
      authenticatorData: toBase64Url(a.authenticatorData),
      clientDataJson: toBase64Url(a.clientDataJSON),
      signature: toBase64Url(a.signature),
      ...(a.userHandle && a.userHandle.byteLength > 0
        ? { userHandle: toBase64Url(a.userHandle) }
        : {}),
    },
  });
  if (!response.ok) throw new ApiError(problemOf(error, response), response.status);
  if (!(await loadSession(client))) throw new ApiError(problemOf(undefined, response), 401);
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
