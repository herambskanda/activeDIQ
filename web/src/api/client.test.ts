import type { Middleware } from "openapi-fetch";
import { describe, expect, it } from "vitest";
import {
  API_BASE_URL,
  ApiError,
  createApiClient,
  csrfMiddleware,
  problemOf,
  setCsrfToken,
  unwrap,
} from "./client";
import type { components } from "./schema.gen";

// The generated type of a response enum admits values this build does not know (ADR-0004 rule 2).
// This is a compile-time proof: `tsc --noEmit` fails if the widening is lost.
const known: components["schemas"]["JobStatus"] = "running";
const fromTheFuture: components["schemas"]["JobStatus"] = "paused-by-a-newer-server";
// A closed request enum would not accept the second line; the problem catalogue's `in` is open.
const location: components["schemas"]["ProblemErrorIn"] = "cookie";

function apply(mw: Middleware, req: Request): void {
  void mw.onRequest?.({ request: req } as Parameters<NonNullable<Middleware["onRequest"]>>[0]);
}

function request(method: string): Request {
  return new Request("http://localhost/api/v1/x", { method });
}

describe("csrfMiddleware", () => {
  const mw = csrfMiddleware(() => "tok-123");
  const run = (method: string) => {
    const req = request(method);
    apply(mw, req);
    return req.headers.get("X-CSRF-Token");
  };

  it.each(["POST", "PUT", "PATCH", "DELETE"])("sets the token on %s", (method) => {
    expect(run(method)).toBe("tok-123");
  });

  it.each(["GET", "HEAD", "OPTIONS"])("does not set the token on %s", (method) => {
    expect(run(method)).toBeNull();
  });

  it("sends nothing before sign-in", () => {
    const none = csrfMiddleware(() => undefined);
    const req = request("POST");
    apply(none, req);
    expect(req.headers.get("X-CSRF-Token")).toBeNull();
  });
});

describe("problem decoding", () => {
  const response = (status: number, statusText = "") => new Response(null, { status, statusText });

  it("passes a problem through", () => {
    const p = { type: "/problems/validation", title: "The request is invalid", status: 400 };
    expect(problemOf(p, response(400))).toBe(p);
  });

  it("makes one up when the body was not a problem", () => {
    expect(problemOf("<html>", response(502, "Bad Gateway"))).toEqual({
      type: "about:blank",
      title: "Bad Gateway",
      status: 502,
    });
    expect(problemOf(undefined, response(503))).toMatchObject({ title: "HTTP 503", status: 503 });
  });

  it("unwrap returns the data on success", async () => {
    await expect(
      unwrap(Promise.resolve({ data: { ok: true }, response: response(200) })),
    ).resolves.toEqual({
      ok: true,
    });
  });

  it("unwrap throws an ApiError carrying the problem", async () => {
    const problem = { type: "/problems/not-found", title: "Not found", status: 404 };
    const err = await unwrap(Promise.resolve({ error: problem, response: response(404) })).catch(
      (e: unknown) => e,
    );
    expect(err).toBeInstanceOf(ApiError);
    expect((err as ApiError).problem).toEqual(problem);
    expect((err as ApiError).status).toBe(404);
  });
});

describe("createApiClient", () => {
  it("is rooted at the contract's one server", () => {
    expect(API_BASE_URL).toBe("/api/v1");
  });

  it("builds a client that uses the injected fetch and the session's CSRF token", async () => {
    setCsrfToken("session-token");
    const seen: Request[] = [];
    const client = createApiClient({
      baseUrl: "http://localhost/api/v1",
      fetch: (req) => {
        seen.push(req);
        return Promise.resolve(
          new Response("{}", { headers: { "content-type": "application/json" } }),
        );
      },
    });
    // The skeleton contract declares no operations yet, so call through the untyped escape of the
    // underlying client: only its middleware chain is under test here.
    await (client as unknown as { POST: (p: string) => Promise<unknown> }).POST("/anything");
    setCsrfToken(undefined);
    expect(seen).toHaveLength(1);
    expect(seen[0]?.url).toContain("/api/v1/anything");
    expect(seen[0]?.headers.get("X-CSRF-Token")).toBe("session-token");
  });
});

it("keeps the compile-time proofs referenced", () => {
  expect([known, fromTheFuture, location]).toHaveLength(3);
});
