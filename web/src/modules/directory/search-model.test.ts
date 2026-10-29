import { describe, expect, it } from "vitest";

import { ApiError } from "../../api/client";
import { failureOf, MAX_QUERY_LENGTH, validateQuery } from "./search-model";

const problem = (status: number, extra: Record<string, unknown> = {}) =>
  new ApiError({ type: "about:blank", title: "t", status, ...extra }, status);

describe("validateQuery", () => {
  it("accepts plain text and the empty string", () => {
    expect(validateQuery("")).toBeUndefined();
    expect(validateQuery("o'brien-smith@example.test")).toBeUndefined();
  });

  it.each(["a(b", "a)b", "a*", "a\\b", "a&b", "a|b", "a=b", "!a", "<a", "a>", "a~", "a\u0007"])(
    "refuses %j, as the API does",
    (q) => {
      expect(validateQuery(q)).toMatch(/can't contain/);
    },
  );

  it("refuses text longer than the API accepts", () => {
    expect(validateQuery("a".repeat(MAX_QUERY_LENGTH))).toBeUndefined();
    expect(validateQuery("a".repeat(MAX_QUERY_LENGTH + 1))).toMatch(/at most 256/);
  });
});

describe("failureOf", () => {
  it("maps 403 to permission denied", () => {
    expect(failureOf(problem(403)).kind).toBe("denied");
  });
  it("maps 401, 429 and 500", () => {
    expect(failureOf(problem(401)).kind).toBe("unauthenticated");
    expect(failureOf(problem(429)).kind).toBe("rate-limited");
    expect(failureOf(problem(500)).kind).toBe("error");
  });
  it("carries the trace ID when the problem has one", () => {
    expect(failureOf(problem(500, { traceId: "trace-1" })).traceId).toBe("trace-1");
    expect(failureOf(problem(500)).traceId).toBeUndefined();
  });
  it("treats a non-API failure as unreachable and never echoes it", () => {
    const f = failureOf(new TypeError("Failed to fetch at https://secret/stack"));
    expect(f.kind).toBe("unreachable");
    expect(JSON.stringify(f)).not.toContain("secret");
  });
});
