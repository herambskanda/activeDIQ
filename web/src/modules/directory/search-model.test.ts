import { describe, expect, it } from "vitest";

import { MAX_QUERY_LENGTH, validateQuery } from "./search-model";

describe("validateQuery", () => {
  it("accepts plain text and the empty string", () => {
    expect(validateQuery("")).toBeUndefined();
    expect(validateQuery("o'brien-smith@example.test")).toBeUndefined();
  });

  it.each(["a(b", "a)b", "a*", "a\\b", "a&b", "a|b", "a=b", "!a", "<a", "a>", "a~", "a\u0007"])(
    "refuses %j in a link",
    (q) => {
      expect(validateQuery(q)).toMatch(/can't contain/);
    },
  );

  it("refuses text longer than the API accepts", () => {
    expect(validateQuery("a".repeat(MAX_QUERY_LENGTH))).toBeUndefined();
    expect(validateQuery("a".repeat(MAX_QUERY_LENGTH + 1))).toMatch(/at most 256/);
  });
});
