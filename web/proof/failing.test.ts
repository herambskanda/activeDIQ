// A deliberately failing test. `make ci-proof` runs it and requires vitest to fail.
import { expect, it } from "vitest";

it("fails on purpose", () => {
  expect(1).toBe(2);
});
