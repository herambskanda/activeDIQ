import { defineConfig } from "vitest/config";

// Pure-logic tests run in Node. Component tests that need a DOM add an environment when the first
// design-system component lands (T-0043).
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx", "eslint/**/*.test.js"],
  },
});
