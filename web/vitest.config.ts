import { defineConfig } from "vitest/config";

// Pure-logic tests run in Node. Component tests that need a DOM add an environment when the first
// design-system component lands (T-0043). `css.include` makes `tokens.css?raw` return the real file
// (by default Vitest stubs CSS imports with an empty string), so tokens.test.ts can check every colour pair.
export default defineConfig({
  test: {
    environment: "node",
    include: ["src/**/*.test.ts", "src/**/*.test.tsx", "eslint/**/*.test.js"],
    css: { include: [/src\/ds\/tokens\.css/] },
  },
});
