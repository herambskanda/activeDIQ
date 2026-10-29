// Console E2E (T-0670). Suites live in e2e/. Without ADIQ_BASE_URL they run against the built
// console served by `vite preview` and answer the API with fixtures; with it, against that server.
// Browsers come from the pinned Playwright cache (`make playwright-install`).
import { defineConfig } from "@playwright/test";

const external = process.env["ADIQ_BASE_URL"];

export default defineConfig({
  testDir: "e2e",
  outputDir: "test-results",
  retries: 1, // the only retry allowed (testing-playbook §6); every retry is a reported flake
  reporter: [["list"]],
  ...(external
    ? {}
    : {
        webServer: {
          command: "npm run build && npx vite preview --host 127.0.0.1 --port 4173 --strictPort",
          url: "http://127.0.0.1:4173",
          reuseExistingServer: false,
        },
      }),
  use: {
    baseURL: external ?? "http://127.0.0.1:4173",
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { browserName: "chromium" } }],
});
