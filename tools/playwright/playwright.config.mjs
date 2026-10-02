// E2E runner config (T-0011). Suites live in <repo>/web/e2e/ (blueprint repo layout; testing-playbook §5); none exist until product UI does.
import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: '../../web/e2e',
  outputDir: './test-results',
  retries: 1, // the only retry allowed (testing-playbook §6); every retry is a reported flake
  reporter: [['list'], ['html', { outputFolder: './playwright-report', open: 'never' }]],
  use: {
    baseURL: process.env.ADIQ_BASE_URL,
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  projects: [{ name: 'chromium', use: { browserName: 'chromium' } }],
});
