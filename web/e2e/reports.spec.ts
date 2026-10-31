// The reports console in a real browser against the built console (T-0966). The API is answered by
// fixtures declared here (tests may carry them); the console is the shipped bundle. The real
// server cannot serve the library yet (B5, 501), so this is the evidence for the screens.
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page, type Route } from "@playwright/test";

const EVIDENCE = "../factory/demos/evidence/T-0966";

const column = (id: string, label: string, type = "text") => ({
  id,
  label,
  type,
  sortable: true,
  filterable: true,
  defaultVisible: true,
  choices: [],
  filterOperators: ["equals", "contains"],
});
const svcFilter = {
  kind: "ReportFilterConditionView",
  column: "probable_service_account",
  operator: "equals",
  values: [{ kind: "ReportValueBoolean", value: false }],
};
const definition = {
  id: "usr-03",
  version: 1,
  name: "Logon activity",
  description: "Who logged on, and when",
  category: "users",
  dataset: "inventory.users",
  freshnessKind: "synced",
  alsoKnownAs: [{ meName: "Recently Logged on Users", presetId: "recent" }],
  columns: [column("name", "Name"), column("days_since", "Days since", "integer")],
  exportFormats: ["csv"],
  minScheduleIntervalHours: 1,
  perDc: false,
  subjectKind: "none",
  presets: [
    {
      id: "inactive",
      name: "Inactive 90 days",
      meName: null,
      periodDays: 90,
      columns: ["name"],
      filters: [svcFilter],
    },
    {
      id: "recent",
      name: "Recently logged on",
      meName: "Recently Logged on Users",
      periodDays: 30,
      columns: ["name"],
      filters: [],
    },
  ],
};
const RUN_ID = "11111111-1111-4111-8111-111111111111";
const run = (over: Record<string, unknown> = {}) => ({
  id: RUN_ID,
  definitionId: "usr-03",
  definitionVersion: 1,
  presetId: "recent",
  state: "succeeded",
  asOf: new Date(Date.now() - 60_000).toISOString(),
  createdAt: new Date().toISOString(),
  createdBy: { kind: "user", id: "u" },
  startedAt: new Date().toISOString(),
  finishedAt: new Date().toISOString(),
  expiresAt: null,
  digest: "abc",
  freshness: { state: "synced", label: "Synced just now" },
  objectsChecked: 150000,
  rowCount: 1200,
  scopeApplied: "Domain lab.test",
  parameters: {
    columns: ["name", "days_since"],
    connectionIds: [],
    filters: [],
    includeReadOnlyDcs: false,
    ouExclude: [],
    ouInclude: [],
    subjects: [],
  },
  progress: { percent: 100, stage: "done" },
  skippedConnections: [],
  ...over,
});

const problem = (status: number, title: string, code?: string) => ({
  status,
  contentType: "application/problem+json",
  body: JSON.stringify({
    type: "about:blank",
    title,
    status,
    traceId: "trace-e2e",
    ...(code ? { code } : {}),
  }),
});

interface Server {
  runPosts: number;
  runBodies: unknown[];
  /** Hold the run start until released, to show the loading state. */
  gate?: Promise<void>;
  runOver: Record<string, unknown>;
  totalRows: number;
  forbidden: boolean;
  /** Answer rows with this instead of a page. */
  rowsFailure?: ReturnType<typeof problem>;
}

const ROWS_PAGE = 500;

/** Fixture API for the reports endpoints; returns the state the test inspects and tweaks. */
async function serve(page: Page, over: Partial<Server> = {}): Promise<Server> {
  const s: Server = {
    runPosts: 0,
    runBodies: [],
    runOver: {},
    totalRows: 1200,
    forbidden: false,
    ...over,
  };
  await page.route(/\/api\/v1\/reports\//, async (route: Route) => {
    const req = route.request();
    const url = new URL(req.url());
    const path = url.pathname.replace("/api/v1/reports", "");
    if (s.forbidden) return route.fulfill(problem(403, "Forbidden"));
    if (path === "/definitions") {
      const q = (url.searchParams.get("q") ?? "").toLowerCase();
      const hit =
        !q ||
        definition.name.toLowerCase().includes(q) ||
        definition.alsoKnownAs.some((a) => a.meName.toLowerCase().includes(q));
      return route.fulfill({
        json: { items: hit ? [definition] : [], page: { nextCursor: null } },
      });
    }
    if (path === "/definitions/usr-03") return route.fulfill({ json: definition });
    if (path === "/runs" && req.method() === "POST") {
      s.runPosts++;
      const body = JSON.parse(req.postData() ?? "{}");
      s.runBodies.push(body);
      // The run records the conditions it applied: the preset's, or the ones the request sent.
      const filters = body.parameters?.filters ?? (body.presetId === "inactive" ? [svcFilter] : []);
      if (s.gate) await s.gate;
      return route.fulfill({
        status: 202,
        json: run({
          rowCount: s.totalRows,
          parameters: { ...run().parameters, filters },
          ...s.runOver,
        }),
      });
    }
    if (path.endsWith("/retry")) return route.fulfill({ status: 202, json: run() });
    if (path.endsWith("/rows")) {
      if (s.rowsFailure) return route.fulfill(s.rowsFailure);
      const start = Number(url.searchParams.get("cursor") ?? "0");
      const n = Math.max(0, Math.min(ROWS_PAGE, s.totalRows - start));
      const next = start + n < s.totalRows ? String(start + n) : null;
      return route.fulfill({
        json: {
          runId: RUN_ID,
          rowCount: s.totalRows,
          page: { nextCursor: next },
          columns: definition.columns,
          rows: Array.from({ length: n }, (_, i) => ({
            rowKey: `r${start + i}`,
            cells: [
              { kind: "ReportCellText", value: `User ${start + i}` },
              { kind: "ReportCellInteger", value: String(start + i) },
            ],
          })),
        },
      });
    }
    return route.fulfill(problem(404, "not found"));
  });
  return s;
}

// The console checks for a session before it shows any screen; these tests are signed in.
test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/auth/csrf", (route) =>
    route.fulfill({ json: { header: "X-CSRF-Token", value: "csrf-e2e" } }),
  );
});

async function noCriticalViolations(page: Page) {
  const { violations } = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(violations.filter((v) => v.impact === "critical" || v.impact === "serious")).toEqual([]);
}

test("an ME name finds the report: / , type, Enter is three interactions, no Generate click (AC-04)", async ({
  page,
}) => {
  const s = await serve(page);
  await page.goto("/reports");
  await expect(page.getByText("Logon activity").first()).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/default-library.png` });

  let interactions = 0;
  await page.keyboard.press("/");
  interactions++;
  const box = page.getByRole("combobox", { name: "Search reports" });
  await expect(box).toBeFocused();
  await box.fill("recently logged");
  interactions++;
  await expect(page.getByRole("option").first()).toContainText("Recently Logged on Users");
  await page.screenshot({ path: `${EVIDENCE}/search-hits.png` });
  await page.keyboard.press("Enter");
  interactions++;

  await expect(page).toHaveURL(/\/reports\/usr-03\?preset=recent/);
  await expect(page.getByText("User 5", { exact: true })).toBeVisible();
  await expect(page.getByText("Synced just now").first()).toBeVisible();
  expect(interactions).toBeLessThanOrEqual(3);
  expect(s.runPosts).toBe(1);
  expect(s.runBodies[0]).toEqual({ definitionId: "usr-03", presetId: "recent" });
  await expect(page.getByRole("button", { name: /generate/i })).toHaveCount(0);
  await page.screenshot({ path: `${EVIDENCE}/default-results.png` });
  await noCriticalViolations(page);
});

test("a role without reports.run sees no report entry and search finds none (AC-42)", async ({
  page,
}) => {
  await serve(page, { forbidden: true });
  await page.goto("/reports");
  await expect(page.getByText("You don't have access to reports")).toBeVisible();
  await expect(page.getByRole("button", { name: "Retry" })).toHaveCount(0);
  await page.keyboard.press("/");
  await page.getByRole("combobox", { name: "Search reports" }).fill("logon");
  await expect(page.getByText("No reports are available to your role.")).toBeVisible();
  await expect(page.getByRole("listbox", { name: "Reports" }).getByRole("option")).toHaveCount(0);
  await page.screenshot({ path: `${EVIDENCE}/permission-denied.png` });
  await page.keyboard.press("Escape");
  await page.goto("/reports/usr-03?preset=recent");
  await expect(page.getByText("You don't have access to reports")).toBeVisible();
  await noCriticalViolations(page);
});

test("the loading state is a skeleton, not a spinner, and then the rows replace it", async ({
  page,
}) => {
  let release: () => void = () => undefined;
  const gate = new Promise<void>((resolve) => (release = resolve));
  await serve(page, { gate });
  await page.goto("/reports/usr-03?preset=recent");
  await expect(page.getByRole("status", { name: "Starting the report" })).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/loading.png` });
  release();
  await expect(page.getByText("User 5", { exact: true })).toBeVisible();
});

test("the empty states name their cause", async ({ page }) => {
  const s = await serve(page, {
    totalRows: 0,
    runOver: { emptyReason: "scope_grants_nothing" },
  });
  await page.goto("/reports/usr-03?preset=recent");
  await expect(page.getByText("Your role covers no directory objects")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/empty-scope-grants-nothing.png` });

  s.runOver = { emptyReason: "unsupported_scope_kind" };
  await page.goto("/reports/usr-03?preset=recent");
  await expect(page.getByText("Reports can’t use your role’s scope yet")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/empty-unsupported-scope.png` });
  await noCriticalViolations(page);

  s.runOver = {};
  await page.goto("/reports/usr-03?preset=recent&f=name:equals:nobody");
  await expect(page.getByText("No rows match")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/empty-no-match.png` });
});

test("a stale result says Stale with its age and the API's reason", async ({ page }) => {
  await serve(page, {
    runOver: {
      asOf: new Date(Date.now() - 3 * 3600_000).toISOString(),
      freshness: { state: "stale", label: "Stale: oldest sync pass 3h0m0s ago" },
    },
  });
  await page.goto("/reports/usr-03?preset=recent");
  await expect(page.getByText("Stale data")).toBeVisible();
  await expect(page.getByText("Stale: oldest sync pass 3h0m0s ago").first()).toBeVisible();
  await expect(page.getByText("3 h ago").first()).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/stale.png` });
  await noCriticalViolations(page);
});

test("a failed run says why, and Retry starts a new run that succeeds", async ({ page }) => {
  await serve(page, {
    runOver: { state: "failed", failure: { reason: "query_timeout", message: "timed out" } },
  });
  await page.goto("/reports/usr-03?preset=recent");
  await expect(page.getByText("This run failed: the query timed out")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/failed.png` });
  await noCriticalViolations(page);
  await page.getByRole("button", { name: "Retry (new run)" }).click();
  await expect(page.getByText("User 5", { exact: true })).toBeVisible();
});

test("an expired result offers a fresh run", async ({ page }) => {
  const s = await serve(page, { runOver: { state: "expired" } });
  await page.goto("/reports/usr-03?preset=recent");
  await expect(page.getByText("This result has expired")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/expired.png` });
  s.runOver = {};
  await page.getByRole("button", { name: "Run again with the same settings" }).click();
  await expect(page.getByText("User 5", { exact: true })).toBeVisible();
  expect(s.runPosts).toBe(2);
});

test("100,000 rows: the grid is windowed, pages come from the server, sort is server-side", async ({
  page,
}) => {
  await serve(page, { totalRows: 100_000, runOver: { objectsChecked: 150_000 } });
  await page.goto("/reports/usr-03?preset=recent");
  await expect(page.getByText("User 5", { exact: true })).toBeVisible();
  await expect(page.getByText(/Showing 500 of 100,000 rows/)).toBeVisible();
  const rendered = await page.locator("tbody tr[data-row]").count();
  expect(rendered).toBeGreaterThan(5);
  expect(rendered).toBeLessThan(120);
  await page.screenshot({ path: `${EVIDENCE}/large-100k.png` });

  await page.getByRole("button", { name: "Load more rows" }).click();
  await expect(page.getByText(/Showing 1,000 of 100,000 rows/)).toBeVisible();
  expect(await page.locator("tbody tr[data-row]").count()).toBeLessThan(120);

  await page.getByRole("columnheader", { name: /Days since/ }).click();
  await expect(page).toHaveURL(/sort=days_since/);
});

test("hidden probable service accounts can be shown, and the choice is in the URL", async ({
  page,
}) => {
  const s = await serve(page);
  await page.goto("/reports/usr-03?preset=inactive");
  await expect(page.getByText("Probable service accounts are hidden")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/hidden-service-accounts.png` });
  await page.getByRole("button", { name: "Show them" }).click();
  await expect(page).toHaveURL(/svc=1/);
  await expect(page.getByText("Probable service accounts are hidden")).toHaveCount(0);
  expect(s.runPosts).toBe(2);
  await page.goBack();
  await expect(page.getByText("Probable service accounts are hidden")).toBeVisible();
});

test("a library filter with no match offers to clear it; the filter is in the URL", async ({
  page,
}) => {
  await serve(page);
  await page.goto("/reports?q=zzqx");
  await expect(page.getByText("No report matches “zzqx”")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/empty-library.png` });
  await page.getByRole("button", { name: "Clear filter" }).click();
  await expect(page).toHaveURL(/\/reports$/);
  await expect(page.getByText("Logon activity").first()).toBeVisible();
});
