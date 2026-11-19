// The /search full results page, in a real browser against the built console (T-1100). The API is
// answered by fixtures here (tests may carry them); the console is the shipped bundle.
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const EVIDENCE = "../factory/demos/evidence/T-1100";

const guid = (n: number) => `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`;
const user = (n: number, over: Record<string, unknown> = {}) => ({
  type: "users",
  objectId: guid(n),
  displayName: `Priya Raman ${n}`,
  distinguishedName: `CN=Priya Raman ${n},OU=Sales,DC=corp,DC=example,DC=test`,
  domain: n % 2 === 0 ? "emea.example.test" : "corp.example.test",
  matchClass: "prefix",
  highlights: [{ field: "displayName", start: 0, length: 5 }],
  status: [] as unknown[],
  samAccountName: `praman${n}`,
  userPrincipalName: `praman${n}@corp.example.test`,
  ...over,
});
const group = (n: number) => ({
  type: "groups",
  objectId: guid(900 + n),
  displayName: `Payroll ${n}`,
  distinguishedName: `CN=Payroll ${n},OU=Groups,DC=corp,DC=example,DC=test`,
  domain: "corp.example.test",
  matchClass: "fuzzy",
  highlights: [],
  status: [],
  samAccountName: `payroll${n}`,
});
const problem = (status: number, title: string) => ({
  status,
  contentType: "application/problem+json",
  body: JSON.stringify({ type: "about:blank", title, status, traceId: "trace-e2e" }),
});

type Body = { q: string; type?: string; cursor?: string; groupLimit?: number };
type Answer = ReturnType<typeof problem> | { json: unknown };

async function answerWith(page: Page, handler: (b: Body) => Answer) {
  await page.route("**/api/v1/directory/search", async (route) => {
    const body = route.request().postDataJSON() as Body;
    const a = handler(body);
    return route.fulfill("json" in a ? { json: a.json } : a);
  });
}

// The console checks for a session before it shows any screen; these tests are signed in.
test.beforeEach(async ({ page }) => {
  await page.route("**/api/v1/auth/csrf", (route) =>
    route.fulfill({ json: { header: "X-CSRF-Token", value: "csrf-e2e" } }),
  );
});

async function noSeriousViolations(page: Page) {
  const { violations } = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(violations.filter((v) => v.impact === "critical" || v.impact === "serious")).toEqual([]);
}

const asOf = "2026-11-01T09:00:00Z";
const users100 = Array.from({ length: 100 }, (_, i) => user(i + 1));

test("the default state, a search with chips and counts, and the type filter", async ({ page }) => {
  await answerWith(page, (b) =>
    b.type === "groups"
      ? { json: { asOf, refine: false, groups: [{ type: "groups", items: [group(1)], count: 2 }] } }
      : {
          json: {
            asOf,
            refine: false,
            groups: [
              {
                type: "users",
                count: 13,
                more: true,
                nextCursor: "c1",
                items: [
                  user(1, {
                    status: [
                      { kind: "locked", at: "2026-11-01T09:12:00Z" },
                      { kind: "passwordExpiresInDays", days: 3 },
                      { kind: "tier0" },
                    ],
                    disambiguator: { title: "Analyst", office: "London" },
                  }),
                  user(2, { status: [{ kind: "disabled" }] }),
                ],
              },
              { type: "groups", count: 2, items: [group(1)] },
              { type: "computers", count: 0, items: [] },
              { type: "contacts", count: 0, items: [] },
            ],
          },
        },
  );
  await page.goto("/search");
  await expect(page.getByText("Type a name")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/default.png` });
  await noSeriousViolations(page);

  await page.getByRole("searchbox", { name: "Search the directory" }).fill("priya");
  await expect(page).toHaveURL(/\/search\?q=priya$/);
  const first = page.getByRole("row", { name: /Priya Raman 1\b/ });
  await expect(first).toBeVisible();
  await expect(first).toContainText("Locked");
  await expect(first).toContainText("Password expires in 3 d");
  await expect(first).toContainText("TIER 0");
  await expect(first).toContainText("Analyst · London");
  await expect(first).toContainText("CN=Priya Raman 1,OU=Sales");
  await expect(page.getByText("Users (13)")).toBeVisible();
  await expect(page.getByRole("link", { name: "Show all 13 users" })).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/results.png` });
  await noSeriousViolations(page);

  // The user row opens the user search; the group row has no link.
  await expect(page.getByRole("row", { name: /Payroll 1/ }).getByRole("link")).toHaveCount(0);
  await page.getByText("Groups (2)").click();
  await expect(page).toHaveURL(/type=groups/);
  await expect(page.getByRole("row", { name: /Payroll 1/ })).toBeVisible();
  await expect(page.getByRole("row", { name: /Priya Raman 1\b/ })).toHaveCount(0);
  await page.goBack();
  await expect(page.getByRole("row", { name: /Priya Raman 1\b/ })).toBeVisible();

  await page.getByRole("link", { name: "Priya Raman 1" }).click();
  await expect(page).toHaveURL(/\/directory\/users\?q=praman1$/);
});

test("Show all pages one type from the first page to the last, and 1,000 hits stop with a message", async ({
  page,
}) => {
  const pageOf = (cursor?: string) => {
    const n = cursor === undefined ? 0 : Number(cursor);
    const items = users100.slice(n * 50, n * 50 + 50);
    const last = n === 1;
    return {
      json: {
        asOf,
        refine: false,
        groups: [
          {
            type: "users",
            count: 100,
            items,
            ...(last ? { limitReached: true } : { more: true, nextCursor: String(n + 1) }),
          },
        ],
      },
    };
  };
  await answerWith(page, (b) => pageOf(b.cursor));
  await page.goto("/search?q=priya&type=users");
  await expect(page.getByRole("row")).toHaveCount(51);
  await expect(page.getByText("Showing 1–50 of 100 users.")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/large.png` });
  await noSeriousViolations(page);
  await page.getByRole("button", { name: "Next page" }).click();
  await expect(page.getByRole("row", { name: /Priya Raman 51\b/ })).toBeVisible();
  await expect(page.getByText("Showing the first 1,000 matches")).toBeVisible();
  await expect(page.getByRole("button", { name: "Next page" })).toHaveCount(0);
  await expect(page).toHaveURL(/\/search\?q=priya&type=users$/);
  await page.getByRole("button", { name: "Previous page" }).click();
  await expect(page.getByRole("row", { name: /Priya Raman 1\b/ })).toBeVisible();
});

test("empty offers Clear search; refine says keep typing", async ({ page }) => {
  let refine = false;
  await answerWith(page, () => ({
    json: {
      asOf,
      refine,
      groups: [
        { type: "users", items: [], ...(refine ? {} : { count: 0 }) },
        { type: "groups", items: [], ...(refine ? {} : { count: 0 }) },
      ],
    },
  }));
  await page.goto("/search?q=zzz");
  await expect(page.getByText("No objects match “zzz” in your scope")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/empty.png` });
  await noSeriousViolations(page);
  await page.getByRole("button", { name: "Clear search" }).click();
  await expect(page.getByText("Type a name")).toBeVisible();
  await expect(page.getByRole("searchbox", { name: "Search the directory" })).toBeFocused();

  refine = true;
  await page.goto("/search?q=a");
  await expect(page.getByText("Keep typing to narrow the search").first()).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/refine.png` });
  await noSeriousViolations(page);
});

for (const [status, text] of [
  [500, "The search failed"],
  [429, "Too many searches"],
  [403, "don't have permission"],
] as const) {
  test(`a ${status} shows its state with the Trace ID`, async ({ page }) => {
    let failing = true;
    await answerWith(page, () =>
      failing
        ? problem(status, "t")
        : {
            json: { asOf, refine: false, groups: [{ type: "users", items: [user(1)], count: 1 }] },
          },
    );
    await page.goto("/search?q=priya");
    const alert = page.getByRole("alert");
    await expect(alert).toContainText(text);
    await expect(alert).toContainText("trace-e2e");
    await page.screenshot({ path: `${EVIDENCE}/error-${status}.png` });
    await noSeriousViolations(page);
    if (status === 403) {
      await expect(page.getByRole("button", { name: "Retry" })).toHaveCount(0);
      return;
    }
    failing = false;
    await page.getByRole("button", { name: "Retry" }).click();
    await expect(page.getByRole("row", { name: /Priya Raman 1\b/ })).toBeVisible();
  });
}

test("a recovery-password-looking query is refused in the browser, sent nowhere and kept out of the address", async ({
  page,
}) => {
  let sent = 0;
  await answerWith(page, () => {
    sent++;
    return { json: { asOf, refine: false, groups: [] } };
  });
  const rp = "123456-123456-123456-123456-123456-123456-123456-123456";
  await page.goto("/search");
  await page.getByRole("searchbox", { name: "Search the directory" }).fill(rp);
  await expect(page.getByText("That looks like a recovery password.")).toBeVisible();
  await page.waitForTimeout(600);
  await page.keyboard.press("Enter");
  expect(sent).toBe(0);
  expect(page.url()).not.toContain("123456");
  await page.screenshot({ path: `${EVIDENCE}/recovery-password.png` });
  await noSeriousViolations(page);

  await page.goto(`/search?q=${rp}`);
  await expect(page.getByText("That looks like a recovery password.")).toBeVisible();
  expect(sent).toBe(0);
  expect(page.url()).not.toContain("123456");
});

test("full-width digits are refused in the browser too, and kept out of the address", async ({
  page,
}) => {
  let sent = 0;
  await answerWith(page, () => {
    sent++;
    return { json: { asOf, refine: false, groups: [] } };
  });
  const fullWidth = "１２３４５６-".repeat(7) + "１２３４５６";
  await page.goto("/search");
  await page.getByRole("searchbox", { name: "Search the directory" }).fill(fullWidth);
  await expect(page.getByText("That looks like a recovery password.")).toBeVisible();
  await page.keyboard.press("Enter");
  await page.waitForTimeout(600);
  expect(sent).toBe(0);
  expect(new URL(page.url()).pathname + new URL(page.url()).search).toBe("/search");
});

test("an answer with nothing usable shows the error state with Retry, not a blank console", async ({
  page,
}) => {
  let mode: "empty" | "ok" = "empty";
  await page.route("**/api/v1/directory/search", (route) =>
    mode === "empty"
      ? route.fulfill({ status: 204, headers: { "X-Trace-Id": "trace-e2e" } })
      : route.fulfill({ json: { asOf, refine: false, groups: [] } }),
  );
  await page.goto("/search?q=priya");
  await expect(page.getByText("The search answer could not be read")).toBeVisible();
  await expect(page.getByText("trace-e2e")).toBeVisible();
  await noSeriousViolations(page);
  mode = "ok";
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByText("No objects match")).toBeVisible();
});

test("every control works from the keyboard", async ({ page }) => {
  await answerWith(page, (b) => ({
    json: {
      asOf,
      refine: false,
      groups: [
        b.cursor === undefined
          ? { type: "users", count: 100, items: users100.slice(0, 50), more: true, nextCursor: "1" }
          : { type: "users", count: 100, items: users100.slice(50) },
      ],
    },
  }));
  await page.goto("/search?q=priya&type=users");
  await expect(page.getByRole("row")).toHaveCount(51);
  await page.getByRole("searchbox", { name: "Search the directory" }).focus();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Clear" })).toBeFocused();
  await page.keyboard.press("Tab");
  // The type filter is one radio group: arrows move and select.
  await expect(page.locator("input[type=radio]:checked")).toBeFocused();
  await page.keyboard.press("ArrowLeft");
  await expect(page).toHaveURL(/\/search\?q=priya$/);
  await page.keyboard.press("ArrowRight");
  await expect(page).toHaveURL(/type=users$/);
  const link = page.getByRole("link", { name: "Priya Raman 1", exact: true });
  await link.focus();
  await expect(link).toBeFocused();
  const next = page.getByRole("button", { name: "Next page" });
  await next.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("row", { name: /Priya Raman 51\b/ })).toBeVisible();
  await page.getByRole("button", { name: "Previous page" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByRole("row", { name: /Priya Raman 1\b/ })).toBeVisible();
  await page.getByRole("button", { name: "Clear" }).focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Type a name")).toBeVisible();
});

test("loading shows a skeleton", async ({ page }) => {
  let release: () => void = () => undefined;
  const gate = new Promise<void>((res) => (release = res));
  await page.route("**/api/v1/directory/search", async (route) => {
    await gate;
    await route.fulfill({
      json: { asOf, refine: false, groups: [{ type: "users", items: [user(1)], count: 1 }] },
    });
  });
  await page.goto("/search?q=priya");
  await expect(page.getByRole("status", { name: "Searching" })).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/loading.png` });
  release();
  await expect(page.getByRole("row", { name: /Priya Raman 1\b/ })).toBeVisible();
});
