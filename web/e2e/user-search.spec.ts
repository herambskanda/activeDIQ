// The user search screen, in a real browser against the built console (T-1473). The API is
// answered by fixtures here (tests may carry them); the console is the shipped bundle.
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const EVIDENCE = "../factory/demos/evidence/T-1473";
const hit = (n: number, displayName: string, sam: string, disabled: boolean) => ({
  type: "users",
  objectId: `00000000-0000-4000-8000-${String(n).padStart(12, "0")}`,
  displayName,
  matchClass: "prefix",
  highlights: [],
  samAccountName: sam,
  userPrincipalName: `${sam}@lab.test`,
  distinguishedName: `CN=${displayName},OU=Lab,DC=lab,DC=test`,
  domain: "",
  status: disabled ? [{ kind: "disabled" }] : [],
});
const users = [hit(1, "Ada Lovelace", "alovelace", false), hit(2, "Grace Hopper", "ghopper", true)];
const answer = (items: unknown[], group: Record<string, unknown> = {}) => ({
  groups: [{ type: "users", items, ...group }],
  refine: false,
  asOf: "2026-11-01T10:00:00Z",
});

const problem = (status: number, title: string) => ({
  status,
  contentType: "application/problem+json",
  body: JSON.stringify({ type: "about:blank", title, status, traceId: "trace-e2e" }),
});

async function answerWith(
  page: Page,
  handler: (q: string) => ReturnType<typeof problem> | undefined,
) {
  await page.route("**/api/v1/directory/search", async (route) => {
    const { q } = route.request().postDataJSON() as { q: string };
    const failure = handler(q);
    if (failure) return route.fulfill(failure);
    const items = users.filter((u) => u.displayName.toLowerCase().includes(q.toLowerCase()));
    return route.fulfill({ json: answer(items) });
  });
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

test("typing a name shows the matching users, and the search is in the URL", async ({ page }) => {
  await answerWith(page, () => undefined);
  await page.goto("/");
  await expect(page.getByText("Type a name")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/default.png` });
  await noCriticalViolations(page);

  await page.getByRole("searchbox", { name: "Search users" }).fill("ada");
  await expect(page.getByRole("row", { name: /Ada Lovelace/ })).toBeVisible();
  await expect(page.getByRole("row", { name: /Grace Hopper/ })).toHaveCount(0);
  await expect(page).toHaveURL(/\?q=ada$/);
  await page.screenshot({ path: `${EVIDENCE}/results.png` });
  await noCriticalViolations(page);

  await page.getByRole("searchbox", { name: "Search users" }).fill("a");
  await expect(page.getByRole("row", { name: /Grace Hopper.*Disabled/ })).toBeVisible();
  await page.goBack();
  await expect(page.getByRole("searchbox", { name: "Search users" })).toHaveValue("ada");
  await expect(page.getByRole("row", { name: /Grace Hopper/ })).toHaveCount(0);
});

test("no match shows the empty state and Clear search returns to the start", async ({ page }) => {
  await answerWith(page, () => undefined);
  await page.goto("/directory/users?q=zzz");
  await expect(page.getByText("No users match “zzz” in your scope")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/empty.png` });
  await page.getByRole("button", { name: "Clear search" }).click();
  await expect(page.getByText("Type a name")).toBeVisible();
  await expect(page.getByRole("searchbox", { name: "Search users" })).toBeFocused();
});

test("a server error shows an actionable error, and Retry recovers", async ({ page }) => {
  let failing = true;
  await answerWith(page, () => (failing ? problem(500, "boom") : undefined));
  await page.goto("/directory/users?q=ada");
  const alert = page.getByRole("alert");
  await expect(alert).toContainText("The search failed");
  await expect(alert).toContainText("trace-e2e");
  await page.screenshot({ path: `${EVIDENCE}/error.png` });
  await noCriticalViolations(page);
  failing = false;
  await page.getByRole("button", { name: "Retry" }).click();
  await expect(page.getByRole("row", { name: /Ada Lovelace/ })).toBeVisible();
});

test("a 403 shows permission denied, not a blank page", async ({ page }) => {
  await answerWith(page, () => problem(403, "Forbidden"));
  await page.goto("/directory/users?q=ada");
  await expect(page.getByRole("alert")).toContainText("don't have permission");
  await expect(page.getByRole("button", { name: "Retry" })).toHaveCount(0);
  await page.screenshot({ path: `${EVIDENCE}/permission-denied.png` });
  await noCriticalViolations(page);
});

test("a recovery-password-looking text is explained beside the box and nothing is sent", async ({
  page,
}) => {
  let sent = 0;
  await answerWith(page, () => {
    sent++;
    return undefined;
  });
  await page.goto("/");
  await page
    .getByRole("searchbox", { name: "Search users" })
    .fill("123456-123456-123456-123456-123456-123456-123456-123456");
  await expect(page.getByText("recovery password")).toBeVisible();
  await page.waitForTimeout(600);
  expect(sent).toBe(0);
  await page.screenshot({ path: `${EVIDENCE}/invalid.png` });
});

test("the whole screen works from the keyboard", async ({ page }) => {
  await answerWith(page, () => undefined);
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();
  await page.keyboard.press("Tab"); // the shell's search button comes first
  await page.keyboard.press("Tab");
  await expect(page.getByRole("searchbox", { name: "Search users" })).toBeFocused();
  await page.keyboard.type("ada");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("row", { name: /Ada Lovelace/ })).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(page.getByRole("button", { name: "Clear" })).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Type a name")).toBeVisible();
});

test("loading shows a skeleton and a long answer pages by the API's cursor", async ({ page }) => {
  const many = Array.from({ length: 50 }, (_, i) =>
    hit(i + 100, `Lab User ${String(i).padStart(2, "0")}`, `labuser${i}`, i % 5 === 0),
  );
  let release: () => void = () => undefined;
  const gate = new Promise<void>((res) => (release = res));
  const bodies: { q: string; type?: string; cursor?: string }[] = [];
  await page.route("**/api/v1/directory/search", async (route) => {
    const body = route.request().postDataJSON() as (typeof bodies)[number];
    bodies.push(body);
    await gate;
    await route.fulfill({
      json:
        body.cursor === undefined
          ? answer(many, { count: 51, nextCursor: "c1" })
          : answer([hit(999, "Lab User 99", "labuser99", false)], { count: 51 }),
    });
  });
  await page.goto("/directory/users?q=lab");
  await expect(page.getByRole("status", { name: "Searching" })).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/loading.png` });
  release();
  await expect(page.getByText("Showing 1–50 of 51 users.")).toBeVisible();
  await expect(page.getByRole("row")).toHaveCount(51);
  await page.screenshot({ path: `${EVIDENCE}/paged.png` });
  await noCriticalViolations(page);
  await page.getByRole("button", { name: "Next page" }).click();
  await expect(page.getByRole("row", { name: /Lab User 99/ })).toBeVisible();
  expect(bodies.every((b) => b.type === "users")).toBe(true);
  expect(bodies[1]?.cursor).toBe("c1");
});

test("a search never calls the old user-search operation", async ({ page }) => {
  const old: string[] = [];
  page.on("request", (r) => {
    if (new URL(r.url()).pathname.endsWith("/api/v1/directory/users")) old.push(r.url());
  });
  await answerWith(page, () => undefined);
  await page.goto("/directory/users?q=ada");
  await expect(page.getByRole("row", { name: /Ada Lovelace/ })).toBeVisible();
  expect(old).toEqual([]);
});
