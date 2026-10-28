// The user search screen, in a real browser against the built console (T-0670). The API is
// answered by fixtures here (tests may carry them); the console is the shipped bundle.
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const EVIDENCE = "../factory/demos/evidence/T-0670";
const users = [
  {
    objectGuid: "00000000-0000-4000-8000-000000000001",
    displayName: "Ada Lovelace",
    samAccountName: "alovelace",
    userPrincipalName: "alovelace@lab.test",
    enabled: true,
  },
  {
    objectGuid: "00000000-0000-4000-8000-000000000002",
    displayName: "Grace Hopper",
    samAccountName: "ghopper",
    userPrincipalName: "ghopper@lab.test",
    enabled: false,
  },
];

const problem = (status: number, title: string) => ({
  status,
  contentType: "application/problem+json",
  body: JSON.stringify({ type: "about:blank", title, status, requestId: "req-e2e" }),
});

async function answerWith(
  page: Page,
  handler: (q: string) => ReturnType<typeof problem> | undefined,
) {
  await page.route("**/api/v1/directory/users?*", async (route) => {
    const q = new URL(route.request().url()).searchParams.get("q") ?? "";
    const failure = handler(q);
    if (failure) return route.fulfill(failure);
    const items = users.filter((u) => u.displayName.toLowerCase().includes(q.toLowerCase()));
    return route.fulfill({ json: { items } });
  });
}

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
  await expect(page.getByText("No users match “zzz”")).toBeVisible();
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
  await expect(alert).toContainText("req-e2e");
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

test("refused characters are explained beside the box and nothing is sent", async ({ page }) => {
  let sent = 0;
  await answerWith(page, () => {
    sent++;
    return undefined;
  });
  await page.goto("/");
  await page.getByRole("searchbox", { name: "Search users" }).fill("a*");
  await expect(page.getByText("can't contain")).toBeVisible();
  await page.waitForTimeout(600);
  expect(sent).toBe(0);
  await page.screenshot({ path: `${EVIDENCE}/invalid.png` });
});

test("the whole screen works from the keyboard", async ({ page }) => {
  await answerWith(page, () => undefined);
  await page.goto("/");
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

test("loading shows a skeleton and a full page of matches says it was capped", async ({ page }) => {
  const many = Array.from({ length: 25 }, (_, i) => ({
    objectGuid: `00000000-0000-4000-8000-${String(i + 100).padStart(12, "0")}`,
    displayName: `Lab User ${String(i).padStart(2, "0")}`,
    samAccountName: `labuser${i}`,
    userPrincipalName: `labuser${i}@lab.test`,
    enabled: i % 5 !== 0,
  }));
  let release: () => void = () => undefined;
  const gate = new Promise<void>((res) => (release = res));
  await page.route("**/api/v1/directory/users?*", async (route) => {
    await gate;
    await route.fulfill({ json: { items: many } });
  });
  await page.goto("/directory/users?q=lab");
  await expect(page.getByRole("status", { name: "Searching" })).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/loading.png` });
  release();
  await expect(page.getByText("Showing the first 25 matches")).toBeVisible();
  await expect(page.getByRole("row")).toHaveCount(26);
  await page.screenshot({ path: `${EVIDENCE}/capped.png` });
  await noCriticalViolations(page);
});
