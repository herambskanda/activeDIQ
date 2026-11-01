// Command palette overlay (T-1101) in a real browser against the built console bundle.
// API answers are routed with test fixtures; evidence captured to factory/demos/evidence/T-1101/.
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const EVIDENCE = "../factory/demos/evidence/T-1101";

const searchResultsFixture = () => ({
  asOf: "2026-11-01T15:00:00Z",
  refine: false,
  groups: [
    {
      type: "users",
      count: 2,
      items: [
        {
          objectId: "u-exact",
          type: "users",
          displayName: "Ada Lovelace",
          samAccountName: "alovelace",
          userPrincipalName: "alovelace@corp.example.test",
          distinguishedName: "CN=Ada Lovelace,OU=Staff,DC=corp,DC=example,DC=test",
          domain: "corp.example.test",
          matchClass: "exact",
          status: [{ kind: "locked", at: "2026-11-01T09:12:00Z" }],
          disambiguator: {
            title: "Chief Mathematician",
            office: "London",
          },
          highlights: [],
        },
        {
          objectId: "u-prefix",
          type: "users",
          displayName: "Adam Smith",
          samAccountName: "asmith",
          userPrincipalName: "asmith@corp.example.test",
          distinguishedName: "CN=Adam Smith,OU=Finance,DC=corp,DC=example,DC=test",
          domain: "corp.example.test",
          matchClass: "prefix",
          status: [{ kind: "disabled" }],
          highlights: [],
        },
      ],
    },
    {
      type: "groups",
      count: 1,
      items: [
        {
          objectId: "g-tier0",
          type: "groups",
          displayName: "Domain Admins",
          samAccountName: "Domain Admins",
          distinguishedName: "CN=Domain Admins,CN=Users,DC=corp,DC=example,DC=test",
          domain: "corp.example.test",
          matchClass: "prefix",
          status: [{ kind: "tier0" }],
          highlights: [],
        },
      ],
    },
  ],
});

test.beforeEach(async ({ page }) => {
  // Session CSRF response
  await page.route("**/api/v1/auth/csrf", (route) =>
    route.fulfill({ json: { header: "X-CSRF-Token", value: "csrf-e2e" } }),
  );
  // Default mock search response
  await page.route("**/api/v1/directory/search", async (route) => {
    return route.fulfill({ json: searchResultsFixture() });
  });
  // Default mock users response
  await page.route("**/api/v1/directory/users?*", (route) =>
    route.fulfill({
      json: {
        items: [
          {
            objectGuid: "00000000-0000-4000-8000-000000000001",
            displayName: "Ada Lovelace",
            samAccountName: "alovelace",
            userPrincipalName: "alovelace@corp.example.test",
            enabled: true,
          },
        ],
      },
    }),
  );
});

async function noCriticalViolations(page: Page) {
  const { violations } = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(violations.filter((v) => v.impact === "critical" || v.impact === "serious")).toEqual([]);
}

test("Command palette opens via top-bar search button and keyboard shortcuts, and closes on Escape", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.getByTestId("top-bar-search")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/top-bar.png` });

  // Click top bar search button
  await page.getByTestId("top-bar-search").click();
  const combobox = page.getByRole("combobox", { name: "Search" });
  await expect(combobox).toBeVisible();
  await expect(combobox).toBeFocused();
  await page.screenshot({ path: `${EVIDENCE}/palette-open-idle.png` });
  await noCriticalViolations(page);

  // Escape closes
  await page.keyboard.press("Escape");
  await expect(combobox).toHaveCount(0);

  // Press / outside text field to open
  await page.keyboard.press("/");
  await expect(combobox).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(combobox).toHaveCount(0);

  // Press Ctrl+K to toggle open and closed
  await page.keyboard.press("Control+KeyK");
  await expect(combobox).toBeVisible();
  await page.keyboard.press("Control+KeyK");
  await expect(combobox).toHaveCount(0);
});

test("Universal directory search shows grouped results with exact hit first, chips, and index footer", async ({
  page,
}) => {
  await page.goto("/");
  await expect(page.getByTestId("top-bar-search")).toBeVisible();
  await page.keyboard.press("Control+KeyK");
  const combobox = page.getByRole("combobox", { name: "Search" });

  await combobox.fill("ada");
  const listbox = page.getByRole("listbox", { name: "Search" });
  await expect(listbox).toBeVisible();

  // Exact group has Ada Lovelace
  await expect(listbox.locator(".diq-pal__gh", { hasText: "Exact" })).toBeVisible();
  await expect(page.getByRole("option", { name: /Ada Lovelace/ })).toBeVisible();
  await expect(page.getByText("Locked 09:12")).toBeVisible();

  // Users group has Adam Smith
  await expect(listbox.locator(".diq-pal__gh", { hasText: "Users" })).toBeVisible();
  await expect(page.getByRole("option", { name: /Adam Smith/ })).toBeVisible();

  // Groups group has Domain Admins with TIER 0
  await expect(listbox.locator(".diq-pal__gh", { hasText: "Groups" })).toBeVisible();
  await expect(page.getByText("TIER 0")).toBeVisible();

  // Footer shows index timestamp
  await expect(page.getByText(/index as of/)).toBeVisible();

  await page.screenshot({ path: `${EVIDENCE}/palette-results-grouped.png` });
  await noCriticalViolations(page);

  // Press Enter on the exact hit -> navigates to /directory/users?q=alovelace
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/directory\/users\?q=alovelace/);
  await page.screenshot({ path: `${EVIDENCE}/palette-exact-navigation.png` });
});

test("Refuses 48-digit recovery passwords in the browser with IA message and sends zero requests", async ({
  page,
}) => {
  let searchCallCount = 0;
  await page.route("**/api/v1/directory/search", async (route) => {
    searchCallCount++;
    return route.fulfill({ json: searchResultsFixture() });
  });

  await page.goto("/");
  await expect(page.getByTestId("top-bar-search")).toBeVisible();
  await page.keyboard.press("Control+KeyK");
  const combobox = page.getByRole("combobox", { name: "Search" });

  const pwd48 = "123456-789012-345678-901234-567890-123456-789012-345678";
  await combobox.fill(pwd48);

  // Refusal message appears in StatePanel
  await expect(
    page.getByText(
      "That looks like a recovery password. Search by the 8-character key ID instead.",
    ),
  ).toBeVisible();
  expect(searchCallCount).toBe(0);

  await page.screenshot({ path: `${EVIDENCE}/palette-recovery-refused.png` });
  await noCriticalViolations(page);
});

test("Shows actionable error state on 403 with Trace ID", async ({ page }) => {
  await page.route("**/api/v1/directory/search", (route) =>
    route.fulfill({
      status: 403,
      contentType: "application/problem+json",
      json: {
        type: "about:blank",
        title: "Forbidden",
        status: 403,
        traceId: "trace-403-e2e",
      },
    }),
  );

  await page.goto("/");
  await expect(page.getByTestId("top-bar-search")).toBeVisible();
  await page.keyboard.press("Control+KeyK");
  const combobox = page.getByRole("combobox", { name: "Search" });
  await combobox.fill("forbidden");

  await expect(page.getByText("Search forbidden")).toBeVisible();
  await expect(page.getByText("trace-403-e2e")).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/palette-error-403.png` });
  await noCriticalViolations(page);
});
