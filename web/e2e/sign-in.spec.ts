// The console sign-in, in a real browser against the built console (T-0764). The API is answered
// by fixtures here; the console is the shipped bundle.
import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

const EVIDENCE = "../factory/demos/evidence/T-0764";

const failed = {
  status: 401,
  contentType: "application/problem+json",
  body: JSON.stringify({
    type: "/problems/sign-in-failed",
    title: "Sign-in failed",
    status: 401,
  }),
};

async function answer(page: Page) {
  let signedIn = false;
  const seen: { csrf: string | null; url: string }[] = [];
  await page.route("**/api/v1/auth/csrf", (route) =>
    signedIn
      ? route.fulfill({ json: { header: "X-CSRF-Token", value: "csrf-e2e" } })
      : route.fulfill({
          ...failed,
          body: JSON.stringify({ type: "about:blank", title: "Unauthenticated", status: 401 }),
        }),
  );
  await page.route("**/api/v1/auth/break-glass/password", (route) => {
    const { password } = route.request().postDataJSON() as { password: string };
    return password === "right" ? route.fulfill({ status: 204 }) : route.fulfill(failed);
  });
  await page.route("**/api/v1/auth/second-factor/totp/verify", (route) => {
    const { code } = route.request().postDataJSON() as { code: string };
    if (code !== "123456") return route.fulfill(failed);
    signedIn = true;
    return route.fulfill({ status: 204 });
  });
  await page.route("**/api/v1/directory/users?*", (route) => {
    seen.push({
      csrf: route.request().headers()["x-csrf-token"] ?? null,
      url: route.request().url(),
    });
    return route.fulfill({ json: { items: [] } });
  });
  return seen;
}

test("no session shows the sign-in screen; signing in returns to the requested page", async ({
  page,
}) => {
  const seen = await answer(page);
  await page.goto("/directory/users?q=ada");
  await expect(page).toHaveURL(/\/sign-in\?next=%2Fdirectory%2Fusers%3Fq%3Dada$/);
  await expect(page.getByRole("heading", { name: "Sign in to activeDIQ" })).toBeVisible();
  await page.screenshot({ path: `${EVIDENCE}/sign-in-default.png` });
  const { violations } = await new AxeBuilder({ page })
    .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
    .analyze();
  expect(violations.filter((v) => v.impact === "critical" || v.impact === "serious")).toEqual([]);

  await page.getByLabel("Account name").fill("breakglass");
  await page.getByLabel("Password").fill("wrong");
  await page.keyboard.press("Enter");
  await expect(page.getByRole("alert")).toContainText("Sign-in failed");
  await page.screenshot({ path: `${EVIDENCE}/sign-in-error.png` });

  await page.getByLabel("Password").fill("right");
  await page.keyboard.press("Enter");
  await page.getByLabel("Authenticator code").fill("123456");
  await page.screenshot({ path: `${EVIDENCE}/sign-in-code.png` });
  await page.keyboard.press("Enter");

  await expect(page).toHaveURL(/\/directory\/users\?q=ada$/);
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();
  await expect.poll(() => seen.length).toBeGreaterThan(0);
  expect(seen[0]?.url).toContain("q=ada");
});
