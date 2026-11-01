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

test("a security key signs in as the second factor (T-0772)", async ({ page }) => {
  let signedIn = false;
  let assertionBody: Record<string, string> | undefined;
  await page.addInitScript(() => {
    // A stand-in key: the browser prompt itself cannot run headless. The console's own encoding,
    // challenge handling and the API calls are the real ones.
    const u8 = (...n: number[]) => new Uint8Array(n).buffer;
    navigator.credentials.get = async () =>
      ({
        type: "public-key",
        rawId: u8(1, 2, 3),
        response: {
          authenticatorData: u8(4, 5),
          clientDataJSON: u8(6, 7),
          signature: u8(8, 9),
          userHandle: null,
        },
      }) as unknown as Credential;
  });
  await page.route("**/api/v1/auth/csrf", (route) =>
    signedIn
      ? route.fulfill({ json: { header: "X-CSRF-Token", value: "csrf-key" } })
      : route.fulfill({
          ...failed,
          body: JSON.stringify({ type: "about:blank", title: "Unauthenticated", status: 401 }),
        }),
  );
  await page.route("**/api/v1/auth/break-glass/password", (route) =>
    route.fulfill({ status: 204 }),
  );
  await page.route("**/api/v1/auth/second-factor/webauthn/challenge", (route) =>
    route.fulfill({
      json: {
        challenge: "AQID",
        rpId: "localhost",
        timeoutMs: 60000,
        userVerification: "preferred",
        allowCredentials: [{ type: "public-key", id: "AQID" }],
      },
    }),
  );
  await page.route("**/api/v1/auth/second-factor/webauthn/verify", (route) => {
    assertionBody = route.request().postDataJSON() as Record<string, string>;
    signedIn = true;
    return route.fulfill({ status: 204 });
  });
  await page.route("**/api/v1/directory/users?*", (route) =>
    route.fulfill({ json: { items: [] } }),
  );

  await page.goto("/directory/users?q=ada");
  await page.getByLabel("Account name").fill("breakglass");
  await page.getByLabel("Password").fill("right");
  await page.keyboard.press("Enter");
  const key = page.getByRole("button", { name: "Use a security key" });
  await expect(key).toBeVisible();
  await page.screenshot({ path: `../factory/demos/evidence/T-0772/sign-in-security-key.png` });
  await key.click();
  await expect(page).toHaveURL(/\/directory\/users\?q=ada$/);
  expect(assertionBody).toEqual({
    credentialId: "AQID",
    authenticatorData: "BAU",
    clientDataJson: "Bgc",
    signature: "CAk",
  });
});
