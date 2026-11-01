// Walking skeleton, end to end (T-0671, M1 demo criterion 2): the real console, the real API, the real
// directory. A person signs in to a REAL lab-built server, types a name, and the real user appears.
// No page.route, no fixtures, no cookie injection: sign-in goes through the sign-in screen (password and
// authenticator code), the search through the search box, and the answer is read off the API response the
// browser received as well as off the screen.
//
// Runs only when ADIQ_BASE_URL is set. lab/e2e/run-skeleton-proof.sh {windows|samba} boots the server on the
// chosen lab and runs this file. Inputs, all environment, none committed:
//   ADIQ_BASE_URL          https://localhost:<port> of the booted server
//   ADIQ_E2E_SERVER_BIN    the `-tags lab` server binary (creates the console account)
//   ADIQ_E2E_CA            the server's per-install certificate; the browser trusts exactly that key
//   ADIQ_E2E_LAB           "windows" or "samba": names the evidence files
//   ADIQ_E2E_USER_SAM      sAMAccountName of the seeded user to find (default lab-user-01)
//   ADIQ_E2E_EVIDENCE_DIR  where screenshots go (default ../factory/demos/evidence/T-0671)
//   the server's own ACTIVEDIQ_DATABASE_DSN / ACTIVEDIQ_KEK_* settings, which `account init-local` reads
import { randomBytes } from "node:crypto";

import { expect, test } from "@playwright/test";

import { createLocalAccount, nextStepCode } from "./support/lab-server";
import { pinnedSpkiArgs } from "./support/pinned-tls";

const base = process.env["ADIQ_BASE_URL"];
const lab = process.env["ADIQ_E2E_LAB"] ?? "lab";
const sam = process.env["ADIQ_E2E_USER_SAM"] ?? "lab-user-01";
const evidence = process.env["ADIQ_E2E_EVIDENCE_DIR"] ?? "../factory/demos/evidence/T-0671";

test.skip(!base, "set ADIQ_BASE_URL (lab/e2e/run-skeleton-proof.sh sets everything)");
test.use({ launchOptions: { args: pinnedSpkiArgs(process.env["ADIQ_E2E_CA"]) } });

interface SearchItem {
  objectGuid?: string;
  samAccountName?: string;
  userPrincipalName?: string;
  enabled?: boolean;
}

test(`typing ${sam} in the console finds the real ${lab} user`, async ({ page }) => {
  // A console account made through the server's own command; it gets directory.read on the lab connection.
  const acct = await createLocalAccount(`skel-${randomBytes(4).toString("hex")}`);

  // 1. Signed out: the console sends us to sign-in and brings us back (real session, real cookie).
  await page.goto("/directory/users");
  await expect(page).toHaveURL(/\/sign-in\?next=%2Fdirectory%2Fusers/);
  await page.getByLabel("Account name").fill(acct.username);
  await page.getByLabel("Password").fill(acct.password);
  await page.keyboard.press("Enter");
  await page.getByLabel("Authenticator code").fill(nextStepCode(acct.seed));
  await page.keyboard.press("Enter");
  await expect(page).toHaveURL(/\/directory\/users$/);
  const box = page.getByRole("searchbox", { name: "Search users" });
  await expect(box).toBeVisible();
  await page.screenshot({ path: `${evidence}/${lab}-1-signed-in-idle.png` });

  // 2. Type the name. The answer comes from the real API; wait for exactly that response.
  const answered = page.waitForResponse(
    (r) => r.url().includes("/api/v1/directory/users?") && r.url().includes(`q=${sam}`),
  );
  await box.fill(sam);
  const res = await answered;
  expect(res.status()).toBe(200);
  const body = (await res.json()) as { items: SearchItem[] };
  const hit = body.items.filter((u) => u.samAccountName === sam);
  expect(hit).toHaveLength(1);
  expect(hit[0]?.objectGuid).toMatch(
    /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i,
  );
  expect(hit[0]?.enabled).toBe(true);

  // 3. The screen shows that same user: row, account name, enabled status, and the URL carries the query.
  const row = page.getByRole("row", { name: new RegExp(sam) });
  await expect(row).toBeVisible();
  await expect(row.getByText("Enabled")).toBeVisible();
  await expect(page).toHaveURL(new RegExp(`/directory/users\\?q=${sam}$`));
  await page.screenshot({ path: `${evidence}/${lab}-2-found.png` });

  // 4. Control: a name nobody has answers an empty list, not the same row and not an error.
  const none = page.waitForResponse(
    (r) => r.url().includes("/api/v1/directory/users?") && r.url().includes("q=no-such-user-zz"),
  );
  await box.fill("no-such-user-zz");
  expect((await none).status()).toBe(200);
  await expect(page.getByText("No users match")).toBeVisible();
  await expect(row).toHaveCount(0);
  await page.screenshot({ path: `${evidence}/${lab}-3-no-match.png` });
});
