// User search against a LIVE lab server (T-0686): no fixtures, the real API and the real directory.
// Runs only when ADIQ_BASE_URL points at a server built with `make web-embed` and started on a lab seed
// (-tags lab with WIN_LAB_* or LAB_* set). Inputs, all environment, none committed:
//   ADIQ_E2E_SESSION      the session cookie value (__Host-adiq_session) of a signed-in administrator
//   ADIQ_E2E_USER_NAME    a seeded user's display name (or a fragment of it)
//   ADIQ_E2E_USER_SAM     that user's sAMAccountName, shown in the row
// The cookie is minted through the sign-in API (see README).
import { createHash, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";
import { expect, test } from "@playwright/test";

const base = process.env["ADIQ_BASE_URL"];
const session = process.env["ADIQ_E2E_SESSION"];
const name = process.env["ADIQ_E2E_USER_NAME"];
const sam = process.env["ADIQ_E2E_USER_SAM"];
const EVIDENCE = process.env["ADIQ_E2E_EVIDENCE_DIR"] ?? "../factory/demos/evidence/T-0686";
const caPath = process.env["ADIQ_E2E_CA"];

test.skip(
  !base || !session || !name || !sam,
  "set ADIQ_BASE_URL, ADIQ_E2E_SESSION, ADIQ_E2E_USER_NAME, ADIQ_E2E_USER_SAM",
);
// TLS stays verified. With ADIQ_E2E_CA (the lab server's per-install certificate, which boot-lab-server.sh
// writes) trust is pinned to that one key: Chromium ignores NODE_EXTRA_CA_CERTS, so
// --ignore-certificate-errors-spki-list names the SHA-256 of its public key and any other key still fails.
// ADIQ_E2E_INSECURE=1 is an explicit, lab-only opt-out for a self-signed certificate.
function pinnedSpki(): string[] {
  if (!caPath) return [];
  const spki = new X509Certificate(readFileSync(caPath)).publicKey.export({
    type: "spki",
    format: "der",
  });
  return [
    `--ignore-certificate-errors-spki-list=${createHash("sha256").update(spki).digest("base64")}`,
  ];
}
test.use({
  ignoreHTTPSErrors: process.env["ADIQ_E2E_INSECURE"] === "1",
  launchOptions: { args: pinnedSpki() },
});

test("typing a seeded name lists the real user", async ({ page, context }) => {
  await context.addCookies([
    {
      name: "__Host-adiq_session",
      value: session ?? "",
      url: base ?? "",
      httpOnly: true,
      secure: true,
      sameSite: "Strict",
    },
  ]);
  await page.goto("/directory/users");
  await page.getByRole("searchbox", { name: "Search users" }).fill(name ?? "");
  const row = page.getByRole("row", { name: new RegExp(sam ?? "") });
  await expect(row).toBeVisible();
  await expect(page).toHaveURL(/\/directory\/users\?q=/);
  await page.screenshot({ path: `${EVIDENCE}/live-results.png` });
});
