// Console sign-in with a security key against a REAL lab-built server (T-0855). No fixtures and no
// page.route: the real console, the real API, the real database and a Chromium virtual authenticator
// (DevTools WebAuthn domain: CTAP2, internal transport, user verification on).
//
// Runs only when ADIQ_BASE_URL is set; boot the server with lab/e2e/boot-lab-server.sh and `source` the env
// file it writes (see knowledge/development/runbooks/playwright-tooling.md §6). Inputs, all environment:
//   ADIQ_BASE_URL          https://localhost:<port>, the server's ACTIVEDIQ_PUBLIC_URL
//   ADIQ_E2E_SERVER_BIN    the `-tags lab` server binary (creates accounts, stores passkey public keys)
//   ADIQ_E2E_CA            the server's per-install certificate (PEM). TLS stays verified: the browser is
//                          told to trust exactly that certificate's key, nothing else
//   ADIQ_E2E_EVIDENCE_DIR  optional: where to save screenshots
//   the server's own ACTIVEDIQ_DATABASE_DSN / ACTIVEDIQ_KEK_* settings, which the account commands read
//
// There is no registration ceremony yet (T-0573). Each test makes an ES256 key pair, hands the PRIVATE key
// to the virtual authenticator and stores the PUBLIC key on a fresh local account through the lab-only
// `account add-passkey` command, so the server verifies a real signature.
import { createHash, randomBytes, X509Certificate } from "node:crypto";
import { readFileSync } from "node:fs";

import {
  type BrowserContext,
  type CDPSession,
  expect,
  type Page,
  test as playwrightTest,
} from "@playwright/test";

import {
  addPasskey,
  createLocalAccount,
  type LocalAccount,
  nextStepCode,
  newPasskey,
  type Passkey,
} from "./support/lab-server";

const base = process.env["ADIQ_BASE_URL"];
const caPath = process.env["ADIQ_E2E_CA"];
const evidenceDir = process.env["ADIQ_E2E_EVIDENCE_DIR"];
const SESSION_COOKIE = "__Host-adiq_session";

const test = playwrightTest.extend<{ networkWatch: undefined }>({
  // Chromium aborts in-flight requests with net::ERR_NETWORK_CHANGED whenever the host's network interfaces
  // change (on a shared Docker host, every container start adds a veth). That is the environment, not the
  // product, and a POST is not retried by the browser. A failure that saw one says so in its annotations,
  // so nobody debugs the server for it; the config's single reported retry covers it.
  networkWatch: [
    async ({ page }, use, testInfo) => {
      let changed = false;
      page.on("requestfailed", (r) => {
        if (r.failure()?.errorText.includes("ERR_NETWORK_CHANGED")) changed = true;
      });
      await use(undefined);
      if (changed && testInfo.status !== testInfo.expectedStatus) {
        testInfo.annotations.push({
          type: "environment",
          description:
            "Chromium reported net::ERR_NETWORK_CHANGED during this test: the host's network interfaces changed (Docker veth churn?). Not a product result.",
        });
      }
    },
    { auto: true },
  ],
});

test.skip(
  !process.env["ADIQ_BASE_URL"],
  "set ADIQ_BASE_URL (and the rest of the env file boot-lab-server.sh writes)",
);

// TLS stays verified. Chromium ignores NODE_EXTRA_CA_CERTS, so trust is pinned to the one certificate:
// --ignore-certificate-errors-spki-list names the SHA-256 of its public key, and any other key still fails.
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
test.use({ launchOptions: { args: pinnedSpki() } });

// Each test makes its own accounts and keys, so none depends on another or on run order.
const unique = () => `e2e-${randomBytes(4).toString("hex")}`;

async function virtualAuthenticator(
  context: BrowserContext,
  page: Page,
  opts: { isUserVerified: boolean },
): Promise<{ cdp: CDPSession; authenticatorId: string }> {
  const cdp = await context.newCDPSession(page);
  await cdp.send("WebAuthn.enable");
  const { authenticatorId } = await cdp.send("WebAuthn.addVirtualAuthenticator", {
    options: {
      protocol: "ctap2",
      transport: "internal",
      hasResidentKey: true,
      hasUserVerification: true,
      isUserVerified: opts.isUserVerified,
      automaticPresenceSimulation: true,
    },
  });
  return { cdp, authenticatorId };
}

/** Puts the key's private half into the authenticator, as a registered credential for the relying party. */
async function holdCredential(
  cdp: CDPSession,
  authenticatorId: string,
  key: Passkey,
  privateKey = key.privateKey,
) {
  await cdp.send("WebAuthn.addCredential", {
    authenticatorId,
    credential: {
      credentialId: key.credentialId.toString("base64"),
      isResidentCredential: true,
      rpId: new URL(base ?? "").hostname,
      privateKey: privateKey.export({ type: "pkcs8", format: "der" }).toString("base64"),
      userHandle: key.userHandle.toString("base64"),
      signCount: 0,
    },
  });
}

/** An active account with TOTP and, when `key` is given, that passkey registered on the server. */
async function account(key?: Passkey): Promise<LocalAccount> {
  const a = await createLocalAccount(unique());
  if (key) await addPasskey(a.id, key);
  return a;
}

async function passwordStep(page: Page, a: LocalAccount) {
  await page.goto("/directory/users"); // no session: the console moves to sign-in and remembers where to return
  await expect(page.getByRole("heading", { name: "Sign in to activeDIQ" })).toBeVisible();
  await page.getByLabel("Account name").fill(a.username);
  await page.getByLabel("Password").fill(a.password);
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("button", { name: "Use a security key" })).toBeVisible();
}

async function sessionCookies(context: BrowserContext) {
  return (await context.cookies()).filter((c) => c.name === SESSION_COOKIE);
}

/** GET /auth/csrf from inside the page, so the browser (which trusts the pinned certificate) sends its own cookies. */
async function csrfProbe(page: Page): Promise<{ status: number; body: unknown }> {
  return page.evaluate(async () => {
    const r = await fetch("/api/v1/auth/csrf", { credentials: "same-origin" });
    return { status: r.status, body: r.ok ? await r.json() : null };
  });
}

async function expectNoSession(context: BrowserContext, page: Page) {
  expect(await sessionCookies(context)).toEqual([]);
  // The server's answer, not the cookie jar alone: the console's own session probe is 401.
  expect((await csrfProbe(page)).status).toBe(401);
}

test("a registered security key signs in: session cookie set by the server, CSRF served, console loads", async ({
  page,
  context,
}, testInfo) => {
  const key = newPasskey();
  const a = await account(key);
  const { cdp, authenticatorId } = await virtualAuthenticator(context, page, {
    isUserVerified: true,
  });
  await holdCredential(cdp, authenticatorId, key);

  await passwordStep(page, a);
  const csrf = page.waitForResponse(
    (r) =>
      new URL(r.url()).pathname === "/api/v1/auth/csrf" && r.request().method() === "GET" && r.ok(),
  );
  await page.getByRole("button", { name: "Use a security key" }).click();

  await expect(page).toHaveURL(/\/directory\/users/);
  expect((await csrf).status()).toBe(200);
  const [session] = await sessionCookies(context);
  expect(session).toMatchObject({ httpOnly: true, secure: true, sameSite: "Strict", path: "/" });
  expect(session?.value.length).toBeGreaterThan(20);
  // The server's own answer to the cookie, from outside the page's code.
  const probe = await csrfProbe(page);
  expect(probe.status).toBe(200);
  expect(probe.body).toMatchObject({ header: "X-CSRF-Token", value: expect.any(String) });
  // The key was used: the authenticator's counter moved, so the assertion was real, not a cached session.
  const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  expect(credentials.map((c) => c.signCount)).toEqual([1]);

  await expect(page.getByRole("searchbox", { name: "Search users" })).toBeVisible();
  if (evidenceDir)
    await page.screenshot({ path: `${evidenceDir}/signed-in-with-security-key.png` });
  await testInfo.attach("session-cookie-flags", {
    body: JSON.stringify({ ...session, value: "<redacted>" }),
    contentType: "application/json",
  });
});

test("a valid TOTP code is refused for an account that has a registered key", async ({
  page,
  context,
}) => {
  const key = newPasskey();
  const a = await account(key);
  await passwordStep(page, a);

  await page.getByLabel("Authenticator code").fill(nextStepCode(a.seed));
  const verify = page.waitForResponse(
    (r) => new URL(r.url()).pathname === "/api/v1/auth/second-factor/totp/verify",
  );
  await page.getByRole("button", { name: "Sign in" }).click();

  expect((await verify).status()).toBe(401);
  await expect(page.getByText("Sign-in failed. Check the details and try again.")).toBeVisible();
  await expect(page.getByRole("heading", { name: "Sign in to activeDIQ" })).toBeVisible();
  await expect(page).not.toHaveURL(/\/directory\/users/);
  await expectNoSession(context, page);
  if (evidenceDir)
    await page.screenshot({ path: `${evidenceDir}/totp-refused-for-key-account.png` });
});

test("control: the same kind of code IS accepted for an account without a key", async ({
  page,
  context,
}) => {
  // Without this, the refusal above could be a bad code rather than the passkey lock.
  const a = await account();
  await passwordStep(page, a);
  await page.getByLabel("Authenticator code").fill(nextStepCode(a.seed));
  await page.getByRole("button", { name: "Sign in" }).click();
  await expect(page).toHaveURL(/\/directory\/users/);
  expect(await sessionCookies(context)).toHaveLength(1);
});

test("an authenticator that does not hold the credential cannot sign in", async ({
  page,
  context,
}) => {
  const key = newPasskey();
  const a = await account(key);
  await virtualAuthenticator(context, page, { isUserVerified: true }); // present, user-verifying, empty
  await passwordStep(page, a);

  await page.getByRole("button", { name: "Use a security key" }).click();
  await expect(page.getByText("The security key was not used.")).toBeVisible();
  await expectNoSession(context, page);
  await expect(page).not.toHaveURL(/\/directory\/users/);
});

test("an authenticator that fails user verification cannot sign in", async ({ page, context }) => {
  const key = newPasskey();
  const a = await account(key);
  const { cdp, authenticatorId } = await virtualAuthenticator(context, page, {
    isUserVerified: false,
  });
  await holdCredential(cdp, authenticatorId, key); // the right credential, but the user is not verified
  await passwordStep(page, a);

  await page.getByRole("button", { name: "Use a security key" }).click();
  await expect(page.getByText("The security key was not used.")).toBeVisible();
  await expectNoSession(context, page);
  const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  expect(credentials.map((c) => c.signCount)).toEqual([0]); // it never signed
});

test("the registered credential ID with a different private key is refused by the server", async ({
  page,
  context,
}) => {
  // The authenticator answers, so the browser sends an assertion; only the SERVER's signature check can refuse it.
  const key = newPasskey();
  const impostor = newPasskey();
  const a = await account(key);
  const { cdp, authenticatorId } = await virtualAuthenticator(context, page, {
    isUserVerified: true,
  });
  await holdCredential(cdp, authenticatorId, key, impostor.privateKey);
  await passwordStep(page, a);

  const verify = page.waitForResponse(
    (r) => new URL(r.url()).pathname === "/api/v1/auth/second-factor/webauthn/verify",
  );
  await page.getByRole("button", { name: "Use a security key" }).click();
  expect((await verify).status()).toBe(401);
  await expect(page.getByText("Sign-in failed. Check the details and try again.")).toBeVisible();
  await expectNoSession(context, page);
  const { credentials } = await cdp.send("WebAuthn.getCredentials", { authenticatorId });
  expect(credentials.map((c) => c.signCount)).toEqual([1]); // it did sign; the server said no
});
