// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { API_BASE_URL, createApiClient, setCsrfToken } from "../api/client";
import { SignInPage } from "./sign-in";
import { fromBase64Url, toBase64Url } from "./session";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const json = (status: number, body?: unknown) =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });
const failed = { type: "/problems/sign-in-failed", title: "Sign-in failed", status: 401 };
const bytes = (...n: number[]) => new Uint8Array(n).buffer;

let calls: { path: string; body: string }[];
let verifyOk: boolean;
let allow: { type: string; id: string }[];
let container: HTMLElement;
let root: Root;
let signedIn: () => void;

const client = () =>
  createApiClient({
    baseUrl: "http://localhost/api/v1",
    fetch: async (req) => {
      const path = new URL(req.url).pathname.replace(API_BASE_URL, "");
      calls.push({ path, body: await req.clone().text() });
      if (path === "/auth/break-glass/password") return new Response(null, { status: 204 });
      if (path === "/auth/second-factor/webauthn/challenge") {
        return json(200, {
          challenge: toBase64Url(bytes(1, 2, 3)),
          rpId: "console.test",
          timeoutMs: 60000,
          userVerification: "preferred",
          allowCredentials: allow,
        });
      }
      if (path === "/auth/second-factor/webauthn/verify") {
        return verifyOk ? new Response(null, { status: 204 }) : json(401, failed);
      }
      if (path === "/auth/csrf") return json(200, { header: "X-CSRF-Token", value: "c" });
      return json(404, { type: "about:blank", title: "nf", status: 404 });
    },
  });

const assertion = {
  rawId: bytes(251, 255, 0),
  type: "public-key",
  response: {
    authenticatorData: bytes(9, 8),
    clientDataJSON: bytes(7),
    signature: bytes(6, 5),
    userHandle: null,
  },
};
const store = (get: (o: CredentialRequestOptions) => Promise<unknown>) =>
  ({ get }) as unknown as CredentialsContainer;

const text = () => container.textContent ?? "";
const click = async (label: string) => {
  const b = [...container.querySelectorAll("button")].find((x) => x.textContent === label);
  await act(async () => b?.click());
};
async function reachSecondStep(credentials: CredentialsContainer) {
  await act(async () =>
    root.render(<SignInPage client={client()} onSignedIn={signedIn} credentials={credentials} />),
  );
  const set = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  for (const [label, value] of [
    ["Account name", "bg"],
    ["Password", "pw"],
  ] as const) {
    const l = [...container.querySelectorAll("label")].find((x) => x.textContent === label);
    const input = container.querySelector(`#${CSS.escape(l?.htmlFor ?? "")}`) as HTMLInputElement;
    await act(async () => {
      set?.call(input, value);
      input.dispatchEvent(new Event("input", { bubbles: true }));
    });
  }
  await act(async () => {
    container
      .querySelector("form")
      ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
}

beforeEach(() => {
  calls = [];
  verifyOk = true;
  allow = [{ type: "public-key", id: toBase64Url(bytes(251, 255, 0)) }];
  signedIn = vi.fn() as unknown as () => void;
  setCsrfToken(undefined);
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

describe("security key second factor", () => {
  it("asks for the challenge, sends the signed assertion as base64url, then loads the session", async () => {
    const get = vi.fn(async (o: CredentialRequestOptions) => {
      expect(o.publicKey?.rpId).toBe("console.test");
      expect(new Uint8Array(o.publicKey?.challenge as ArrayBuffer)).toEqual(
        new Uint8Array([1, 2, 3]),
      );
      expect(o.publicKey?.allowCredentials).toHaveLength(1);
      return assertion;
    });
    await reachSecondStep(store(get));
    await click("Use a security key");
    const verify = calls.find((c) => c.path === "/auth/second-factor/webauthn/verify");
    expect(JSON.parse(verify?.body ?? "{}")).toEqual({
      credentialId: "-_8A",
      authenticatorData: "CQg",
      clientDataJson: "Bw",
      signature: "BgU",
    });
    expect(calls.at(-1)?.path).toBe("/auth/csrf");
    expect(signedIn as ReturnType<typeof vi.fn>).toHaveBeenCalledOnce();
  });

  it("does not sign in when the server refuses the assertion, and starts over", async () => {
    verifyOk = false;
    await reachSecondStep(store(async () => assertion));
    await click("Use a security key");
    expect(signedIn as ReturnType<typeof vi.fn>).not.toHaveBeenCalled();
    expect(container.querySelector('[role="alert"]')?.textContent).toContain("Sign-in failed");
    expect(text()).toContain("Password");
  });

  it("keeps the code step when the user dismisses the key prompt", async () => {
    await reachSecondStep(
      store(async () => {
        throw new DOMException("denied", "NotAllowedError");
      }),
    );
    await click("Use a security key");
    expect(container.querySelector('[role="alert"]')?.textContent).toContain(
      "security key was not used",
    );
    expect(text()).toContain("Authenticator code");
    expect(calls.some((c) => c.path.endsWith("/webauthn/verify"))).toBe(false);
  });

  it("refuses when the account has no enrolled key, without prompting", async () => {
    allow = [];
    const get = vi.fn();
    await reachSecondStep(store(get));
    await click("Use a security key");
    expect(get).not.toHaveBeenCalled();
    expect(signedIn as ReturnType<typeof vi.fn>).not.toHaveBeenCalled();
  });
});

describe("base64url", () => {
  it("round-trips without padding and rejects other alphabets", () => {
    const b = bytes(251, 255, 0, 1);
    expect(toBase64Url(b)).toBe("-_8AAQ");
    expect(new Uint8Array(fromBase64Url("-_8AAQ"))).toEqual(new Uint8Array(b));
    expect(() => fromBase64Url("a+b/")).toThrow();
  });
});
