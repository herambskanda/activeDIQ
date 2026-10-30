// @vitest-environment jsdom
import { act } from "react";
import { createRoot, type Root } from "react-dom/client";
import { afterEach, beforeEach, describe, expect, it } from "vitest";

import { API_BASE_URL, createApiClient, setCsrfToken } from "../api/client";
import type { WebModule } from "./modules";
import { safeNext } from "./session";
import { Shell } from "./shell";

(globalThis as { IS_REACT_ACT_ENVIRONMENT?: boolean }).IS_REACT_ACT_ENVIRONMENT = true;

const json = (status: number, body?: unknown) =>
  new Response(body === undefined ? null : JSON.stringify(body), {
    status,
    headers: { "content-type": "application/json" },
  });

let hasSession: boolean;
let calls: { path: string; method: string; csrf: string | null; body: string }[];
let container: HTMLElement;
let root: Root;
let totpOk: boolean;

const client = () =>
  createApiClient({
    baseUrl: "http://localhost/api/v1",
    fetch: async (req) => {
      const path = new URL(req.url).pathname.replace(API_BASE_URL, "");
      calls.push({
        path,
        method: req.method,
        csrf: req.headers.get("X-CSRF-Token"),
        body: await req.clone().text(),
      });
      if (path === "/auth/csrf") {
        return hasSession
          ? json(200, { header: "X-CSRF-Token", value: "csrf-1" })
          : json(401, { type: "/problems/unauthenticated", title: "Unauthenticated", status: 401 });
      }
      if (path === "/auth/break-glass/password") {
        const ok = JSON.parse(await req.clone().text()).password === "right";
        return ok
          ? new Response(null, { status: 204 })
          : json(401, { type: "/problems/sign-in-failed", title: "Sign-in failed", status: 401 });
      }
      if (path === "/auth/second-factor/totp/verify") {
        if (!totpOk) {
          return json(401, {
            type: "/problems/sign-in-failed",
            title: "Sign-in failed",
            status: 401,
          });
        }
        hasSession = true;
        return new Response(null, { status: 204 });
      }
      return json(404, { type: "about:blank", title: "nf", status: 404 });
    },
  });

const modules: WebModule[] = [
  {
    id: "t",
    register: (r) => r.route({ path: "/directory/users", component: () => <p>Users screen</p> }),
  },
  {
    id: "u",
    register: (r) => r.route({ path: "/other", component: () => <p>Other screen</p> }),
  },
];

const text = () => container.textContent ?? "";
const setValue = (input: HTMLInputElement, value: string) => {
  const setter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value")?.set;
  setter?.call(input, value);
  input.dispatchEvent(new Event("input", { bubbles: true }));
};
const field = (label: string) => {
  const l = [...container.querySelectorAll("label")].find((x) => x.textContent === label);
  return container.querySelector(`#${CSS.escape(l?.htmlFor ?? "none")}`) as HTMLInputElement;
};
async function fill(label: string, value: string) {
  await act(async () => setValue(field(label), value));
}
async function submit() {
  await act(async () => {
    container
      .querySelector("form")
      ?.dispatchEvent(new Event("submit", { bubbles: true, cancelable: true }));
  });
}
async function mount() {
  await act(async () => root.render(<Shell modules={modules} client={client()} />));
}

beforeEach(() => {
  hasSession = false;
  totpOk = true;
  calls = [];
  setCsrfToken(undefined);
  window.history.replaceState(null, "", "/other?x=1");
  container = document.createElement("div");
  document.body.append(container);
  root = createRoot(container);
});
afterEach(async () => {
  await act(async () => root.unmount());
  container.remove();
});

describe("Shell session gate", () => {
  it("shows the sign-in screen when there is no session, keeping the requested address", async () => {
    await mount();
    expect(text()).toContain("Sign in to activeDIQ");
    expect(text()).not.toContain("Other screen");
    expect(window.location.pathname).toBe("/sign-in");
    expect(new URLSearchParams(window.location.search).get("next")).toBe("/other?x=1");
  });

  it("opens the requested screen at once when a session exists", async () => {
    hasSession = true;
    await mount();
    expect(text()).toContain("Other screen");
    expect(window.location.pathname).toBe("/other");
  });

  it("signs in with password then code, lands on the requested page and sends the CSRF value", async () => {
    await mount();
    await fill("Account name", "breakglass");
    await fill("Password", "right");
    await submit();
    expect(text()).toContain("Authenticator code");
    expect(calls.find((c) => c.path === "/auth/break-glass/password")?.body).toBe(
      JSON.stringify({ username: "breakglass", password: "right" }),
    );
    await fill("Authenticator code", "123456");
    await submit();
    expect(text()).toContain("Other screen");
    expect(window.location.pathname + window.location.search).toBe("/other?x=1");
    // The session's CSRF value is now attached to mutations.
    const c = client();
    await c.POST("/auth/logout");
    expect(calls.at(-1)?.csrf).toBe("csrf-1");
  });

  it("shows one generic error on a wrong password and stays on the form with the account kept", async () => {
    await mount();
    await fill("Account name", "breakglass");
    await fill("Password", "wrong");
    await submit();
    expect(container.querySelector('[role="alert"]')?.textContent).toContain("Sign-in failed");
    expect(field("Account name").value).toBe("breakglass");
    expect(text()).not.toContain("Authenticator code");
  });

  it("validates empty fields beside the field without calling the API", async () => {
    await mount();
    const before = calls.length;
    await submit();
    expect(text()).toContain("Enter your account name.");
    expect(calls.length).toBe(before);
  });

  it("starts over when the code is refused", async () => {
    totpOk = false;
    await mount();
    await fill("Account name", "breakglass");
    await fill("Password", "right");
    await submit();
    await fill("Authenticator code", "000000");
    await submit();
    expect(container.querySelector('[role="alert"]')?.textContent).toContain("Sign-in failed");
    expect(text()).toContain("Password");
  });
});

describe("safeNext", () => {
  it("follows only paths on this console", () => {
    expect(safeNext("/directory/users?q=a", "/h")).toBe("/directory/users?q=a");
    expect(safeNext("//evil.test", "/h")).toBe("/h");
    expect(safeNext("https://evil.test", "/h")).toBe("/h");
    expect(safeNext("/\\evil.test", "/h")).toBe("/h");
    expect(safeNext("/sign-in?next=/x", "/h")).toBe("/h");
    expect(safeNext(null, "/h")).toBe("/h");
  });
});
